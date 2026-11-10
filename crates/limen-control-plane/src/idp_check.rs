//! IdP-driven offboarding (ADR-0047).
//!
//! A login that handed over a refresh token is checked against the IdP every
//! few minutes. The IdP refusing the token ends that login (its person was
//! deactivated, or the IdP session was revoked); a refreshed ID token that no
//! longer grants a role the login relied on ends it too. Not reaching the IdP
//! keeps sessions and alerts, unless the deployment fails closed.
//!
//! The refresh token is sealed with AES-256-GCM under `--idp-token-key`, bound
//! to its login id, and never returned by any API, logged, or audited.

use std::collections::BTreeSet;
use std::time::Duration;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use limen_audit::{Context, EventKind};
use limen_core::secret::Secret;
use serde_json::json;
use sqlx::Row;
use time::OffsetDateTime;
use tokio::sync::watch;

use crate::config::IdpCheckFailure;
use crate::db::Db;
use crate::http_client::HttpClient;
use crate::services::ops;
use crate::state::AppState;

/// Logins claimed per tick, so one slow IdP cannot hold a whole fleet's checks.
const BATCH: i64 = 50;
/// The most one IdP call may take (the HTTP client's timeout).
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// The name on the lock a deactivation places. A lock by this name is lifted
/// when the IdP vouches for the person again at their next sign-in; any other
/// lock (an admin's) is never touched.
pub const LOCK_ACTOR: &str = "system:idp-check";
/// How often a replica looks for due logins.
const TICK: Duration = Duration::from_secs(20);

/// Whether refresh tokens are kept and checked: a key is set and the interval
/// is not zero.
#[must_use]
pub fn enabled(config: &crate::config::Config) -> bool {
    config.idp_token_key.is_some() && !config.idp_check_interval.is_zero()
}

// ---- sealing ----------------------------------------------------------------

/// `nonce (12) || ciphertext || tag`, with the login id as associated data so
/// a sealed token cannot be moved to another login's row.
pub fn seal(key: &[u8; 32], login_id: &str, token: &str) -> Result<Vec<u8>, String> {
    let sealing = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|e| e.to_string())?);
    let mut nonce = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|e| e.to_string())?;
    let mut buf = token.as_bytes().to_vec();
    sealing
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(login_id.as_bytes()),
            &mut buf,
        )
        .map_err(|e| e.to_string())?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&buf);
    Ok(out)
}

/// The inverse of [`seal`]. `None` for a wrong key, a different login id, or
/// damaged bytes.
#[must_use]
pub fn open(key: &[u8; 32], login_id: &str, sealed: &[u8]) -> Option<Secret<String>> {
    if sealed.len() < NONCE_LEN + AES_256_GCM.tag_len() {
        return None;
    }
    let (nonce, rest) = sealed.split_at(NONCE_LEN);
    let opening = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).ok()?);
    let mut buf = rest.to_vec();
    let plain = opening
        .open_in_place(
            Nonce::try_assume_unique_for_key(nonce).ok()?,
            Aad::from(login_id.as_bytes()),
            &mut buf,
        )
        .ok()?;
    String::from_utf8(plain.to_vec()).ok().map(Secret::new)
}

// ---- storage ----------------------------------------------------------------

/// A login due for a check.
#[derive(Debug, Clone)]
pub struct Tracked {
    pub login_id: String,
    pub username: String,
    pub refresh_token: Vec<u8>,
    pub groups: Vec<String>,
    pub expires_at: OffsetDateTime,
    pub last_ok_at: OffsetDateTime,
}

/// Seconds to the next check: the interval, spread by up to ±10% so a fleet
/// that logged in together does not ask the IdP together.
fn jittered_secs(interval: Duration) -> f64 {
    let spread = (rand::random::<f64>() - 0.5) * 0.2;
    interval.as_secs_f64() * (1.0 + spread)
}

/// Keep a login's sealed refresh token for checking.
pub async fn track(
    db: &Db,
    login_id: &str,
    username: &str,
    sealed: &[u8],
    groups: &[String],
    expires_at: OffsetDateTime,
    interval: Duration,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO idp_logins (login_id, username, refresh_token, groups, expires_at, next_check_at)
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))
         ON CONFLICT (login_id) DO NOTHING",
    )
    .bind(login_id)
    .bind(username)
    .bind(sealed)
    .bind(groups)
    .bind(expires_at)
    .bind(jittered_secs(interval))
    .execute(db)
    .await
    .map(|_| ())
}

/// Record where a person came from and whether this login is checked.
pub async fn note_user(
    db: &Db,
    username: &str,
    issuer: &str,
    checked: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE users SET issuer = $2, source = 'idp_login',
                idp_status = CASE WHEN $3 THEN 'ok' ELSE 'unchecked' END,
                idp_checked_at = CASE WHEN $3 THEN now() ELSE NULL END
         WHERE username = $1 AND actor_type = 'user'",
    )
    .bind(username)
    .bind(issuer)
    .bind(checked)
    .execute(db)
    .await
    .map(|_| ())
}

/// Claim the logins due for a check, pushing their next check out first, so
/// replicas never take the same login and a crash mid-check only delays it.
async fn claim_due(db: &Db, interval: Duration) -> Result<Vec<Tracked>, sqlx::Error> {
    // Long enough that a whole batch of slow calls finishes before another
    // replica can claim the same rows: two redemptions of one rotating token
    // would make the second look like a refusal.
    let claim_for = interval.max(CALL_TIMEOUT * u32::try_from(BATCH).unwrap_or(50) + CALL_TIMEOUT);
    sqlx::query(
        "UPDATE idp_logins SET next_check_at = now() + make_interval(secs => $2)
         WHERE login_id IN (
             SELECT login_id FROM idp_logins WHERE next_check_at <= now()
             ORDER BY next_check_at LIMIT $1 FOR UPDATE SKIP LOCKED)
         RETURNING login_id, username, refresh_token, groups, expires_at, last_ok_at",
    )
    .bind(BATCH)
    .bind(jittered_secs(claim_for))
    .fetch_all(db)
    .await?
    .iter()
    .map(|r| {
        Ok(Tracked {
            login_id: r.try_get("login_id")?,
            username: r.try_get("username")?,
            refresh_token: r.try_get("refresh_token")?,
            groups: r.try_get("groups")?,
            expires_at: r.try_get("expires_at")?,
            last_ok_at: r.try_get("last_ok_at")?,
        })
    })
    .collect()
}

async fn forget(db: &Db, login_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM idp_logins WHERE login_id = $1")
        .bind(login_id)
        .execute(db)
        .await
        .map(|_| ())
}

/// Drop the token of a login that has ended (logout) or run out.
pub async fn forget_login(db: &Db, login_id: &str) -> Result<(), sqlx::Error> {
    forget(db, login_id).await
}

async fn mark_ok(
    db: &Db,
    t: &Tracked,
    rotated: Option<&[u8]>,
    next: Duration,
) -> Result<(), sqlx::Error> {
    // The groups stay those the login was issued with: a role gained since
    // and lost again was never this login's.
    sqlx::query(
        "UPDATE idp_logins SET last_ok_at = now(),
                refresh_token = COALESCE($2, refresh_token),
                next_check_at = now() + make_interval(secs => $3)
         WHERE login_id = $1",
    )
    .bind(&t.login_id)
    .bind(rotated)
    .bind(jittered_secs(next))
    .execute(db)
    .await?;
    set_status(db, &t.username, "ok").await
}

async fn set_status(db: &Db, username: &str, status: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE users SET idp_status = $2, idp_checked_at = now()
         WHERE lower(username) = lower($1) AND actor_type = 'user'",
    )
    .bind(username)
    .bind(status)
    .execute(db)
    .await
    .map(|_| ())
}

/// Whether the user's status was already `check_failed`, so a long outage
/// raises one event per person and not one per check.
async fn already_failing(db: &Db, username: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT idp_status = 'check_failed' FROM users WHERE lower(username) = lower($1)",
    )
    .bind(username)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .unwrap_or(false)
}

// ---- the IdP ------------------------------------------------------------------

/// What a refresh grant told us.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// The IdP still vouches. The ID token and rotated refresh token, if sent.
    Valid {
        id_token: Option<Secret<String>>,
        refresh_token: Option<Secret<String>>,
    },
    /// The IdP refused the token (`invalid_grant`): the person is deactivated
    /// or the IdP session was revoked or expired.
    Refused(String),
    /// Could not be asked, or the answer made no sense.
    Unreachable(String),
}

/// Read a token endpoint's reply.
#[must_use]
pub fn interpret(status: u16, body: &[u8]) -> Answer {
    let json: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let text = |k: &str| json.get(k).and_then(|v| v.as_str()).map(str::to_owned);
    let secret = |k: &str| text(k).map(Secret::new);
    if status == 200 {
        return if text("id_token").is_some() || text("access_token").is_some() {
            Answer::Valid {
                id_token: secret("id_token"),
                refresh_token: secret("refresh_token"),
            }
        } else {
            Answer::Unreachable("the token endpoint answered without a token".into())
        };
    }
    match text("error").as_deref() {
        Some("invalid_grant") => Answer::Refused(text("error_description").map_or_else(
            || "invalid_grant".to_owned(),
            |d| {
                format!(
                    "invalid_grant: {}",
                    d.chars()
                        .filter(|c| !c.is_control())
                        .take(200)
                        .collect::<String>()
                )
            },
        )),
        Some(other) => Answer::Unreachable(format!("token endpoint error: {other}")),
        None => Answer::Unreachable(format!("token endpoint answered {status}")),
    }
}

/// Talks to the IdP's token endpoint.
#[derive(Debug)]
pub struct Idp {
    http: HttpClient,
    endpoint: tokio::sync::Mutex<Option<String>>,
}

impl Idp {
    pub fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            http: HttpClient::new()?,
            endpoint: tokio::sync::Mutex::new(None),
        })
    }

    /// The `token_endpoint`, from discovery, moved to the internal base URL
    /// when the IdP is reached at another address (as the JWKS is).
    async fn token_endpoint(&self, state: &AppState) -> Result<String, String> {
        let mut cached = self.endpoint.lock().await;
        if let Some(e) = cached.as_ref() {
            return Ok(e.clone());
        }
        let c = &state.config;
        let public = c.oidc_issuer.trim_end_matches('/');
        let internal = c
            .oidc_internal_url
            .as_deref()
            .unwrap_or(public)
            .trim_end_matches('/');
        let url = format!("{internal}/.well-known/openid-configuration");
        let doc: serde_json::Value = self
            .http
            .inner()
            .get(&url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| format!("discovery: {e}"))?
            .json()
            .await
            .map_err(|e| format!("discovery: {e}"))?;
        let endpoint = doc
            .get("token_endpoint")
            .and_then(|v| v.as_str())
            .ok_or("discovery has no token_endpoint")?;
        let endpoint = match endpoint.strip_prefix(public) {
            Some(path) => format!("{internal}{path}"),
            None => endpoint.to_owned(),
        };
        *cached = Some(endpoint.clone());
        Ok(endpoint)
    }

    pub async fn refresh(&self, state: &AppState, refresh_token: &str) -> Answer {
        let endpoint = match self.token_endpoint(state).await {
            Ok(e) => e,
            Err(e) => return Answer::Unreachable(e),
        };
        let reply = self
            .http
            .inner()
            .post(&endpoint)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", state.config.oidc_client_id.as_str()),
            ])
            .send()
            .await;
        let reply = match reply {
            Ok(r) => r,
            Err(e) => return Answer::Unreachable(format!("token endpoint: {}", e.without_url())),
        };
        let status = reply.status().as_u16();
        match reply.bytes().await {
            Ok(b) if b.len() <= 256 * 1024 => interpret(status, &b),
            Ok(_) => Answer::Unreachable("the token endpoint's reply was too large".into()),
            Err(e) => Answer::Unreachable(format!("token endpoint: {}", e.without_url())),
        }
    }
}

// ---- deciding -----------------------------------------------------------------

/// The roles `groups` map to under the current policy.
fn roles_of(state: &AppState, groups: &[String]) -> BTreeSet<String> {
    state
        .policy
        .current()
        .policy
        .roles_for_groups(
            groups.iter().map(String::as_str),
            &state.config.bootstrap_admin_groups,
        )
        .into_iter()
        .collect()
}

/// Roles a login had that its person's current groups no longer give.
#[must_use]
pub fn lost(before: &BTreeSet<String>, after: &BTreeSet<String>) -> Vec<String> {
    before.difference(after).cloned().collect()
}

/// End a login, audited first: if the event cannot be written the login
/// stays and the next check tries again.
async fn end_login(state: &AppState, t: &Tracked, reason: &str, deactivated: bool) {
    let emitted = state
        .audit
        .emit(
            EventKind::IdpOffboard,
            Context {
                user: Some(t.username.clone()),
                session_id: None,
            },
            json!({
                "action": "revoke_login",
                "login_id": t.login_id,
                "reason": reason,
                "deactivated": deactivated,
            }),
        )
        .await;
    if let Err(e) = emitted {
        tracing::error!(error = %e, user = %t.username, "audit unavailable; not ending the login yet");
        return;
    }
    if let Err(e) = crate::db::revoke_login(&state.db, &t.login_id, &t.username, t.expires_at).await
    {
        tracing::error!(error = %e, user = %t.username, "ending a login failed");
        return;
    }
    let _ = forget(&state.db, &t.login_id).await;
    if deactivated {
        // Lock them, so what a login does not cover (console and web sessions,
        // logins that sent no refresh token) ends too. The lock lifts itself
        // when the IdP vouches for them at their next sign-in.
        let lock_reason: String = format!("deactivated in the identity provider: {reason}")
            .chars()
            .filter(|c| !c.is_control())
            .take(400)
            .collect();
        if let Err(e) = crate::services::ops::lock_user(
            state,
            crate::services::ops::Actor {
                username: LOCK_ACTOR,
                via: "idp",
            },
            &t.username,
            &lock_reason,
        )
        .await
        {
            tracing::error!(error = %e, user = %t.username, "locking a deactivated person failed");
        }
        // Their other logins will be refused too: ask now, not in minutes.
        let _ = sqlx::query(
            "UPDATE idp_logins SET next_check_at = now() WHERE lower(username) = lower($1)",
        )
        .bind(&t.username)
        .execute(&state.db)
        .await;
        let _ = set_status(&state.db, &t.username, "offboarded").await;
    }
    metrics::counter!("limen_idp_offboards_total", "deactivated" => deactivated.to_string())
        .increment(1);
    tracing::warn!(user = %t.username, login = %t.login_id, reason, "login ended by the identity provider check");
}

async fn check_failed(state: &AppState, t: &Tracked, why: &str) {
    metrics::counter!("limen_idp_checks_total", "outcome" => "failed").increment(1);
    tracing::warn!(user = %t.username, why, "identity provider check failed");
    let grace_over = state.config.idp_check_failure == IdpCheckFailure::Closed
        && OffsetDateTime::now_utc() - t.last_ok_at
            > time::Duration::try_from(state.config.idp_check_grace)
                .unwrap_or(time::Duration::HOUR);
    if grace_over {
        end_login(
            state,
            t,
            "the identity provider could not be reached within the grace period",
            false,
        )
        .await;
        return;
    }
    if !already_failing(&state.db, &t.username).await {
        let _ = state
            .audit
            .emit(
                EventKind::IdpCheckFailed,
                Context {
                    user: Some(t.username.clone()),
                    session_id: None,
                },
                json!({ "login_id": t.login_id, "reason": why,
                        "failure_mode": format!("{:?}", state.config.idp_check_failure).to_lowercase() }),
            )
            .await;
    }
    // Ask again at the usual interval, not the longer claim.
    let _ = sqlx::query(
        "UPDATE idp_logins SET next_check_at = now() + make_interval(secs => $2) WHERE login_id = $1",
    )
    .bind(&t.login_id)
    .bind(jittered_secs(state.config.idp_check_interval))
    .execute(&state.db)
    .await;
    let _ = set_status(&state.db, &t.username, "check_failed").await;
}

/// Check one login.
async fn check_one(state: &AppState, idp: &Idp, key: &[u8; 32], t: Tracked) {
    let Some(token) = open(key, &t.login_id, &t.refresh_token) else {
        // The key changed or the row is damaged: nothing to check with.
        tracing::warn!(login = %t.login_id, "cannot open a sealed refresh token; dropping it");
        let _ = forget(&state.db, &t.login_id).await;
        return;
    };
    match idp.refresh(state, token.expose()).await {
        Answer::Refused(why) => {
            metrics::counter!("limen_idp_checks_total", "outcome" => "refused").increment(1);
            end_login(
                state,
                &t,
                &format!("the identity provider refused the session ({why})"),
                true,
            )
            .await;
        }
        Answer::Unreachable(why) => check_failed(state, &t, &why).await,
        Answer::Valid {
            id_token,
            refresh_token,
        } => {
            if let Some(raw) = id_token {
                match state.oidc.verify(raw.expose().clone(), None).await {
                    Ok(id) => {
                        if !id.username.eq_ignore_ascii_case(&t.username) {
                            end_login(
                                state,
                                &t,
                                "the refreshed ID token is for another user",
                                false,
                            )
                            .await;
                            return;
                        }
                        if !state.config.idp_ignore_groups {
                            let gone =
                                lost(&roles_of(state, &t.groups), &roles_of(state, &id.groups));
                            if !gone.is_empty() {
                                metrics::counter!("limen_idp_checks_total", "outcome" => "roles_lost")
                                    .increment(1);
                                end_login(
                                    state,
                                    &t,
                                    &format!("no longer in a group granting: {}", gone.join(", ")),
                                    false,
                                )
                                .await;
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        check_failed(state, &t, &format!("the refreshed ID token: {e}")).await;
                        return;
                    }
                }
            }
            let rotated = refresh_token.and_then(|r| seal(key, &t.login_id, r.expose()).ok());
            metrics::counter!("limen_idp_checks_total", "outcome" => "ok").increment(1);
            if let Err(e) = mark_ok(
                &state.db,
                &t,
                rotated.as_deref(),
                state.config.idp_check_interval,
            )
            .await
            {
                tracing::warn!(error = %e, "recording a successful check");
            }
        }
    }
}

/// The background job (every replica runs it; claims keep them apart).
/// How often the purge looks for people to delete.
const PURGE_EVERY: Duration = Duration::from_secs(3600);

/// Delete the record of people the IdP check disabled more than
/// `--idp-purge-after` ago and who never came back (a sign-in the IdP vouches
/// for lifts the lock, so a person still locked here has not). An admin's lock
/// never qualifies. Returns how many were deleted.
pub async fn purge_disabled(state: &AppState) -> usize {
    let after = state.config.idp_purge_after;
    if after.is_zero() {
        return 0;
    }
    let due: Vec<String> = match sqlx::query_scalar(
        "SELECT username FROM user_locks
         WHERE released_at IS NULL AND locked_by = $1
           AND locked_at < now() - make_interval(secs => $2)
         ORDER BY locked_at LIMIT $3",
    )
    .bind(LOCK_ACTOR)
    .bind(after.as_secs_f64())
    .bind(BATCH)
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "looking for disabled people to purge failed");
            return 0;
        }
    };
    let mut deleted = 0;
    for username in due {
        let reason = format!(
            "disabled by the identity provider check for more than {}",
            humantime_days(after)
        );
        match ops::delete_disabled_user(
            state,
            ops::Actor {
                username: LOCK_ACTOR,
                via: "idp",
            },
            &username,
            &reason,
        )
        .await
        {
            Ok(Ok(())) => deleted += 1,
            Ok(Err(why)) => tracing::debug!(user = %username, ?why, "not purged"),
            Err(e) => {
                tracing::warn!(user = %username, error = %e, "purging a disabled person failed");
            }
        }
    }
    if deleted > 0 {
        metrics::counter!("limen_idp_purged_total").increment(deleted as u64);
    }
    deleted
}

fn humantime_days(d: Duration) -> String {
    let days = d.as_secs() / 86_400;
    if days > 0 {
        format!("{days} days")
    } else {
        format!("{}s", d.as_secs())
    }
}

pub async fn job(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let interval = state.config.idp_check_interval;
    let key = match state.config.idp_token_key() {
        Ok(Some(k)) if !interval.is_zero() => k,
        _ => return,
    };
    let Ok(idp) = Idp::new() else {
        tracing::error!("cannot build the HTTP client for identity provider checks");
        return;
    };
    let mut tick = tokio::time::interval(interval.clamp(Duration::from_millis(200), TICK));
    let mut last_purge: Option<std::time::Instant> = None;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        if last_purge.is_none_or(|t| t.elapsed() >= PURGE_EVERY) {
            last_purge = Some(std::time::Instant::now());
            purge_disabled(&state).await;
        }
        let _ = sqlx::query("DELETE FROM idp_logins WHERE expires_at < now() - interval '1 hour'")
            .execute(&state.db)
            .await;
        match claim_due(&state.db, interval).await {
            Ok(due) => {
                for t in due {
                    check_one(&state, &idp, &key, t).await;
                }
            }
            Err(e) => tracing::warn!(error = %e, "claiming logins to check failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    #[test]
    fn a_sealed_token_opens_only_with_its_key_and_login() {
        let sealed = seal(&KEY, "login-1", "refresh-secret").expect("seal");
        assert!(
            !String::from_utf8_lossy(&sealed).contains("refresh-secret"),
            "the token is not stored in the clear"
        );
        assert_eq!(
            open(&KEY, "login-1", &sealed)
                .map(Secret::into_inner)
                .as_deref(),
            Some("refresh-secret")
        );
        assert_eq!(open(&KEY, "login-2", &sealed), None, "bound to its login");
        assert_eq!(open(&[8; 32], "login-1", &sealed), None, "wrong key");
        let mut damaged = sealed.clone();
        *damaged.last_mut().expect("bytes") ^= 1;
        assert_eq!(open(&KEY, "login-1", &damaged), None);
        assert_eq!(open(&KEY, "login-1", &[1, 2, 3]), None);
    }

    #[test]
    fn sealing_twice_gives_different_bytes() {
        let a = seal(&KEY, "l", "t").expect("seal");
        let b = seal(&KEY, "l", "t").expect("seal");
        assert_ne!(a, b);
    }

    #[test]
    fn invalid_grant_is_a_refusal_and_other_errors_are_not() {
        assert!(matches!(
            interpret(400, br#"{"error":"invalid_grant","error_description":"User is deactivated"}"#),
            Answer::Refused(r) if r.contains("deactivated")
        ));
        assert!(matches!(
            interpret(400, br#"{"error":"invalid_client"}"#),
            Answer::Unreachable(_)
        ));
        assert!(matches!(interpret(503, b"<html>"), Answer::Unreachable(_)));
        assert!(matches!(interpret(200, br"{}"), Answer::Unreachable(_)));
        assert!(matches!(
            interpret(200, br#"{"id_token":"a.b.c","refresh_token":"r2"}"#),
            Answer::Valid {
                id_token: Some(_),
                refresh_token: Some(_)
            }
        ));
    }

    #[test]
    fn only_lost_roles_count() {
        let set = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<BTreeSet<_>>();
        assert_eq!(
            lost(&set(&["a", "b"]), &set(&["a", "c"])),
            vec!["b".to_owned()]
        );
        assert_eq!(lost(&set(&["a"]), &set(&["a", "b"])).len(), 0);
    }
}

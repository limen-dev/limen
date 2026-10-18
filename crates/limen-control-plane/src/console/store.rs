//! Queries behind the console: users, sessions (a projection of the audit
//! stream), browser sessions, and in-flight logins.

use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::Db;

/// A session started more than this long ago without an end event is shown as
/// ended-unknown rather than active: its proxy must have died.
pub const ACTIVE_WINDOW_HOURS: i32 = 24;

// ---- users ----------------------------------------------------------------

/// Record a login. Called for every successful login, CLI or console.
pub async fn upsert_user(
    db: &Db,
    username: &str,
    subject: &str,
    roles: &[String],
    groups: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO users (username, subject, roles, groups) VALUES ($1, $2, $3, $4)
         ON CONFLICT (username) DO UPDATE SET subject = $2, roles = $3, groups = $4,
           last_login_at = now(), login_count = users.login_count + 1",
    )
    .bind(username)
    .bind(subject)
    .bind(roles)
    .bind(groups)
    .execute(db)
    .await
    .map(|_| ())
}

/// Record a bot's login: a row in `users` named `bot:<name>`, with the facts
/// about the run (ADR-0019). Returns `false`, changing nothing, when a row of
/// that name exists and isn't a bot's: a person's row is never taken over.
pub async fn upsert_bot(
    db: &Db,
    username: &str,
    subject: &str,
    roles: &[String],
    ci: &std::collections::BTreeMap<String, String>,
) -> Result<bool, sqlx::Error> {
    sqlx::query(
        "INSERT INTO users (username, subject, roles, groups, actor_type, last_ci)
         VALUES ($1, $2, $3, '{}', 'bot', $4)
         ON CONFLICT (username) DO UPDATE SET subject = $2, roles = $3,
           last_ci = $4, last_login_at = now(), login_count = users.login_count + 1
         WHERE users.actor_type = 'bot'",
    )
    .bind(username)
    .bind(subject)
    .bind(roles)
    .bind(serde_json::json!(ci))
    .execute(db)
    .await
    .map(|done| done.rows_affected() == 1)
}

#[derive(Debug, Clone)]
pub struct UserRow {
    pub username: String,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub first_login_at: OffsetDateTime,
    pub last_login_at: OffsetDateTime,
    pub login_count: i64,
    pub lock_reason: Option<String>,
    pub locked_by: Option<String>,
    pub locked_at: Option<OffsetDateTime>,
    /// `user` or `bot`.
    pub actor_type: String,
    /// The CI run of a bot's latest login.
    pub last_ci: Option<serde_json::Value>,
}

fn user_from_row(r: &sqlx::postgres::PgRow) -> Result<UserRow, sqlx::Error> {
    Ok(UserRow {
        username: r.try_get("username")?,
        roles: r.try_get("roles")?,
        groups: r.try_get("groups")?,
        first_login_at: r.try_get("first_login_at")?,
        last_login_at: r.try_get("last_login_at")?,
        login_count: r.try_get("login_count")?,
        lock_reason: r.try_get("lock_reason")?,
        locked_by: r.try_get("locked_by")?,
        locked_at: r.try_get("locked_at")?,
        actor_type: r.try_get("actor_type")?,
        last_ci: r.try_get("last_ci")?,
    })
}

macro_rules! user_select {
    () => {
        "SELECT u.username, u.roles, u.groups, u.first_login_at, u.last_login_at, u.login_count,
        l.reason AS lock_reason, l.locked_by, l.locked_at, u.actor_type, u.last_ci
     FROM users u LEFT JOIN user_locks l ON l.username = u.username AND l.released_at IS NULL"
    };
}

/// People. Bots are listed by [`list_bots`].
pub async fn list_users(db: &Db) -> Result<Vec<UserRow>, sqlx::Error> {
    sqlx::query(concat!(
        user_select!(),
        " WHERE u.actor_type = 'user' ORDER BY u.username"
    ))
    .fetch_all(db)
    .await?
    .iter()
    .map(user_from_row)
    .collect()
}

/// Bots that have logged in at least once (ADR-0019).
pub async fn list_bots(db: &Db) -> Result<Vec<UserRow>, sqlx::Error> {
    sqlx::query(concat!(
        user_select!(),
        " WHERE u.actor_type = 'bot' ORDER BY u.username"
    ))
    .fetch_all(db)
    .await?
    .iter()
    .map(user_from_row)
    .collect()
}

pub async fn user(db: &Db, username: &str) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query(concat!(user_select!(), " WHERE u.username = $1"))
        .bind(username)
        .fetch_optional(db)
        .await?
        .as_ref()
        .map(user_from_row)
        .transpose()
}

// ---- sessions -------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub session_id: Uuid,
    pub username: Option<String>,
    pub kind: Option<String>,
    pub resource: Option<String>,
    pub login: Option<String>,
    pub worker_id: Option<String>,
    pub proxy_id: Option<String>,
    pub client_addr: Option<String>,
    pub started_at: Option<OffsetDateTime>,
    pub ended_at: Option<OffsetDateTime>,
    pub end_reason: Option<String>,
    pub duration_ms: Option<i64>,
    pub bytes_in: Option<i64>,
    pub bytes_out: Option<i64>,
    pub recording_uri: Option<String>,
    pub recording_sha256: Option<String>,
    pub active: bool,
    /// `user` or `bot`.
    pub actor_type: String,
    /// The CI run, for a bot's session.
    pub ci: Option<serde_json::Value>,
}

macro_rules! session_select {
    () => {
        "SELECT session_id, username, kind, resource, login, worker_id, proxy_id, client_addr,
        started_at, ended_at, end_reason, duration_ms, bytes_in, bytes_out, recording_uri, recording_sha256,
        actor_type, ci,
        (ended_at IS NULL AND started_at IS NOT NULL AND started_at > now() - make_interval(hours => $1)) AS active
     FROM sessions"
    };
}

fn session_from_row(r: &sqlx::postgres::PgRow) -> Result<SessionRow, sqlx::Error> {
    Ok(SessionRow {
        session_id: r.try_get("session_id")?,
        username: r.try_get("username")?,
        kind: r.try_get("kind")?,
        resource: r.try_get("resource")?,
        login: r.try_get("login")?,
        worker_id: r.try_get("worker_id")?,
        proxy_id: r.try_get("proxy_id")?,
        client_addr: r.try_get("client_addr")?,
        started_at: r.try_get("started_at")?,
        ended_at: r.try_get("ended_at")?,
        end_reason: r.try_get("end_reason")?,
        duration_ms: r.try_get("duration_ms")?,
        bytes_in: r.try_get("bytes_in")?,
        bytes_out: r.try_get("bytes_out")?,
        recording_uri: r.try_get("recording_uri")?,
        recording_sha256: r.try_get("recording_sha256")?,
        active: r.try_get("active")?,
        actor_type: r.try_get("actor_type")?,
        ci: r.try_get("ci")?,
    })
}

#[derive(Debug, Clone, Default)]
pub struct SessionFilter {
    pub username: Option<String>,
    pub resource: Option<String>,
    pub active_only: bool,
    pub limit: i64,
    pub offset: i64,
}

/// Newest first. Fetches one more than `limit` so the caller can tell if
/// there is another page.
pub async fn list_sessions(db: &Db, f: &SessionFilter) -> Result<Vec<SessionRow>, sqlx::Error> {
    sqlx::query(concat!(
        session_select!(),
        "
         WHERE ($2::text IS NULL OR username = $2)
           AND ($6::text IS NULL OR resource = $6)
           AND (NOT $3 OR (ended_at IS NULL AND started_at > now() - make_interval(hours => $1)))
         ORDER BY COALESCE(started_at, ended_at) DESC, session_id DESC
         LIMIT $4 OFFSET $5"
    ))
    .bind(ACTIVE_WINDOW_HOURS)
    .bind(&f.username)
    .bind(f.active_only)
    .bind(f.limit + 1)
    .bind(f.offset)
    .bind(&f.resource)
    .fetch_all(db)
    .await?
    .iter()
    .map(session_from_row)
    .collect()
}

pub async fn session(db: &Db, id: Uuid) -> Result<Option<SessionRow>, sqlx::Error> {
    sqlx::query(concat!(session_select!(), " WHERE session_id = $2"))
        .bind(ACTIVE_WINDOW_HOURS)
        .bind(id)
        .fetch_optional(db)
        .await?
        .as_ref()
        .map(session_from_row)
        .transpose()
}

/// Sessions per resource: (all time, active now).
pub async fn session_counts_by_resource(
    db: &Db,
) -> Result<std::collections::HashMap<String, (i64, i64)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT resource, count(*) AS total,
                count(*) FILTER (WHERE ended_at IS NULL AND started_at > now() - make_interval(hours => $1)) AS active
         FROM sessions WHERE resource IS NOT NULL GROUP BY resource",
    )
    .bind(ACTIVE_WINDOW_HOURS)
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|r| {
            Ok((
                r.try_get::<String, _>("resource")?,
                (
                    r.try_get::<i64, _>("total")?,
                    r.try_get::<i64, _>("active")?,
                ),
            ))
        })
        .collect()
}

pub async fn active_session_count(db: &Db) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM sessions WHERE ended_at IS NULL AND started_at > now() - make_interval(hours => $1)",
    )
    .bind(ACTIVE_WINDOW_HOURS)
    .fetch_one(db)
    .await
}

// ---- projection of audit events -------------------------------------------

fn text<'a>(data: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    data.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

fn number(data: &serde_json::Value, key: &str) -> Option<i64> {
    data.get(key).and_then(serde_json::Value::as_i64)
}

/// Data fields that may appear in the console's audit trail, in display
/// order. Everything else (statements, claims, groups) stays in the sinks.
const SUMMARY_KEYS: [&str; 17] = [
    "action",
    "target_user",
    "component_id",
    "kind",
    "resource",
    "login",
    "reason",
    "by",
    "via",
    "worker_id",
    "bot",
    "method",
    // kube.request
    "verb",
    "k8s_resource",
    "namespace",
    "name",
    "status",
];

/// Facts about a bot's CI run that may appear in the trail.
const CI_SUMMARY_KEYS: [&str; 4] = ["repository", "project_path", "ref", "run_id"];

/// The wire name of an event kind, such as `auth.login`.
fn kind_name(kind: limen_audit::EventKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn summarize(data: &serde_json::Value) -> String {
    let mut parts: Vec<String> = SUMMARY_KEYS
        .iter()
        .filter_map(|k| text(data, k).map(|v| format!("{k}={v}")))
        .collect();
    if let Some(ci) = data.get("ci") {
        parts.extend(
            CI_SUMMARY_KEYS
                .iter()
                .filter_map(|k| text(ci, k).map(|v| format!("{k}={v}"))),
        );
    }
    let mut out = parts.join("  ");
    if out.len() > 300 {
        let mut end = 300;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.push('…');
    }
    out
}

/// Apply session events to the `sessions` table. Idempotent and
/// order-independent: every column is filled by exactly one kind of event
/// and never overwritten by another, so redelivery and reordering are safe.
pub async fn project_events(db: &Db, events: &[limen_audit::Event]) -> Result<(), sqlx::Error> {
    use limen_audit::EventKind;
    let mut tx = db.begin().await?;
    for e in events {
        sqlx::query(
            "INSERT INTO audit_events (event_id, at, kind, username, session_id, summary)
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (event_id) DO NOTHING",
        )
        .bind(e.event_id)
        .bind(e.time)
        .bind(kind_name(e.kind))
        .bind(&e.user)
        .bind(e.session_id)
        .bind(summarize(&e.data))
        .execute(&mut *tx)
        .await?;
        if e.kind == EventKind::KubeRequest {
            sqlx::query(
                "INSERT INTO kube_requests (event_id, at, username, session_id, cluster, verb, api_group, resource,
                                            subresource, namespace, name, method, status, latency_ms, error)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                 ON CONFLICT (event_id) DO NOTHING",
            )
            .bind(e.event_id)
            .bind(e.time)
            .bind(&e.user)
            .bind(e.session_id)
            .bind(text(&e.data, "resource").unwrap_or_default())
            .bind(text(&e.data, "verb").unwrap_or_default())
            .bind(text(&e.data, "k8s_group").unwrap_or_default())
            .bind(text(&e.data, "k8s_resource").unwrap_or_default())
            .bind(text(&e.data, "subresource").unwrap_or_default())
            .bind(text(&e.data, "namespace").unwrap_or_default())
            .bind(text(&e.data, "name").unwrap_or_default())
            .bind(text(&e.data, "method").unwrap_or_default())
            .bind(i32::try_from(number(&e.data, "status").unwrap_or(0)).unwrap_or(0))
            .bind(number(&e.data, "latency_ms"))
            .bind(text(&e.data, "error"))
            .execute(&mut *tx)
            .await?;
        }
        let Some(session_id) = e.session_id else {
            continue;
        };
        match e.kind {
            EventKind::SessionStart => {
                sqlx::query(
                    "INSERT INTO sessions (session_id, username, kind, resource, login, worker_id, proxy_id, client_addr, started_at, actor_type, ci)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                     ON CONFLICT (session_id) DO UPDATE SET username = EXCLUDED.username, kind = EXCLUDED.kind,
                       resource = EXCLUDED.resource, login = EXCLUDED.login, worker_id = EXCLUDED.worker_id,
                       proxy_id = EXCLUDED.proxy_id, client_addr = EXCLUDED.client_addr, started_at = EXCLUDED.started_at,
                       actor_type = EXCLUDED.actor_type, ci = EXCLUDED.ci",
                )
                .bind(session_id)
                .bind(&e.user)
                .bind(text(&e.data, "kind"))
                .bind(text(&e.data, "resource"))
                .bind(text(&e.data, "login"))
                .bind(text(&e.data, "worker_id"))
                .bind(text(&e.data, "proxy_id"))
                .bind(text(&e.data, "client_addr"))
                .bind(e.time)
                .bind(text(&e.data, "actor_type").unwrap_or("user"))
                .bind(e.data.get("ci").filter(|c| c.is_object()))
                .execute(&mut *tx)
                .await?;
            }
            EventKind::SessionEnd => {
                sqlx::query(
                    "INSERT INTO sessions (session_id, username, kind, resource, login, worker_id, ended_at, end_reason, duration_ms, bytes_in, bytes_out, recording_sha256, actor_type)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                     ON CONFLICT (session_id) DO UPDATE SET ended_at = EXCLUDED.ended_at, end_reason = EXCLUDED.end_reason,
                       duration_ms = EXCLUDED.duration_ms, bytes_in = EXCLUDED.bytes_in, bytes_out = EXCLUDED.bytes_out,
                       recording_sha256 = EXCLUDED.recording_sha256,
                       username = COALESCE(sessions.username, EXCLUDED.username),
                       resource = COALESCE(sessions.resource, EXCLUDED.resource),
                       login = COALESCE(sessions.login, EXCLUDED.login),
                       kind = COALESCE(sessions.kind, EXCLUDED.kind),
                       worker_id = COALESCE(sessions.worker_id, EXCLUDED.worker_id)",
                )
                .bind(session_id)
                .bind(&e.user)
                .bind(text(&e.data, "kind"))
                .bind(text(&e.data, "resource"))
                .bind(text(&e.data, "login"))
                .bind(text(&e.data, "worker_id"))
                .bind(e.time)
                .bind(text(&e.data, "reason"))
                .bind(number(&e.data, "duration_ms"))
                .bind(number(&e.data, "bytes_in"))
                .bind(number(&e.data, "bytes_out"))
                .bind(text(&e.data, "recording_sha256"))
                .bind(text(&e.data, "actor_type").unwrap_or("user"))
                .execute(&mut *tx)
                .await?;
            }
            EventKind::SessionRecording => {
                sqlx::query(
                    "INSERT INTO sessions (session_id, username, recording_uri) VALUES ($1, $2, $3)
                     ON CONFLICT (session_id) DO UPDATE SET recording_uri = EXCLUDED.recording_uri",
                )
                .bind(session_id)
                .bind(&e.user)
                .bind(text(&e.data, "recording_uri"))
                .execute(&mut *tx)
                .await?;
            }
            _ => {}
        }
    }
    tx.commit().await
}

// ---- browser sessions and logins -------------------------------------------

#[derive(Debug, Clone)]
pub struct ConsoleSession {
    pub username: String,
    pub roles: Vec<String>,
    pub login_id: String,
    pub csrf: String,
    pub expires_at: OffsetDateTime,
}

pub async fn create_console_session(
    db: &Db,
    token_hash: &[u8],
    s: &ConsoleSession,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO console_sessions (token_hash, username, roles, login_id, csrf, expires_at) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(token_hash)
    .bind(&s.username)
    .bind(&s.roles)
    .bind(&s.login_id)
    .bind(&s.csrf)
    .bind(s.expires_at)
    .execute(db)
    .await
    .map(|_| ())
}

pub async fn console_session(
    db: &Db,
    token_hash: &[u8],
) -> Result<Option<ConsoleSession>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT username, roles, login_id, csrf, expires_at FROM console_sessions WHERE token_hash = $1 AND expires_at > now()",
    )
    .bind(token_hash)
    .fetch_optional(db)
    .await?;
    row.map(|r| {
        Ok(ConsoleSession {
            username: r.try_get("username")?,
            roles: r.try_get("roles")?,
            login_id: r.try_get("login_id")?,
            csrf: r.try_get("csrf")?,
            expires_at: r.try_get("expires_at")?,
        })
    })
    .transpose()
}

pub async fn delete_console_session(db: &Db, token_hash: &[u8]) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM console_sessions WHERE token_hash = $1")
        .bind(token_hash)
        .execute(db)
        .await
        .map(|_| ())
}

/// End every browser session a user has (when they are locked).
pub async fn delete_console_sessions_of(db: &Db, username: &str) -> Result<u64, sqlx::Error> {
    sqlx::query("DELETE FROM console_sessions WHERE username = $1")
        .bind(username)
        .execute(db)
        .await
        .map(|r| r.rows_affected())
}

pub async fn insert_login(
    db: &Db,
    state_hash: &[u8],
    nonce: &str,
    pkce_verifier: &str,
    expires_at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO console_logins (state_hash, nonce, pkce_verifier, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(state_hash)
        .bind(nonce)
        .bind(pkce_verifier)
        .bind(expires_at)
        .execute(db)
        .await
        .map(|_| ())
}

/// Take (and delete) the login state, once. `None` if unknown or expired.
pub async fn take_login(
    db: &Db,
    state_hash: &[u8],
) -> Result<Option<(String, String)>, sqlx::Error> {
    let row = sqlx::query(
        "DELETE FROM console_logins WHERE state_hash = $1 RETURNING nonce, pkce_verifier, expires_at",
    )
    .bind(state_hash)
    .fetch_optional(db)
    .await?;
    let Some(r) = row else { return Ok(None) };
    let expires_at: OffsetDateTime = r.try_get("expires_at")?;
    if expires_at < OffsetDateTime::now_utc() {
        return Ok(None);
    }
    Ok(Some((r.try_get("nonce")?, r.try_get("pkce_verifier")?)))
}

/// Bot sessions started in the last 30 days, by bot.
pub async fn bot_session_counts(db: &Db) -> Result<Vec<(String, i64)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT username, count(*) AS n FROM sessions
         WHERE actor_type = 'bot' AND username IS NOT NULL AND started_at > now() - interval '30 days'
         GROUP BY username",
    )
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|r| Ok((r.try_get("username")?, r.try_get("n")?)))
        .collect()
}

// ---- the audit trail ---------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EventRow {
    pub at: OffsetDateTime,
    pub kind: String,
    pub username: Option<String>,
    pub session_id: Option<Uuid>,
    pub summary: String,
}

/// Newest first. `limit` rows starting at `offset`.
pub async fn list_events(
    db: &Db,
    username: Option<&str>,
    kind: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<EventRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT at, kind, username, session_id, summary FROM audit_events
         WHERE ($1::text IS NULL OR username = $1) AND ($2::text IS NULL OR kind = $2)
         ORDER BY at DESC, event_id DESC LIMIT $3 OFFSET $4",
    )
    .bind(username)
    .bind(kind)
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(EventRow {
                at: r.try_get("at")?,
                kind: r.try_get("kind")?,
                username: r.try_get("username")?,
                session_id: r.try_get("session_id")?,
                summary: r.try_get("summary")?,
            })
        })
        .collect()
}

/// The kinds seen in the trail, for the filter.
pub async fn event_kinds(db: &Db) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT DISTINCT kind FROM audit_events ORDER BY kind")
        .fetch_all(db)
        .await
}

// ---- Kubernetes requests --------------------------------------------------------

#[derive(Debug, Clone)]
pub struct KubeRow {
    pub at: OffsetDateTime,
    pub username: Option<String>,
    pub session_id: Option<Uuid>,
    pub cluster: String,
    pub verb: String,
    pub api_group: String,
    pub resource: String,
    pub subresource: String,
    pub namespace: String,
    pub name: String,
    pub method: String,
    pub status: i32,
    pub latency_ms: Option<i64>,
    pub error: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct KubeFilter {
    pub username: Option<String>,
    pub cluster: Option<String>,
    pub namespace: Option<String>,
    pub verb: Option<String>,
    /// Only requests the cluster (or Limen) refused or failed: status 400 and up.
    pub problems_only: bool,
    pub limit: i64,
    pub offset: i64,
}

/// Newest first.
pub async fn list_kube_requests(db: &Db, f: &KubeFilter) -> Result<Vec<KubeRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT at, username, session_id, cluster, verb, api_group, resource, subresource, namespace, name,
                method, status, latency_ms, error
         FROM kube_requests
         WHERE ($1::text IS NULL OR username = $1) AND ($2::text IS NULL OR cluster = $2)
           AND ($3::text IS NULL OR namespace = $3) AND ($4::text IS NULL OR verb = $4)
           AND (NOT $5 OR status >= 400)
         ORDER BY at DESC, event_id DESC LIMIT $6 OFFSET $7",
    )
    .bind(&f.username)
    .bind(&f.cluster)
    .bind(&f.namespace)
    .bind(&f.verb)
    .bind(f.problems_only)
    .bind(f.limit + 1)
    .bind(f.offset)
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(KubeRow {
                at: r.try_get("at")?,
                username: r.try_get("username")?,
                session_id: r.try_get("session_id")?,
                cluster: r.try_get("cluster")?,
                verb: r.try_get("verb")?,
                api_group: r.try_get("api_group")?,
                resource: r.try_get("resource")?,
                subresource: r.try_get("subresource")?,
                namespace: r.try_get("namespace")?,
                name: r.try_get("name")?,
                method: r.try_get("method")?,
                status: r.try_get("status")?,
                latency_ms: r.try_get("latency_ms")?,
                error: r.try_get("error")?,
            })
        })
        .collect()
}

/// The clusters and verbs seen, for the filters.
pub async fn kube_filter_options(db: &Db) -> Result<(Vec<String>, Vec<String>), sqlx::Error> {
    let clusters = sqlx::query_scalar("SELECT DISTINCT cluster FROM kube_requests ORDER BY cluster")
        .fetch_all(db)
        .await?;
    let verbs = sqlx::query_scalar("SELECT DISTINCT verb FROM kube_requests ORDER BY verb")
        .fetch_all(db)
        .await?;
    Ok((clusters, verbs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_keeps_only_listed_fields() {
        let data = serde_json::json!({
            "reason": "stolen laptop",
            "target_user": "developer@example.com",
            "statement": "select * from secrets where token = 'abc'",
            "groups": ["sre"],
            "idp_subject": "subject-123",
        });
        let summary = summarize(&data);
        assert_eq!(
            summary,
            "target_user=developer@example.com  reason=stolen laptop"
        );
        assert!(!summary.contains("secrets") && !summary.contains("subject"));
    }

    #[test]
    fn summary_is_capped_on_a_character_boundary() {
        let data = serde_json::json!({ "reason": "é".repeat(400) });
        let summary = summarize(&data);
        assert!(summary.chars().count() < 305);
        assert!(summary.ends_with('…'));
    }

    #[test]
    fn kind_names_match_the_wire_format() {
        assert_eq!(kind_name(limen_audit::EventKind::AuthLogin), "auth.login");
        assert_eq!(kind_name(limen_audit::EventKind::UserLock), "user.lock");
    }
}

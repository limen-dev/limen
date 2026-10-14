//! Admin actions shared by the gRPC API and the web console, so both do the
//! same checks and write the same audit events (ADR-0017). Callers have
//! already checked that the actor is an admin.

use std::collections::BTreeMap;
use std::time::Duration;

use limen_audit::{Context, EventKind};
use limen_core::labels::Labels;
use serde_json::json;
use time::OffsetDateTime;
use tonic::Status;
use uuid::Uuid;

use super::{admin, sha256};
use crate::db;
use crate::state::{AppState, internal, unix};

pub const DEFAULT_TOKEN_TTL: Duration = Duration::from_mins(15);
pub const MAX_TOKEN_TTL: Duration = Duration::from_hours(24);

/// Who is acting, and through what.
#[derive(Debug, Clone, Copy)]
pub struct Actor<'a> {
    pub username: &'a str,
    /// `api` (CLI or CI) or `console`.
    pub via: &'static str,
}

/// Audit an admin action. If the event can't be written the error says so:
/// the change itself has already been applied.
async fn audit(
    state: &AppState,
    kind: EventKind,
    actor: Actor<'_>,
    session_id: Option<Uuid>,
    mut data: serde_json::Value,
) -> Result<(), Status> {
    data["by"] = json!(actor.username);
    data["via"] = json!(actor.via);
    state
        .audit
        .emit(
            kind,
            Context {
                user: Some(actor.username.to_owned()),
                session_id,
            },
            data,
        )
        .await
        .map(|_| ())
        .map_err(|e| {
            tracing::error!(error = %e, "audit unavailable for an admin action");
            Status::unavailable("the change was applied but audit is unavailable")
        })
}

/// Reasons are free text shown to admins and stored in audit.
pub fn clean_reason(reason: &str) -> Result<String, Status> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(Status::invalid_argument("a reason is required"));
    }
    if reason.len() > 500 || reason.chars().any(char::is_control) {
        return Err(Status::invalid_argument(
            "reason must be at most 500 characters, without control characters",
        ));
    }
    Ok(reason.to_owned())
}

pub async fn lock_user(
    state: &AppState,
    actor: Actor<'_>,
    username: &str,
    reason: &str,
) -> Result<bool, Status> {
    let username = username.trim();
    if username.is_empty() || username.len() > 256 {
        return Err(Status::invalid_argument("username is required"));
    }
    let reason = clean_reason(reason)?;
    let locked = db::lock_user(&state.db, username, &reason, actor.username)
        .await
        .map_err(|e| internal("locking user", e))?;
    if locked {
        tracing::warn!(user = username, by = actor.username, via = actor.via, %reason, "user locked");
        audit(
            state,
            EventKind::UserLock,
            actor,
            None,
            json!({ "target_user": username, "reason": reason }),
        )
        .await?;
    }
    Ok(locked)
}

pub async fn unlock_user(
    state: &AppState,
    actor: Actor<'_>,
    username: &str,
) -> Result<bool, Status> {
    let username = username.trim();
    let unlocked = db::unlock_user(&state.db, username, actor.username)
        .await
        .map_err(|e| internal("unlocking user", e))?;
    if unlocked {
        tracing::info!(
            user = username,
            by = actor.username,
            via = actor.via,
            "user unlocked"
        );
        audit(
            state,
            EventKind::UserUnlock,
            actor,
            None,
            json!({ "target_user": username }),
        )
        .await?;
    }
    Ok(unlocked)
}

pub async fn kill_session(
    state: &AppState,
    actor: Actor<'_>,
    session_id: &str,
    reason: &str,
) -> Result<bool, Status> {
    let session_id = Uuid::parse_str(session_id.trim())
        .map_err(|_| Status::invalid_argument("session_id must be a session UUID"))?;
    let reason = clean_reason(reason)?;
    let killed = db::kill_session(&state.db, &session_id.to_string(), &reason, actor.username)
        .await
        .map_err(|e| internal("killing session", e))?;
    if killed {
        tracing::warn!(session = %session_id, by = actor.username, via = actor.via, %reason, "session kill requested");
        audit(
            state,
            EventKind::SessionKill,
            actor,
            Some(session_id),
            json!({ "reason": reason }),
        )
        .await?;
    }
    Ok(killed)
}

pub async fn revoke_component(
    state: &AppState,
    actor: Actor<'_>,
    component_id: &str,
    reason: &str,
) -> Result<bool, Status> {
    let component_id = component_id.trim();
    let reason = clean_reason(reason)?;
    if db::component(&state.db, component_id)
        .await
        .map_err(|e| internal("loading component", e))?
        .is_none()
    {
        return Err(Status::not_found("no such component"));
    }
    let revoked = db::revoke_component(&state.db, component_id, actor.username)
        .await
        .map_err(|e| internal("revoking component", e))?;
    if revoked {
        tracing::warn!(component = component_id, by = actor.username, via = actor.via, %reason, "component revoked");
        audit(
            state,
            EventKind::ComponentRevoke,
            actor,
            None,
            json!({ "component_id": component_id, "reason": reason }),
        )
        .await?;
    }
    Ok(revoked)
}

/// Create a single-use join token. Returns the token and its expiry.
pub async fn create_join_token(
    state: &AppState,
    actor: Actor<'_>,
    kind: &str,
    labels: &BTreeMap<String, String>,
    ttl: Option<Duration>,
    dns_names: &[String],
) -> Result<(String, OffsetDateTime), Status> {
    if !matches!(kind, "proxy" | "worker") {
        return Err(Status::invalid_argument("kind must be proxy or worker"));
    }
    if kind == "worker" && !dns_names.is_empty() {
        return Err(Status::invalid_argument(
            "worker certificates carry no DNS names",
        ));
    }
    let labels =
        Labels::try_from(labels.clone()).map_err(|e| Status::invalid_argument(e.to_string()))?;
    let ttl = ttl.unwrap_or(DEFAULT_TOKEN_TTL);
    if ttl > MAX_TOKEN_TTL {
        return Err(Status::invalid_argument("ttl must be at most 24h"));
    }
    let token = admin::new_token();
    let expires_at = OffsetDateTime::now_utc() + ttl;
    let labels_json = serde_json::to_value(&labels).map_err(|e| internal("labels", e))?;
    db::insert_join_token(
        &state.db,
        &sha256(token.as_bytes()),
        kind,
        &labels_json,
        dns_names,
        actor.username,
        expires_at,
    )
    .await
    .map_err(|e| internal("storing join token", e))?;
    audit(
        state,
        EventKind::JoinTokenCreate,
        actor,
        None,
        json!({ "kind": kind, "labels": labels, "dns_names": dns_names, "expires_at": unix(expires_at) }),
    )
    .await?;
    Ok((token, expires_at))
}

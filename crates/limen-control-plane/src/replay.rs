//! Replay recorded sessions against a proposed policy (ADR-0050).
//!
//! Reads the `sessions` projection, `users` and `access_grants`, turns each
//! group of sessions into a [`ReplayRecord`] and hands them to
//! [`limen_policy::Policy::replay`], the same decision code as enforcement.
//! **Every replay is audited before it runs** (who, window, policy digests;
//! never the sessions) and rate limited, because a replay is also a way to
//! read who used what.

use std::collections::{BTreeMap, BTreeSet};

use limen_audit::{Context, EventKind};
use limen_core::identity::BOT_PREFIX;
use limen_policy::Policy;
use limen_policy::replay::{Holder, ReplayRecord, ReplayReport, principal_from_session};
use serde_json::json;
use sqlx::Row;
use time::OffsetDateTime;
use tonic::Status;
use uuid::Uuid;

use crate::state::{AppState, internal};

/// The longest window. The console's audit copy (which tells when a resource
/// was relabelled) is trimmed after 30 days.
pub const MAX_DAYS: u32 = 30;
/// The most groups of sessions replayed. More is reported as truncated.
pub const MAX_GROUPS: usize = 20_000;

/// Who is asking.
#[derive(Debug, Clone, Copy)]
pub struct Asker<'a> {
    pub username: &'a str,
    /// `api` or `console`.
    pub via: &'static str,
}

struct Group {
    username: String,
    kind: Option<String>,
    resource: String,
    upstream: Option<String>,
    database: Option<String>,
    request_ids: Vec<Uuid>,
    sessions: u64,
    first: i64,
    last: i64,
}

/// Replay the last `days` days of sessions: `active` is what decides today,
/// `proposed` what would.
pub async fn replay(
    state: &AppState,
    who: Asker<'_>,
    active: &Policy,
    proposed: &Policy,
    days: u32,
) -> Result<ReplayReport, Status> {
    if days == 0 || days > MAX_DAYS {
        return Err(Status::invalid_argument(format!(
            "the replay window is 1 to {MAX_DAYS} days"
        )));
    }
    state.limits.check_replay(who.username)?;
    // Recorded before the replay runs: one that can't be audited doesn't happen.
    let context = || Context {
        user: Some(who.username.to_owned()),
        session_id: None,
    };
    state
        .audit
        .emit(
            EventKind::PolicyReplay,
            context(),
            json!({
                "phase": "start", "via": who.via, "window_days": days,
                "active_digest": active.digest(), "proposed_digest": proposed.digest(),
            }),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "audit unavailable; refusing a policy replay");
            Status::unavailable("audit unavailable")
        })?;
    metrics::counter!("limen_policy_replays_total").increment(1);

    let (mut report, groups_found) = match run(state, active, proposed, days).await {
        Ok(done) => done,
        Err(e) => {
            // Leave an outcome next to the start event.
            let _ = state
                .audit
                .emit(
                    EventKind::PolicyReplay,
                    context(),
                    json!({ "phase": "failed", "via": who.via, "window_days": days }),
                )
                .await;
            return Err(e);
        }
    };
    report.window_days = days;
    // The counts, for the record. The start event is what must not be lost.
    if let Err(e) = state
        .audit
        .emit(
            EventKind::PolicyReplay,
            context(),
            json!({
                "phase": "done", "via": who.via, "window_days": days,
                "groups": groups_found, "examined": report.examined,
                "affected_sessions": report.affected_sessions,
                "already_refused": report.already_refused,
                "skipped": report.skipped_total(), "truncated": report.truncated,
            }),
        )
        .await
    {
        tracing::warn!(error = %e, "could not record the result of a policy replay");
    }
    Ok(report)
}

async fn run(
    state: &AppState,
    active: &Policy,
    proposed: &Policy,
    days: u32,
) -> Result<(ReplayReport, usize), Status> {
    let (groups, truncated) = load_groups(state, days).await?;
    let found = groups.len();
    let mut report = ReplayReport {
        truncated,
        ..ReplayReport::default()
    };
    // Rows without a user or a resource (a session.end that arrived first,
    // say) can't be replayed; they are counted, not dropped.
    let unattributed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sessions
         WHERE started_at >= now() - make_interval(days => $1)
           AND (username IS NULL OR resource IS NULL)",
    )
    .bind(i32::try_from(days).unwrap_or(i32::MAX))
    .fetch_one(&state.db)
    .await
    .map_err(|e| internal("reading sessions to replay", e))?;
    report.skip(
        "session rows without a recorded user or resource",
        u64::try_from(unattributed).unwrap_or(0),
    );

    let people: Vec<String> = groups
        .iter()
        .filter(|g| !g.username.starts_with(BOT_PREFIX))
        .map(|g| g.username.to_lowercase())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let user_groups = load_user_groups(state, &people).await?;
    let ids: Vec<Uuid> = groups
        .iter()
        .flat_map(|g| g.request_ids.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let grants = load_grants(state, &ids).await?;

    let mut records = Vec::with_capacity(groups.len());
    for g in groups {
        let principal = match principal_from_session(
            g.kind.as_deref().unwrap_or(""),
            g.upstream.as_deref(),
            g.database.as_deref(),
        ) {
            Ok(p) => p,
            Err(e) => {
                report.skip(e.reason(), g.sessions);
                continue;
            }
        };
        let holder = if let Some(name) = g.username.strip_prefix(BOT_PREFIX) {
            Holder::Bot {
                name: name.to_owned(),
            }
        } else if let Some(groups) = user_groups.get(&g.username.to_lowercase()) {
            Holder::Person {
                groups: groups.clone(),
            }
        } else {
            report.skip("the person is no longer known to Limen", g.sessions);
            continue;
        };
        // Roles from approved requests count on the resource they were
        // granted for, to the person they were granted to.
        let granted_roles: Vec<String> = g
            .request_ids
            .iter()
            .filter_map(|id| grants.get(id))
            .filter(|gr| gr.resource == g.resource && gr.username.eq_ignore_ascii_case(&g.username))
            .map(|gr| gr.role.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        records.push(ReplayRecord {
            user: g.username,
            holder,
            resource: g.resource,
            principal,
            granted_roles,
            sessions: g.sessions,
            first_unix: g.first,
            last_unix: g.last,
        });
    }

    let relabeled = relabeled_resources(state, days).await?;
    let replayed = active.replay(
        proposed,
        &records,
        &state.config.bootstrap_admin_groups,
        &relabeled,
    );
    report.examined = replayed.examined;
    report.unchanged = replayed.unchanged;
    report.already_refused = replayed.already_refused;
    report.affected_sessions = replayed.affected_sessions;
    report.affected = replayed.affected;
    report.shadow = replayed.shadow;
    Ok((report, found))
}

async fn load_groups(state: &AppState, days: u32) -> Result<(Vec<Group>, bool), Status> {
    // A heavy scan is stopped, not left to hold the database.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal("reading sessions to replay", e))?;
    sqlx::query("SET LOCAL statement_timeout = '10s'")
        .execute(&mut *tx)
        .await
        .map_err(|e| internal("reading sessions to replay", e))?;
    // One more than the cap, to know whether there were more.
    let rows = sqlx::query(
        "SELECT username, kind, resource, login, database, request_ids,
                count(*) AS n, min(started_at) AS first, max(started_at) AS last
         FROM sessions
         WHERE started_at >= now() - make_interval(days => $1)
           AND username IS NOT NULL AND resource IS NOT NULL
         GROUP BY username, kind, resource, login, database, request_ids
         ORDER BY last DESC, username, resource
         LIMIT $2",
    )
    .bind(i32::try_from(days).unwrap_or(i32::MAX))
    .bind(i64::try_from(MAX_GROUPS + 1).unwrap_or(i64::MAX))
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| internal("reading sessions to replay", e))?;
    let truncated = rows.len() > MAX_GROUPS;
    let mut out = Vec::with_capacity(rows.len().min(MAX_GROUPS));
    for row in rows.into_iter().take(MAX_GROUPS) {
        let ids: Vec<String> = row
            .try_get("request_ids")
            .map_err(|e| internal("reading sessions to replay", e))?;
        let ts = |name: &str| -> Result<i64, Status> {
            row.try_get::<OffsetDateTime, _>(name)
                .map(OffsetDateTime::unix_timestamp)
                .map_err(|e| internal("reading sessions to replay", e))
        };
        let get = |name: &str| -> Result<Option<String>, Status> {
            row.try_get(name)
                .map_err(|e| internal("reading sessions to replay", e))
        };
        out.push(Group {
            username: get("username")?.unwrap_or_default(),
            kind: get("kind")?,
            resource: get("resource")?.unwrap_or_default(),
            upstream: get("login")?,
            database: get("database")?,
            request_ids: ids.iter().filter_map(|i| Uuid::parse_str(i).ok()).collect(),
            sessions: u64::try_from(
                row.try_get::<i64, _>("n")
                    .map_err(|e| internal("reading sessions to replay", e))?,
            )
            .unwrap_or(0),
            first: ts("first")?,
            last: ts("last")?,
        });
    }
    Ok((out, truncated))
}

/// Latest IdP groups per (lower-cased) username.
async fn load_user_groups(
    state: &AppState,
    names: &[String],
) -> Result<BTreeMap<String, Vec<String>>, Status> {
    if names.is_empty() {
        return Ok(BTreeMap::new());
    }
    let rows = sqlx::query("SELECT username, groups FROM users WHERE lower(username) = ANY($1)")
        .bind(names)
        .fetch_all(&state.db)
        .await
        .map_err(|e| internal("reading users to replay", e))?;
    let mut out = BTreeMap::new();
    for row in rows {
        let name: String = row
            .try_get("username")
            .map_err(|e| internal("reading users to replay", e))?;
        let groups: Vec<String> = row
            .try_get("groups")
            .map_err(|e| internal("reading users to replay", e))?;
        out.insert(name.to_lowercase(), groups);
    }
    Ok(out)
}

struct GrantRow {
    username: String,
    role: String,
    resource: String,
}

async fn load_grants(state: &AppState, ids: &[Uuid]) -> Result<BTreeMap<Uuid, GrantRow>, Status> {
    if ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let rows = sqlx::query(
        "SELECT request_id, username, role, resource FROM access_grants WHERE request_id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal("reading grants to replay", e))?;
    let mut out = BTreeMap::new();
    for row in rows {
        let err = |e| internal("reading grants to replay", e);
        out.insert(
            row.try_get::<Uuid, _>("request_id").map_err(err)?,
            GrantRow {
                username: row.try_get("username").map_err(err)?,
                role: row.try_get("role").map_err(err)?,
                resource: row.try_get("resource").map_err(err)?,
            },
        );
    }
    Ok(out)
}

/// Resources with a `resource.relabel` event in the window: their labels
/// may not be what they were when the sessions ran.
async fn relabeled_resources(state: &AppState, days: u32) -> Result<BTreeSet<String>, Status> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT summary FROM audit_events
         WHERE kind = 'resource.relabel' AND at >= now() - make_interval(days => $1)
         LIMIT 10000",
    )
    .bind(i32::try_from(days).unwrap_or(i32::MAX))
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal("reading relabel events", e))?;
    Ok(rows
        .iter()
        .flat_map(|s| s.split("  "))
        .filter_map(|part| part.strip_prefix("resource="))
        .map(str::to_owned)
        .collect())
}

//! `limen policy suggest` (ADR-0050): the control plane gathers what people
//! used and the pure `limen_policy::suggest` decides. Nothing here changes
//! policy. The call writes a `policy.suggest` audit event before it answers,
//! because the answer shows who used what.

use std::collections::BTreeMap;

use limen_audit::{Context, EventKind};
use limen_policy::suggest::{DEFAULT_WINDOW_DAYS, SuggestError, SuggestInput, UsageRow, suggest};
use limen_proto::v1::SuggestPolicyResponse;
use serde_json::json;
use sqlx::Row as _;
use time::OffsetDateTime;
use tonic::Status;

use crate::state::{AppState, internal};

/// More distinct (person, resource, principal) rows than this and the answer
/// would be built from part of the history, so there is none.
const MAX_USAGE_ROWS: i64 = 500_000;

#[allow(clippy::too_many_lines)]
pub async fn run(
    state: &AppState,
    who: &str,
    window_days: u32,
) -> Result<SuggestPolicyResponse, Status> {
    let window_days = if window_days == 0 {
        DEFAULT_WINDOW_DAYS
    } else {
        window_days
    };
    // Out-of-range windows are refused here too, so the query below is bounded.
    if !(limen_policy::suggest::MIN_WINDOW_DAYS..=limen_policy::suggest::MAX_WINDOW_DAYS)
        .contains(&window_days)
    {
        return Err(Status::invalid_argument(
            SuggestError::Window(window_days).to_string(),
        ));
    }
    let loaded = state.policy.current();
    let now = OffsetDateTime::now_utc();
    let since = now - time::Duration::days(i64::from(window_days));

    let watching: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT min(first_login_at) FROM users")
            .fetch_one(&state.db)
            .await
            .map_err(|e| internal("reading history", e))?;

    // One row per person, resource and principal seen in the window.
    let rows = sqlx::query(
        "SELECT username, resource, COALESCE(login, '') AS principal, count(*) AS n, max(COALESCE(ended_at, started_at)) AS last
         FROM sessions
         WHERE COALESCE(ended_at, started_at) >= $1 AND username IS NOT NULL AND resource IS NOT NULL
         GROUP BY username, resource, COALESCE(login, '')
         LIMIT $2",
    )
    .bind(since)
    .bind(MAX_USAGE_ROWS + 1)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal("reading usage", e))?;
    if i64::try_from(rows.len()).unwrap_or(i64::MAX) > MAX_USAGE_ROWS {
        return Err(Status::failed_precondition(
            "too much history to judge in one pass; try a shorter --window-days",
        ));
    }
    let mut usage = Vec::with_capacity(rows.len());
    for r in &rows {
        let last: Option<OffsetDateTime> = r.try_get("last").map_err(|e| internal("usage", e))?;
        let n: i64 = r.try_get("n").map_err(|e| internal("usage", e))?;
        usage.push(UsageRow {
            user: r.try_get("username").map_err(|e| internal("usage", e))?,
            resource: r.try_get("resource").map_err(|e| internal("usage", e))?,
            principal: r.try_get("principal").map_err(|e| internal("usage", e))?,
            sessions: u64::try_from(n).unwrap_or(0),
            last_used_unix: last.map_or(0, OffsetDateTime::unix_timestamp),
        });
    }

    let mut people: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in sqlx::query("SELECT username, roles FROM users")
        .fetch_all(&state.db)
        .await
        .map_err(|e| internal("reading people", e))?
    {
        people.insert(
            r.try_get("username").map_err(|e| internal("people", e))?,
            r.try_get("roles").map_err(|e| internal("people", e))?,
        );
    }

    // When each document last changed. A document with no recorded head is
    // treated as changed just now: not knowing its age must not make it look old.
    let mut changed: BTreeMap<String, i64> = BTreeMap::new();
    let mut created: BTreeMap<String, i64> = BTreeMap::new();
    let heads = sqlx::query(
        "SELECT kind, name, created_at, updated_at FROM policy_document_heads WHERE kind IN ('role', 'resource')",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal("reading policy history", e))?;
    for h in &heads {
        let kind: String = h.try_get("kind").map_err(|e| internal("heads", e))?;
        let name: String = h.try_get("name").map_err(|e| internal("heads", e))?;
        if kind == "role" {
            let at: OffsetDateTime = h.try_get("updated_at").map_err(|e| internal("heads", e))?;
            changed.insert(name, at.unix_timestamp());
        } else {
            let at: OffsetDateTime = h.try_get("created_at").map_err(|e| internal("heads", e))?;
            created.insert(name, at.unix_timestamp());
        }
    }
    let known_roles: Vec<String> = loaded
        .policy
        .roles()
        .map(|r| r.metadata.name.clone())
        .collect();
    for r in known_roles {
        changed.entry(r).or_insert(now.unix_timestamp());
    }
    let known_resources: Vec<String> = loaded
        .policy
        .resources()
        .map(|r| r.metadata.name.clone())
        .collect();
    for r in known_resources {
        created.entry(r).or_insert(now.unix_timestamp());
    }

    let result = suggest(
        &loaded.policy,
        &SuggestInput {
            usage: &usage,
            people: &people,
            role_changed_unix: &changed,
            resource_created_unix: &created,
            watching_since_unix: watching.map(OffsetDateTime::unix_timestamp),
            now_unix: now.unix_timestamp(),
            window_days,
        },
    )
    .map_err(|e| match e {
        SuggestError::Window(_) => Status::invalid_argument(e.to_string()),
        SuggestError::NoHistory | SuggestError::ShortHistory { .. } => {
            Status::failed_precondition(e.to_string())
        }
        SuggestError::Unsafe(_) => internal("checking a suggestion", e),
    })?;

    let yaml = result
        .to_yaml(u64::try_from(loaded.version).unwrap_or(0))
        .map_err(|e| internal("writing the suggestion", e))?;
    let diff = if result.roles.is_empty() {
        String::new()
    } else {
        let next = result
            .apply_to(&loaded.policy)
            .map_err(|e| internal("checking a suggestion", e))?;
        loaded.policy.access_diff(&next).render_text()
    };
    let report_json =
        serde_json::to_string(&result).map_err(|e| internal("encoding the suggestion", e))?;

    // Before answering: the answer shows who used what.
    state
        .audit
        .emit(
            EventKind::PolicySuggest,
            Context {
                user: Some(who.to_owned()),
                session_id: None,
            },
            json!({
                "window_days": window_days,
                "policy_version": loaded.version,
                "policy_digest": result.policy_digest,
                "roles_to_tighten": result.roles.len(),
                "unused_roles": result.unused_roles.len(),
                "people": result.people.len(),
            }),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "audit unavailable; refusing a policy suggestion");
            Status::unavailable("audit unavailable")
        })?;

    Ok(SuggestPolicyResponse {
        policy_version: loaded.version,
        policy_digest: result.policy_digest.clone(),
        report_json,
        yaml,
        text: result.render_text(),
        diff,
    })
}

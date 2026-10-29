//! Policy writes held for a person's approval because they widen standing
//! access (ADR-0042 §6): what needs approval, and the stored changes.
//!
//! A held change keeps its writes as `policy_store` will apply them (`Plan`)
//! and the access gains the approver reviewed. Approving it writes again on
//! the current policy; if that would give access nobody reviewed, or a
//! document it touches changed, it is superseded instead.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use limen_audit::{Context, EventKind};
use limen_policy::tooling::{ChangeKind, Via};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::WideningApproval;
use crate::db::Db;
use crate::policy_store::{Change, Hold, Key, Outcome};
use crate::state::AppState;

/// The warning a dry run of a write that would be held carries.
pub const WOULD_BE_HELD: &str =
    "this write widens standing access: applying it waits for a person's approval";

/// How long one approver's claim on a change lasts. A claim older than this
/// is from a replica that died while applying, and may be taken again.
const CLAIM: &str = "5 minutes";

/// A change's state, as stored (`applying` reads as pending).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Pending,
    Applied,
    Rejected,
    Cancelled,
    Expired,
    Superseded,
}

impl State {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Applied => "applied",
            State::Rejected => "rejected",
            State::Cancelled => "cancelled",
            State::Expired => "expired",
            State::Superseded => "superseded",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" | "applying" => State::Pending,
            "applied" => State::Applied,
            "rejected" => State::Rejected,
            "cancelled" => State::Cancelled,
            "expired" => State::Expired,
            "superseded" => State::Superseded,
            _ => return None,
        })
    }
}

/// The write, as the control plane applies it on approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub changes: Vec<Change>,
    pub require_tests: bool,
    /// The standing access gains the approver reviews, as one line each.
    pub gains: Vec<String>,
    /// The documents it was checked against (`Outcome::basis`): if any moved,
    /// approving it supersedes it.
    #[serde(default)]
    pub basis: Vec<(Key, Option<String>)>,
}

/// One held change.
#[derive(Debug, Clone)]
pub struct Held {
    pub id: Uuid,
    pub state: State,
    /// The person or `bot:<name>` that made the write.
    pub author: String,
    pub author_ci: BTreeMap<String, String>,
    pub plan: Plan,
    /// The request as sent (`limen.manage.v1.BatchWriteRequest`, encoded).
    pub writes: Vec<u8>,
    /// The impact when it was made (`limen.manage.v1.Impact`, encoded).
    pub impact: Vec<u8>,
    pub base_policy_version: i64,
    pub reason: String,
    pub source_ref: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub decided_by: Option<String>,
    pub decision_note: Option<String>,
    pub decided_at: Option<OffsetDateTime>,
    pub applied_policy_version: Option<i64>,
}

/// A change to hold.
#[derive(Debug, Clone)]
pub struct New {
    pub author: String,
    pub author_ci: BTreeMap<String, String>,
    pub plan: Plan,
    pub writes: Vec<u8>,
    pub impact: Vec<u8>,
    pub base_policy_version: i64,
    pub reason: String,
    pub source_ref: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("audit unavailable")]
    AuditUnavailable,
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("{0}")]
    Corrupt(String),
}

// ---- What needs approval ----------------------------------------------------

/// The standing access a write gives that nobody had, one line each.
#[must_use]
pub fn widening_gains(outcome: &Outcome) -> Vec<String> {
    outcome
        .access
        .changes
        .iter()
        .filter(|c| c.change == ChangeKind::Gain && c.via == Via::Standing)
        .map(limen_policy::tooling::AccessChange::text)
        .collect()
}

/// Whether `changes` can widen standing access in a way a grant doesn't
/// already approve: anything but resources a writer completes from a
/// profile, whose bounds are the approval (ADR-0042 §5).
#[must_use]
pub fn beyond_profiles(changes: &[Change]) -> bool {
    changes.iter().any(|c| match c {
        Change::Create { input, .. } | Change::Update { input, .. } => {
            input.kind != "resource" || input.profile.is_none()
        }
        Change::Delete { key, .. } => key.0 != "resource",
        Change::ReplaceSource { .. } => true,
        Change::Transfer { .. } => false,
    })
}

/// The hold for a write by `author`: a bot's widening beyond its profiles
/// always waits; a person's waits with `--widening-approval=all`.
#[must_use]
pub fn hold_for(bot: bool, mode: WideningApproval, changes: &[Change]) -> Option<Hold> {
    let held = if bot {
        beyond_profiles(changes)
    } else {
        mode == WideningApproval::All
    };
    held.then(|| -> Hold { Arc::new(|outcome| !widening_gains(outcome).is_empty()) })
}

/// The hold an approval writes with: it stops (and the change is superseded)
/// when the write would now give standing access the approver didn't see.
#[must_use]
pub fn unreviewed(reviewed: &[String]) -> Hold {
    let reviewed: BTreeSet<String> = reviewed.iter().cloned().collect();
    Arc::new(move |outcome| {
        widening_gains(outcome)
            .iter()
            .any(|g| !reviewed.contains(g))
    })
}

/// Whether `name` is the CI account that started `ci`'s run (`actor` on
/// GitHub, `user_login` on GitLab). Compared without case, and also with
/// the part of an email address before the `@`, so `octocat@example.com`
/// can't approve the run `octocat` pushed.
#[must_use]
pub fn started_the_run(name: &str, ci: &BTreeMap<String, String>) -> bool {
    let local = name.split('@').next().unwrap_or(name);
    ["actor", "user_login"]
        .iter()
        .filter_map(|k| ci.get(*k))
        .any(|account| account.eq_ignore_ascii_case(name) || account.eq_ignore_ascii_case(local))
}

// ---- Rows -------------------------------------------------------------------

macro_rules! columns {
    () => {
        "id, state, author, author_ci, plan, writes, impact, base_policy_version, reason, \
         source_ref, created_at, expires_at, decided_by, decision_note, decided_at, \
         applied_policy_version"
    };
}

fn from_row(row: &sqlx::postgres::PgRow) -> Result<Held, Error> {
    let state: String = row.try_get("state")?;
    let expires_at: OffsetDateTime = row.try_get("expires_at")?;
    let mut parsed =
        State::parse(&state).ok_or_else(|| Error::Corrupt(format!("unknown state {state:?}")))?;
    // Expired the moment its time passed, whether or not marked yet.
    if parsed == State::Pending && expires_at <= OffsetDateTime::now_utc() {
        parsed = State::Expired;
    }
    let ci: Value = row.try_get("author_ci")?;
    let plan: Value = row.try_get("plan")?;
    Ok(Held {
        id: row.try_get("id")?,
        state: parsed,
        author: row.try_get("author")?,
        author_ci: serde_json::from_value(ci).map_err(|e| Error::Corrupt(e.to_string()))?,
        plan: serde_json::from_value(plan).map_err(|e| Error::Corrupt(e.to_string()))?,
        writes: row.try_get("writes")?,
        impact: row.try_get("impact")?,
        base_policy_version: row.try_get("base_policy_version")?,
        reason: row.try_get("reason")?,
        source_ref: row.try_get("source_ref")?,
        created_at: row.try_get("created_at")?,
        expires_at,
        decided_by: row.try_get("decided_by")?,
        decision_note: row.try_get("decision_note")?,
        decided_at: row.try_get("decided_at")?,
        applied_policy_version: row.try_get("applied_policy_version")?,
    })
}

fn context(user: &str) -> Context {
    Context {
        user: Some(user.to_owned()),
        session_id: None,
    }
}

/// Hold a change. The `policy.change_pending` event is written in the same
/// transaction: if it can't be, nothing is held.
pub async fn hold(state: &AppState, new: New, ttl: Duration) -> Result<Held, Error> {
    let id = Uuid::now_v7();
    let ttl = time::Duration::try_from(ttl).unwrap_or(time::Duration::days(7));
    let expires_at = OffsetDateTime::now_utc() + ttl;
    let mut tx = state.db.begin().await?;
    let plan = serde_json::to_value(&new.plan).map_err(|e| Error::Corrupt(e.to_string()))?;
    let row = sqlx::query(concat!(
        "INSERT INTO policy_changes (id, state, author, author_ci, plan, writes, impact, \
         base_policy_version, reason, source_ref, expires_at) \
         VALUES ($1, 'pending', $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING ",
        columns!()
    ))
    .bind(id)
    .bind(&new.author)
    .bind(json!(new.author_ci))
    .bind(plan)
    .bind(&new.writes)
    .bind(&new.impact)
    .bind(new.base_policy_version)
    .bind(&new.reason)
    .bind(&new.source_ref)
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await?;
    let held = from_row(&row)?;
    state
        .audit
        .emit(
            EventKind::PolicyChangePending,
            context(&new.author),
            json!({
                "change_id": id,
                "base_version": new.base_policy_version,
                "gains": new.plan.gains.iter().take(200).collect::<Vec<_>>(),
                "reason": new.reason,
                "source_ref": new.source_ref,
                "ci": new.author_ci,
                "expires_at": expires_at.unix_timestamp(),
            }),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "audit unavailable; not holding a policy change");
            Error::AuditUnavailable
        })?;
    tx.commit().await?;
    Ok(held)
}

pub async fn get(db: &Db, id: Uuid) -> Result<Option<Held>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM policy_changes WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await?
    .as_ref()
    .map(from_row)
    .transpose()
}

/// Changes in `state`, newest first, after `before` (the previous page's
/// last `(created_at, id)`), `author`'s only when given.
pub async fn list(
    db: &Db,
    state: State,
    author: Option<&str>,
    before: Option<(OffsetDateTime, Uuid)>,
    limit: i64,
) -> Result<Vec<Held>, Error> {
    let stored: &[&str] = match state {
        State::Pending => &["pending", "applying"],
        other => &[other.as_str()],
    };
    let (at, id) = before.unwrap_or((
        OffsetDateTime::now_utc() + time::Duration::days(3650),
        Uuid::max(),
    ));
    let rows = sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM policy_changes \
         WHERE state = ANY($1) AND ($2::text IS NULL OR author = $2) \
           AND (created_at, id) < ($3, $4) \
           AND (state NOT IN ('pending', 'applying') OR expires_at > now()) \
         ORDER BY created_at DESC, id DESC LIMIT $5"
    ))
    .bind(stored)
    .bind(author)
    .bind(at)
    .bind(id)
    .bind(limit)
    .fetch_all(db)
    .await?;
    rows.iter().map(from_row).collect()
}

/// Take a pending change to apply it. `None` when it isn't pending any more,
/// or another approver is applying it.
pub async fn claim(db: &Db, id: Uuid) -> Result<Option<Held>, Error> {
    sqlx::query(concat!(
        "UPDATE policy_changes SET state = 'applying', claimed_at = now() \
         WHERE id = $1 AND expires_at > now() \
           AND (state = 'pending' OR (state = 'applying' AND claimed_at < now() - $2::interval)) \
         RETURNING ",
        columns!()
    ))
    .bind(id)
    .bind(CLAIM)
    .fetch_optional(db)
    .await?
    .as_ref()
    .map(from_row)
    .transpose()
}

/// Give a claimed change back: applying it failed for a reason that may pass.
pub async fn release(db: &Db, id: Uuid) {
    let released = sqlx::query(
        "UPDATE policy_changes SET state = 'pending' WHERE id = $1 AND state = 'applying'",
    )
    .bind(id)
    .execute(db)
    .await;
    if let Err(e) = released {
        tracing::warn!(error = %e, %id, "couldn't release a policy change; it frees itself in {CLAIM}");
    }
}

/// A decision.
#[derive(Debug, Clone)]
pub struct Decision<'a> {
    pub to: State,
    pub by: &'a str,
    pub note: &'a str,
    pub applied_version: Option<i64>,
}

/// Record a decision on a change that is still pending (or claimed, for
/// `applied` and `superseded`), with its `policy.change_decided` event in the
/// same transaction. `None` when it was decided already.
///
/// An approval's write has committed before this runs, and its
/// `policy.change` event names the change and the approver, so for
/// `applied` a missing decision event is logged instead of failing.
pub async fn decide(state: &AppState, id: Uuid, d: &Decision<'_>) -> Result<Option<Held>, Error> {
    let from: &[&str] = match d.to {
        State::Applied | State::Superseded | State::Expired => &["applying", "pending"],
        _ => &["pending"],
    };
    let mut tx = state.db.begin().await?;
    let row = sqlx::query(concat!(
        "UPDATE policy_changes SET state = $2, decided_by = $3, decision_note = $4, \
         decided_at = now(), applied_policy_version = $5 \
         WHERE id = $1 AND state = ANY($6) \
           AND (expires_at > now() OR $2 IN ('expired', 'applied', 'superseded')) RETURNING ",
        columns!()
    ))
    .bind(id)
    .bind(d.to.as_str())
    .bind(d.by)
    .bind(d.note)
    .bind(d.applied_version)
    .bind(from)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let held = from_row(&row)?;
    let event = state
        .audit
        .emit(
            EventKind::PolicyChangeDecided,
            context(d.by),
            json!({
                "change_id": id,
                "state": d.to.as_str(),
                "author": held.author,
                "note": d.note,
                "applied_version": d.applied_version,
            }),
        )
        .await;
    match event {
        Ok(_) => {}
        Err(e) if d.to == State::Applied => {
            tracing::error!(error = %e, %id, "couldn't audit an approval; its policy.change event records it");
        }
        Err(e) => {
            tracing::error!(error = %e, "audit unavailable; not deciding a policy change");
            return Err(Error::AuditUnavailable);
        }
    }
    tx.commit().await?;
    Ok(Some(held))
}

/// Mark changes whose time ran out as expired, each with its event. Their
/// state already reads as expired; this records it. One being applied is
/// left to its approver unless the claim is stale.
pub async fn expire(state: &AppState) {
    let due: Result<Vec<Uuid>, sqlx::Error> = sqlx::query_scalar(
        "SELECT id FROM policy_changes WHERE expires_at <= now() \
           AND (state = 'pending' OR (state = 'applying' AND claimed_at < now() - $1::interval)) \
         LIMIT 100",
    )
    .bind(CLAIM)
    .fetch_all(&state.db)
    .await;
    let due = match due {
        Ok(due) => due,
        Err(e) => {
            tracing::warn!(error = %e, "couldn't look for expired policy changes");
            return;
        }
    };
    for id in due {
        let decision = Decision {
            to: State::Expired,
            by: "limen",
            note: "not decided in time",
            applied_version: None,
        };
        if let Err(e) = decide(state, id, &decision).await {
            tracing::warn!(error = %e, %id, "couldn't mark a policy change expired");
        }
    }
}

#[cfg(test)]
mod tests;

//! Access reviews and deny overrides (ADR-0029).
//!
//! A review takes a snapshot of effective access: who holds which role, what
//! it reaches, and whether it was used in the last 90 days. Each item goes to
//! an owner (the role's, else its resources', else any admin) who certifies
//! it or flags it. **Nobody reviews their own access.** A flag becomes a
//! *deny override*: carried in the signed snapshot like a lock, it withholds
//! the role from that person, ends their open sessions on what the role
//! reaches, and expires, or lifts once the IdP change shows up at their next
//! login. Overdue items escalate to the admins.

use std::collections::BTreeMap;

use limen_audit::{Context, EventKind};
use limen_proto::v1::{DenyInfo, ReviewInfo, ReviewItemInfo, ReviewReach};
use serde_json::{Value, json};
use sqlx::Row as _;
use time::OffsetDateTime;
use tonic::Status;
use uuid::Uuid;

use crate::access::notify::{Event, Notice};
use crate::db::Db;
use crate::services::ops;
use crate::state::{AppState, internal, unix};

/// The pool that stands for "any admin".
pub const ADMIN_POOL: &str = "*admin";
/// Days the reviewers have unless told otherwise.
pub const DEFAULT_DUE_DAYS: u32 = 14;
/// Days a flagged role stays withheld unless told otherwise.
pub const DEFAULT_OVERRIDE_DAYS: u32 = 30;
/// An item whose access was not used for this long is marked.
const UNUSED_DAYS: i64 = 90;
/// Most things listed as reached by one item.
const MAX_REACHES: usize = 200;
/// Reminders go out this often to reviewers who haven't answered.
const REMIND_EVERY_DAYS: i32 = 3;

#[derive(Debug, Clone, Copy)]
pub struct Who<'a> {
    pub username: &'a str,
    pub is_admin: bool,
    pub is_auditor: bool,
    pub via: &'static str,
}

async fn audit(state: &AppState, kind: EventKind, user: &str, data: Value) -> Result<(), Status> {
    state
        .audit
        .emit(
            kind,
            Context {
                user: Some(user.to_owned()),
                session_id: None,
            },
            data,
        )
        .await
        .map(|_| ())
        .map_err(|e| {
            tracing::error!(error = %e, "audit unavailable; refusing a review change");
            Status::unavailable("audit unavailable")
        })
}

/// Who should look at a role: its `owner` label, else the owner that most of
/// the resources it reaches name, else any admin.
fn reviewer_for(policy: &limen_policy::Policy, role: &str, reaches: &[(String, String)]) -> String {
    if let Some(owner) = policy
        .role(role)
        .and_then(|r| r.metadata.labels.get("owner"))
        .filter(|o| !o.is_empty())
    {
        return owner.to_owned();
    }
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (name, _) in reaches {
        if let Some(o) = policy
            .resource(name)
            .and_then(|r| r.metadata.labels.get("owner"))
            .filter(|o| !o.is_empty())
        {
            *counts.entry(o).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .map_or_else(|| ADMIN_POOL.to_owned(), |(o, _)| o.to_owned())
}

struct Item {
    subject: String,
    subject_type: &'static str,
    role: String,
    via: &'static str,
    reaches: Vec<limen_policy::AccessibleResource>,
}

/// Everything someone holds right now: roles from their groups at their last
/// login, bots' roles from policy, and active grants.
async fn gather(state: &AppState) -> Result<Vec<Item>, Status> {
    let policy = state.policy.current();
    let policy = &policy.policy;
    let reach = |role: &str| -> Vec<limen_policy::AccessibleResource> {
        let mut r = policy.accessible(&[role.to_owned()]);
        r.truncate(MAX_REACHES);
        r
    };
    let mut items = Vec::new();
    let users = sqlx::query("SELECT username, roles, actor_type FROM users ORDER BY username")
        .fetch_all(&state.db)
        .await
        .map_err(|e| internal("reading users", e))?;
    let mut bots_seen: Vec<String> = Vec::new();
    for u in &users {
        let name: String = u
            .try_get("username")
            .map_err(|e| internal("reading users", e))?;
        let roles: Vec<String> = u
            .try_get("roles")
            .map_err(|e| internal("reading users", e))?;
        let kind: String = u
            .try_get("actor_type")
            .map_err(|e| internal("reading users", e))?;
        if kind == "bot" {
            bots_seen.push(name.clone());
        }
        for role in roles {
            items.push(Item {
                subject: name.clone(),
                subject_type: if kind == "bot" { "bot" } else { "user" },
                reaches: reach(&role),
                role,
                via: "standing",
            });
        }
    }
    // Bots that never logged in still hold what their document gives them.
    for bot in policy.bots() {
        let name = format!("bot:{}", bot.metadata.name);
        if bots_seen.contains(&name) {
            continue;
        }
        for role in &bot.spec.roles {
            items.push(Item {
                subject: name.clone(),
                subject_type: "bot",
                reaches: reach(role),
                role: role.clone(),
                via: "standing",
            });
        }
    }
    for g in crate::access::store::active_grants(&state.db)
        .await
        .map_err(|e| internal("reading grants", e))?
    {
        let mut r = policy.accessible(std::slice::from_ref(&g.role));
        r.retain(|x| x.name == g.resource);
        items.push(Item {
            subject: g.username,
            subject_type: "user",
            role: g.role,
            via: if g.break_glass {
                "break_glass"
            } else {
                "grant"
            },
            reaches: r,
        });
    }
    Ok(items)
}

/// Start a review. Items go to owners; bots and people alike.
pub async fn start(
    state: &AppState,
    who: &Who<'_>,
    name: &str,
    due_days: u32,
    override_days: u32,
) -> Result<ReviewInfo, Status> {
    if !who.is_admin {
        return Err(Status::permission_denied(
            "the limen:admin role is required",
        ));
    }
    let name = name.trim();
    let name = if name.is_empty() {
        format!("Access review {}", OffsetDateTime::now_utc().date())
    } else {
        ops::clean_reason(name)?
    };
    let due = i64::from(if due_days == 0 {
        DEFAULT_DUE_DAYS
    } else {
        due_days.min(90)
    });
    let override_days = i32::try_from(if override_days == 0 {
        DEFAULT_OVERRIDE_DAYS
    } else {
        override_days.min(365)
    })
    .unwrap_or(30);
    let items = gather(state).await?;
    let policy = state.policy.current();
    let digest = policy.policy.digest();
    let id = Uuid::now_v7();

    // What each person used in the last 90 days, by resource.
    let usage = sqlx::query(
        "SELECT username, resource, count(*) AS n, max(started_at) AS last
         FROM sessions WHERE started_at > now() - make_interval(days => $1) AND resource IS NOT NULL
         GROUP BY username, resource",
    )
    .bind(i32::try_from(UNUSED_DAYS).unwrap_or(90))
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal("reading usage", e))?;
    let mut usage_by: BTreeMap<(String, String), (i64, Option<OffsetDateTime>)> = BTreeMap::new();
    for r in &usage {
        let user: Option<String> = r.try_get("username").map_err(|e| internal("usage", e))?;
        let res: Option<String> = r.try_get("resource").map_err(|e| internal("usage", e))?;
        if let (Some(u), Some(res)) = (user, res) {
            usage_by.insert(
                (u, res),
                (
                    r.try_get("n").map_err(|e| internal("usage", e))?,
                    r.try_get("last").map_err(|e| internal("usage", e))?,
                ),
            );
        }
    }

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal("starting transaction", e))?;
    sqlx::query(
        "INSERT INTO access_reviews (id, name, started_by, due_at, policy_digest, override_days)
         VALUES ($1, $2, $3, now() + make_interval(days => $4), $5, $6)",
    )
    .bind(id)
    .bind(&name)
    .bind(who.username)
    .bind(i32::try_from(due).unwrap_or(14))
    .bind(&digest)
    .bind(override_days)
    .execute(&mut *tx)
    .await
    .map_err(|e| internal("storing the review", e))?;
    let mut count = 0usize;
    for item in &items {
        let reaches: Vec<(String, String)> = item
            .reaches
            .iter()
            .map(|r| (r.name.clone(), r.kind.as_str().to_owned()))
            .collect();
        let mut reviewer = reviewer_for(&policy.policy, &item.role, &reaches);
        // Nobody reviews their own access.
        if reviewer.eq_ignore_ascii_case(&item.subject) {
            ADMIN_POOL.clone_into(&mut reviewer);
        }
        let (mut sessions, mut last): (i64, Option<OffsetDateTime>) = (0, None);
        for r in &item.reaches {
            if let Some((n, l)) = usage_by.get(&(item.subject.clone(), r.name.clone())) {
                sessions += n;
                last = last.max(*l);
            }
        }
        let reach_json: Vec<Value> = item
            .reaches
            .iter()
            .map(|r| json!({ "name": r.name, "kind": r.kind.as_str(), "principals": r.principals }))
            .collect();
        sqlx::query(
            "INSERT INTO review_items (id, review_id, subject, subject_type, role, via, reaches, sessions_90d, last_used_at, reviewer)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(Uuid::now_v7())
        .bind(id)
        .bind(&item.subject)
        .bind(item.subject_type)
        .bind(&item.role)
        .bind(item.via)
        .bind(Value::Array(reach_json))
        .bind(i32::try_from(sessions).unwrap_or(i32::MAX))
        .bind(last)
        .bind(&reviewer)
        .execute(&mut *tx)
        .await
        .map_err(|e| internal("storing a review item", e))?;
        count += 1;
    }
    if count == 0 {
        // Nothing to look at is a finished review, not an open one nobody can close.
        sqlx::query(
            "UPDATE access_reviews SET status = 'complete', completed_at = now() WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| internal("closing the review", e))?;
    }
    audit(
        state,
        EventKind::ReviewStart,
        who.username,
        json!({ "review_id": id, "name": name, "items": count, "due_days": due, "policy_digest": digest, "via": who.via }),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|e| internal("committing the review", e))?;
    metrics::counter!("limen_access_reviews_started_total").increment(1);
    info(&state.db, id).await
}

macro_rules! info_sql {
    () => {
        "SELECT r.id, r.name, r.started_by, r.started_at, r.due_at, r.status,
        count(i.id) AS items,
        count(i.decision) AS decided,
        count(*) FILTER (WHERE i.decision = 'flag') AS flagged,
        count(*) FILTER (WHERE i.decision = 'certify' AND i.comment = '') AS silent
     FROM access_reviews r LEFT JOIN review_items i ON i.review_id = r.id"
    };
}

fn info_from(r: &sqlx::postgres::PgRow) -> Result<ReviewInfo, Status> {
    let e = |e| internal("reading a review", e);
    let due: OffsetDateTime = r.try_get("due_at").map_err(e)?;
    let status: String = r.try_get("status").map_err(e)?;
    let n = |c: &str| -> Result<u32, Status> {
        Ok(u32::try_from(r.try_get::<i64, _>(c).map_err(e)?).unwrap_or(u32::MAX))
    };
    Ok(ReviewInfo {
        id: r.try_get::<Uuid, _>("id").map_err(e)?.to_string(),
        name: r.try_get("name").map_err(e)?,
        started_by: r.try_get("started_by").map_err(e)?,
        started_at_unix: unix(r.try_get("started_at").map_err(e)?),
        due_at_unix: unix(due),
        overdue: status == "open" && due < OffsetDateTime::now_utc(),
        status,
        items: n("items")?,
        decided: n("decided")?,
        flagged: n("flagged")?,
        certified_silently: n("silent")?,
    })
}

async fn info(db: &Db, id: Uuid) -> Result<ReviewInfo, Status> {
    let row = sqlx::query(concat!(info_sql!(), " WHERE r.id = $1 GROUP BY r.id"))
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(|e| internal("reading a review", e))?
        .ok_or_else(|| Status::not_found("no such review"))?;
    info_from(&row)
}

/// Reviews: all of them (admins, auditors), or those with items for the caller.
pub async fn list(state: &AppState, who: &Who<'_>, all: bool) -> Result<Vec<ReviewInfo>, Status> {
    if all && !(who.is_admin || who.is_auditor) {
        return Err(Status::permission_denied(
            "listing every review needs the limen:admin or limen:auditor role",
        ));
    }
    let rows = sqlx::query(concat!(
        info_sql!(),
        " WHERE $1 OR EXISTS (SELECT 1 FROM review_items m WHERE m.review_id = r.id
            AND (lower(m.reviewer) = lower($2) OR (m.reviewer = '*admin' AND $3)))
         GROUP BY r.id ORDER BY r.started_at DESC LIMIT 100"
    ))
    .bind(all)
    .bind(who.username)
    .bind(who.is_admin)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal("listing reviews", e))?;
    rows.iter().map(info_from).collect()
}

fn item_from(r: &sqlx::postgres::PgRow, who: &Who<'_>) -> Result<ReviewItemInfo, Status> {
    let e = |e| internal("reading a review item", e);
    let reviewer: String = r.try_get("reviewer").map_err(e)?;
    let subject: String = r.try_get("subject").map_err(e)?;
    let decision: Option<String> = r.try_get("decision").map_err(e)?;
    let sessions: i32 = r.try_get("sessions_90d").map_err(e)?;
    let last: Option<OffsetDateTime> = r.try_get("last_used_at").map_err(e)?;
    let reaches: Value = r.try_get("reaches").map_err(e)?;
    let can_decide = decision.is_none()
        && !subject.eq_ignore_ascii_case(who.username)
        && (reviewer.eq_ignore_ascii_case(who.username)
            || (reviewer == ADMIN_POOL && who.is_admin));
    Ok(ReviewItemInfo {
        id: r.try_get::<Uuid, _>("id").map_err(e)?.to_string(),
        review_id: r.try_get::<Uuid, _>("review_id").map_err(e)?.to_string(),
        subject,
        subject_type: r.try_get("subject_type").map_err(e)?,
        role: r.try_get("role").map_err(e)?,
        via: r.try_get("via").map_err(e)?,
        reaches: reaches
            .as_array()
            .into_iter()
            .flatten()
            .map(|v| ReviewReach {
                name: v["name"].as_str().unwrap_or_default().to_owned(),
                kind: v["kind"].as_str().unwrap_or_default().to_owned(),
                principals: v["principals"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|p| p.as_str().map(str::to_owned))
                    .collect(),
            })
            .collect(),
        sessions_90d: u32::try_from(sessions).unwrap_or(0),
        last_used_unix: last.map_or(0, unix),
        reviewer,
        unused: sessions == 0,
        decision: decision.unwrap_or_default(),
        comment: r.try_get("comment").map_err(e)?,
        decided_by: r
            .try_get::<Option<String>, _>("decided_by")
            .map_err(e)?
            .unwrap_or_default(),
        decided_at_unix: r
            .try_get::<Option<OffsetDateTime>, _>("decided_at")
            .map_err(e)?
            .map_or(0, unix),
        can_decide,
    })
}

macro_rules! item_cols {
    () => {
        "id, review_id, subject, subject_type, role, via, reaches, sessions_90d, last_used_at, reviewer, decision, comment, decided_by, decided_at"
    };
}

macro_rules! item_cols_i {
    () => {
        "i.id, i.review_id, i.subject, i.subject_type, i.role, i.via, i.reaches, i.sessions_90d, i.last_used_at, i.reviewer, i.decision, i.comment, i.decided_by, i.decided_at"
    };
}

/// The items of a review the caller may see: all of them for admins and
/// auditors, otherwise their own.
pub async fn items(
    state: &AppState,
    who: &Who<'_>,
    review_id: &str,
    mine: bool,
    open_only: bool,
) -> Result<Vec<ReviewItemInfo>, Status> {
    let id = Uuid::parse_str(review_id.trim())
        .map_err(|_| Status::invalid_argument("not a review id"))?;
    let everything = (who.is_admin || who.is_auditor) && !mine;
    let rows = sqlx::query(concat!(
        "SELECT ",
        item_cols!(),
        " FROM review_items WHERE review_id = $1
           AND ($2 OR lower(reviewer) = lower($3) OR (reviewer = '*admin' AND $4))
           AND (NOT $5 OR decision IS NULL)
         ORDER BY (decision IS NULL) DESC, subject, role LIMIT 5000"
    ))
    .bind(id)
    .bind(everything)
    .bind(who.username)
    .bind(who.is_admin)
    .bind(open_only)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal("listing review items", e))?;
    rows.iter().map(|r| item_from(r, who)).collect()
}

/// Certify or flag one item.
#[allow(clippy::too_many_lines)] // one linear sequence of checks, then the writes
pub async fn decide(
    state: &AppState,
    who: &Who<'_>,
    item_id: &str,
    certify: bool,
    comment: &str,
) -> Result<ReviewItemInfo, Status> {
    let item_id =
        Uuid::parse_str(item_id.trim()).map_err(|_| Status::invalid_argument("not an item id"))?;
    let comment = comment.trim();
    if comment.len() > 500 || comment.chars().any(char::is_control) {
        return Err(Status::invalid_argument(
            "comment must be at most 500 characters, without control characters",
        ));
    }
    if !certify && comment.is_empty() {
        return Err(Status::invalid_argument(
            "say why when flagging access for removal",
        ));
    }
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal("starting transaction", e))?;
    let row = sqlx::query(concat!(
        "SELECT ",
        item_cols_i!(),
        ", r.status AS review_status, r.name AS review_name, r.override_days
         FROM review_items i JOIN access_reviews r ON r.id = i.review_id WHERE i.id = $1 FOR UPDATE OF i"
    ))
    .bind(item_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| internal("reading a review item", e))?
    .ok_or_else(|| Status::not_found("no such review item"))?;
    let item = item_from(&row, who)?;
    let e = |e| internal("reading a review item", e);
    let review_status: String = row.try_get("review_status").map_err(e)?;
    let review_name: String = row.try_get("review_name").map_err(e)?;
    let override_days: i32 = row.try_get("override_days").map_err(e)?;
    if review_status != "open" {
        return Err(Status::failed_precondition("the review is closed"));
    }
    if !item.decision.is_empty() {
        return Err(Status::already_exists("this item was already decided"));
    }
    if item.subject.eq_ignore_ascii_case(who.username) {
        return Err(Status::permission_denied(
            "you can't review your own access",
        ));
    }
    if !item.can_decide {
        // The same answer whether it exists or belongs to someone else.
        return Err(Status::permission_denied("this item isn't yours to decide"));
    }
    sqlx::query(
        "UPDATE review_items SET decision = $2, comment = $3, decided_by = $4, decided_at = now() WHERE id = $1",
    )
    .bind(item_id)
    .bind(if certify { "certify" } else { "flag" })
    .bind(comment)
    .bind(who.username)
    .execute(&mut *tx)
    .await
    .map_err(|e| internal("storing the decision", e))?;
    audit(
        state,
        EventKind::ReviewDecide,
        who.username,
        json!({
            "review_id": item.review_id, "item_id": item_id, "target_user": item.subject, "role": item.role,
            "action": if certify { "certify" } else { "flag" }, "comment": comment, "via": who.via,
        }),
    )
    .await?;
    if !certify {
        // The role is withheld from them, and what they have open on it ends.
        sqlx::query(
            "INSERT INTO access_denies (id, username, role, reason, created_by, review_item_id, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(days => $7))
             ON CONFLICT (username, role) WHERE lifted_at IS NULL DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(&item.subject)
        .bind(&item.role)
        .bind(format!("{review_name}: {comment}"))
        .bind(who.username)
        .bind(item_id)
        .bind(override_days)
        .execute(&mut *tx)
        .await
        .map_err(|e| internal("storing the override", e))?;
        let names: Vec<String> = item.reaches.iter().map(|r| r.name.clone()).collect();
        let ended = sqlx::query(
            "INSERT INTO session_kills (session_id, reason, killed_by)
             SELECT session_id::text, 'access removed in a review', $3 FROM sessions
             WHERE username = $1 AND resource = ANY($2) AND ended_at IS NULL
               AND started_at > now() - interval '24 hours'
             ON CONFLICT DO NOTHING",
        )
        .bind(&item.subject)
        .bind(&names)
        .bind(who.username)
        .execute(&mut *tx)
        .await
        .map_err(|e| internal("ending sessions", e))?
        .rows_affected();
        audit(
            state,
            EventKind::AccessDenyOverride,
            who.username,
            json!({
                "target_user": item.subject, "role": item.role, "expires_in_days": override_days,
                "sessions_ended": ended, "review_id": item.review_id, "via": who.via,
            }),
        )
        .await?;
    }
    // The review closes when its last item is decided.
    let review_id = Uuid::parse_str(&item.review_id).map_err(|e| internal("review id", e))?;
    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM review_items WHERE review_id = $1 AND decision IS NULL",
    )
    .bind(review_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| internal("counting open items", e))?;
    if open == 0 {
        sqlx::query(
            "UPDATE access_reviews SET status = 'complete', completed_at = now() WHERE id = $1",
        )
        .bind(review_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| internal("closing the review", e))?;
        audit(
            state,
            EventKind::ReviewComplete,
            who.username,
            json!({ "review_id": review_id, "name": review_name }),
        )
        .await?;
    }
    tx.commit()
        .await
        .map_err(|e| internal("committing the decision", e))?;
    metrics::counter!("limen_review_decisions_total", "decision" => if certify { "certify" } else { "flag" }).increment(1);
    let updated = sqlx::query(concat!(
        "SELECT ",
        item_cols!(),
        " FROM review_items WHERE id = $1"
    ))
    .bind(item_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| internal("reading a review item", e))?;
    item_from(&updated, who)
}

// ---- overrides --------------------------------------------------------------------------------

/// The overrides in force, in the form the snapshot carries.
pub async fn active_denies(db: &Db) -> Result<Vec<limen_session::snapshot::RoleDeny>, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT id, username, role, expires_at FROM access_denies WHERE lifted_at IS NULL AND expires_at > now()",
    )
    .fetch_all(db)
    .await?
    .iter()
    .filter_map(|r| {
        Some(limen_session::snapshot::RoleDeny {
            id: r.try_get::<Uuid, _>("id").ok()?.to_string(),
            username: r.try_get("username").ok()?,
            role: r.try_get("role").ok()?,
            expires_at_unix: unix(r.try_get("expires_at").ok()?),
        })
    })
    .collect())
}

pub async fn list_denies(
    state: &AppState,
    who: &Who<'_>,
    include_ended: bool,
) -> Result<Vec<DenyInfo>, Status> {
    if !(who.is_admin || who.is_auditor) {
        return Err(Status::permission_denied(
            "listing overrides needs the limen:admin or limen:auditor role",
        ));
    }
    let rows = sqlx::query(
        "SELECT id, username, role, reason, created_by, created_at, expires_at,
                (lifted_at IS NULL AND expires_at > now()) AS active
         FROM access_denies WHERE $1 OR (lifted_at IS NULL AND expires_at > now())
         ORDER BY created_at DESC LIMIT 500",
    )
    .bind(include_ended)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal("listing overrides", e))?;
    let e = |e| internal("reading an override", e);
    rows.iter()
        .map(|r| {
            Ok(DenyInfo {
                id: r.try_get::<Uuid, _>("id").map_err(e)?.to_string(),
                username: r.try_get("username").map_err(e)?,
                role: r.try_get("role").map_err(e)?,
                reason: r.try_get("reason").map_err(e)?,
                created_by: r.try_get("created_by").map_err(e)?,
                created_at_unix: unix(r.try_get("created_at").map_err(e)?),
                expires_at_unix: unix(r.try_get("expires_at").map_err(e)?),
                active: r.try_get("active").map_err(e)?,
            })
        })
        .collect()
}

pub async fn lift_deny(
    state: &AppState,
    who: &Who<'_>,
    id: &str,
    reason: &str,
) -> Result<bool, Status> {
    if !who.is_admin {
        return Err(Status::permission_denied(
            "the limen:admin role is required",
        ));
    }
    let id =
        Uuid::parse_str(id.trim()).map_err(|_| Status::invalid_argument("not an override id"))?;
    let reason = ops::clean_reason(reason)?;
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal("starting transaction", e))?;
    let lifted = sqlx::query(
        "UPDATE access_denies SET lifted_at = now(), lifted_by = $2, lift_reason = $3
         WHERE id = $1 AND lifted_at IS NULL RETURNING username, role",
    )
    .bind(id)
    .bind(who.username)
    .bind(&reason)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| internal("lifting an override", e))?;
    let Some(row) = lifted else {
        return Ok(false);
    };
    audit(
        state,
        EventKind::AccessDenyOverride,
        who.username,
        json!({
            "lifted": true, "target_user": row.try_get::<String, _>("username").unwrap_or_default(),
            "role": row.try_get::<String, _>("role").unwrap_or_default(), "reason": reason, "via": who.via,
        }),
    )
    .await?;
    tx.commit().await.map_err(|e| internal("committing", e))?;
    Ok(true)
}

// ---- the background tick ----------------------------------------------------------------

/// Lift overrides whose IdP change has shown up, remind and escalate, and
/// start the scheduled review when it is due.
pub async fn tick(state: &AppState) -> Result<(), Status> {
    // The person's roles at their latest login no longer hold the role: the
    // IdP change was made, so the override has done its job.
    let confirmed = sqlx::query(
        "UPDATE access_denies d SET lifted_at = now(), lifted_by = 'system', lift_reason = 'the IdP change was confirmed at their next login'
         FROM users u WHERE d.lifted_at IS NULL AND u.username = d.username AND u.last_login_at > d.created_at
           AND NOT (d.role = ANY(u.roles)) RETURNING d.username, d.role",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal("confirming overrides", e))?;
    for r in &confirmed {
        audit(
            state,
            EventKind::AccessDenyOverride,
            "system",
            json!({
                "lifted": true, "confirmed": true,
                "target_user": r.try_get::<String, _>("username").unwrap_or_default(),
                "role": r.try_get::<String, _>("role").unwrap_or_default(),
            }),
        )
        .await?;
    }

    // Overdue items go to the admins.
    let escalated = sqlx::query(
        "UPDATE review_items i SET reviewer = '*admin', escalated_at = now()
         FROM access_reviews r WHERE r.id = i.review_id AND r.status = 'open' AND r.due_at < now()
           AND i.decision IS NULL AND i.reviewer <> '*admin' AND i.escalated_at IS NULL
         RETURNING i.id, i.review_id, i.subject, i.role, i.reviewer",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal("escalating items", e))?;
    for r in &escalated {
        audit(
            state,
            EventKind::ReviewDecide,
            "system",
            json!({
                "action": "escalated", "item_id": r.try_get::<Uuid, _>("id").map(|u| u.to_string()).unwrap_or_default(),
                "review_id": r.try_get::<Uuid, _>("review_id").map(|u| u.to_string()).unwrap_or_default(),
                "target_user": r.try_get::<String, _>("subject").unwrap_or_default(),
                "role": r.try_get::<String, _>("role").unwrap_or_default(),
            }),
        )
        .await?;
    }
    if !escalated.is_empty() {
        metrics::counter!("limen_review_items_escalated_total").increment(escalated.len() as u64);
    }

    // A reminder every few days to whoever hasn't answered, one notice per review.
    let due = sqlx::query(
        "WITH due AS (
            UPDATE review_items i SET reminded_at = now()
            FROM access_reviews r WHERE r.id = i.review_id AND r.status = 'open' AND i.decision IS NULL
              AND (i.reminded_at IS NULL OR i.reminded_at < now() - make_interval(days => $1))
              AND r.due_at < now() + interval '3 days'
            RETURNING r.id AS review_id, r.name
         ) SELECT review_id, name, count(*) AS n FROM due GROUP BY review_id, name",
    )
    .bind(REMIND_EVERY_DAYS)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal("reminding reviewers", e))?;
    for r in &due {
        let id: Uuid = r
            .try_get("review_id")
            .map_err(|e| internal("reminder", e))?;
        state.notifier.send(&Notice {
            event: Event::ReviewDue,
            request_id: id.to_string(),
            link: state
                .console
                .as_ref()
                .map(|c| format!("{}/console/reviews", c.origin)),
            requester: String::new(),
            role: String::new(),
            resource: r.try_get::<String, _>("name").unwrap_or_default(),
            reason: String::new(),
            duration_secs: 0,
        });
    }

    // The scheduled review, started at most once per interval across replicas.
    let every = state.config.review_interval;
    if !every.is_zero() {
        let mut tx = state
            .db
            .begin()
            .await
            .map_err(|e| internal("starting transaction", e))?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(crate::db::locks::REVIEW_SCHEDULE)
            .execute(&mut *tx)
            .await
            .map_err(|e| internal("locking", e))?;
        let recent: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM access_reviews WHERE started_at > now() - make_interval(secs => $1))",
        )
        .bind(every.as_secs_f64())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| internal("checking reviews", e))?;
        // A deployment nobody has signed in to has nothing to review.
        let anyone: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users)")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| internal("checking users", e))?;
        if !recent && anyone {
            let who = Who {
                username: "system",
                is_admin: true,
                is_auditor: false,
                via: "schedule",
            };
            let name = format!(
                "Scheduled access review {}",
                OffsetDateTime::now_utc().date()
            );
            // Started inside the lock, so a second replica waits and then sees it.
            start(state, &who, &name, 0, 0).await?;
        }
        tx.commit().await.map_err(|e| internal("committing", e))?;
    }
    Ok(())
}

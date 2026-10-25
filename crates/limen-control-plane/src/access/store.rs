//! SQL behind access requests (ADR-0025). Plain functions over a pool or a
//! transaction; the rules live in the parent module.

use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone)]
pub struct RequestRow {
    pub id: Uuid,
    pub requester: String,
    pub role: String,
    pub resource: String,
    pub reason: String,
    pub duration_secs: i32,
    pub status: String,
    pub break_glass: bool,
    pub approvals_required: i32,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub decided_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone)]
pub struct ApprovalRow {
    pub request_id: Uuid,
    pub approver: String,
    pub decision: String,
    pub comment: String,
    pub decided_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct GrantRow {
    pub request_id: Uuid,
    pub username: String,
    pub role: String,
    pub resource: String,
    pub reason: String,
    pub break_glass: bool,
    pub approvers: Vec<String>,
    pub granted_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub revoked_by: Option<String>,
}

macro_rules! request_cols {
    () => {
        "id, requester, role, resource, reason, duration_secs, status, break_glass, approvals_required, created_at, expires_at, decided_at"
    };
}

macro_rules! grant_cols {
    () => {
        "request_id, username, role, resource, reason, break_glass, approvers, granted_at, expires_at, revoked_at, revoked_by"
    };
}

fn request_from(r: &PgRow) -> Result<RequestRow, sqlx::Error> {
    Ok(RequestRow {
        id: r.try_get("id")?,
        requester: r.try_get("requester")?,
        role: r.try_get("role")?,
        resource: r.try_get("resource")?,
        reason: r.try_get("reason")?,
        duration_secs: r.try_get("duration_secs")?,
        status: r.try_get("status")?,
        break_glass: r.try_get("break_glass")?,
        approvals_required: r.try_get("approvals_required")?,
        created_at: r.try_get("created_at")?,
        expires_at: r.try_get("expires_at")?,
        decided_at: r.try_get("decided_at")?,
    })
}

fn grant_from(r: &PgRow) -> Result<GrantRow, sqlx::Error> {
    Ok(GrantRow {
        request_id: r.try_get("request_id")?,
        username: r.try_get("username")?,
        role: r.try_get("role")?,
        resource: r.try_get("resource")?,
        reason: r.try_get("reason")?,
        break_glass: r.try_get("break_glass")?,
        approvers: r.try_get("approvers")?,
        granted_at: r.try_get("granted_at")?,
        expires_at: r.try_get("expires_at")?,
        revoked_at: r.try_get("revoked_at")?,
        revoked_by: r.try_get("revoked_by")?,
    })
}

#[derive(Debug)]
pub struct NewRequest<'a> {
    pub id: Uuid,
    pub requester: &'a str,
    pub role: &'a str,
    pub resource: &'a str,
    pub reason: &'a str,
    pub duration_secs: i32,
    pub break_glass: bool,
    pub approvals_required: i32,
    pub expires_at: OffsetDateTime,
}

/// `Ok(false)` if the person already has this request open.
pub async fn insert_request(
    tx: &mut Transaction<'_, Postgres>,
    r: &NewRequest<'_>,
) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "INSERT INTO access_requests (id, requester, role, resource, reason, duration_secs, status, break_glass, approvals_required, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9)
         ON CONFLICT (requester, role, resource) WHERE status = 'pending' DO NOTHING",
    )
    .bind(r.id)
    .bind(r.requester)
    .bind(r.role)
    .bind(r.resource)
    .bind(r.reason)
    .bind(r.duration_secs)
    .bind(r.break_glass)
    .bind(r.approvals_required)
    .bind(r.expires_at)
    .execute(&mut **tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

pub async fn request(db: &Db, id: Uuid) -> Result<Option<RequestRow>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        request_cols!(),
        " FROM access_requests WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await?
    .as_ref()
    .map(request_from)
    .transpose()
}

/// The request, locked until the transaction ends, so two approvers deciding
/// at once are serialised.
pub async fn request_for_update(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<RequestRow>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        request_cols!(),
        " FROM access_requests WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .as_ref()
    .map(request_from)
    .transpose()
}

pub async fn set_status(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE access_requests SET status = $2, decided_at = COALESCE(decided_at, now()) WHERE id = $1")
        .bind(id)
        .bind(status)
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

/// `Ok(false)` if this approver already decided it.
pub async fn insert_approval(
    tx: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    approver: &str,
    decision: &str,
    comment: &str,
) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "INSERT INTO access_approvals (request_id, approver, decision, comment)
         VALUES ($1, $2, $3, $4) ON CONFLICT (request_id, approver) DO NOTHING",
    )
    .bind(request_id)
    .bind(approver)
    .bind(decision)
    .bind(comment)
    .execute(&mut **tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

pub async fn approvals_in(
    tx: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<Vec<ApprovalRow>, sqlx::Error> {
    sqlx::query("SELECT request_id, approver, decision, comment, decided_at FROM access_approvals WHERE request_id = $1 ORDER BY decided_at")
        .bind(request_id)
        .fetch_all(&mut **tx)
        .await?
        .iter()
        .map(approval_from)
        .collect()
}

/// Approvals of several requests at once.
pub async fn approvals_of(db: &Db, ids: &[Uuid]) -> Result<Vec<ApprovalRow>, sqlx::Error> {
    sqlx::query("SELECT request_id, approver, decision, comment, decided_at FROM access_approvals WHERE request_id = ANY($1) ORDER BY decided_at")
        .bind(ids)
        .fetch_all(db)
        .await?
        .iter()
        .map(approval_from)
        .collect()
}

fn approval_from(r: &PgRow) -> Result<ApprovalRow, sqlx::Error> {
    Ok(ApprovalRow {
        request_id: r.try_get("request_id")?,
        approver: r.try_get("approver")?,
        decision: r.try_get("decision")?,
        comment: r.try_get("comment")?,
        decided_at: r.try_get("decided_at")?,
    })
}

#[derive(Debug)]
pub struct NewGrant<'a> {
    pub request_id: Uuid,
    pub username: &'a str,
    pub role: &'a str,
    pub resource: &'a str,
    pub reason: &'a str,
    pub break_glass: bool,
    pub approvers: &'a [String],
    pub expires_at: OffsetDateTime,
}

pub async fn insert_grant(
    tx: &mut Transaction<'_, Postgres>,
    g: &NewGrant<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO access_grants (request_id, username, role, resource, reason, break_glass, approvers, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(g.request_id)
    .bind(g.username)
    .bind(g.role)
    .bind(g.resource)
    .bind(g.reason)
    .bind(g.break_glass)
    .bind(g.approvers)
    .bind(g.expires_at)
    .execute(&mut **tx)
    .await
    .map(|_| ())
}

/// Grants that are in force: not revoked, not past their deadline. These go
/// into the signed snapshot.
pub async fn active_grants(db: &Db) -> Result<Vec<GrantRow>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        grant_cols!(),
        " FROM access_grants WHERE revoked_at IS NULL AND expires_at > now() ORDER BY granted_at"
    ))
    .fetch_all(db)
    .await?
    .iter()
    .map(grant_from)
    .collect()
}

pub async fn grant(db: &Db, id: Uuid) -> Result<Option<GrantRow>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        grant_cols!(),
        " FROM access_grants WHERE request_id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await?
    .as_ref()
    .map(grant_from)
    .transpose()
}

/// Active grants, plus ended ones from the last 30 days if asked.
pub async fn list_grants(db: &Db, include_ended: bool) -> Result<Vec<GrantRow>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        grant_cols!(),
        " FROM access_grants
          WHERE ($1 OR (revoked_at IS NULL AND expires_at > now()))
            AND granted_at > now() - interval '30 days'
          ORDER BY granted_at DESC LIMIT 500"
    ))
    .bind(include_ended)
    .fetch_all(db)
    .await?
    .iter()
    .map(grant_from)
    .collect()
}

/// End a grant that is still in force. `None` if it had ended already.
pub async fn revoke_grant(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    by: &str,
    reason: &str,
) -> Result<Option<GrantRow>, sqlx::Error> {
    sqlx::query(concat!(
        "UPDATE access_grants SET revoked_at = now(), revoked_by = $2, revoke_reason = $3
         WHERE request_id = $1 AND revoked_at IS NULL AND expires_at > now()
         RETURNING ",
        grant_cols!()
    ))
    .bind(id)
    .bind(by)
    .bind(reason)
    .fetch_optional(&mut **tx)
    .await?
    .as_ref()
    .map(grant_from)
    .transpose()
}

/// Ask the proxies to end every open session that was allowed by this grant.
/// Returns how many sessions that is.
pub async fn kill_sessions_of(
    tx: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    by: &str,
    reason: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "INSERT INTO session_kills (session_id, reason, killed_by)
         SELECT session_id::text, $2, $3 FROM sessions
         WHERE $1 = ANY(request_ids) AND ended_at IS NULL
         ON CONFLICT DO NOTHING",
    )
    .bind(request_id.to_string())
    .bind(reason)
    .bind(by)
    .execute(&mut **tx)
    .await
    .map(|d| d.rows_affected())
}

/// Requests, newest first.
pub async fn list_requests(
    db: &Db,
    requester: Option<&str>,
    status: Option<&str>,
    limit: i64,
) -> Result<Vec<RequestRow>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        request_cols!(),
        " FROM access_requests
          WHERE ($1::text IS NULL OR requester = $1) AND ($2::text IS NULL OR status = $2)
          ORDER BY created_at DESC LIMIT $3"
    ))
    .bind(requester)
    .bind(status)
    .bind(limit)
    .fetch_all(db)
    .await?
    .iter()
    .map(request_from)
    .collect()
}

/// Pending requests that have not lapsed.
pub async fn pending(db: &Db) -> Result<Vec<RequestRow>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        request_cols!(),
        " FROM access_requests WHERE status = 'pending' AND expires_at > now() ORDER BY created_at LIMIT 500"
    ))
    .fetch_all(db)
    .await?
    .iter()
    .map(request_from)
    .collect()
}

/// How many requests the person has open, and has made in the last day.
pub async fn request_counts(db: &Db, requester: &str) -> Result<(i64, i64), sqlx::Error> {
    let row = sqlx::query(
        "SELECT count(*) FILTER (WHERE status = 'pending') AS open,
                count(*) FILTER (WHERE created_at > now() - interval '1 day') AS day
         FROM access_requests WHERE requester = $1",
    )
    .bind(requester)
    .fetch_one(db)
    .await?;
    Ok((row.try_get("open")?, row.try_get("day")?))
}

/// Pending requests whose time has run out, locked for this transaction so
/// that only one replica writes each `access.expire` event.
pub async fn lapsed_requests(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Vec<RequestRow>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        request_cols!(),
        " FROM access_requests WHERE status = 'pending' AND expires_at <= now()
          ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED"
    ))
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(request_from)
    .collect()
}

/// Grants past their deadline whose expiry has not been audited yet.
pub async fn lapsed_grants(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Vec<GrantRow>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        grant_cols!(),
        " FROM access_grants WHERE expires_at <= now() AND revoked_at IS NULL AND expiry_noted_at IS NULL
          ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED"
    ))
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(grant_from)
    .collect()
}

pub async fn note_grant_expired(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE access_grants SET expiry_noted_at = now() WHERE request_id = $1")
        .bind(id)
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

/// What the person did on a resource in the past 30 days: how many sessions,
/// and when the latest started. The context an approver needs.
pub async fn requester_activity(
    db: &Db,
    username: &str,
    resource: &str,
) -> Result<(i64, Option<OffsetDateTime>), sqlx::Error> {
    let row = sqlx::query(
        "SELECT count(*) AS n, max(started_at) AS last FROM sessions
         WHERE username = $1 AND resource = $2 AND started_at > now() - interval '30 days'",
    )
    .bind(username)
    .bind(resource)
    .fetch_one(db)
    .await?;
    Ok((row.try_get("n")?, row.try_get("last")?))
}

/// The groups the IdP reported at the person's latest login. `None` if they
/// have never logged in.
pub async fn user_groups(db: &Db, username: &str) -> Result<Option<Vec<String>>, sqlx::Error> {
    sqlx::query_scalar("SELECT groups FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(db)
        .await
}

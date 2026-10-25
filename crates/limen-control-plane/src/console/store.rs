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
    /// When the login behind this session was ended by `limen logout`.
    pub logged_out_at: Option<OffsetDateTime>,
    /// Connections that carry this row: a driver opens several per run, and
    /// they share a group. 1 for everything else.
    pub connections: i64,
}

/// Whether a `sessions` row is live, with the window in hours as `$1`. A
/// `kubectl` row (one per login and cluster) has no end event: its `ended_at`
/// is its last request, and it is live while that is recent.
macro_rules! is_active {
    () => {
        "(CASE WHEN kind = 'kubectl' THEN ended_at > now() - interval '5 minutes'
                 AND NOT EXISTS (SELECT 1 FROM login_revocations r WHERE r.login_id = sessions.login_id)
               ELSE ended_at IS NULL AND started_at IS NOT NULL AND started_at > now() - make_interval(hours => $1) END)"
    };
}

/// A connection of the same run as `sessions`' row: same group, user, and
/// resource (the group id comes from the client, so it only groups what is
/// already the same user's and resource's).
macro_rules! same_run {
    () => {
        "o.conn_group = sessions.conn_group AND o.username = sessions.username AND o.resource = sessions.resource"
    };
}

/// `o` did something, or is still open. The empty startup check of
/// `limen mongo connect` doesn't count as a connection.
macro_rules! carries_traffic {
    () => {
        "(COALESCE(o.bytes_in, 0) > 0 OR o.ended_at IS NULL)"
    };
}

/// A row is live when it is, or another connection of its run is.
macro_rules! run_active {
    () => {
        concat!(
            "(",
            is_active!(),
            " OR (conn_group IS NOT NULL AND EXISTS (SELECT 1 FROM sessions o WHERE ",
            same_run!(),
            " AND o.ended_at IS NULL AND o.started_at > now() - make_interval(hours => $1))))"
        )
    };
}

macro_rules! session_select {
    () => {
        concat!(
            "SELECT session_id, username, kind, resource, login, worker_id, proxy_id, client_addr,
        started_at, ended_at, end_reason, duration_ms, bytes_in, bytes_out, recording_uri, recording_sha256,
        actor_type, ci,
        (SELECT r.revoked_at FROM login_revocations r WHERE r.login_id = sessions.login_id) AS logged_out_at,
        CASE WHEN conn_group IS NULL THEN 1 ELSE GREATEST(1, (SELECT count(*) FROM sessions o WHERE ",
            same_run!(),
            " AND ",
            carries_traffic!(),
            ")) END AS connections, ",
            run_active!(),
            " AS active FROM sessions"
        )
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
        logged_out_at: r.try_get("logged_out_at")?,
        connections: r.try_get("connections")?,
    })
}

#[derive(Debug, Clone, Default)]
pub struct SessionFilter {
    pub username: Option<String>,
    pub resource: Option<String>,
    /// `user` or `bot`.
    pub actor: Option<String>,
    pub kind: Option<String>,
    pub login: Option<String>,
    pub client_addr: Option<String>,
    pub end_reason: Option<String>,
    /// The repository or project a bot's CI job ran for.
    pub repo: Option<String>,
    pub from: Option<OffsetDateTime>,
    /// Exclusive.
    pub to: Option<OffsetDateTime>,
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
           AND ($7::text IS NULL OR actor_type = $7)
           AND ($8::text IS NULL OR kind = $8)
           AND ($9::text IS NULL OR login = $9)
           AND ($10::text IS NULL OR client_addr = $10)
           AND ($11::text IS NULL OR end_reason = $11)
           AND ($12::text IS NULL OR COALESCE(ci->>'repository', ci->>'project_path', username) = $12)
           AND ($13::timestamptz IS NULL OR started_at >= $13)
           AND ($14::timestamptz IS NULL OR started_at < $14)
           AND (NOT $3 OR ",
        run_active!(),
        ")
           AND (conn_group IS NULL OR session_id = (
                SELECT o.session_id FROM sessions o WHERE ",
        same_run!(),
        " ORDER BY ",
        carries_traffic!(),
        " DESC, o.started_at, o.session_id LIMIT 1))
         ORDER BY COALESCE(started_at, ended_at) DESC, session_id DESC
         LIMIT $4 OFFSET $5"
    ))
    .bind(ACTIVE_WINDOW_HOURS)
    .bind(&f.username)
    .bind(f.active_only)
    .bind(f.limit + 1)
    .bind(f.offset)
    .bind(&f.resource)
    .bind(&f.actor)
    .bind(&f.kind)
    .bind(&f.login)
    .bind(&f.client_addr)
    .bind(&f.end_reason)
    .bind(&f.repo)
    .bind(f.from)
    .bind(f.to)
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
    let rows = sqlx::query(concat!(
        "SELECT resource, count(*) AS total, count(*) FILTER (WHERE ",
        is_active!(),
        ") AS active FROM sessions WHERE resource IS NOT NULL GROUP BY resource"
    ))
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
    sqlx::query_scalar(concat!(
        "SELECT count(*) FROM sessions WHERE ",
        is_active!()
    ))
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

/// The access requests whose grants allowed a session (`data.request_ids`).
/// Only well-formed ids are kept: the column is matched against grant ids.
fn request_ids(data: &serde_json::Value) -> Vec<String> {
    data.get("request_ids")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_str)
                .filter(|s| Uuid::parse_str(s).is_ok())
                .take(16)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn number(data: &serde_json::Value, key: &str) -> Option<i64> {
    data.get(key).and_then(serde_json::Value::as_i64)
}

/// Data fields that may appear in the console's audit trail, in display
/// order. Everything else (statements, claims, groups) stays in the sinks.
const SUMMARY_KEYS: [&str; 27] = [
    "request_id",
    "role",
    "what",
    "action",
    "target_user",
    "component_id",
    "component_name",
    "kind",
    "name",
    "resource",
    "login",
    "redis_user",
    "mongo_role",
    "mq_user",
    "kafka_user",
    "reason",
    "by",
    "via",
    "worker_id",
    "worker_name",
    "bot",
    "break_glass",
    "method",
    // kube.request
    "verb",
    "k8s_resource",
    "namespace",
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

/// One statement of a database session, with how it ended.
#[derive(Debug)]
pub struct DbStatementRow {
    pub at: OffsetDateTime,
    pub phase: Option<String>,
    pub statement_type: Option<String>,
    pub statement: Option<String>,
    pub truncated: bool,
    pub status: Option<String>,
    pub rows: Option<i64>,
    pub duration_ms: Option<i64>,
    pub error_code: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WebRequestRow {
    pub at: OffsetDateTime,
    pub method: String,
    pub path: String,
    pub status: Option<i32>,
    pub bytes_in: Option<i64>,
    pub bytes_out: Option<i64>,
    pub duration_ms: Option<i64>,
    pub outcome: Option<String>,
}

/// The longest statement text kept in the console's table.
const MAX_STATEMENT_TEXT: usize = 16 * 1024;

/// `db_statements` rows of session `$1` and of the other connections of its run.
macro_rules! run_sessions {
    () => {
        "(session_id = $1 OR session_id IN (
            SELECT o.session_id FROM sessions o, sessions me
            WHERE me.session_id = $1 AND me.conn_group IS NOT NULL AND o.conn_group = me.conn_group
              AND o.username = me.username AND o.resource = me.resource))"
    };
}

/// The statements of a session (and of the other connections of its run) in
/// the order they were sent, at most `limit`.
pub async fn db_statements(
    db: &Db,
    id: Uuid,
    limit: i64,
) -> Result<Vec<DbStatementRow>, sqlx::Error> {
    let rows = sqlx::query(concat!(
        "SELECT at, phase, statement_type, statement, truncated, status, \"rows\", duration_ms, error_code, error
         FROM db_statements WHERE ",
        run_sessions!(),
        " AND statement_type IS NOT NULL
         ORDER BY at, event_id LIMIT $2"
    ))
    .bind(id)
    .bind(limit)
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(DbStatementRow {
                at: r.try_get("at")?,
                phase: r.try_get("phase")?,
                statement_type: r.try_get("statement_type")?,
                statement: r.try_get("statement")?,
                truncated: r.try_get("truncated")?,
                status: r.try_get("status")?,
                rows: r.try_get("rows")?,
                duration_ms: r.try_get("duration_ms")?,
                error_code: r.try_get("error_code")?,
                error: r.try_get("error")?,
            })
        })
        .collect()
}

/// `(statements, errors)` of a session. Errors include Redis commands that
/// policy refused.
pub async fn db_session_counts(db: &Db, id: Uuid) -> Result<(i64, i64), sqlx::Error> {
    let row = sqlx::query(concat!(
        "SELECT count(*) FILTER (WHERE statement_type IS NOT NULL) AS statements,
                count(*) FILTER (WHERE status IN ('error', 'denied')) AS errors
         FROM db_statements WHERE ",
        run_sessions!()
    ))
    .bind(id)
    .fetch_one(db)
    .await?;
    Ok((row.try_get("statements")?, row.try_get("errors")?))
}

pub async fn web_requests(
    db: &Db,
    id: Uuid,
    limit: i64,
) -> Result<Vec<WebRequestRow>, sqlx::Error> {
    sqlx::query(
        "SELECT at, method, path, status, bytes_in, bytes_out, duration_ms, outcome
         FROM web_requests WHERE request_id = $1 ORDER BY at LIMIT $2",
    )
    .bind(id)
    .bind(limit)
    .fetch_all(db)
    .await?
    .iter()
    .map(|row| {
        Ok(WebRequestRow {
            at: row.try_get("at")?,
            method: row.try_get("method")?,
            path: row.try_get("path")?,
            status: row.try_get("status")?,
            bytes_in: row.try_get("bytes_in")?,
            bytes_out: row.try_get("bytes_out")?,
            duration_ms: row.try_get("duration_ms")?,
            outcome: row.try_get("outcome")?,
        })
    })
    .collect()
}

pub async fn web_session_counts(db: &Db, id: Uuid) -> Result<(i64, i64), sqlx::Error> {
    let row = sqlx::query(
        "SELECT count(*) AS requests,
                count(*) FILTER (WHERE status >= 400) AS errors
         FROM web_requests WHERE request_id = $1",
    )
    .bind(id)
    .fetch_one(db)
    .await?;
    Ok((row.try_get("requests")?, row.try_get("errors")?))
}

fn cut(text: &str, max: usize) -> (&str, bool) {
    if text.len() <= max {
        return (text, false);
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

/// Apply session events to the `sessions` table. Idempotent and
/// order-independent: every column is filled by exactly one kind of event
/// and never overwritten by another, so redelivery and reordering are safe.
#[allow(clippy::too_many_lines)] // one arm per audit event kind
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
            project_kube_request(&mut tx, e).await?;
        }
        // A copy of what was done, to search (ADR-0026).
        crate::search::index::index_event(&mut tx, e, &kind_name(e.kind)).await?;
        let Some(session_id) = e.session_id else {
            continue;
        };
        match e.kind {
            EventKind::SessionStart => {
                sqlx::query(
                    "INSERT INTO sessions (session_id, username, kind, resource, login, worker_id, proxy_id, client_addr, started_at, actor_type, ci, conn_group, request_ids)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                     ON CONFLICT (session_id) DO UPDATE SET username = EXCLUDED.username, kind = EXCLUDED.kind,
                       resource = EXCLUDED.resource, login = EXCLUDED.login, worker_id = EXCLUDED.worker_id,
                       proxy_id = EXCLUDED.proxy_id, client_addr = EXCLUDED.client_addr, started_at = EXCLUDED.started_at,
                       actor_type = EXCLUDED.actor_type, ci = EXCLUDED.ci,
                       conn_group = EXCLUDED.conn_group, request_ids = EXCLUDED.request_ids",
                )
                .bind(session_id)
                .bind(&e.user)
                .bind(text(&e.data, "kind"))
                .bind(text(&e.data, "resource"))
                .bind(text(&e.data, "login")
                    .or_else(|| text(&e.data, "redis_user"))
                    .or_else(|| text(&e.data, "mongo_role"))
                    .or_else(|| text(&e.data, "mq_user"))
                    .or_else(|| text(&e.data, "kafka_user")))
                .bind(text(&e.data, "worker_id"))
                .bind(text(&e.data, "proxy_id"))
                .bind(text(&e.data, "client_addr"))
                .bind(e.time)
                .bind(text(&e.data, "actor_type").unwrap_or("user"))
                .bind(e.data.get("ci").filter(|c| c.is_object()))
                .bind(text(&e.data, "group"))
                .bind(request_ids(&e.data))
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
                .bind(text(&e.data, "login")
                    .or_else(|| text(&e.data, "redis_user"))
                    .or_else(|| text(&e.data, "mongo_role"))
                    .or_else(|| text(&e.data, "mq_user"))
                    .or_else(|| text(&e.data, "kafka_user")))
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
            EventKind::DbQuery => {
                project_db_query(&mut tx, e, session_id).await?;
            }
            // Redis sessions have no recording either; their commands share the
            // statements table (ADR-0034). The text holds key names (hashed if
            // the resource asks) and never values.
            EventKind::RedisCommand => {
                project_redis_command(&mut tx, e, session_id, "allowed", None).await?;
            }
            EventKind::AuthDenied if text(&e.data, "action") == Some("redis") => {
                project_redis_command(&mut tx, e, session_id, "denied", text(&e.data, "reason"))
                    .await?;
            }
            // MongoDB sessions have no recording either (ADR-0035). The commands
            // share the statements table; the text is the command's shape with
            // every value replaced (or the values, if the resource keeps them).
            EventKind::MongoCommand => {
                project_mongo_command(&mut tx, e, session_id).await?;
            }
            EventKind::MongoCommandEnd => {
                project_mongo_end(&mut tx, e, session_id).await?;
            }
            // Search sessions have no recording either (ADR-0036): each request
            // is a row, the response fills in how it ended, and a refused
            // request is a row with status `denied`. Bodies are never here.
            EventKind::SearchRequest => {
                project_search_request(&mut tx, e, session_id).await?;
            }
            EventKind::SearchResponse => {
                project_search_response(&mut tx, e, session_id).await?;
            }
            EventKind::WebRequest => {
                project_web_request(&mut tx, e, session_id).await?;
            }
            EventKind::WebResponse => {
                project_web_response(&mut tx, e, session_id).await?;
            }
            EventKind::WebSocket => {
                project_websocket(&mut tx, e, session_id).await?;
            }
            EventKind::AuthDenied if text(&e.data, "action") == Some("search") => {
                project_search_denied(&mut tx, e, session_id).await?;
            }
            // RabbitMQ and Kafka sessions are listed the same way (ADR-0037): the
            // text holds names and sizes, never message content.
            EventKind::MqOperation | EventKind::KafkaRequest => {
                let (kind, statement) = broker_statement(e.kind, &e.data);
                project_statement(&mut tx, e, session_id, "allowed", None, &kind, &statement)
                    .await?;
            }
            EventKind::AuthDenied if matches!(text(&e.data, "action"), Some("mq" | "kafka")) => {
                let (kind, statement) = broker_statement(e.kind, &e.data);
                project_statement(
                    &mut tx,
                    e,
                    session_id,
                    "denied",
                    text(&e.data, "reason"),
                    &kind,
                    &statement,
                )
                .await?;
            }
            EventKind::DbQueryEnd => {
                let Some(query_id) = text(&e.data, "query_id").and_then(|q| q.parse::<Uuid>().ok())
                else {
                    continue;
                };
                sqlx::query(
                    "INSERT INTO db_statements (event_id, session_id, at, status, \"rows\", duration_ms, error_code, error)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                     ON CONFLICT (event_id) DO UPDATE SET status = EXCLUDED.status, \"rows\" = EXCLUDED.\"rows\",
                       duration_ms = EXCLUDED.duration_ms, error_code = EXCLUDED.error_code, error = EXCLUDED.error",
                )
                .bind(query_id)
                .bind(session_id)
                .bind(e.time)
                .bind(text(&e.data, "status"))
                .bind(number(&e.data, "rows"))
                .bind(number(&e.data, "duration_ms"))
                .bind(text(&e.data, "error_code"))
                .bind(text(&e.data, "error"))
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

/// One `kube.request` event into the Kubernetes view's table.
async fn project_kube_request(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &limen_audit::Event,
) -> Result<(), sqlx::Error> {
    let field = |key: &str| text(&e.data, key).unwrap_or_default();
    let login_session = kube_login_session(&e.data);
    // A path only where there is no resource to name (`/version`), and never
    // its query string.
    let path = if text(&e.data, "k8s_resource").is_none() {
        field("path").split('?').next().unwrap_or_default()
    } else {
        ""
    };
    sqlx::query(
        "INSERT INTO kube_requests (event_id, at, username, session_id, login_session, cluster, verb, api_group,
                                    resource, subresource, namespace, name, path, method, status, latency_ms, error)
         VALUES ($1, $2, $3, $4, $17, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
         ON CONFLICT (event_id) DO NOTHING",
    )
    .bind(e.event_id)
    .bind(e.time)
    .bind(&e.user)
    .bind(e.session_id)
    .bind(field("resource"))
    .bind(field("verb"))
    .bind(field("k8s_group"))
    .bind(field("k8s_resource"))
    .bind(field("subresource"))
    .bind(field("namespace"))
    .bind(field("name"))
    .bind(path)
    .bind(field("method"))
    .bind(i32::try_from(number(&e.data, "status").unwrap_or(0)).unwrap_or(0))
    .bind(number(&e.data, "latency_ms"))
    .bind(text(&e.data, "error"))
    .bind(login_session)
    .execute(&mut **tx)
    .await?;
    if let Some(id) = login_session {
        // One console session per login and cluster. It has no end event: it
        // spans its first to its last request, so each request only widens
        // it, which is idempotent and order-independent.
        sqlx::query(
            "INSERT INTO sessions (session_id, username, kind, resource, login, worker_id, proxy_id, client_addr,
                                   started_at, ended_at, duration_ms, actor_type, ci, login_id)
             VALUES ($1, $2, 'kubectl', $3, 'kubectl', $4, $5, $6, $7, $7, 0, $8, $9, $10)
             ON CONFLICT (session_id) DO UPDATE SET
               started_at = LEAST(sessions.started_at, EXCLUDED.started_at),
               ended_at = GREATEST(sessions.ended_at, EXCLUDED.ended_at),
               duration_ms = (EXTRACT(EPOCH FROM (GREATEST(sessions.ended_at, EXCLUDED.ended_at)
                                                  - LEAST(sessions.started_at, EXCLUDED.started_at))) * 1000)::bigint",
        )
        .bind(id)
        .bind(&e.user)
        .bind(field("resource"))
        .bind(text(&e.data, "worker_id"))
        .bind(text(&e.data, "proxy_id"))
        .bind(text(&e.data, "client_addr"))
        .bind(e.time)
        .bind(text(&e.data, "actor_type").unwrap_or("user"))
        .bind(e.data.get("ci").filter(|c| c.is_object()))
        .bind(text(&e.data, "login_id"))
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// The console session a `kube.request` belongs to: the same for every
/// request of one login on one cluster, derived so that any order of delivery
/// agrees. `None` for events from before the worker named the login.
fn kube_login_session(data: &serde_json::Value) -> Option<Uuid> {
    let login = text(data, "login_id")?;
    let cluster = text(data, "resource")?;
    Some(Uuid::new_v5(
        &Uuid::NAMESPACE_OID,
        format!("limen/kubectl/{login}/{cluster}").as_bytes(),
    ))
}

/// A statement sent to a SQL database, as the console shows it.
async fn project_db_query(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &limen_audit::Event,
    session_id: Uuid,
) -> Result<(), sqlx::Error> {
    let (statement, truncated) = cut(
        e.data
            .get("statement")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default(),
        MAX_STATEMENT_TEXT,
    );
    let truncated = truncated
        || e.data
            .get("truncated")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
    sqlx::query(
            "INSERT INTO db_statements (event_id, session_id, at, phase, statement_type, statement, truncated)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (event_id) DO UPDATE SET session_id = EXCLUDED.session_id, at = EXCLUDED.at,
               phase = EXCLUDED.phase, statement_type = EXCLUDED.statement_type,
               statement = EXCLUDED.statement, truncated = EXCLUDED.truncated",
        )
        .bind(e.event_id)
        .bind(session_id)
        .bind(e.time)
        .bind(text(&e.data, "phase"))
        .bind(text(&e.data, "statement_type"))
        .bind((!statement.is_empty()).then_some(statement))
        .bind(truncated)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// How a MongoDB command ended, onto the row of the command itself.
async fn project_mongo_end(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &limen_audit::Event,
    session_id: Uuid,
) -> Result<(), sqlx::Error> {
    let Some(command_id) = text(&e.data, "command_id").and_then(|q| q.parse::<Uuid>().ok()) else {
        return Ok(());
    };
    sqlx::query(
        "INSERT INTO db_statements (event_id, session_id, at, status, \"rows\", duration_ms, error_code, error)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (event_id) DO UPDATE SET status = EXCLUDED.status, \"rows\" = EXCLUDED.\"rows\",
           duration_ms = EXCLUDED.duration_ms, error_code = EXCLUDED.error_code, error = EXCLUDED.error",
    )
    .bind(command_id)
    .bind(session_id)
    .bind(e.time)
    .bind(text(&e.data, "status"))
    .bind(number(&e.data, "docs"))
    .bind(number(&e.data, "duration_ms"))
    .bind(
        text(&e.data, "error_code_name")
            .map(str::to_owned)
            .or_else(|| number(&e.data, "error_code").map(|c| c.to_string())),
    )
    .bind(text(&e.data, "error"))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The command a MongoDB event names, as the console shows it: namespace,
/// then the redacted shape.
fn mongo_statement(data: &serde_json::Value) -> String {
    let db = text(data, "database").unwrap_or_default();
    let namespace = match text(data, "collection") {
        Some(c) => format!("{db}.{c}"),
        None => db.to_owned(),
    };
    let summary = text(data, "summary")
        .filter(|s| *s != "{}")
        .unwrap_or_default();
    format!("{namespace} {summary}").trim().to_owned()
}

async fn project_mongo_command(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &limen_audit::Event,
    session_id: Uuid,
) -> Result<(), sqlx::Error> {
    let refused = text(&e.data, "phase") == Some("refused");
    let statement = mongo_statement(&e.data);
    let (statement, truncated) = cut(&statement, MAX_STATEMENT_TEXT);
    let truncated = truncated
        || e.data
            .get("summary_truncated")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
    // A forwarded command has no status until its end event arrives.
    sqlx::query(
        "INSERT INTO db_statements (event_id, session_id, at, phase, statement_type, statement, truncated, status, error)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (event_id) DO UPDATE SET session_id = EXCLUDED.session_id, at = EXCLUDED.at,
           phase = EXCLUDED.phase, statement_type = EXCLUDED.statement_type,
           statement = EXCLUDED.statement, truncated = EXCLUDED.truncated,
           status = COALESCE(db_statements.status, EXCLUDED.status), error = COALESCE(db_statements.error, EXCLUDED.error)",
    )
    .bind(e.event_id)
    .bind(session_id)
    .bind(e.time)
    .bind(text(&e.data, "phase"))
    .bind(text(&e.data, "command").map_or_else(|| "mongo".to_owned(), str::to_owned))
    .bind((!statement.is_empty()).then_some(statement))
    .bind(truncated)
    .bind(refused.then_some("denied"))
    .bind(if refused { text(&e.data, "reason") } else { None })
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The command a Redis event names, as the console shows it: the command,
/// its subcommand, then the arguments if the resource logs them, else the
/// keys it touched.
fn redis_statement(data: &serde_json::Value) -> String {
    let words = |key: &str| -> Option<Vec<String>> {
        data.get(key)?.as_array().map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
    };
    let mut parts: Vec<String> = Vec::new();
    parts.extend(text(data, "command").map(str::to_owned));
    parts.extend(text(data, "subcommand").map(str::to_owned));
    let listed = words("args").or_else(|| words("keys")).unwrap_or_default();
    let shown = listed.len();
    parts.extend(listed);
    // The event lists at most 100 keys; say when there were more.
    if let Some(total) = number(data, "keys_total")
        && let Ok(total) = usize::try_from(total)
        && total > shown
    {
        parts.push(format!("… (+{} more keys)", total - shown));
    }
    parts.join(" ")
}

/// `(type, text)` of a `RabbitMQ` or Kafka event, as the console lists it.
fn broker_statement(kind: limen_audit::EventKind, data: &serde_json::Value) -> (String, String) {
    let field = |k: &str| text(data, k).map(str::to_owned);
    let strings = |k: &str| -> Vec<String> {
        data.get(k)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| {
                        v.as_str()
                            .map(str::to_owned)
                            .or_else(|| text(v, "name").map(str::to_owned))
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut parts: Vec<String> = Vec::new();
    let name = if kind == limen_audit::EventKind::AuthDenied {
        field("operation")
    } else if text(data, "action").is_some() {
        field("action")
    } else {
        field("api")
    }
    .unwrap_or_else(|| "operation".to_owned());
    parts.push(name.clone());
    for (label, key) in [
        ("vhost", "vhost"),
        ("exchange", "exchange"),
        ("queue", "queue"),
        ("key", "routing_key"),
        ("group", "group"),
    ] {
        if let Some(v) = field(key) {
            parts.push(format!("{label}={v}"));
        }
    }
    let topics = strings("topics");
    if !topics.is_empty() {
        parts.push(format!("topics={}", topics.join(",")));
    }
    if let Some(size) = number(data, "size") {
        parts.push(format!("{size} B"));
    }
    (name.to_lowercase(), parts.join(" "))
}

async fn project_redis_command(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &limen_audit::Event,
    session_id: Uuid,
    status: &str,
    reason: Option<&str>,
) -> Result<(), sqlx::Error> {
    let kind = text(&e.data, "command").map_or_else(|| "redis".to_owned(), str::to_lowercase);
    project_statement(
        tx,
        e,
        session_id,
        status,
        reason,
        &kind,
        &redis_statement(&e.data),
    )
    .await
}

async fn project_statement(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &limen_audit::Event,
    session_id: Uuid,
    status: &str,
    reason: Option<&str>,
    kind: &str,
    statement: &str,
) -> Result<(), sqlx::Error> {
    let (statement, truncated) = cut(statement, MAX_STATEMENT_TEXT);
    sqlx::query(
        "INSERT INTO db_statements (event_id, session_id, at, statement_type, statement, truncated, status, error)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (event_id) DO UPDATE SET session_id = EXCLUDED.session_id, at = EXCLUDED.at,
           statement_type = EXCLUDED.statement_type, statement = EXCLUDED.statement,
           truncated = EXCLUDED.truncated, status = EXCLUDED.status, error = EXCLUDED.error",
    )
    .bind(e.event_id)
    .bind(session_id)
    .bind(e.time)
    .bind(kind)
    .bind((!statement.is_empty()).then_some(statement))
    .bind(truncated)
    .bind(status)
    .bind(reason)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// `GET /logs-1/_search`, with the query string if the resource logs it.
fn search_statement(data: &serde_json::Value) -> String {
    let mut out = format!(
        "{} {}",
        text(data, "method").unwrap_or("?"),
        text(data, "path").unwrap_or("/")
    );
    if let Some(q) = text(data, "query") {
        out.push('?');
        out.push_str(q);
    }
    out
}

async fn project_search_request(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &limen_audit::Event,
    session_id: Uuid,
) -> Result<(), sqlx::Error> {
    let statement = search_statement(&e.data);
    let (statement, truncated) = cut(&statement, MAX_STATEMENT_TEXT);
    sqlx::query(
        "INSERT INTO db_statements (event_id, session_id, at, phase, statement_type, statement, truncated)
         VALUES ($1, $2, $3, 'request', $4, $5, $6)
         ON CONFLICT (event_id) DO UPDATE SET session_id = EXCLUDED.session_id, at = EXCLUDED.at,
           phase = EXCLUDED.phase, statement_type = EXCLUDED.statement_type,
           statement = EXCLUDED.statement, truncated = EXCLUDED.truncated",
    )
    .bind(e.event_id)
    .bind(session_id)
    .bind(e.time)
    .bind(text(&e.data, "api").unwrap_or("search"))
    .bind(statement)
    .bind(truncated)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn project_search_response(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &limen_audit::Event,
    session_id: Uuid,
) -> Result<(), sqlx::Error> {
    let Some(request_id) = text(&e.data, "request_id").and_then(|q| q.parse::<Uuid>().ok()) else {
        return Ok(());
    };
    sqlx::query(
        "INSERT INTO db_statements (event_id, session_id, at, status, duration_ms, error_code, error)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (event_id) DO UPDATE SET status = EXCLUDED.status,
           duration_ms = EXCLUDED.duration_ms, error_code = EXCLUDED.error_code, error = EXCLUDED.error",
    )
    .bind(request_id)
    .bind(session_id)
    .bind(e.time)
    .bind(text(&e.data, "outcome"))
    .bind(number(&e.data, "duration_ms"))
    .bind(number(&e.data, "status").map(|s| s.to_string()))
    .bind(text(&e.data, "error_type"))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn project_search_denied(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &limen_audit::Event,
    session_id: Uuid,
) -> Result<(), sqlx::Error> {
    let statement = search_statement(&e.data);
    let (statement, truncated) = cut(&statement, MAX_STATEMENT_TEXT);
    sqlx::query(
        "INSERT INTO db_statements (event_id, session_id, at, phase, statement_type, statement, truncated, status, error)
         VALUES ($1, $2, $3, 'request', $4, $5, $6, 'denied', $7)
         ON CONFLICT (event_id) DO UPDATE SET session_id = EXCLUDED.session_id, at = EXCLUDED.at,
           phase = EXCLUDED.phase, statement_type = EXCLUDED.statement_type, statement = EXCLUDED.statement,
           truncated = EXCLUDED.truncated, status = EXCLUDED.status, error = EXCLUDED.error",
    )
    .bind(e.event_id)
    .bind(session_id)
    .bind(e.time)
    .bind(text(&e.data, "api").unwrap_or("search"))
    .bind(statement)
    .bind(truncated)
    .bind(text(&e.data, "reason"))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn project_web_request(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &limen_audit::Event,
    request_id: Uuid,
) -> Result<(), sqlx::Error> {
    let method = text(&e.data, "method").unwrap_or_default();
    let path = text(&e.data, "path").unwrap_or_default();
    sqlx::query(
        "INSERT INTO sessions (session_id, username, kind, resource, login, started_at, actor_type)
         VALUES ($1, $2, 'web', $3, 'browser', $4, $5)
         ON CONFLICT (session_id) DO UPDATE SET username = EXCLUDED.username, kind = EXCLUDED.kind,
           resource = EXCLUDED.resource, login = EXCLUDED.login,
           started_at = LEAST(COALESCE(sessions.started_at, EXCLUDED.started_at), EXCLUDED.started_at),
           actor_type = EXCLUDED.actor_type",
    )
    .bind(request_id)
    .bind(&e.user)
    .bind(text(&e.data, "resource"))
    .bind(e.time)
    .bind(text(&e.data, "actor_type").unwrap_or("user"))
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO web_requests (request_id, request_event_id, at, username, resource, host, method, path)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (request_id) DO UPDATE SET request_event_id = EXCLUDED.request_event_id,
           at = EXCLUDED.at, username = EXCLUDED.username, resource = EXCLUDED.resource,
           host = EXCLUDED.host, method = EXCLUDED.method, path = EXCLUDED.path",
    )
    .bind(request_id)
    .bind(e.event_id)
    .bind(e.time)
    .bind(&e.user)
    .bind(text(&e.data, "resource").unwrap_or_default())
    .bind(text(&e.data, "host").unwrap_or_default())
    .bind(method)
    .bind(path)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn project_web_response(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &limen_audit::Event,
    request_id: Uuid,
) -> Result<(), sqlx::Error> {
    let duration_ms = number(&e.data, "duration_ms");
    let at = e.time;
    let started_at = duration_ms.map_or(at, |ms| at - time::Duration::milliseconds(ms));
    let status = number(&e.data, "status").and_then(|value| i32::try_from(value).ok());
    sqlx::query(
        "INSERT INTO sessions (session_id, username, kind, resource, login, started_at, ended_at,
                               end_reason, duration_ms, bytes_in, bytes_out, actor_type)
         VALUES ($1, $2, 'web', $3, 'browser', $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (session_id) DO UPDATE SET username = COALESCE(sessions.username, EXCLUDED.username),
           kind = COALESCE(sessions.kind, EXCLUDED.kind), resource = COALESCE(sessions.resource, EXCLUDED.resource),
           login = COALESCE(sessions.login, EXCLUDED.login), started_at = COALESCE(sessions.started_at, EXCLUDED.started_at),
           ended_at = EXCLUDED.ended_at, end_reason = EXCLUDED.end_reason, duration_ms = EXCLUDED.duration_ms,
           bytes_in = EXCLUDED.bytes_in, bytes_out = EXCLUDED.bytes_out, actor_type = EXCLUDED.actor_type",
    )
    .bind(request_id)
    .bind(&e.user)
    .bind(text(&e.data, "resource"))
    .bind(started_at)
    .bind(at)
    .bind(text(&e.data, "reason"))
    .bind(duration_ms)
    .bind(number(&e.data, "bytes_in"))
    .bind(number(&e.data, "bytes_out"))
    .bind(text(&e.data, "actor_type").unwrap_or("user"))
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO web_requests (request_id, request_event_id, response_event_id, at, username,
                                   resource, host, method, path, status, bytes_in, bytes_out, duration_ms, outcome)
         VALUES ($1, $2, $2, $3, $4, $5, $6, $7, '', $8, $9, $10, $11, $12)
         ON CONFLICT (request_id) DO UPDATE SET response_event_id = EXCLUDED.response_event_id,
           status = EXCLUDED.status, bytes_in = EXCLUDED.bytes_in, bytes_out = EXCLUDED.bytes_out,
           duration_ms = EXCLUDED.duration_ms, outcome = EXCLUDED.outcome",
    )
    .bind(request_id)
    .bind(e.event_id)
    .bind(at)
    .bind(&e.user)
    .bind(text(&e.data, "resource").unwrap_or_default())
    .bind(text(&e.data, "host").unwrap_or_default())
    .bind(text(&e.data, "method").unwrap_or_default())
    .bind(status)
    .bind(number(&e.data, "bytes_in"))
    .bind(number(&e.data, "bytes_out"))
    .bind(duration_ms)
    .bind(text(&e.data, "reason"))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn project_websocket(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &limen_audit::Event,
    request_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE sessions SET bytes_in = $2, bytes_out = $3, duration_ms = $4, end_reason = $5,
                              ended_at = $6
         WHERE session_id = $1",
    )
    .bind(request_id)
    .bind(number(&e.data, "bytes_in"))
    .bind(number(&e.data, "bytes_out"))
    .bind(number(&e.data, "duration_ms"))
    .bind(text(&e.data, "reason"))
    .bind(e.time)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE web_requests SET bytes_in = $2, bytes_out = $3, duration_ms = $4, outcome = $5
         WHERE request_id = $1",
    )
    .bind(request_id)
    .bind(number(&e.data, "bytes_in"))
    .bind(number(&e.data, "bytes_out"))
    .bind(number(&e.data, "duration_ms"))
    .bind(text(&e.data, "reason"))
    .execute(&mut **tx)
    .await?;
    Ok(())
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

#[derive(Debug, Clone)]
pub struct WebAppLogin {
    pub resource: String,
    pub host: String,
    pub return_path: String,
    pub browser_nonce_hash: Vec<u8>,
    pub nonce: String,
    pub pkce_verifier: String,
    pub expires_at: OffsetDateTime,
}

pub(super) struct WebAppHandoff {
    pub(super) token_hash: Vec<u8>,
    pub(super) resource: String,
    pub(super) host: String,
    pub(super) return_path: String,
    pub(super) browser_nonce_hash: Vec<u8>,
    pub(super) session: Vec<u8>,
    pub(super) expires_at: OffsetDateTime,
}

pub async fn insert_web_app_login(
    db: &Db,
    state_hash: &[u8],
    login: &WebAppLogin,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO web_app_logins (state_hash, resource, host, return_path, browser_nonce_hash, nonce, pkce_verifier, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(state_hash)
    .bind(&login.resource)
    .bind(&login.host)
    .bind(&login.return_path)
    .bind(&login.browser_nonce_hash)
    .bind(&login.nonce)
    .bind(&login.pkce_verifier)
    .bind(login.expires_at)
    .execute(db)
    .await
    .map(|_| ())
}

/// Take and delete OIDC state exactly once.
pub async fn take_web_app_login(
    db: &Db,
    state_hash: &[u8],
) -> Result<Option<WebAppLogin>, sqlx::Error> {
    let row = sqlx::query(
        "DELETE FROM web_app_logins WHERE state_hash = $1
         RETURNING resource, host, return_path, browser_nonce_hash, nonce, pkce_verifier, expires_at",
    )
    .bind(state_hash)
    .fetch_optional(db)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let expires_at: OffsetDateTime = row.try_get("expires_at")?;
    if expires_at <= OffsetDateTime::now_utc() {
        return Ok(None);
    }
    Ok(Some(WebAppLogin {
        resource: row.try_get("resource")?,
        host: row.try_get("host")?,
        return_path: row.try_get("return_path")?,
        browser_nonce_hash: row.try_get("browser_nonce_hash")?,
        nonce: row.try_get("nonce")?,
        pkce_verifier: row.try_get("pkce_verifier")?,
        expires_at,
    }))
}

pub(super) async fn insert_web_app_handoff(
    db: &Db,
    handoff: &WebAppHandoff,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO web_app_handoffs (token_hash, resource, host, return_path, browser_nonce_hash, session, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&handoff.token_hash)
    .bind(&handoff.resource)
    .bind(&handoff.host)
    .bind(&handoff.return_path)
    .bind(&handoff.browser_nonce_hash)
    .bind(&handoff.session)
    .bind(handoff.expires_at)
    .execute(db)
    .await
    .map(|_| ())
}

/// Atomically consume a handoff only for its configured app and host.
pub async fn take_web_app_handoff(
    db: &Db,
    token_hash: &[u8],
    resource: &str,
    host: &str,
    browser_nonce_hash: &[u8],
) -> Result<Option<(Vec<u8>, String)>, sqlx::Error> {
    let row = sqlx::query(
        "DELETE FROM web_app_handoffs
         WHERE token_hash = $1 AND resource = $2 AND host = $3
           AND browser_nonce_hash = $4 AND expires_at > now()
         RETURNING session, return_path",
    )
    .bind(token_hash)
    .bind(resource)
    .bind(host)
    .bind(browser_nonce_hash)
    .fetch_optional(db)
    .await?;
    row.map(|row| Ok((row.try_get("session")?, row.try_get("return_path")?)))
        .transpose()
}

pub async fn register_web_identity_jwk(
    db: &Db,
    kid: &str,
    jwk: &serde_json::Value,
    not_after: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM web_identity_jwks WHERE not_after <= now()")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO web_identity_jwks (kid, jwk, not_after) VALUES ($1, $2, $3)
         ON CONFLICT (kid) DO UPDATE SET jwk = EXCLUDED.jwk, not_after = EXCLUDED.not_after",
    )
    .bind(kid)
    .bind(jwk)
    .bind(not_after)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

pub async fn web_identity_jwks(db: &Db) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    sqlx::query_scalar("SELECT jwk FROM web_identity_jwks WHERE not_after > now() ORDER BY kid")
        .fetch_all(db)
        .await
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

/// What the audit trail can be narrowed by. Everything is optional and combines with AND.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    pub username: Option<String>,
    /// Exact kinds or prefixes ending in `.*` (`auth.*`), separated by commas.
    pub kind: Option<String>,
    /// `user` or `bot`: the kind of identity behind the event.
    pub actor: Option<String>,
    /// Case-insensitive text in the summary.
    pub text: Option<String>,
    pub session_id: Option<Uuid>,
    pub from: Option<OffsetDateTime>,
    /// Exclusive.
    pub to: Option<OffsetDateTime>,
}

/// Newest first. `limit` rows starting at `offset`.
pub async fn list_events(
    db: &Db,
    f: &EventFilter,
    limit: i64,
    offset: i64,
) -> Result<Vec<EventRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT at, kind, username, session_id, summary FROM audit_events e
         WHERE ($1::text IS NULL OR username = $1)
           AND ($2::text IS NULL OR EXISTS (SELECT 1 FROM unnest(string_to_array($2, ',')) p
                             WHERE kind = p OR (p LIKE '%.*' AND starts_with(kind, left(p, -1)))))
           AND ($3::text IS NULL OR EXISTS (SELECT 1 FROM users u WHERE u.username = e.username AND u.actor_type = $3))
           AND ($4::text IS NULL OR position(lower($4) in lower(summary)) > 0)
           AND ($5::uuid IS NULL OR session_id = $5)
           AND ($6::timestamptz IS NULL OR at >= $6)
           AND ($7::timestamptz IS NULL OR at < $7)
         ORDER BY at DESC, event_id DESC LIMIT $8 OFFSET $9",
    )
    .bind(&f.username)
    .bind(&f.kind)
    .bind(&f.actor)
    .bind(&f.text)
    .bind(f.session_id)
    .bind(f.from)
    .bind(f.to)
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

/// Names to complete while typing in a filter box. With `only` set (a person looking at
/// their own sessions) the lists come from their sessions alone and name no other user.
pub async fn suggestions(db: &Db, only: Option<&str>) -> super::views::Suggestions {
    async fn column(db: &Db, sql: &'static str, only: Option<&str>) -> Vec<String> {
        sqlx::query_scalar(sql)
            .bind(only)
            .fetch_all(db)
            .await
            .unwrap_or_default()
    }
    super::views::Suggestions {
        users: if only.is_some() {
            Vec::new()
        } else {
            column(db, "SELECT username FROM users WHERE $1::text IS NULL ORDER BY 1 LIMIT 300", only).await
        },
        resources: column(
            db,
            "SELECT DISTINCT resource FROM sessions WHERE resource IS NOT NULL AND ($1::text IS NULL OR username = $1) ORDER BY 1 LIMIT 300",
            only,
        )
        .await,
        kinds: column(
            db,
            "SELECT DISTINCT kind FROM sessions WHERE kind IS NOT NULL AND ($1::text IS NULL OR username = $1) ORDER BY 1 LIMIT 100",
            only,
        )
        .await,
        ends: column(
            db,
            "SELECT DISTINCT end_reason FROM sessions WHERE end_reason IS NOT NULL AND ($1::text IS NULL OR username = $1) ORDER BY 1 LIMIT 100",
            only,
        )
        .await,
    }
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
    /// The request's own session: an exec's recording lives under it.
    pub session_id: Option<Uuid>,
    /// The console session of the login: the page that lists the request.
    pub login_session: Option<Uuid>,
    pub cluster: String,
    pub verb: String,
    pub api_group: String,
    pub resource: String,
    pub subresource: String,
    pub namespace: String,
    pub name: String,
    pub path: String,
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
    /// Only this console session's requests, oldest first.
    pub login_session: Option<Uuid>,
    pub limit: i64,
    pub offset: i64,
}

/// Newest first.
pub async fn list_kube_requests(db: &Db, f: &KubeFilter) -> Result<Vec<KubeRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT at, username, session_id, login_session, cluster, verb, api_group, resource, subresource, namespace, name,
                path, method, status, latency_ms, error
         FROM kube_requests
         WHERE ($1::text IS NULL OR username = $1) AND ($2::text IS NULL OR cluster = $2)
           AND ($3::text IS NULL OR namespace = $3) AND ($4::text IS NULL OR verb = $4)
           AND (NOT $5 OR status >= 400) AND ($8::uuid IS NULL OR login_session = $8)
         ORDER BY (CASE WHEN $8::uuid IS NOT NULL THEN at END) ASC, at DESC, event_id DESC LIMIT $6 OFFSET $7",
    )
    .bind(&f.username)
    .bind(&f.cluster)
    .bind(&f.namespace)
    .bind(&f.verb)
    .bind(f.problems_only)
    .bind(f.limit + 1)
    .bind(f.offset)
    .bind(f.login_session)
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(KubeRow {
                at: r.try_get("at")?,
                username: r.try_get("username")?,
                session_id: r.try_get("session_id")?,
                login_session: r.try_get("login_session")?,
                cluster: r.try_get("cluster")?,
                verb: r.try_get("verb")?,
                api_group: r.try_get("api_group")?,
                resource: r.try_get("resource")?,
                subresource: r.try_get("subresource")?,
                namespace: r.try_get("namespace")?,
                name: r.try_get("name")?,
                path: r.try_get("path")?,
                method: r.try_get("method")?,
                status: r.try_get("status")?,
                latency_ms: r.try_get("latency_ms")?,
                error: r.try_get("error")?,
            })
        })
        .collect()
}

/// `(requests, refused or failed)` of a console session.
pub async fn kube_session_counts(db: &Db, id: Uuid) -> Result<(i64, i64), sqlx::Error> {
    let row = sqlx::query(
        "SELECT count(*) AS total, count(*) FILTER (WHERE status >= 400) AS problems
         FROM kube_requests WHERE login_session = $1",
    )
    .bind(id)
    .fetch_one(db)
    .await?;
    Ok((row.try_get("total")?, row.try_get("problems")?))
}

/// The clusters and verbs seen, for the filters.
pub async fn kube_filter_options(db: &Db) -> Result<(Vec<String>, Vec<String>), sqlx::Error> {
    let clusters =
        sqlx::query_scalar("SELECT DISTINCT cluster FROM kube_requests ORDER BY cluster")
            .fetch_all(db)
            .await?;
    let verbs = sqlx::query_scalar("SELECT DISTINCT verb FROM kube_requests ORDER BY verb")
        .fetch_all(db)
        .await?;
    Ok((clusters, verbs))
}

/// Which of Access and Reviews are worth a place in this person's menu: Access
/// if they can ask for or approve a role, or have asked; Reviews if an item
/// is, or was, assigned to them. A failure shows both, so nothing hides.
pub async fn menu_pages(state: &crate::state::AppState, username: &str) -> (bool, bool) {
    let groups = crate::access::store::user_groups(&state.db, username)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let takes_part = state
        .policy
        .current()
        .policy
        .takes_part_in_requests(username, groups.iter().map(String::as_str));
    let asked: Result<bool, _> =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM access_requests WHERE requester = $1)")
            .bind(username)
            .fetch_one(&state.db)
            .await;
    let reviewing: Result<bool, _> = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM review_items WHERE lower(reviewer) = lower($1))",
    )
    .bind(username)
    .fetch_one(&state.db)
    .await;
    (
        takes_part || asked.unwrap_or(true),
        reviewing.unwrap_or(true),
    )
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

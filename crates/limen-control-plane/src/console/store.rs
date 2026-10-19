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

fn number(data: &serde_json::Value, key: &str) -> Option<i64> {
    data.get(key).and_then(serde_json::Value::as_i64)
}

/// Data fields that may appear in the console's audit trail, in display
/// order. Everything else (statements, claims, groups) stays in the sinks.
const SUMMARY_KEYS: [&str; 23] = [
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
        let Some(session_id) = e.session_id else {
            continue;
        };
        match e.kind {
            EventKind::SessionStart => {
                sqlx::query(
                    "INSERT INTO sessions (session_id, username, kind, resource, login, worker_id, proxy_id, client_addr, started_at, actor_type, ci, conn_group)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                     ON CONFLICT (session_id) DO UPDATE SET username = EXCLUDED.username, kind = EXCLUDED.kind,
                       resource = EXCLUDED.resource, login = EXCLUDED.login, worker_id = EXCLUDED.worker_id,
                       proxy_id = EXCLUDED.proxy_id, client_addr = EXCLUDED.client_addr, started_at = EXCLUDED.started_at,
                       actor_type = EXCLUDED.actor_type, ci = EXCLUDED.ci,
                       conn_group = EXCLUDED.conn_group",
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

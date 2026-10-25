//! Watching a live session (ADR-0030): the control plane's half.
//!
//! **Where the stream comes from.** The ADR guessed the proxy would tee the
//! session. It can't: an SSH session is encrypted end to end between the
//! user's client and the worker, so the proxy only carries ciphertext. The
//! worker is the one that holds the plaintext (it records it), so the worker
//! publishes. It gets to the console through the database, which every
//! control plane replica shares, so the replica serving the browser needn't
//! be the one the worker talked to. A slow or absent watcher costs the
//! session nothing: the worker keeps a small ring and drops, and only sends
//! while someone is watching.

use std::time::Duration;

use limen_audit::{Context, EventKind};
use serde_json::json;
use sqlx::Row as _;
use tonic::Status;
use uuid::Uuid;

use crate::db::Db;
use crate::state::{AppState, internal};

/// A watcher whose browser hasn't asked for this long is gone.
pub const WATCHER_TTL_SECS: i32 = 20;
/// Most people watching one session, and most sessions one person watches.
pub const MAX_PER_SESSION: i64 = 5;
pub const MAX_PER_OBSERVER: i64 = 5;
/// Chunks kept per session, and for how long.
const KEEP_CHUNKS: i64 = 2_000;
/// The largest chunk accepted.
pub const MAX_CHUNK_BYTES: usize = 64 * 1024;
/// How much recent output a late watcher sees first.
pub const REPLAY_BYTES: i64 = 16 * 1024;

/// Who may watch (admins; auditors only if the operator allows it).
#[must_use]
pub fn may_watch(state: &AppState, is_admin: bool, is_auditor: bool) -> bool {
    is_admin || (is_auditor && state.config.auditors_may_watch)
}

pub async fn is_watched(db: &Db, session_id: Uuid) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM session_watches WHERE session_id = $1 AND stopped_at IS NULL
                         AND last_seen_at > now() - make_interval(secs => $2))",
    )
    .bind(session_id)
    .bind(f64::from(WATCHER_TTL_SECS))
    .fetch_one(db)
    .await
}

/// Of these sessions, those `worker_id` runs that someone is watching.
pub async fn watched_among(
    db: &Db,
    worker_id: &str,
    ids: &[Uuid],
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT DISTINCT w.session_id FROM session_watches w JOIN sessions s ON s.session_id = w.session_id
         WHERE w.session_id = ANY($1) AND s.worker_id = $2 AND s.ended_at IS NULL
           AND w.stopped_at IS NULL AND w.last_seen_at > now() - make_interval(secs => $3)",
    )
    .bind(ids)
    .bind(worker_id)
    .bind(f64::from(WATCHER_TTL_SECS))
    .fetch_all(db)
    .await
}

/// Store output for a session the worker runs. Returns whether anyone is
/// still watching.
pub async fn publish(
    db: &Db,
    worker_id: &str,
    session_id: Uuid,
    text: &str,
    elapsed_ms: u64,
    cols: u32,
    rows: u32,
) -> Result<bool, Status> {
    if text.len() > MAX_CHUNK_BYTES {
        return Err(Status::invalid_argument("chunk too large"));
    }
    let ours: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sessions WHERE session_id = $1 AND worker_id = $2 AND ended_at IS NULL)",
    )
    .bind(session_id)
    .bind(worker_id)
    .fetch_one(db)
    .await
    .map_err(|e| internal("checking the session", e))?;
    if !ours {
        // Not a session this worker runs (or already over): the same answer
        // either way, so a worker learns nothing about others' sessions.
        return Ok(false);
    }
    if !is_watched(db, session_id)
        .await
        .map_err(|e| internal("checking watchers", e))?
    {
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO watch_chunks (session_id, elapsed_ms, cols, rows, text) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(session_id)
    .bind(i64::try_from(elapsed_ms).unwrap_or(i64::MAX))
    .bind(i32::try_from(cols.clamp(1, 1000)).unwrap_or(80))
    .bind(i32::try_from(rows.clamp(1, 1000)).unwrap_or(24))
    .bind(text)
    .execute(db)
    .await
    .map_err(|e| internal("storing output", e))?;
    // Keep it bounded however fast the session writes.
    sqlx::query(
        "DELETE FROM watch_chunks WHERE session_id = $1 AND seq <= (
           SELECT COALESCE(max(seq), 0) - $2 FROM watch_chunks WHERE session_id = $1)",
    )
    .bind(session_id)
    .bind(KEEP_CHUNKS)
    .execute(db)
    .await
    .map_err(|e| internal("trimming output", e))?;
    Ok(true)
}

/// One person watching one session.
#[derive(Debug)]
pub struct Watcher {
    pub id: Uuid,
    pub session_id: Uuid,
    pub observer: String,
}

/// Start watching: checks the caps, records the watcher, and audits it. The
/// audit comes first: a watch that can't be recorded doesn't happen.
pub async fn begin(
    state: &AppState,
    observer: &str,
    session_id: Uuid,
    via: &'static str,
) -> Result<Watcher, Status> {
    let row =
        sqlx::query("SELECT username, resource, ended_at FROM sessions WHERE session_id = $1")
            .bind(session_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| internal("reading the session", e))?
            .ok_or_else(|| Status::not_found("no such session"))?;
    if row
        .try_get::<Option<time::OffsetDateTime>, _>("ended_at")
        .map_err(|e| internal("reading the session", e))?
        .is_some()
    {
        return Err(Status::failed_precondition(
            "the session has ended; play its recording instead",
        ));
    }
    let subject: Option<String> = row
        .try_get("username")
        .map_err(|e| internal("reading the session", e))?;
    let resource: Option<String> = row
        .try_get("resource")
        .map_err(|e| internal("reading the session", e))?;
    // Nobody watches themselves through the console; they have the session.
    if subject
        .as_deref()
        .is_some_and(|s| s.eq_ignore_ascii_case(observer))
    {
        return Err(Status::failed_precondition("this is your own session"));
    }
    let (per_session, per_observer): (i64, i64) = {
        let r = sqlx::query(
            "SELECT count(*) FILTER (WHERE session_id = $1) AS s, count(*) FILTER (WHERE observer = $2) AS o
             FROM session_watches WHERE stopped_at IS NULL AND last_seen_at > now() - make_interval(secs => $3)",
        )
        .bind(session_id)
        .bind(observer)
        .bind(f64::from(WATCHER_TTL_SECS))
        .fetch_one(&state.db)
        .await
        .map_err(|e| internal("counting watchers", e))?;
        (r.try_get("s").unwrap_or(0), r.try_get("o").unwrap_or(0))
    };
    if per_session >= MAX_PER_SESSION || per_observer >= MAX_PER_OBSERVER {
        return Err(Status::resource_exhausted(
            "too many people are watching this, or you are watching too many",
        ));
    }
    let id = Uuid::now_v7();
    state
        .audit
        .emit(
            EventKind::SessionWatchStart,
            Context { user: Some(observer.to_owned()), session_id: Some(session_id) },
            json!({ "watch_id": id, "observer": observer, "target_user": subject, "resource": resource, "via": via }),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "audit unavailable; refusing a watch");
            Status::unavailable("audit unavailable")
        })?;
    sqlx::query("INSERT INTO session_watches (id, session_id, observer) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(session_id)
        .bind(observer)
        .execute(&state.db)
        .await
        .map_err(|e| internal("recording the watcher", e))?;
    metrics::gauge!("limen_session_watchers").increment(1.0);
    Ok(Watcher {
        id,
        session_id,
        observer: observer.to_owned(),
    })
}

/// The watcher is still here. False if it was ended.
pub async fn heartbeat(db: &Db, w: &Watcher) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE session_watches SET last_seen_at = now() WHERE id = $1 AND stopped_at IS NULL",
    )
    .bind(w.id)
    .execute(db)
    .await?
    .rows_affected()
        == 1)
}

/// Stop watching, and say so in the audit trail.
pub async fn end(state: &AppState, w: &Watcher, via: &'static str, why: &str) {
    metrics::gauge!("limen_session_watchers").decrement(1.0);
    let _ = sqlx::query("UPDATE session_watches SET stopped_at = now() WHERE id = $1")
        .bind(w.id)
        .execute(&state.db)
        .await;
    if let Err(e) = state
        .audit
        .emit(
            EventKind::SessionWatchStop,
            Context {
                user: Some(w.observer.clone()),
                session_id: Some(w.session_id),
            },
            json!({ "watch_id": w.id, "observer": w.observer, "reason": why, "via": via }),
        )
        .await
    {
        tracing::error!(error = %e, "failed to audit the end of a watch");
    }
}

/// A chunk, as the console streams it.
#[derive(Debug, Clone)]
pub struct Chunk {
    pub seq: i64,
    pub elapsed_ms: i64,
    pub cols: i32,
    pub rows: i32,
    pub text: String,
}

/// Output after `after`. With `None`, the most recent output up to
/// [`REPLAY_BYTES`], so a late watcher sees the screen's recent past.
pub async fn chunks(
    db: &Db,
    session_id: Uuid,
    after: Option<i64>,
) -> Result<Vec<Chunk>, sqlx::Error> {
    let rows = match after {
        Some(after) => {
            sqlx::query("SELECT seq, elapsed_ms, cols, rows, text FROM watch_chunks WHERE session_id = $1 AND seq > $2 ORDER BY seq LIMIT 200")
                .bind(session_id)
                .bind(after)
                .fetch_all(db)
                .await?
        }
        None => {
            sqlx::query(
                "SELECT seq, elapsed_ms, cols, rows, text FROM (
                   SELECT *, sum(length(text)) OVER (ORDER BY seq DESC) AS running FROM watch_chunks WHERE session_id = $1
                 ) t WHERE running - length(text) < $2 ORDER BY seq",
            )
            .bind(session_id)
            .bind(REPLAY_BYTES)
            .fetch_all(db)
            .await?
        }
    };
    Ok(rows
        .iter()
        .map(|r| Chunk {
            seq: r.try_get("seq").unwrap_or(0),
            elapsed_ms: r.try_get("elapsed_ms").unwrap_or(0),
            cols: r.try_get("cols").unwrap_or(80),
            rows: r.try_get("rows").unwrap_or(24),
            text: r.try_get("text").unwrap_or_default(),
        })
        .collect())
}

/// Whether the session is still running.
pub async fn is_live(db: &Db, session_id: Uuid) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sessions WHERE session_id = $1 AND ended_at IS NULL)",
    )
    .bind(session_id)
    .fetch_one(db)
    .await
}

/// How often the stream looks for new output.
pub const POLL: Duration = Duration::from_millis(300);

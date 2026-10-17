//! Database access. Queries are checked at runtime and covered by the
//! integration tests against a real PostgreSQL (ADR-0010 amendment).

use std::time::Duration;

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Row, Transaction};
use time::OffsetDateTime;

pub type Db = PgPool;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Advisory lock keys. Arbitrary, but fixed forever.
pub mod locks {
    pub const CA_BOOTSTRAP: i64 = 0x4c49_4d45_4e00_0001;
    pub const CLEANUP_JOB: i64 = 0x4c49_4d45_4e00_0002;
}

/// Connections a replica's pool may hold unless told otherwise.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 16;

pub async fn connect(url: &str) -> Result<Db, sqlx::Error> {
    connect_with(url, DEFAULT_MAX_CONNECTIONS).await
}

/// [`connect`] with a pool of at most `max_connections`. With several
/// replicas the database sees up to that many times the replica count.
pub async fn connect_with(url: &str, max_connections: u32) -> Result<Db, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect(url)
        .await?;
    // sqlx serializes concurrent migrators with its own advisory lock.
    MIGRATOR.run(&pool).await?;
    Ok(pool)
}

pub async fn ping(db: &Db) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT 1").execute(db).await.map(|_| ())
}

// ---- CA certificates -------------------------------------------------------

pub async fn ca_cert(
    tx: &mut Transaction<'_, Postgres>,
    purpose: &str,
    key_ref: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT cert_pem FROM ca_certs WHERE purpose = $1 AND key_ref = $2")
        .bind(purpose)
        .bind(key_ref)
        .fetch_optional(&mut **tx)
        .await
}

pub async fn insert_ca_cert(
    tx: &mut Transaction<'_, Postgres>,
    purpose: &str,
    key_ref: &str,
    cert_pem: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO ca_certs (purpose, key_ref, cert_pem) VALUES ($1, $2, $3)")
        .bind(purpose)
        .bind(key_ref)
        .bind(cert_pem)
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

// ---- Policy ----------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PolicyRow {
    pub version: i64,
    pub digest: String,
    pub documents: serde_json::Value,
    pub author: String,
    pub created_at: OffsetDateTime,
}

pub async fn latest_policy_version(db: &Db) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar("SELECT max(version) FROM policy_versions")
        .fetch_one(db)
        .await
}

pub async fn latest_policy(db: &Db) -> Result<Option<PolicyRow>, sqlx::Error> {
    let row = sqlx::query("SELECT version, digest, documents, author, created_at FROM policy_versions ORDER BY version DESC LIMIT 1")
        .fetch_optional(db)
        .await?;
    row.map(|r| {
        Ok(PolicyRow {
            version: r.try_get("version")?,
            digest: r.try_get("digest")?,
            documents: r.try_get("documents")?,
            author: r.try_get("author")?,
            created_at: r.try_get("created_at")?,
        })
    })
    .transpose()
}

pub async fn insert_policy(
    tx: &mut Transaction<'_, Postgres>,
    digest: &str,
    documents: &serde_json::Value,
    author: &str,
    source_ref: Option<&str>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("INSERT INTO policy_versions (digest, documents, author, source_ref) VALUES ($1, $2, $3, $4) RETURNING version")
        .bind(digest)
        .bind(documents)
        .bind(author)
        .bind(source_ref)
        .fetch_one(&mut **tx)
        .await
}

// ---- Join tokens -----------------------------------------------------------

/// A join token to store. `name` is the approved name or pattern, if any.
#[derive(Debug, Clone)]
pub struct NewJoinToken<'a> {
    pub token_hash: &'a [u8],
    pub kind: &'a str,
    pub labels: &'a serde_json::Value,
    pub dns_names: &'a [String],
    pub name: Option<&'a str>,
    pub created_by: &'a str,
    pub expires_at: OffsetDateTime,
}

pub async fn insert_join_token(db: &Db, t: &NewJoinToken<'_>) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO join_tokens (token_hash, kind, labels, dns_names, name, created_by, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(t.token_hash.to_vec())
        .bind(t.kind)
        .bind(t.labels)
        .bind(t.dns_names.to_vec())
        .bind(t.name)
        .bind(t.created_by)
        .bind(t.expires_at)
        .execute(db)
        .await
        .map(|_| ())
}

/// A join token that can still be used. The secret itself is never stored.
#[derive(Debug, Clone)]
pub struct PendingToken {
    pub kind: String,
    /// The approved name or pattern, if any.
    pub name: Option<String>,
    pub labels: serde_json::Value,
    pub created_by: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

pub async fn list_pending_join_tokens(db: &Db) -> Result<Vec<PendingToken>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT kind, name, labels, created_by, created_at, expires_at FROM join_tokens
         WHERE used_at IS NULL AND expires_at > now() ORDER BY expires_at",
    )
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(PendingToken {
                kind: r.try_get("kind")?,
                name: r.try_get("name")?,
                labels: r.try_get("labels")?,
                created_by: r.try_get("created_by")?,
                created_at: r.try_get("created_at")?,
                expires_at: r.try_get("expires_at")?,
            })
        })
        .collect()
}

/// What a consumed single-use token grants.
#[derive(Debug, Clone)]
pub struct ConsumedToken {
    pub labels: serde_json::Value,
    pub dns_names: Vec<String>,
    /// The approved name or pattern, if any.
    pub name: Option<String>,
}

/// Atomically consume a single-use token, inside `tx` (rolled back with it).
/// `None` if it doesn't exist, has expired, was already used, or is for
/// another component kind.
pub async fn consume_join_token(
    tx: &mut Transaction<'_, Postgres>,
    token_hash: &[u8],
    kind: &str,
    used_by: &str,
) -> Result<Option<ConsumedToken>, sqlx::Error> {
    let row = sqlx::query(
        "UPDATE join_tokens SET used_at = now(), used_by = $3
         WHERE token_hash = $1 AND kind = $2 AND used_at IS NULL AND expires_at > now()
         RETURNING labels, dns_names, name",
    )
    .bind(token_hash.to_vec())
    .bind(kind)
    .bind(used_by)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| {
        Ok(ConsumedToken {
            labels: r.try_get("labels")?,
            dns_names: r.try_get("dns_names")?,
            name: r.try_get("name")?,
        })
    })
    .transpose()
}

// ---- Components and tunnels ------------------------------------------------

#[derive(Debug, Clone)]
pub struct ComponentRow {
    pub id: String,
    pub kind: String,
    /// Display name, if it was given one at enrollment.
    pub name: Option<String>,
    pub labels: serde_json::Value,
    pub dns_names: Vec<String>,
    pub enrolled_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub cert_expires_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

fn component_from_row(r: &sqlx::postgres::PgRow) -> Result<ComponentRow, sqlx::Error> {
    Ok(ComponentRow {
        id: r.try_get("id")?,
        kind: r.try_get("kind")?,
        name: r.try_get("name")?,
        labels: r.try_get("labels")?,
        dns_names: r.try_get("dns_names")?,
        enrolled_at: r.try_get("enrolled_at")?,
        last_seen_at: r.try_get("last_seen_at")?,
        cert_expires_at: r.try_get("cert_expires_at")?,
        revoked_at: r.try_get("revoked_at")?,
    })
}

macro_rules! component_columns {
    () => {
        "id, kind, name, labels, dns_names, enrolled_at, last_seen_at, cert_expires_at, revoked_at"
    };
}

/// Unique index on the names of components that are not revoked (0009).
const LIVE_NAME_INDEX: &str = "components_live_name_idx";

/// Whether `e` is a second live component trying to take a name. With
/// concurrent enrollments, the later insert waits for the earlier
/// transaction and fails like this if it commits.
#[must_use]
pub fn is_name_taken(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .is_some_and(|d| d.is_unique_violation() && d.constraint() == Some(LIVE_NAME_INDEX))
}

/// Store an enrolled component. Fails with [`is_name_taken`] if a live
/// component already has `name`.
pub async fn insert_component(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    kind: &str,
    name: Option<&str>,
    labels: &serde_json::Value,
    dns_names: &[String],
    cert_expires_at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO components (id, kind, name, labels, dns_names, cert_expires_at) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(id)
        .bind(kind)
        .bind(name)
        .bind(labels)
        .bind(dns_names.to_vec())
        .bind(cert_expires_at)
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

pub async fn component(db: &Db, id: &str) -> Result<Option<ComponentRow>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        component_columns!(),
        " FROM components WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await?
    .map(|r| component_from_row(&r))
    .transpose()
}

pub async fn record_renewal(
    db: &Db,
    id: &str,
    cert_expires_at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE components SET last_seen_at = now(), cert_expires_at = $2 WHERE id = $1")
        .bind(id)
        .bind(cert_expires_at)
        .execute(db)
        .await
        .map(|_| ())
}

#[derive(Debug, Clone)]
pub struct TunnelRow {
    pub proxy_id: String,
    pub proxy_name: Option<String>,
    pub tunnel_id: String,
    pub worker_id: String,
    pub worker_name: Option<String>,
    pub lease_expires_at: OffsetDateTime,
}

pub async fn list_components(db: &Db) -> Result<(Vec<ComponentRow>, Vec<TunnelRow>), sqlx::Error> {
    let components = sqlx::query(concat!(
        "SELECT ",
        component_columns!(),
        " FROM components ORDER BY kind, id"
    ))
    .fetch_all(db)
    .await?
    .iter()
    .map(component_from_row)
    .collect::<Result<Vec<_>, _>>()?;
    let tunnels = sqlx::query(
        "SELECT t.proxy_id, p.name AS proxy_name, t.tunnel_id, t.worker_id, w.name AS worker_name, t.lease_expires_at
         FROM tunnels t
         JOIN components p ON p.id = t.proxy_id
         JOIN components w ON w.id = t.worker_id
         WHERE t.lease_expires_at > now() ORDER BY t.worker_id, t.proxy_id",
    )
        .fetch_all(db)
        .await?
        .iter()
        .map(|r| {
            Ok(TunnelRow {
                proxy_id: r.try_get("proxy_id")?,
                proxy_name: r.try_get("proxy_name")?,
                tunnel_id: r.try_get("tunnel_id")?,
                worker_id: r.try_get("worker_id")?,
                worker_name: r.try_get("worker_name")?,
                lease_expires_at: r.try_get("lease_expires_at")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok((components, tunnels))
}

/// One tunnel a proxy reports, with the worker load it last saw (0/0: unknown).
#[derive(Debug, Clone, Default)]
pub struct ReportedTunnel {
    pub tunnel_id: String,
    pub worker_id: String,
    pub active_sessions: u32,
    pub max_sessions: u32,
}

/// Replace every tunnel lease held by `proxy_id` with `tunnels`, and mark the
/// proxy and those workers as seen. Unknown or revoked workers are skipped
/// and returned.
pub async fn replace_tunnels(
    db: &Db,
    proxy_id: &str,
    peer_address: Option<&str>,
    tunnels: &[ReportedTunnel],
    lease: Duration,
) -> Result<Vec<String>, sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query("UPDATE components SET last_seen_at = now(), peer_address = COALESCE($2, peer_address) WHERE id = $1")
        .bind(proxy_id)
        .bind(peer_address)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM tunnels WHERE proxy_id = $1")
        .bind(proxy_id)
        .execute(&mut *tx)
        .await?;
    let lease_secs = f64::from(u32::try_from(lease.as_secs()).unwrap_or(u32::MAX));
    let mut skipped = Vec::new();
    for t in tunnels {
        let inserted = sqlx::query(
            "INSERT INTO tunnels (proxy_id, tunnel_id, worker_id, lease_expires_at, active_sessions, max_sessions)
             SELECT $1, $2, id, now() + make_interval(secs => $4), $5, $6
             FROM components WHERE id = $3 AND kind = 'worker' AND revoked_at IS NULL",
        )
        .bind(proxy_id)
        .bind(&t.tunnel_id)
        .bind(&t.worker_id)
        .bind(lease_secs)
        .bind(i32::try_from(t.active_sessions).unwrap_or(i32::MAX))
        .bind(i32::try_from(t.max_sessions).unwrap_or(i32::MAX))
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() == 0 {
            skipped.push(t.worker_id.clone());
            continue;
        }
        sqlx::query("UPDATE components SET last_seen_at = now() WHERE id = $1")
            .bind(&t.worker_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(skipped)
}

/// A live tunnel with what peering needs: the worker's labels and how to
/// reach the proxy holding it.
#[derive(Debug, Clone)]
pub struct PeerTunnelRow {
    pub worker_id: String,
    pub worker_name: Option<String>,
    pub worker_labels: serde_json::Value,
    pub proxy_id: String,
    pub proxy_name: Option<String>,
    pub peer_address: String,
    /// The worker's load as that proxy last reported it (0/0: unknown).
    pub active_sessions: u32,
    pub max_sessions: u32,
}

pub async fn live_peer_tunnels(db: &Db) -> Result<Vec<PeerTunnelRow>, sqlx::Error> {
    sqlx::query(
        "SELECT t.worker_id, w.name AS worker_name, w.labels AS worker_labels, t.proxy_id, p.name AS proxy_name, p.peer_address,
                MAX(t.active_sessions) AS active_sessions, MAX(t.max_sessions) AS max_sessions
         FROM tunnels t
         JOIN components w ON w.id = t.worker_id AND w.revoked_at IS NULL
         JOIN components p ON p.id = t.proxy_id AND p.revoked_at IS NULL AND p.peer_address IS NOT NULL
         WHERE t.lease_expires_at > now()
         GROUP BY t.worker_id, w.name, w.labels, t.proxy_id, p.name, p.peer_address
         ORDER BY t.worker_id, t.proxy_id",
    )
    .fetch_all(db)
    .await?
    .iter()
    .map(|r| {
        Ok(PeerTunnelRow {
            worker_id: r.try_get("worker_id")?,
            worker_name: r.try_get("worker_name")?,
            worker_labels: r.try_get("worker_labels")?,
            proxy_id: r.try_get("proxy_id")?,
            proxy_name: r.try_get("proxy_name")?,
            peer_address: r.try_get("peer_address")?,
            active_sessions: u32::try_from(r.try_get::<i32, _>("active_sessions")?)
                .unwrap_or(0),
            max_sessions: u32::try_from(r.try_get::<i32, _>("max_sessions")?).unwrap_or(0),
        })
    })
    .collect()
}

// ---- Login nonces ----------------------------------------------------------

/// Record a used nonce. Returns `false` if it was already used (a replay).
///
/// Takes the pool and hash by value: borrowing them here trips a rustc
/// higher-ranked `Send` inference limitation inside `async_trait` handlers.
pub async fn use_nonce(
    db: Db,
    nonce_hash: Vec<u8>,
    expires_at: OffsetDateTime,
) -> Result<bool, sqlx::Error> {
    let mut conn = db.acquire().await?;
    let result = sqlx::query(
        "INSERT INTO login_nonces (nonce_hash, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(nonce_hash)
    .bind(expires_at)
    .execute(&mut *conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Forget a nonce, for a login that failed after taking it and issued
/// nothing, so the caller can try again with the same token.
pub async fn release_nonce(db: &Db, nonce_hash: &[u8]) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM login_nonces WHERE nonce_hash = $1")
        .bind(nonce_hash.to_vec())
        .execute(db)
        .await
        .map(|_| ())
}

// ---- Housekeeping ----------------------------------------------------------

/// Delete expired rows. Runs on one replica at a time (advisory lock).
/// Returns `None` if another replica holds the lock.
pub async fn cleanup(db: &Db) -> Result<Option<u64>, sqlx::Error> {
    let mut tx = db.begin().await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(locks::CLEANUP_JOB)
        .fetch_one(&mut *tx)
        .await?;
    if !locked {
        return Ok(None);
    }
    let mut deleted = 0;
    deleted += sqlx::query("DELETE FROM login_nonces WHERE expires_at < now()")
        .execute(&mut *tx)
        .await?
        .rows_affected();
    deleted += sqlx::query("DELETE FROM join_tokens WHERE expires_at < now() - interval '7 days'")
        .execute(&mut *tx)
        .await?
        .rows_affected();
    deleted += sqlx::query("DELETE FROM audit_events WHERE at < now() - interval '30 days'")
        .execute(&mut *tx)
        .await?
        .rows_affected();
    // The statement text of database sessions goes with the audit events it came from.
    deleted += sqlx::query("DELETE FROM db_statements WHERE at < now() - interval '30 days'")
        .execute(&mut *tx)
        .await?
        .rows_affected();
    deleted += sqlx::query("DELETE FROM console_sessions WHERE expires_at < now()")
        .execute(&mut *tx)
        .await?
        .rows_affected();
    deleted += sqlx::query("DELETE FROM console_logins WHERE expires_at < now()")
        .execute(&mut *tx)
        .await?
        .rows_affected();
    deleted += sqlx::query("DELETE FROM session_kills WHERE killed_at < now() - interval '2 days'")
        .execute(&mut *tx)
        .await?
        .rows_affected();
    deleted += sqlx::query("DELETE FROM tunnels WHERE lease_expires_at < now()")
        .execute(&mut *tx)
        .await?
        .rows_affected();
    deleted += sqlx::query(
        "DELETE FROM control_plane_replicas WHERE heartbeat_at < now() - interval '1 day'",
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(Some(deleted))
}

#[derive(Debug, Clone)]
pub struct LockRow {
    pub username: String,
    pub reason: String,
    pub locked_by: String,
    pub locked_at: OffsetDateTime,
}

/// Lock a user. `false` if they already have an active lock.
pub async fn lock_user(
    db: &Db,
    username: &str,
    reason: &str,
    by: &str,
) -> Result<bool, sqlx::Error> {
    let inserted = sqlx::query(
        "INSERT INTO user_locks (id, username, reason, locked_by) VALUES ($1, $2, $3, $4) ON CONFLICT (username) WHERE released_at IS NULL DO NOTHING",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(username)
    .bind(reason)
    .bind(by)
    .execute(db)
    .await?;
    Ok(inserted.rows_affected() > 0)
}

/// Release a user's active lock. `false` if they weren't locked.
pub async fn unlock_user(db: &Db, username: &str, by: &str) -> Result<bool, sqlx::Error> {
    let updated = sqlx::query(
        "UPDATE user_locks SET released_at = now(), released_by = $2 WHERE username = $1 AND released_at IS NULL",
    )
    .bind(username)
    .bind(by)
    .execute(db)
    .await?;
    Ok(updated.rows_affected() > 0)
}

pub async fn active_locks(db: &Db) -> Result<Vec<LockRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT username, reason, locked_by, locked_at FROM user_locks WHERE released_at IS NULL ORDER BY locked_at",
    )
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(LockRow {
                username: r.try_get("username")?,
                reason: r.try_get("reason")?,
                locked_by: r.try_get("locked_by")?,
                locked_at: r.try_get("locked_at")?,
            })
        })
        .collect()
}

pub async fn is_locked(db: &Db, username: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM user_locks WHERE username = $1 AND released_at IS NULL)",
    )
    .bind(username)
    .fetch_one(db)
    .await
}

/// Mark a session to be ended. `false` if it already was.
pub async fn kill_session(
    db: &Db,
    session_id: &str,
    reason: &str,
    by: &str,
) -> Result<bool, sqlx::Error> {
    let inserted = sqlx::query(
        "INSERT INTO session_kills (session_id, reason, killed_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(session_id)
    .bind(reason)
    .bind(by)
    .execute(db)
    .await?;
    Ok(inserted.rows_affected() > 0)
}

/// Revoke a proxy or worker. `false` if it's unknown or already revoked.
pub async fn revoke_component(db: &Db, id: &str, by: &str) -> Result<bool, sqlx::Error> {
    let updated = sqlx::query(
        "UPDATE components SET revoked_at = now(), revoked_by = $2 WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(by)
    .execute(db)
    .await?;
    if updated.rows_affected() > 0 {
        sqlx::query("DELETE FROM tunnels WHERE worker_id = $1 OR proxy_id = $1")
            .bind(id)
            .execute(db)
            .await?;
    }
    Ok(updated.rows_affected() > 0)
}

pub async fn revoked_components(db: &Db) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT id FROM components WHERE revoked_at IS NOT NULL")
        .fetch_all(db)
        .await
}

/// Sessions killed within the last day (no session lives longer).
pub async fn recent_kills(db: &Db) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT session_id FROM session_kills WHERE killed_at > now() - interval '1 day'",
    )
    .fetch_all(db)
    .await
}

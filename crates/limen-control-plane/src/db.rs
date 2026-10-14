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

pub async fn connect(url: &str) -> Result<Db, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(16)
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

pub async fn insert_join_token(
    db: &Db,
    token_hash: &[u8],
    kind: &str,
    labels: &serde_json::Value,
    dns_names: &[String],
    created_by: &str,
    expires_at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO join_tokens (token_hash, kind, labels, dns_names, created_by, expires_at) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(token_hash.to_vec())
        .bind(kind)
        .bind(labels)
        .bind(dns_names.to_vec())
        .bind(created_by)
        .bind(expires_at)
        .execute(db)
        .await
        .map(|_| ())
}

/// Atomically consume a single-use token. Returns its labels and allowed DNS
/// names, or `None` if it doesn't exist, has expired, was already used, or
/// is for another component kind.
pub async fn consume_join_token(
    tx: &mut Transaction<'_, Postgres>,
    token_hash: &[u8],
    kind: &str,
    used_by: &str,
) -> Result<Option<(serde_json::Value, Vec<String>)>, sqlx::Error> {
    let row = sqlx::query(
        "UPDATE join_tokens SET used_at = now(), used_by = $3
         WHERE token_hash = $1 AND kind = $2 AND used_at IS NULL AND expires_at > now()
         RETURNING labels, dns_names",
    )
    .bind(token_hash.to_vec())
    .bind(kind)
    .bind(used_by)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| Ok((r.try_get("labels")?, r.try_get("dns_names")?)))
        .transpose()
}

// ---- Components and tunnels ------------------------------------------------

#[derive(Debug, Clone)]
pub struct ComponentRow {
    pub id: String,
    pub kind: String,
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
        "id, kind, labels, dns_names, enrolled_at, last_seen_at, cert_expires_at, revoked_at"
    };
}

pub async fn insert_component(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    kind: &str,
    labels: &serde_json::Value,
    dns_names: &[String],
    cert_expires_at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO components (id, kind, labels, dns_names, cert_expires_at) VALUES ($1, $2, $3, $4, $5)")
        .bind(id)
        .bind(kind)
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
    pub tunnel_id: String,
    pub worker_id: String,
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
    let tunnels = sqlx::query("SELECT proxy_id, tunnel_id, worker_id, lease_expires_at FROM tunnels WHERE lease_expires_at > now() ORDER BY worker_id, proxy_id")
        .fetch_all(db)
        .await?
        .iter()
        .map(|r| {
            Ok(TunnelRow {
                proxy_id: r.try_get("proxy_id")?,
                tunnel_id: r.try_get("tunnel_id")?,
                worker_id: r.try_get("worker_id")?,
                lease_expires_at: r.try_get("lease_expires_at")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok((components, tunnels))
}

/// Replace every tunnel lease held by `proxy_id` with `tunnels`
/// (`(tunnel_id, worker_id)` pairs), and mark the proxy and those workers as seen.
/// Unknown or revoked workers are skipped and returned.
pub async fn replace_tunnels(
    db: &Db,
    proxy_id: &str,
    peer_address: Option<&str>,
    tunnels: &[(String, String)],
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
    for (tunnel_id, worker_id) in tunnels {
        let inserted = sqlx::query(
            "INSERT INTO tunnels (proxy_id, tunnel_id, worker_id, lease_expires_at)
             SELECT $1, $2, id, now() + make_interval(secs => $4)
             FROM components WHERE id = $3 AND kind = 'worker' AND revoked_at IS NULL",
        )
        .bind(proxy_id)
        .bind(tunnel_id)
        .bind(worker_id)
        .bind(lease_secs)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() == 0 {
            skipped.push(worker_id.clone());
            continue;
        }
        sqlx::query("UPDATE components SET last_seen_at = now() WHERE id = $1")
            .bind(worker_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(skipped)
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
    deleted += sqlx::query("DELETE FROM tunnels WHERE lease_expires_at < now()")
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(Some(deleted))
}

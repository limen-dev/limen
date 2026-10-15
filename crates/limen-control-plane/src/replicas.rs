//! Replica registry: writer-ID safety and peer discovery (Phase 5).
//!
//! A replica registers before it opens its spool, heartbeats while it runs,
//! and deregisters on clean shutdown. A row whose heartbeat is older than
//! [`STALE_AFTER_SECS`] (three heartbeat intervals) is dead and may be taken
//! over by a restarting replica with the same id.

use clap::ValueEnum;

use crate::db::Db;

/// Heartbeat interval.
pub const HEARTBEAT_SECS: u64 = 5;
/// Rows older than this are stale. Keep in sync with the SQL below.
pub const STALE_AFTER_SECS: u64 = 15;

/// Whether the spool directory survives this replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SpoolMode {
    Durable,
    Ephemeral,
}

impl SpoolMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Durable => "durable",
            Self::Ephemeral => "ephemeral",
        }
    }
}

/// A live peer replica.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Replica {
    pub id: String,
    pub ingest_url: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("another live replica uses the id {0:?}; give each replica its own --id")]
    IdInUse(String),
    #[error("replica registry: {0}")]
    Db(#[from] sqlx::Error),
}

/// Claim `id`. Fails if a live row has it; takes over a stale one.
pub async fn register(
    db: &Db,
    id: &str,
    ingest_url: &str,
    mode: SpoolMode,
) -> Result<(), RegisterError> {
    let claimed = sqlx::query(
        "INSERT INTO control_plane_replicas (id, ingest_url, spool_mode) VALUES ($1, $2, $3) \
         ON CONFLICT (id) DO UPDATE SET ingest_url = EXCLUDED.ingest_url, \
         spool_mode = EXCLUDED.spool_mode, started_at = now(), heartbeat_at = now() \
         WHERE control_plane_replicas.heartbeat_at < now() - interval '15 seconds'",
    )
    .bind(id)
    .bind(ingest_url)
    .bind(mode.as_str())
    .execute(db)
    .await?
    .rows_affected();
    if claimed == 0 {
        return Err(RegisterError::IdInUse(id.to_owned()));
    }
    Ok(())
}

pub async fn heartbeat(db: &Db, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE control_plane_replicas SET heartbeat_at = now() WHERE id = $1")
        .bind(id)
        .execute(db)
        .await
        .map(|_| ())
}

/// Live replicas other than `except_id`, oldest first.
pub async fn live_peers(db: &Db, except_id: &str) -> Result<Vec<Replica>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, ingest_url FROM control_plane_replicas \
         WHERE id <> $1 AND heartbeat_at >= now() - interval '15 seconds' \
         ORDER BY started_at, id",
    )
    .bind(except_id)
    .fetch_all(db)
    .await
}

pub async fn deregister(db: &Db, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM control_plane_replicas WHERE id = $1")
        .bind(id)
        .execute(db)
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parallel first-time migrations of a shared database race; connect one at a time.
    static CONNECT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn db() -> Option<Db> {
        let url = limen_testkit::database_url()?;
        let _one_at_a_time = CONNECT.lock().await;
        Some(crate::db::connect(&url).await.expect("connect"))
    }

    fn uid(tag: &str) -> String {
        format!("{tag}-{}", uuid::Uuid::now_v7().simple())
    }

    async fn age(db: &Db, id: &str) {
        sqlx::query(
            "UPDATE control_plane_replicas SET heartbeat_at = now() - interval '1 minute' \
             WHERE id = $1",
        )
        .bind(id)
        .execute(db)
        .await
        .expect("age row");
    }

    #[tokio::test]
    async fn second_register_with_live_id_is_refused() {
        let Some(db) = db().await else { return };
        let id = uid("live");
        register(&db, &id, "https://a:1", SpoolMode::Durable)
            .await
            .expect("first");
        let err = register(&db, &id, "https://b:1", SpoolMode::Durable)
            .await
            .expect_err("second must fail");
        assert!(matches!(err, RegisterError::IdInUse(ref i) if *i == id));
        deregister(&db, &id).await.expect("cleanup");
    }

    #[tokio::test]
    async fn stale_row_is_taken_over() {
        let Some(db) = db().await else { return };
        let id = uid("stale");
        register(&db, &id, "https://old:1", SpoolMode::Durable)
            .await
            .expect("first");
        age(&db, &id).await;
        register(&db, &id, "https://new:1", SpoolMode::Ephemeral)
            .await
            .expect("takeover");
        let (url, mode): (String, String) = sqlx::query_as(
            "SELECT ingest_url, spool_mode FROM control_plane_replicas WHERE id = $1",
        )
        .bind(&id)
        .fetch_one(&db)
        .await
        .expect("row");
        assert_eq!(
            (url.as_str(), mode.as_str()),
            ("https://new:1", "ephemeral")
        );
        deregister(&db, &id).await.expect("cleanup");
    }

    #[tokio::test]
    async fn live_peers_excludes_self_and_stale() {
        let Some(db) = db().await else { return };
        let (me, peer, dead) = (uid("me"), uid("peer"), uid("dead"));
        for (id, url) in [
            (&me, "https://me:1"),
            (&peer, "https://peer:1"),
            (&dead, "https://dead:1"),
        ] {
            register(&db, id, url, SpoolMode::Durable)
                .await
                .expect("register");
        }
        age(&db, &dead).await;
        let peers = live_peers(&db, &me).await.expect("peers");
        assert!(
            peers
                .iter()
                .any(|r| r.id == peer && r.ingest_url == "https://peer:1")
        );
        assert!(!peers.iter().any(|r| r.id == me || r.id == dead));
        for id in [&me, &peer, &dead] {
            deregister(&db, id).await.expect("cleanup");
        }
    }

    #[tokio::test]
    async fn deregister_removes_row() {
        let Some(db) = db().await else { return };
        let id = uid("gone");
        register(&db, &id, "https://a:1", SpoolMode::Durable)
            .await
            .expect("register");
        deregister(&db, &id).await.expect("deregister");
        register(&db, &id, "https://a:1", SpoolMode::Durable)
            .await
            .expect("id is free again");
        deregister(&db, &id).await.expect("cleanup");
    }
}

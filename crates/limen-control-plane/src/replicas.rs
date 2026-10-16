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

/// Proof that this process owns a registry row. `heartbeat` and
/// `deregister` only touch the row while the nonce still matches.
#[derive(Debug, Clone)]
pub struct Registration {
    pub id: String,
    nonce: String,
}

#[derive(Debug, thiserror::Error)]
pub enum HeartbeatError {
    #[error("this replica's id was taken over by another process")]
    Lost,
    #[error("replica registry: {0}")]
    Db(#[from] sqlx::Error),
}

/// Claim `id`. Fails if a live row has it; takes over a stale one.
pub async fn register(
    db: &Db,
    id: &str,
    ingest_url: &str,
    mode: SpoolMode,
) -> Result<Registration, RegisterError> {
    let nonce = format!("{:032x}", rand::random::<u128>());
    let claimed = sqlx::query(
        "INSERT INTO control_plane_replicas (id, ingest_url, spool_mode, owner_nonce) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (id) DO UPDATE SET ingest_url = EXCLUDED.ingest_url, \
         spool_mode = EXCLUDED.spool_mode, owner_nonce = EXCLUDED.owner_nonce, \
         started_at = now(), heartbeat_at = now() \
         WHERE control_plane_replicas.heartbeat_at < now() - interval '15 seconds'",
    )
    .bind(id)
    .bind(ingest_url)
    .bind(mode.as_str())
    .bind(&nonce)
    .execute(db)
    .await?
    .rows_affected();
    if claimed == 0 {
        return Err(RegisterError::IdInUse(id.to_owned()));
    }
    Ok(Registration {
        id: id.to_owned(),
        nonce,
    })
}

/// Refresh the row. [`HeartbeatError::Lost`] means someone else owns the id
/// now (or the row is gone): this replica must stop.
pub async fn heartbeat(db: &Db, me: &Registration) -> Result<(), HeartbeatError> {
    let touched = sqlx::query(
        "UPDATE control_plane_replicas SET heartbeat_at = now() \
         WHERE id = $1 AND owner_nonce = $2",
    )
    .bind(&me.id)
    .bind(&me.nonce)
    .execute(db)
    .await?
    .rows_affected();
    if touched == 0 {
        return Err(HeartbeatError::Lost);
    }
    Ok(())
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

/// How many replicas (this one included) have a fresh heartbeat.
pub async fn live_count(db: &Db) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM control_plane_replicas \
         WHERE heartbeat_at >= now() - interval '15 seconds'",
    )
    .fetch_one(db)
    .await
}

/// Whether a replica with this id has a fresh heartbeat.
pub async fn is_live(db: &Db, id: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM control_plane_replicas \
         WHERE id = $1 AND heartbeat_at >= now() - interval '15 seconds')",
    )
    .bind(id)
    .fetch_one(db)
    .await
}

/// Delete this replica's row, unless the id has since been taken over.
pub async fn deregister(db: &Db, me: &Registration) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM control_plane_replicas WHERE id = $1 AND owner_nonce = $2")
        .bind(&me.id)
        .bind(&me.nonce)
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
        // Small pools: these tests run in parallel with the rest of the crate's,
        // and every pool of 16 counts against the server's connection limit.
        Some(crate::db::connect_with(&url, 3).await.expect("connect"))
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
        let first = register(&db, &id, "https://a:1", SpoolMode::Durable)
            .await
            .expect("first");
        let err = register(&db, &id, "https://b:1", SpoolMode::Durable)
            .await
            .expect_err("second must fail");
        assert!(matches!(err, RegisterError::IdInUse(ref i) if *i == id));
        deregister(&db, &first).await.expect("cleanup");
    }

    #[tokio::test]
    async fn stale_row_is_taken_over() {
        let Some(db) = db().await else { return };
        let id = uid("stale");
        register(&db, &id, "https://old:1", SpoolMode::Durable)
            .await
            .expect("first");
        age(&db, &id).await;
        let second = register(&db, &id, "https://new:1", SpoolMode::Ephemeral)
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
        deregister(&db, &second).await.expect("cleanup");
    }

    #[tokio::test]
    async fn live_count_counts_fresh_replicas_only() {
        let Some(db) = db().await else { return };
        let (a, b, dead) = (uid("a"), uid("b"), uid("dead"));
        let mut regs = Vec::new();
        for (id, url) in [
            (&a, "https://a:1"),
            (&b, "https://b:1"),
            (&dead, "https://d:1"),
        ] {
            regs.push(
                register(&db, id, url, SpoolMode::Durable)
                    .await
                    .expect("register"),
            );
        }
        let with_stale = live_count(&db).await.expect("count");
        age(&db, &dead).await;
        let without = live_count(&db).await.expect("count");
        // Other tests share the table, so only the differences are stable.
        assert!(without >= 2, "both fresh replicas are counted: {without}");
        assert!(
            with_stale >= without,
            "a stale replica is not counted once aged"
        );
        for r in &regs {
            deregister(&db, r).await.expect("cleanup");
        }
    }

    #[tokio::test]
    async fn live_peers_excludes_self_and_stale() {
        let Some(db) = db().await else { return };
        let (me, peer, dead) = (uid("me"), uid("peer"), uid("dead"));
        let mut regs = Vec::new();
        for (id, url) in [
            (&me, "https://me:1"),
            (&peer, "https://peer:1"),
            (&dead, "https://dead:1"),
        ] {
            regs.push(
                register(&db, id, url, SpoolMode::Durable)
                    .await
                    .expect("register"),
            );
        }
        age(&db, &dead).await;
        let peers = live_peers(&db, &me).await.expect("peers");
        assert!(
            peers
                .iter()
                .any(|r| r.id == peer && r.ingest_url == "https://peer:1")
        );
        assert!(!peers.iter().any(|r| r.id == me || r.id == dead));
        for r in &regs {
            deregister(&db, r).await.expect("cleanup");
        }
    }

    #[tokio::test]
    async fn deregister_removes_row() {
        let Some(db) = db().await else { return };
        let id = uid("gone");
        let me = register(&db, &id, "https://a:1", SpoolMode::Durable)
            .await
            .expect("register");
        deregister(&db, &me).await.expect("deregister");
        let again = register(&db, &id, "https://a:1", SpoolMode::Durable)
            .await
            .expect("id is free again");
        deregister(&db, &again).await.expect("cleanup");
    }

    async fn set_age(db: &Db, id: &str, secs: i32) {
        sqlx::query(
            "UPDATE control_plane_replicas \
             SET heartbeat_at = now() - make_interval(secs => $2) WHERE id = $1",
        )
        .bind(id)
        .bind(f64::from(secs))
        .execute(db)
        .await
        .expect("set age");
    }

    #[tokio::test]
    async fn liveness_boundary_is_between_14_and_16_seconds() {
        let Some(db) = db().await else { return };
        let id = uid("edge");
        let first = register(&db, &id, "https://a:1", SpoolMode::Durable)
            .await
            .expect("first");
        set_age(&db, &id, 14).await;
        assert!(
            register(&db, &id, "https://b:1", SpoolMode::Durable)
                .await
                .is_err(),
            "a 14 s old heartbeat is still live"
        );
        assert!(
            live_peers(&db, "nobody")
                .await
                .expect("peers")
                .iter()
                .any(|r| r.id == id)
        );
        set_age(&db, &id, 16).await;
        assert!(
            !live_peers(&db, "nobody")
                .await
                .expect("peers")
                .iter()
                .any(|r| r.id == id)
        );
        let second = register(&db, &id, "https://b:1", SpoolMode::Durable)
            .await
            .expect("a 16 s old heartbeat is dead");
        deregister(&db, &first).await.expect("no-op");
        deregister(&db, &second).await.expect("cleanup");
    }

    #[tokio::test]
    async fn stale_heartbeat_after_takeover_is_refused() {
        let Some(db) = db().await else { return };
        let id = uid("takeover");
        let old = register(&db, &id, "https://old:1", SpoolMode::Durable)
            .await
            .expect("first");
        age(&db, &id).await;
        let new = register(&db, &id, "https://new:1", SpoolMode::Durable)
            .await
            .expect("takeover");
        // The stalled old owner wakes up.
        assert!(matches!(
            heartbeat(&db, &old).await,
            Err(HeartbeatError::Lost)
        ));
        age(&db, &id).await;
        assert!(matches!(
            heartbeat(&db, &old).await,
            Err(HeartbeatError::Lost)
        ));
        let (stale,): (bool,) = sqlx::query_as(
            "SELECT heartbeat_at < now() - interval '15 seconds' \
             FROM control_plane_replicas WHERE id = $1",
        )
        .bind(&id)
        .fetch_one(&db)
        .await
        .expect("row");
        assert!(stale, "the old owner must not refresh the new owner's row");
        heartbeat(&db, &new).await.expect("the new owner can");
        deregister(&db, &new).await.expect("cleanup");
    }

    #[tokio::test]
    async fn stale_deregister_does_not_delete_the_new_owner() {
        let Some(db) = db().await else { return };
        let id = uid("keep");
        let old = register(&db, &id, "https://old:1", SpoolMode::Durable)
            .await
            .expect("first");
        age(&db, &id).await;
        let new = register(&db, &id, "https://new:1", SpoolMode::Durable)
            .await
            .expect("takeover");
        deregister(&db, &old).await.expect("a no-op");
        assert!(
            register(&db, &id, "https://x:1", SpoolMode::Durable)
                .await
                .is_err(),
            "the new owner's row must survive"
        );
        deregister(&db, &new).await.expect("cleanup");
    }
}

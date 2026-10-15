//! Adopting an orphaned audit spool (design §A, "Orphan spools").
//!
//! A durable-mode replica that was scaled in for good leaves its spool
//! volume behind, with records its sinks never shipped. `limen-spool-adopt`
//! opens that volume and hands every unshipped record to a live replica,
//! over the same mTLS handoff stream a shutting-down ephemeral replica uses.
//!
//! The tool runs with a replica's configuration (database, CA backend). The
//! receiver only accepts control plane certificates whose id has a live
//! registry row, so the tool registers a short-lived row under a unique
//! `spool-adopt-<random>` id, keeps it fresh while it sends, and removes it
//! at the end. It never weakens that check: it holds a control plane
//! certificate from the internal CA, as any replica does.
//!
//! Guards against two writers: the spool takes an exclusive advisory lock
//! (`<dir>/lock`) while open, so a running replica using the volume makes
//! this refuse; `--expect-id` additionally refuses while the registry shows
//! the spool's former owner alive.

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Args;
use limen_audit::spool::{Spool, SpoolConfig, SpoolError};

use crate::config::{Config, parse_duration};
use crate::handoff_client::{self, HandoffError, HandoffTls};
use crate::pipeline;
use crate::replicas::{self, RegisterError, SpoolMode};

/// Command line of `limen-spool-adopt`: the replica's own [`Config`] plus
/// what to adopt.
#[derive(Debug, Clone, Args)]
pub struct AdoptArgs {
    /// The orphaned spool directory (the one `--audit-spool-dir` pointed at).
    #[arg(long, env = "LIMEN_ADOPT_DIR")]
    pub dir: PathBuf,

    /// Id of the replica that owned the spool. Refuse while the registry
    /// shows that replica alive.
    #[arg(long, env = "LIMEN_ADOPT_EXPECT_ID")]
    pub expect_id: Option<String>,

    /// Consumer names the spool was written with (console, jsonl, s3,
    /// datadog), in addition to those this configuration implies and those
    /// found from the offset files in the spool.
    #[arg(long, env = "LIMEN_ADOPT_CONSUMERS", value_delimiter = ',')]
    pub consumers: Vec<String>,

    /// Give up after this long.
    #[arg(long, env = "LIMEN_ADOPT_DEADLINE", default_value = "60s", value_parser = parse_duration)]
    pub deadline: Duration,

    #[command(flatten)]
    pub config: Config,
}

#[derive(Debug, thiserror::Error)]
pub enum AdoptError {
    #[error("{0} is not an audit spool (no segments directory)")]
    NotASpool(PathBuf),
    #[error("the replica {0:?} that owned this spool is alive; stop it before adopting its spool")]
    OwnerLive(String),
    #[error("audit spool: {0}")]
    Spool(#[from] SpoolError),
    #[error("replica registry: {0}")]
    Db(#[from] sqlx::Error),
    #[error("registering the adopter: {0}")]
    Register(#[from] RegisterError),
    #[error("{0:#}")]
    Setup(anyhow::Error),
    #[error("{0}")]
    Handoff(#[from] HandoffError),
    #[error("handed the records off but {left} are still pending in the spool")]
    NotDrained { left: u64 },
}

/// What was handed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adopted {
    pub sent: u64,
    /// The replica that took them; `None` when the spool had nothing left.
    pub peer: Option<String>,
}

/// Consumer names with an offset file in `dir`.
fn discovered(dir: &Path) -> std::io::Result<Vec<String>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir.join("offsets"))? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        // `commit` writes `<consumer>.tmp` and renames it.
        if Path::new(&name).extension().is_none_or(|e| e != "tmp") {
            found.push(name);
        }
    }
    Ok(found)
}

/// Adopt the spool: see the module documentation.
pub async fn run(args: AdoptArgs) -> Result<Adopted, AdoptError> {
    if !args.dir.join("segments").is_dir() {
        return Err(AdoptError::NotASpool(args.dir));
    }
    let mut consumers = discovered(&args.dir).map_err(SpoolError::from)?;
    // What a replica with these settings would have run, what the spool
    // remembers, and what the operator adds. A consumer that never committed
    // has no offset file, so the configuration is what names it.
    consumers.extend(
        pipeline::consumer_names(&args.config)
            .into_iter()
            .map(str::to_owned),
    );
    consumers.extend(args.consumers.iter().cloned());
    consumers.sort();
    consumers.dedup();
    // Fails when any process (a replica still using the volume) holds it.
    let names: Vec<&str> = consumers.iter().map(String::as_str).collect();
    // Unlike a replica, never proceed without the lock: it is the guard.
    let spool = Spool::open(SpoolConfig {
        require_lock: true,
        ..SpoolConfig::new(&args.dir, &names)
    })?;

    let config = &args.config;
    let db = crate::db::connect(config.database_url.expose()).await?;
    if let Some(owner) = &args.expect_id
        && replicas::is_live(&db, owner).await?
    {
        return Err(AdoptError::OwnerLive(owner.clone()));
    }
    if spool.read_from(spool.min_offset(), 1)?.is_empty() {
        tracing::info!("the spool has nothing left to hand off");
        return Ok(Adopted {
            sent: 0,
            peer: None,
        });
    }

    let cas = crate::ca_store::load(config, &db)
        .await
        .map_err(AdoptError::Setup)?;
    let me = format!("spool-adopt-{:016x}", rand::random::<u64>());
    let registration =
        replicas::register(&db, &me, &config.ingest_url(), SpoolMode::Ephemeral).await?;
    let heartbeat = {
        let (db, registration) = (db.clone(), registration.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(replicas::HEARTBEAT_SECS));
            loop {
                tick.tick().await;
                match replicas::heartbeat(&db, &registration).await {
                    Ok(()) => {}
                    Err(e @ replicas::HeartbeatError::Lost) => {
                        tracing::warn!(error = %e, "the adopter's registry row is gone; peers may refuse the handoff");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "adopter heartbeat failed; retrying (peers refuse the handoff once the row is 15 s old)");
                    }
                }
            }
        })
    };

    let outcome = async {
        let mut peers = replicas::live_peers(&db, &me).await?;
        handoff_client::shuffle(&mut peers);
        let tls = HandoffTls::issue(&cas, &me, &config.dns_names).await?;
        Ok::<_, AdoptError>(
            handoff_client::send_spool_via(&spool, &peers, &tls, args.deadline).await?,
        )
    }
    .await;

    heartbeat.abort();
    if let Err(e) = replicas::deregister(&db, &registration).await {
        tracing::warn!(error = %e, "could not remove the adopter's registry row; it expires on its own");
    }

    let (sent, peer) = outcome?;
    let left = consumers
        .iter()
        .map(|c| spool.pending(c))
        .max()
        .unwrap_or(0);
    if left > 0 {
        return Err(AdoptError::NotDrained { left });
    }
    Ok(Adopted { sent, peer })
}

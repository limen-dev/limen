//! The control plane end of the audit pipeline (ADR-0009): its spool, the
//! sinks that drain it, and where session recordings are stored.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use limen_audit::ship::{ConsumerConfig, ShipError, run_consumer};
use limen_audit::spool::{Spool, SpoolConfig};
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

use crate::config::Config;

pub const JSONL: &str = "jsonl";

/// Where recordings are stored.
#[derive(Debug, Clone)]
pub enum RecordingStore {
    /// A local directory (development, tests).
    Local(PathBuf),
}

impl RecordingStore {
    /// Store a finished recording. Returns its URI.
    pub async fn put(&self, session_id: &str, file: &std::path::Path) -> anyhow::Result<String> {
        match self {
            RecordingStore::Local(dir) => {
                let day = time::OffsetDateTime::now_utc().date();
                let dest_dir = dir.join(format!("dt={day}"));
                tokio::fs::create_dir_all(&dest_dir).await?;
                let dest = dest_dir.join(format!("{session_id}.cast"));
                tokio::fs::copy(file, &dest).await?;
                Ok(format!("file://{}", dest.display()))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pipeline {
    pub spool: Spool,
    pub recordings: RecordingStore,
    config: Arc<Config>,
}

impl Pipeline {
    pub fn open(config: &Arc<Config>) -> anyhow::Result<Self> {
        let mut consumers: Vec<&str> = Vec::new();
        if config.audit_file.is_some() {
            consumers.push(JSONL);
        }
        if consumers.is_empty() {
            anyhow::bail!(
                "no audit sink is configured: set --audit-file, an S3 bucket, or Datadog"
            );
        }
        let mut spool_config = SpoolConfig::new(&config.audit_spool_dir, &consumers);
        spool_config.max_bytes = config.audit_spool_max_bytes;
        let spool = Spool::open(spool_config).with_context(|| {
            format!(
                "opening the audit spool in {}",
                config.audit_spool_dir.display()
            )
        })?;
        spool.start();
        Ok(Self {
            spool,
            recordings: RecordingStore::Local(config.recordings_dir.clone()),
            config: Arc::clone(config),
        })
    }

    /// Start every configured sink.
    pub fn start_sinks(&self, shutdown: &watch::Receiver<bool>) {
        if let Some(path) = self.config.audit_file.clone() {
            let consumer = ConsumerConfig {
                name: JSONL.into(),
                batch_max: 500,
                linger: Duration::ZERO,
            };
            tokio::spawn(run_consumer(
                self.spool.clone(),
                consumer,
                move |batch| write_jsonl(path.clone(), batch),
                shutdown.clone(),
            ));
        }
    }
}

async fn write_jsonl(path: PathBuf, batch: Vec<(u64, Vec<u8>)>) -> Result<(), ShipError> {
    let fail = |e: std::io::Error| ShipError::Retry(format!("{}: {e}", path.display()));
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(fail)?;
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
        .map_err(fail)?;
    let mut buf = Vec::new();
    for (_, line) in batch {
        buf.extend_from_slice(&line);
        buf.push(b'\n');
    }
    file.write_all(&buf).await.map_err(fail)?;
    file.sync_data().await.map_err(fail)
}

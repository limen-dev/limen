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
use crate::sinks::{DatadogSink, S3Sink, SignerSlot};

pub const JSONL: &str = "jsonl";
pub const S3: &str = "s3";
pub const DATADOG: &str = "datadog";
/// Fills the `sessions` table the web console reads.
pub const CONSOLE: &str = "console";

/// Largest recording the console will load into memory to play.
pub const MAX_PLAYBACK_BYTES: usize = 64 * 1024 * 1024;

/// Where recordings are stored.
#[derive(Debug, Clone)]
pub enum RecordingStore {
    /// A local directory (development, tests).
    Local(PathBuf),
    S3(S3Sink),
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
            RecordingStore::S3(sink) => sink.put_recording(session_id, file).await,
        }
    }

    /// Read a stored recording by the URI `put` returned. Refuses anything
    /// outside this store.
    pub async fn get(&self, uri: &str) -> anyhow::Result<Vec<u8>> {
        match self {
            RecordingStore::Local(dir) => {
                let path = uri
                    .strip_prefix("file://")
                    .ok_or_else(|| anyhow::anyhow!("not a local recording: {uri}"))?;
                let root = tokio::fs::canonicalize(dir).await?;
                let path = tokio::fs::canonicalize(path).await?;
                anyhow::ensure!(path.starts_with(&root), "recording is outside the store");
                let len = tokio::fs::metadata(&path).await?.len();
                anyhow::ensure!(
                    usize::try_from(len).is_ok_and(|n| n <= MAX_PLAYBACK_BYTES),
                    "recording is too large to play in the browser ({len} bytes)"
                );
                Ok(tokio::fs::read(path).await?)
            }
            RecordingStore::S3(sink) => {
                let rest = uri
                    .strip_prefix("s3://")
                    .ok_or_else(|| anyhow::anyhow!("not an S3 recording: {uri}"))?;
                let (bucket, key) = rest
                    .split_once('/')
                    .ok_or_else(|| anyhow::anyhow!("malformed recording URI"))?;
                anyhow::ensure!(
                    bucket == sink.bucket && key.contains("recordings/"),
                    "recording is outside the store"
                );
                let out = sink
                    .client
                    .get_object()
                    .bucket(bucket)
                    .key(key)
                    .send()
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!("{}", aws_sdk_s3::error::DisplayErrorContext(&e))
                    })?;
                let len = out.content_length().unwrap_or(0);
                anyhow::ensure!(
                    usize::try_from(len).is_ok_and(|n| n <= MAX_PLAYBACK_BYTES),
                    "recording is too large to play in the browser ({len} bytes)"
                );
                Ok(out.body.collect().await?.into_bytes().to_vec())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pipeline {
    pub spool: Spool,
    pub recordings: RecordingStore,
    s3: Option<S3Sink>,
    datadog: Option<DatadogSink>,
    config: Arc<Config>,
}

impl Pipeline {
    pub async fn open(config: &Arc<Config>, signer: SignerSlot) -> anyhow::Result<Self> {
        let mut consumers: Vec<&str> = vec![CONSOLE];
        if config.audit_file.is_some() {
            consumers.push(JSONL);
        }
        let s3 = match &config.audit_s3_bucket {
            Some(bucket) => {
                consumers.push(S3);
                let client = crate::sinks::s3_client(
                    config.audit_s3_endpoint.as_deref(),
                    config.audit_s3_path_style,
                )
                .await;
                if config.audit_s3_create_bucket
                    && client.head_bucket().bucket(bucket).send().await.is_err()
                {
                    match client.create_bucket().bucket(bucket).send().await {
                        Ok(_) => tracing::info!(%bucket, "created the audit bucket"),
                        Err(e) => {
                            tracing::warn!(%bucket, error = %aws_sdk_s3::error::DisplayErrorContext(&e), "couldn't create the audit bucket; will retry when shipping");
                        }
                    }
                }
                Some(S3Sink::new(
                    client,
                    bucket.clone(),
                    config.audit_s3_prefix.clone(),
                    config.audit_s3_kms_key.clone(),
                    config.id.clone(),
                    signer,
                ))
            }
            None => None,
        };
        let datadog = match (&config.datadog_logs_url, &config.datadog_api_key) {
            (Some(url), Some(key)) => {
                consumers.push(DATADOG);
                let http = reqwest::Client::builder()
                    .timeout(Duration::from_secs(30))
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?;
                Some(DatadogSink {
                    http,
                    url: url.clone(),
                    api_key: key.clone(),
                    hostname: config.id.clone(),
                    environment: config.environment.clone(),
                })
            }
            (Some(_), None) => anyhow::bail!("--datadog-logs-url needs DD_API_KEY"),
            _ => None,
        };
        if consumers.len() == 1 {
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
        let recordings = match &s3 {
            Some(sink) => RecordingStore::S3(sink.clone()),
            None => RecordingStore::Local(config.recordings_dir.clone()),
        };
        Ok(Self {
            spool,
            recordings,
            s3,
            datadog,
            config: Arc::clone(config),
        })
    }

    /// Start every configured sink.
    pub fn start_sinks(&self, db: &crate::db::Db, shutdown: &watch::Receiver<bool>) {
        let db = db.clone();
        tokio::spawn(run_consumer(
            self.spool.clone(),
            ConsumerConfig {
                name: CONSOLE.into(),
                batch_max: 500,
                linger: Duration::from_millis(200),
            },
            move |batch| project(db.clone(), batch),
            shutdown.clone(),
        ));
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
        if let Some(sink) = self.s3.clone() {
            let consumer = ConsumerConfig {
                name: S3.into(),
                batch_max: 10_000,
                linger: self.config.audit_s3_flush,
            };
            tokio::spawn(run_consumer(
                self.spool.clone(),
                consumer,
                move |batch| {
                    let sink = sink.clone();
                    async move { sink.ship(batch).await }
                },
                shutdown.clone(),
            ));
        }
        if let Some(sink) = self.datadog.clone() {
            let consumer = ConsumerConfig {
                name: DATADOG.into(),
                batch_max: 1000,
                linger: Duration::from_secs(1),
            };
            tokio::spawn(run_consumer(
                self.spool.clone(),
                consumer,
                move |batch| {
                    let sink = sink.clone();
                    async move { sink.ship(batch).await }
                },
                shutdown.clone(),
            ));
        }
    }
}

/// Project session events into the database for the console. A batch that
/// can't be read is skipped (it's still in every other sink); a database
/// error is retried.
async fn project(db: crate::db::Db, batch: Vec<(u64, Vec<u8>)>) -> Result<(), ShipError> {
    let events: Vec<limen_audit::Event> = batch
        .iter()
        .filter_map(|(seq, line)| {
            serde_json::from_slice(line)
                .map_err(|e| tracing::warn!(seq, error = %e, "skipping an unreadable audit event"))
                .ok()
        })
        .collect();
    crate::console::store::project_events(&db, &events)
        .await
        .map_err(|e| ShipError::Retry(format!("projecting sessions: {e}")))
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

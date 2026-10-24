//! Audit sinks that leave the host: S3 and Datadog (ADR-0009).

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, RwLock};

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::ServerSideEncryption;
use base64::Engine as _;
use limen_audit::ship::ShipError;
use limen_core::secret::Secret;
use limen_session::envelope::{EnvelopeSigner, Purpose};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

pub type SignerSlot = Arc<RwLock<Option<Arc<EnvelopeSigner>>>>;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    // Deterministic output: no file name, zero mtime.
    let mut enc = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::default());
    enc.write_all(data)?;
    enc.finish()
}

/// Events for one `(date, hour)` partition, with their parsed heads.
type Partition = Vec<(EventHead, Vec<u8>)>;

/// Minimal view of an event, for partitioning and manifests.
#[derive(Debug, Deserialize)]
struct EventHead {
    event_id: String,
    time: String,
}

// ---- S3 ---------------------------------------------------------------------

/// What a manifest records about one batch object. Manifests chain: each
/// names the SHA-256 of the previous manifest file from the same writer, so
/// a deleted, reordered, or altered batch breaks the chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: u32,
    pub writer: String,
    pub seq: u64,
    pub object: String,
    pub sha256: String,
    pub count: usize,
    pub first_event_id: String,
    pub last_event_id: String,
    pub prev_manifest_sha256: String,
    pub created_at: String,
}

/// The manifest file in S3: the manifest JSON, its signature, and the signer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    pub manifest: String,
    pub signature: String,
    pub signer_cert: String,
}

#[derive(Debug, Clone)]
pub struct S3Sink {
    pub client: aws_sdk_s3::Client,
    pub bucket: String,
    pub prefix: String,
    pub kms_key: Option<String>,
    pub writer: String,
    signer: SignerSlot,
    /// `(next seq, sha256 of the last manifest)`; `None` until loaded from S3.
    chain: Arc<Mutex<Option<(u64, String)>>>,
}

impl S3Sink {
    pub fn new(
        client: aws_sdk_s3::Client,
        bucket: String,
        prefix: String,
        kms_key: Option<String>,
        writer: String,
        signer: SignerSlot,
    ) -> Self {
        Self {
            client,
            bucket,
            prefix,
            kms_key,
            writer,
            signer,
            chain: Arc::new(Mutex::new(None)),
        }
    }

    fn key(&self, rest: &str) -> String {
        format!("{}{rest}", self.prefix)
    }

    fn manifest_key(&self, seq: u64) -> String {
        self.key(&format!("manifests/{}/{seq:012}.json", self.writer))
    }

    /// The chain position, recovered from S3: the latest manifest for this
    /// writer is the source of truth, so a crash between upload and local
    /// commit never forks the chain.
    async fn chain_head(&self) -> Result<(u64, String), ShipError> {
        let prefix = self.key(&format!("manifests/{}/", self.writer));
        let mut last: Option<String> = None;
        let mut pages = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&prefix)
            .into_paginator()
            .send();
        while let Some(page) = pages.next().await {
            let page = page.map_err(|e| {
                ShipError::Retry(format!(
                    "listing manifests: {}",
                    aws_sdk_s3::error::DisplayErrorContext(&e)
                ))
            })?;
            for obj in page.contents() {
                if let Some(k) = obj.key()
                    && last.as_deref().is_none_or(|l| k > l)
                {
                    last = Some(k.to_owned());
                }
            }
        }
        let Some(key) = last else {
            return Ok((0, String::new()));
        };
        let body = self.get(&key).await?;
        let signed: SignedManifest = serde_json::from_slice(&body)
            .map_err(|e| ShipError::Retry(format!("bad manifest {key}: {e}")))?;
        let manifest: Manifest = serde_json::from_str(&signed.manifest)
            .map_err(|e| ShipError::Retry(format!("bad manifest {key}: {e}")))?;
        Ok((manifest.seq + 1, hex(&Sha256::digest(&body))))
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, ShipError> {
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                ShipError::Retry(format!(
                    "get {key}: {}",
                    aws_sdk_s3::error::DisplayErrorContext(&e)
                ))
            })?;
        out.body
            .collect()
            .await
            .map(|b| b.into_bytes().to_vec())
            .map_err(|e| ShipError::Retry(format!("get {key}: {e}")))
    }

    async fn put(&self, key: &str, body: Vec<u8>, content_type: &str) -> Result<(), ShipError> {
        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body))
            .content_type(content_type);
        if let Some(kms) = &self.kms_key {
            req = req
                .server_side_encryption(ServerSideEncryption::AwsKms)
                .ssekms_key_id(kms);
        }
        req.send().await.map(|_| ()).map_err(|e| {
            ShipError::Retry(format!(
                "put {key}: {}",
                aws_sdk_s3::error::DisplayErrorContext(&e)
            ))
        })
    }

    /// Upload a recording file to `recordings/dt=YYYY-MM-DD/<session>.cast`.
    pub async fn put_recording(
        &self,
        session_id: &str,
        file: &std::path::Path,
    ) -> anyhow::Result<String> {
        let day = time::OffsetDateTime::now_utc().date();
        let key = self.key(&format!("recordings/dt={day}/{session_id}.cast"));
        let body = ByteStream::from_path(file).await?;
        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(body)
            .content_type("application/x-asciicast");
        if let Some(kms) = &self.kms_key {
            req = req
                .server_side_encryption(ServerSideEncryption::AwsKms)
                .ssekms_key_id(kms);
        }
        req.send().await.map_err(|e| {
            anyhow::anyhow!("put {key}: {}", aws_sdk_s3::error::DisplayErrorContext(&e))
        })?;
        Ok(format!("s3://{}/{key}", self.bucket))
    }

    /// Write a batch: one object per (date, hour) partition, each with its
    /// signed, chained manifest.
    pub async fn ship(&self, batch: Vec<(u64, Vec<u8>)>) -> Result<(), ShipError> {
        let signer = self
            .signer
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| ShipError::Retry("manifest signer not ready".into()))?;
        let mut partitions: BTreeMap<(String, String), Partition> = BTreeMap::new();
        for (_, raw) in batch {
            let head: EventHead = match serde_json::from_slice(&raw) {
                Ok(h) => h,
                Err(e) => {
                    // Producers only spool valid events; this would be a bug. Keep it, under "unknown".
                    tracing::error!(error = %e, "unparseable event in the spool; storing it under dt=unknown");
                    EventHead {
                        event_id: String::new(),
                        time: String::new(),
                    }
                }
            };
            let (dt, hour) = if head.time.len() >= 13 {
                (head.time[..10].to_owned(), head.time[11..13].to_owned())
            } else {
                ("unknown".into(), "00".into())
            };
            partitions.entry((dt, hour)).or_default().push((head, raw));
        }

        let mut chain = self.chain.lock().await;
        if chain.is_none() {
            *chain = Some(self.chain_head().await?);
        }
        for ((dt, hour), events) in partitions {
            let (seq, prev) = chain.clone().unwrap_or_default();
            let mut jsonl = Vec::new();
            for (_, raw) in &events {
                jsonl.extend_from_slice(raw);
                jsonl.push(b'\n');
            }
            let body = gzip(&jsonl).map_err(|e| ShipError::Retry(e.to_string()))?;
            let object = self.key(&format!(
                "events/dt={dt}/hour={hour}/{}-{seq:012}.jsonl.gz",
                self.writer
            ));
            let manifest = Manifest {
                version: 1,
                writer: self.writer.clone(),
                seq,
                object: object.clone(),
                sha256: hex(&Sha256::digest(&body)),
                count: events.len(),
                first_event_id: events
                    .first()
                    .map(|(h, _)| h.event_id.clone())
                    .unwrap_or_default(),
                last_event_id: events
                    .last()
                    .map(|(h, _)| h.event_id.clone())
                    .unwrap_or_default(),
                prev_manifest_sha256: prev,
                created_at: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            };
            let manifest_json =
                serde_json::to_string(&manifest).map_err(|e| ShipError::Retry(e.to_string()))?;
            let envelope = signer
                .sign(Purpose::AuditManifest, manifest_json.clone().into_bytes())
                .map_err(|e| ShipError::Retry(e.to_string()))?;
            let b64 = base64::engine::general_purpose::STANDARD;
            let file = serde_json::to_vec(&SignedManifest {
                manifest: manifest_json,
                signature: b64.encode(&envelope.signature),
                signer_cert: b64.encode(&envelope.signer_cert_der),
            })
            .map_err(|e| ShipError::Retry(e.to_string()))?;
            // Batch first, then its manifest: a manifest never points at a missing object.
            self.put(&object, body, "application/gzip").await?;
            self.put(&self.manifest_key(seq), file.clone(), "application/json")
                .await?;
            *chain = Some((seq + 1, hex(&Sha256::digest(&file))));
            metrics::counter!("limen_audit_s3_batches_total").increment(1);
        }
        Ok(())
    }
}

// ---- Datadog ----------------------------------------------------------------

/// Datadog intake limits (<https://docs.datadoghq.com/api/latest/logs/send-logs>).
const DD_MAX_ENTRIES: usize = 1000;
const DD_MAX_PAYLOAD: usize = 5 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct DatadogSink {
    pub http: reqwest::Client,
    pub url: String,
    pub api_key: Secret<String>,
    pub hostname: String,
    pub environment: String,
}

impl DatadogSink {
    fn log_entry(&self, raw: &[u8]) -> serde_json::Value {
        let mut event: serde_json::Value = serde_json::from_slice(raw)
            .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(raw) }));
        let kind = event
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();
        let user = event
            .get("user")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_owned();
        let component = event
            .pointer("/producer/component")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();
        if let Some(obj) = event.as_object_mut() {
            obj.insert("ddsource".into(), "limen".into());
            obj.insert("service".into(), "limen".into());
            obj.insert("hostname".into(), self.hostname.clone().into());
            obj.insert(
                "ddtags".into(),
                format!(
                    "env:{},version:{},event_kind:{kind},component:{component}",
                    self.environment,
                    limen_core::VERSION
                )
                .into(),
            );
            obj.insert("message".into(), format!("{kind} {user}").into());
        }
        event
    }

    /// Send a batch. Retryable failures (network, 408, 429, 5xx) retry the
    /// whole batch; a payload rejected as malformed or too large is split in
    /// half until the offending event is isolated, which is then dropped
    /// from Datadog only (it's still in S3 and the JSONL sink).
    pub async fn ship(&self, batch: Vec<(u64, Vec<u8>)>) -> Result<(), ShipError> {
        let entries: Vec<serde_json::Value> =
            batch.iter().map(|(_, raw)| self.log_entry(raw)).collect();
        let mut queue = vec![entries];
        while let Some(chunk) = queue.pop() {
            if chunk.is_empty() {
                continue;
            }
            let body = serde_json::to_vec(&chunk).map_err(|e| ShipError::Retry(e.to_string()))?;
            if chunk.len() > DD_MAX_ENTRIES || (body.len() > DD_MAX_PAYLOAD && chunk.len() > 1) {
                let (a, b) = chunk.split_at(chunk.len() / 2);
                queue.push(b.to_vec());
                queue.push(a.to_vec());
                continue;
            }
            match self.post(&body).await? {
                Outcome::Accepted => metrics::counter!("limen_audit_datadog_logs_total")
                    .increment(chunk.len() as u64),
                Outcome::Rejected(status) if chunk.len() > 1 => {
                    let (a, b) = chunk.split_at(chunk.len() / 2);
                    tracing::warn!(%status, size = chunk.len(), "Datadog rejected a batch; splitting it");
                    queue.push(b.to_vec());
                    queue.push(a.to_vec());
                }
                Outcome::Rejected(status) => {
                    let id = chunk[0].get("event_id").cloned().unwrap_or_default();
                    tracing::warn!(%status, event_id = %id, "Datadog rejected an audit event; skipping it in Datadog only (it's in S3)");
                    metrics::counter!("limen_audit_datadog_rejected_total").increment(1);
                }
            }
        }
        Ok(())
    }

    async fn post(&self, body: &[u8]) -> Result<Outcome, ShipError> {
        let gz = gzip(body).map_err(|e| ShipError::Retry(e.to_string()))?;
        let response = self
            .http
            .post(&self.url)
            .header("DD-API-KEY", self.api_key.expose())
            .header("Content-Type", "application/json")
            .header("Content-Encoding", "gzip")
            .body(gz)
            .send()
            .await
            .map_err(|e| ShipError::Retry(format!("Datadog unreachable: {e}")))?;
        let status = response.status();
        match status.as_u16() {
            200..=299 => Ok(Outcome::Accepted),
            400 | 413 => Ok(Outcome::Rejected(status)),
            401 | 403 => Err(ShipError::Retry(format!(
                "Datadog refused the API key ({status}); check DD_API_KEY"
            ))),
            _ => Err(ShipError::Retry(format!("Datadog returned {status}"))),
        }
    }
}

enum Outcome {
    Accepted,
    Rejected(reqwest::StatusCode),
}

/// Build an S3 client, honoring an endpoint override and path-style addressing.
pub async fn s3_client(endpoint: Option<&str>, path_style: bool) -> aws_sdk_s3::Client {
    let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let mut builder = aws_sdk_s3::config::Builder::from(&shared).force_path_style(path_style);
    if let Some(endpoint) = endpoint {
        builder = builder.endpoint_url(endpoint);
    }
    aws_sdk_s3::Client::from_conf(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_is_deterministic() {
        assert_eq!(gzip(b"same").expect("gz"), gzip(b"same").expect("gz"));
    }

    #[test]
    fn datadog_entries_keep_the_event_and_add_tags() {
        let sink = DatadogSink {
            http: reqwest::Client::new(),
            url: String::new(),
            api_key: Secret::new("k".into()),
            hostname: "cp-1".into(),
            environment: "test".into(),
        };
        let raw = br#"{"kind":"ssh.exec","user":"developer","event_id":"e1","producer":{"component":"worker","instance_id":"w/1","seq":3},"data":{"command":"id"}}"#;
        let entry = sink.log_entry(raw);
        assert_eq!(entry["data"]["command"], "id");
        assert_eq!(entry["message"], "ssh.exec developer");
        assert!(entry["ddtags"].as_str().expect("tags").contains("env:test"));
        assert!(
            entry["ddtags"]
                .as_str()
                .expect("tags")
                .contains("event_kind:ssh.exec")
        );
    }
}

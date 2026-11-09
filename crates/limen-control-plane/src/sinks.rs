//! Audit sinks that leave the host: S3, Datadog (ADR-0009) and the OCSF
//! projection (ADR-0047).

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, RwLock};

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::ServerSideEncryption;
use base64::Engine as _;
use limen_audit::ship::ShipError;
use limen_core::secret::Secret;
use limen_session::envelope::{EnvelopeSigner, Purpose};
pub use limen_verify::manifest::{Manifest, SignedManifest, signer_problem};
pub use limen_verify::s3_client;
use serde::Deserialize;
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

#[derive(Debug, Clone)]
pub struct S3Sink {
    pub client: aws_sdk_s3::Client,
    pub bucket: String,
    pub prefix: String,
    pub kms_key: Option<String>,
    pub writer: String,
    signer: SignerSlot,
    /// The internal CA, to check the signature of the manifest the chain resumes
    /// from. `None` (tests) skips that check.
    internal_ca: Option<Arc<Vec<u8>>>,
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
            internal_ca: None,
            chain: Arc::new(Mutex::new(None)),
        }
    }

    /// Check the signature of the manifest a restart resumes from, against
    /// this CA.
    #[must_use]
    pub fn with_internal_ca(mut self, der: Vec<u8>) -> Self {
        self.internal_ca = Some(Arc::new(der));
        self
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
        let mut keys: Vec<String> = Vec::new();
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
            keys.extend(
                page.contents()
                    .iter()
                    .filter_map(|o| o.key())
                    .map(str::to_owned),
            );
        }
        keys.sort_unstable_by(|a, b| b.cmp(a));
        let highest = keys.first().and_then(|k| key_seq(k));
        // The newest manifest that is consistent with its key and writer. A key
        // that is not (planted, corrupt, another writer's) is skipped with an
        // error in the log rather than stopping the writer for good; the
        // verifier reports the break it leaves. The signature is checked as of
        // the time the manifest records, so a restart after the signing
        // certificate's day is over can still resume from its own last manifest.
        let mut trusted = None;
        for key in &keys {
            let body = self.get(key).await?;
            let checked = consistent_manifest(&body, key, &self.writer)
                .and_then(|m| self.signature_problem(&body, &m).map_or(Ok(m), Err));
            match checked {
                Ok(manifest) => {
                    trusted = Some((manifest.seq, hex(&Sha256::digest(&body))));
                    break;
                }
                Err(why) => {
                    tracing::error!(%key, %why, "skipping a manifest that is not this writer's when resuming the audit chain");
                }
            }
        }
        Ok(resume_point(highest, trusted))
    }

    /// Why the manifest's signature does not hold, if it does not (as of the
    /// time the manifest records, and by this writer's own certificate).
    #[must_use]
    pub fn signature_problem(&self, file: &[u8], manifest: &Manifest) -> Option<String> {
        let ca = self.internal_ca.as_ref()?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let signed: SignedManifest = serde_json::from_slice(file).ok()?;
        let envelope = limen_proto::v1::Signed {
            payload: signed.manifest.clone().into_bytes(),
            signature: b64.decode(&signed.signature).unwrap_or_default(),
            signer_cert_der: b64.decode(&signed.signer_cert).unwrap_or_default(),
        };
        let at = match time::OffsetDateTime::parse(
            &manifest.created_at,
            &time::format_description::well_known::Rfc3339,
        ) {
            Ok(at) => at,
            Err(e) => return Some(format!("unreadable manifest time: {e}")),
        };
        let ca = rustls_pki_types::CertificateDer::from(ca.as_slice());
        match limen_session::envelope::verify_at(&envelope, Purpose::AuditManifest, &ca, at) {
            Ok((by, _)) => signer_problem(&by.id, &manifest.writer),
            Err(e) => Some(format!("signature: {e}")),
        }
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

    /// Upload a recording file to `recordings/dt=YYYY-MM-DD/<session>-<id>.cast`.
    /// The key is never reused, so a second upload for a session cannot replace the first.
    pub async fn put_recording(
        &self,
        session_id: &str,
        file: &std::path::Path,
    ) -> anyhow::Result<String> {
        let day = time::OffsetDateTime::now_utc().date();
        let key = self.key(&format!(
            "recordings/dt={day}/{session_id}-{}.cast",
            uuid::Uuid::now_v7().simple()
        ));
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

/// `manifests/<writer>/000000000007.json` -> 7.
fn key_seq(key: &str) -> Option<u64> {
    key.rsplit('/').next()?.strip_suffix(".json")?.parse().ok()
}

/// Where the chain continues: after the newest manifest that verified, but
/// never at a sequence number that already has a key (so nothing is
/// overwritten). A skipped key beyond it leaves a visible gap for the verifier.
fn resume_point(highest_key: Option<u64>, trusted: Option<(u64, String)>) -> (u64, String) {
    let (after_trusted, prev) = trusted.map_or((0, String::new()), |(seq, hash)| (seq + 1, hash));
    let after_keys = highest_key.map_or(0, |k| k + 1);
    (after_trusted.max(after_keys), prev)
}

/// A manifest file that parses and agrees with its key (`<seq>.json`) and its writer.
fn consistent_manifest(file: &[u8], key: &str, writer: &str) -> Result<Manifest, String> {
    let signed: SignedManifest = serde_json::from_slice(file).map_err(|e| e.to_string())?;
    let manifest: Manifest = serde_json::from_str(&signed.manifest).map_err(|e| e.to_string())?;
    if manifest.writer != writer {
        return Err(format!("manifest names writer {}", manifest.writer));
    }
    if key_seq(key) != Some(manifest.seq) {
        return Err(format!("manifest has seq {}, not its key's", manifest.seq));
    }
    Ok(manifest)
}

// ---- OCSF -------------------------------------------------------------------

/// The OCSF projection (ADR-0047): gzipped NDJSON in a bucket of its own, one
/// object per `(date, hour)` of the events in a batch. It is a projection of
/// the native trail and never part of the hash chain.
#[derive(Debug, Clone)]
pub struct OcsfSink {
    pub client: aws_sdk_s3::Client,
    pub bucket: String,
    pub prefix: String,
    pub kms_key: Option<String>,
    pub writer: String,
}

impl OcsfSink {
    /// The object key for one partition of a batch. Named by the SHA-256 of
    /// its content, so shipping the same batch again (a retry, or a restart
    /// before the commit) writes the same key with the same bytes, and a
    /// spool that was wiped can never overwrite an older, different object.
    fn key(&self, day: &str, hour: &str, digest: &str) -> String {
        format!(
            "{}dt={day}/hour={hour}/{}-{}.jsonl.gz",
            self.prefix,
            self.writer,
            &digest[..32]
        )
    }

    /// Project a batch into `(day, hour) -> NDJSON`. Unreadable lines are kept
    /// as Base Events under `unknown/00` (fixed, so a retry rewrites the same
    /// bytes); nothing is dropped.
    fn partitions(batch: &[(u64, Vec<u8>)]) -> BTreeMap<(String, String), Vec<u8>> {
        let mut out: BTreeMap<(String, String), Vec<u8>> = BTreeMap::new();
        for (_, raw) in batch {
            let (record, day_hour) = limen_audit::ocsf::raw_to_ocsf(raw, limen_core::VERSION);
            let (day, hour) = day_hour
                .as_deref()
                .and_then(|dh| dh.split_once('/'))
                .unwrap_or(("unknown", "00"));
            let body = out.entry((day.to_owned(), hour.to_owned())).or_default();
            // `Value` always serializes.
            if serde_json::to_writer(&mut *body, &record).is_ok() {
                body.push(b'\n');
            }
        }
        out
    }

    async fn put(&self, key: &str, body: Vec<u8>) -> Result<(), ShipError> {
        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body))
            .content_type("application/gzip");
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

    /// Write a batch. Retryable failures retry the whole batch.
    pub async fn ship(&self, batch: Vec<(u64, Vec<u8>)>) -> Result<(), ShipError> {
        let count = batch.len() as u64;
        for ((day, hour), ndjson) in Self::partitions(&batch) {
            let body = gzip(&ndjson).map_err(|e| ShipError::Retry(e.to_string()))?;
            let key = self.key(&day, &hour, &hex(&Sha256::digest(&ndjson)));
            self.put(&key, body).await?;
        }
        metrics::counter!("limen_audit_ocsf_events_total").increment(count);
        Ok(())
    }
}

// ---- Datadog ----------------------------------------------------------------

/// Datadog intake limits (<https://docs.datadoghq.com/api/latest/logs/send-logs>).
const DD_MAX_ENTRIES: usize = 1000;
const DD_MAX_PAYLOAD: usize = 5 * 1024 * 1024;

/// A value safe to put in a Datadog tag list: a comma would start another
/// tag and a colon would change the key, so anything but letters, digits and
/// `_ - . /` becomes `_`. The component name comes from an event, which a
/// compromised component writes.
fn tag_value(value: &str) -> String {
    value
        .chars()
        .take(200)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

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
                    "env:{},version:{},event_kind:{},component:{}",
                    tag_value(&self.environment),
                    limen_core::VERSION,
                    tag_value(&kind),
                    tag_value(&component),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_file(writer: &str, seq: u64) -> Vec<u8> {
        let manifest = Manifest {
            version: 1,
            writer: writer.into(),
            seq,
            object: "events/x".into(),
            sha256: String::new(),
            count: 0,
            first_event_id: String::new(),
            last_event_id: String::new(),
            prev_manifest_sha256: String::new(),
            created_at: String::new(),
        };
        serde_json::to_vec(&SignedManifest {
            manifest: serde_json::to_string(&manifest).expect("json"),
            signature: String::new(),
            signer_cert: String::new(),
        })
        .expect("file")
    }

    fn event_line(kind: limen_audit::EventKind, at: time::OffsetDateTime) -> Vec<u8> {
        let mut e = limen_audit::Event::new(
            kind,
            limen_audit::Producer {
                component: "proxy".into(),
                instance_id: "p-1".into(),
                seq: 1,
            },
            serde_json::json!({"password": "hunter2", "resource": "orders"}),
        );
        e.time = at;
        serde_json::to_vec(&e).expect("line")
    }

    #[test]
    fn ocsf_batches_split_by_utc_hour_keep_unreadable_lines_and_hide_secrets() {
        use limen_audit::EventKind::AuthLogin;
        let h1 = time::macros::datetime!(2026-11-09 10:05:00 UTC);
        let h2 = time::macros::datetime!(2026-11-09 11:05:00 UTC);
        let batch = vec![
            (0, event_line(AuthLogin, h1)),
            (1, event_line(AuthLogin, h2)),
            (2, event_line(AuthLogin, h1)),
            (3, b"not json at all".to_vec()),
        ];
        let parts = OcsfSink::partitions(&batch);
        let lines = |day: &str, hour: &str| -> Vec<serde_json::Value> {
            parts
                .get(&(day.to_owned(), hour.to_owned()))
                .map(|b| {
                    String::from_utf8_lossy(b)
                        .lines()
                        .map(|l| serde_json::from_str(l).expect("one json value per line"))
                        .collect()
                })
                .unwrap_or_default()
        };
        assert_eq!(lines("2026-11-09", "10").len(), 2);
        assert_eq!(lines("2026-11-09", "11").len(), 1);
        // The unreadable line is under unknown/00, as a Base Event; 4 records in all.
        assert_eq!(lines("unknown", "00").len(), 1);
        let total: usize = parts.keys().map(|(d, h)| lines(d, h).len()).sum();
        assert_eq!(total, 4);
        let all = parts
            .values()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect::<String>();
        assert!(
            !all.contains("not json at all"),
            "unparseable text is not copied"
        );
        assert!(!all.contains("hunter2"), "a secret reached the projection");
        assert!(all.contains("orders"));
    }

    #[test]
    fn ocsf_object_keys_are_stable_for_a_batch_and_differ_for_another() {
        let sink = |prefix: &str| OcsfSink {
            client: aws_sdk_s3::Client::from_conf(
                aws_sdk_s3::Config::builder()
                    .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
                    .region(aws_sdk_s3::config::Region::new("us-east-1"))
                    .build(),
            ),
            bucket: "siem".into(),
            prefix: prefix.into(),
            kms_key: None,
            writer: "cp-a".into(),
        };
        let s = sink("ocsf/");
        let a = hex(&Sha256::digest(b"one"));
        let b = hex(&Sha256::digest(b"two"));
        let key = s.key("2026-11-09", "10", &a);
        assert_eq!(
            key,
            s.key("2026-11-09", "10", &a),
            "a retry writes the same key"
        );
        assert_ne!(key, s.key("2026-11-09", "10", &b));
        assert!(key.starts_with("ocsf/dt=2026-11-09/hour=10/cp-a-"));
        assert!(key.ends_with(".jsonl.gz"));
        assert!(sink("").key("d", "h", &a).starts_with("dt=d/hour=h/"));
    }

    #[test]
    fn only_a_manifest_that_fits_its_key_and_writer_is_resumed_from() {
        let key = "manifests/cp-a/000000000003.json";
        assert_eq!(
            consistent_manifest(&manifest_file("cp-a", 3), key, "cp-a")
                .expect("fits")
                .seq,
            3
        );
        assert!(consistent_manifest(&manifest_file("cp-b", 3), key, "cp-a").is_err());
        assert!(consistent_manifest(&manifest_file("cp-a", 4), key, "cp-a").is_err());
        assert!(consistent_manifest(b"garbage", key, "cp-a").is_err());
        assert!(
            consistent_manifest(&manifest_file("cp-a", 3), "manifests/cp-a/zzz", "cp-a").is_err()
        );
    }

    #[test]
    fn the_chain_resumes_after_the_newest_verified_manifest_and_overwrites_nothing() {
        assert_eq!(resume_point(None, None), (0, String::new()));
        assert_eq!(
            resume_point(Some(4), Some((4, "h".into()))),
            (5, "h".into())
        );
        // A planted key at 999 is skipped; the chain goes on beyond it.
        assert_eq!(
            resume_point(Some(999), Some((4, "h".into()))),
            (1000, "h".into())
        );
        assert_eq!(key_seq("manifests/cp-a/000000000007.json"), Some(7));
        assert_eq!(key_seq("manifests/cp-a/junk"), None);
    }

    #[test]
    fn a_signer_must_be_the_writer() {
        assert_eq!(signer_problem("cp-a", "cp-a"), None);
        assert!(signer_problem("cp-b", "cp-a").is_some());
    }

    #[test]
    fn gzip_is_deterministic() {
        assert_eq!(gzip(b"same").expect("gz"), gzip(b"same").expect("gz"));
    }

    #[test]
    fn a_component_name_cannot_add_datadog_tags() {
        let sink = DatadogSink {
            http: reqwest::Client::new(),
            url: String::new(),
            api_key: Secret::new("k".into()),
            hostname: "cp-1".into(),
            environment: "test".into(),
        };
        let raw = br#"{"kind":"ssh.exec","user":"u","event_id":"e1","producer":{"component":"worker,env:prod,team:x","instance_id":"w","seq":1},"data":{}}"#;
        let entry = sink.log_entry(raw);
        let tags = entry["ddtags"].as_str().expect("tags");
        assert_eq!(tags.split(',').count(), 4, "{tags}");
        assert!(tags.contains("component:worker_env_prod_team_x"), "{tags}");
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

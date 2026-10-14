//! Verifying the S3 audit trail (ADR-0009): every writer's manifests must be
//! signed by a control plane, numbered without gaps, chained by hash, and
//! point at batch objects whose content matches. Any deleted, reordered, or
//! modified batch shows up as a problem.

use std::collections::BTreeMap;
use std::io::Read;

use base64::Engine as _;
use limen_proto::v1::Signed;
use limen_session::envelope::{Purpose, verify};
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};

use crate::sinks::{Manifest, SignedManifest};

#[derive(Debug, Default)]
pub struct Report {
    pub writers: usize,
    pub batches: usize,
    pub events: usize,
    pub problems: Vec<String>,
}

impl Report {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

async fn get(client: &aws_sdk_s3::Client, bucket: &str, key: &str) -> anyhow::Result<Vec<u8>> {
    let out = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{}", aws_sdk_s3::error::DisplayErrorContext(&e)))?;
    Ok(out.body.collect().await?.into_bytes().to_vec())
}

/// Check every manifest chain under `prefix`.
pub async fn verify_bucket(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    prefix: &str,
    internal_ca: &CertificateDer<'_>,
) -> anyhow::Result<Report> {
    let mut by_writer: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let manifests = format!("{prefix}manifests/");
    let mut pages = client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(&manifests)
        .into_paginator()
        .send();
    while let Some(page) = pages.next().await {
        let page =
            page.map_err(|e| anyhow::anyhow!("{}", aws_sdk_s3::error::DisplayErrorContext(&e)))?;
        for obj in page.contents() {
            if let Some(key) = obj.key()
                && let Some(writer) = key
                    .strip_prefix(&manifests)
                    .and_then(|r| r.split('/').next())
            {
                by_writer
                    .entry(writer.to_owned())
                    .or_default()
                    .push(key.to_owned());
            }
        }
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    let mut report = Report {
        writers: by_writer.len(),
        ..Report::default()
    };
    for (writer, mut keys) in by_writer {
        keys.sort();
        let mut prev_sha = String::new();
        for (expected_seq, key) in (0u64..).zip(keys) {
            let file = get(client, bucket, &key).await?;
            let problem = |what: String| format!("{writer} #{expected_seq} ({key}): {what}");
            let signed: SignedManifest = match serde_json::from_slice(&file) {
                Ok(s) => s,
                Err(e) => {
                    report
                        .problems
                        .push(problem(format!("unreadable manifest: {e}")));
                    break;
                }
            };
            let envelope = Signed {
                payload: signed.manifest.clone().into_bytes(),
                signature: b64.decode(&signed.signature).unwrap_or_default(),
                signer_cert_der: b64.decode(&signed.signer_cert).unwrap_or_default(),
            };
            if let Err(e) = verify(&envelope, Purpose::AuditManifest, internal_ca) {
                report.problems.push(problem(format!("signature: {e}")));
            }
            let manifest: Manifest = match serde_json::from_str(&signed.manifest) {
                Ok(m) => m,
                Err(e) => {
                    report
                        .problems
                        .push(problem(format!("unreadable manifest body: {e}")));
                    break;
                }
            };
            if manifest.seq != expected_seq {
                report.problems.push(problem(format!(
                    "sequence {} found where {expected_seq} was expected (a batch is missing)",
                    manifest.seq
                )));
            }
            if manifest.writer != writer {
                report.problems.push(problem(format!(
                    "manifest names writer {}",
                    manifest.writer
                )));
            }
            if manifest.prev_manifest_sha256 != prev_sha {
                report.problems.push(problem(
                    "chain broken: previous manifest hash doesn't match".into(),
                ));
            }
            match get(client, bucket, &manifest.object).await {
                Ok(object) => {
                    if hex(&Sha256::digest(&object)) == manifest.sha256 {
                        let mut text = String::new();
                        let lines = flate2::read::GzDecoder::new(&object[..])
                            .read_to_string(&mut text)
                            .map(|_| text.lines().count());
                        match lines {
                            Ok(n) if n == manifest.count => report.events += n,
                            Ok(n) => report.problems.push(problem(format!(
                                "batch has {n} events, manifest says {}",
                                manifest.count
                            ))),
                            Err(e) => report
                                .problems
                                .push(problem(format!("batch unreadable: {e}"))),
                        }
                    } else {
                        report.problems.push(problem(format!(
                            "batch {} was modified (hash mismatch)",
                            manifest.object
                        )));
                    }
                }
                Err(e) => report
                    .problems
                    .push(problem(format!("batch {} missing: {e}", manifest.object))),
            }
            prev_sha = hex(&Sha256::digest(&file));
            report.batches += 1;
        }
    }
    Ok(report)
}

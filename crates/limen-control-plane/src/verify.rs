//! Verifying the S3 audit trail (ADR-0009): every writer's manifests must be
//! signed by a control plane, numbered without gaps, chained by hash, and
//! point at batch objects whose content matches. Any deleted, reordered, or
//! modified batch shows up as a problem.
//!
//! It also checks the events themselves: every producer numbers its events
//! (`producer.seq`, from 0 per process start; a restart gets a new
//! `instance_id`), so a missing run of `seq` for one
//! `(component, instance_id)` is an event lost between the producer and S3.
//! Duplicates (at-least-once retries, handoff) are expected: they are counted
//! once and never hide or create a gap.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::Read;

use base64::Engine as _;
use limen_proto::v1::Signed;
use limen_session::envelope::{Purpose, verify};
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};

use crate::sinks::{Manifest, SignedManifest};

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub writers: usize,
    pub batches: usize,
    /// Lines in all verified batches, duplicates included.
    pub records: usize,
    /// Distinct events (by `event_id`).
    pub events: u64,
    /// Chain, signature, and batch problems.
    pub problems: Vec<String>,
    /// Missing runs of `seq` per producer, between the lowest and highest
    /// `seq` seen for it. Sorted by producer, then `seq`.
    pub seq_gaps: Vec<SeqGap>,
}

impl VerifyReport {
    /// Every chain verifies and no producer has a gap.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.chain_ok() && self.seq_gaps.is_empty()
    }

    /// Every batch is present, unmodified, signed, and chained.
    #[must_use]
    pub fn chain_ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Events `missing_from..=missing_to` of one producer never reached S3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeqGap {
    pub component: String,
    pub instance_id: String,
    pub missing_from: u64,
    pub missing_to: u64,
}

impl std::fmt::Display for SeqGap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.missing_to - self.missing_from + 1;
        write!(
            f,
            "{} {}: seq {}..={} missing ({n} event{})",
            self.component,
            self.instance_id,
            self.missing_from,
            self.missing_to,
            if n == 1 { "" } else { "s" }
        )
    }
}

/// The parts of an event the gap check needs.
#[derive(serde::Deserialize)]
struct EventSeq {
    event_id: uuid::Uuid,
    producer: limen_audit::Producer,
}

/// Distinct events and the `seq` values seen per producer.
#[derive(Default)]
struct Tally {
    ids: HashSet<uuid::Uuid>,
    seqs: BTreeMap<(String, String), BTreeSet<u64>>,
}

impl Tally {
    fn add(&mut self, line: &str) -> Result<(), serde_json::Error> {
        let e: EventSeq = serde_json::from_str(line)?;
        self.ids.insert(e.event_id);
        self.seqs
            .entry((e.producer.component, e.producer.instance_id))
            .or_default()
            .insert(e.producer.seq);
        Ok(())
    }

    fn gaps(&self) -> Vec<SeqGap> {
        let mut gaps = Vec::new();
        for ((component, instance_id), seqs) in &self.seqs {
            let mut prev: Option<u64> = None;
            for &seq in seqs {
                if let Some(p) = prev
                    && seq > p + 1
                {
                    gaps.push(SeqGap {
                        component: component.clone(),
                        instance_id: instance_id.clone(),
                        missing_from: p + 1,
                        missing_to: seq - 1,
                    });
                }
                prev = Some(seq);
            }
        }
        gaps
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
) -> anyhow::Result<VerifyReport> {
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
    let mut report = VerifyReport {
        writers: by_writer.len(),
        ..VerifyReport::default()
    };
    let mut tally = Tally::default();
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
                            Ok(n) if n == manifest.count => {
                                report.records += n;
                                for (i, line) in text.lines().enumerate() {
                                    if let Err(e) = tally.add(line) {
                                        report.problems.push(problem(format!(
                                            "line {} of {} is not an event: {e}",
                                            i + 1,
                                            manifest.object
                                        )));
                                    }
                                }
                            }
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
    report.events = tally.ids.len() as u64;
    report.seq_gaps = tally.gaps();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(instance: &str, seq: u64) -> String {
        let producer = limen_audit::Producer {
            component: "proxy".into(),
            instance_id: instance.into(),
            seq,
        };
        serde_json::to_string(&limen_audit::Event::new(
            limen_audit::EventKind::SshExec,
            producer,
            serde_json::Value::Null,
        ))
        .expect("json")
    }

    #[test]
    fn one_missing_seq_is_one_gap_and_duplicates_count_once() {
        let mut t = Tally::default();
        let two = line("p/a", 2);
        for l in [line("p/a", 1), two.clone(), two, line("p/a", 4)] {
            t.add(&l).expect("event");
        }
        assert_eq!(t.ids.len(), 3);
        assert_eq!(
            t.gaps(),
            vec![SeqGap {
                component: "proxy".into(),
                instance_id: "p/a".into(),
                missing_from: 3,
                missing_to: 3,
            }]
        );
    }

    #[test]
    fn a_restart_is_a_new_producer_not_a_gap() {
        let mut t = Tally::default();
        for l in [
            line("p/a", 0),
            line("p/a", 1),
            line("p/b", 0),
            line("p/b", 1),
        ] {
            t.add(&l).expect("event");
        }
        assert_eq!(t.gaps(), vec![]);
        assert!(t.add("not json").is_err());
    }
}

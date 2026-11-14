//! Verifying the S3 audit trail (ADR-0009): every writer's manifests must be
//! signed by a control plane, numbered without gaps, chained by hash, and
//! point at batch objects whose content matches. Any deleted, reordered, or
//! modified batch shows up as a problem.
//!
//! It also checks the events themselves: every producer numbers its events
//! (`producer.seq`, from 0 per process start; a restart gets a new
//! `instance_id`), so a missing run of `seq` for one
//! `(component, instance_id)`, including a missing head (lowest `seq` above
//! 0), means an event was not recorded or not shipped. Not recorded
//! includes an emit that failed under the `fail_closed` audit mode: it uses
//! up its `seq` and the action it audited was refused. Lost events after a
//! producer's highest `seq` can't be seen. Duplicates (at-least-once
//! retries, handoff) are expected: they are counted once and never hide or
//! create a gap. One `seq` carried by two different `event_id`s is reported
//! as a conflict: a producer never does that.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use std::io::Read;
use uuid::Uuid;

use base64::Engine as _;
use limen_proto::v1::Signed;
use limen_session::envelope::{Purpose, verify_at};
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};

use crate::manifest::{Manifest, SignedManifest};

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
    /// Missing runs of `seq` per producer, from 0 to the highest `seq`
    /// seen for it. Sorted by producer, then `seq`.
    pub seq_gaps: Vec<SeqGap>,
    /// `seq` values that two or more different events carry.
    pub seq_conflicts: Vec<SeqConflict>,
}

impl VerifyReport {
    /// Every chain verifies, and no producer has a gap or a conflict.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.chain_ok() && self.seq_gaps.is_empty() && self.seq_conflicts.is_empty()
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

/// Several different events of one producer carry the same `seq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeqConflict {
    pub component: String,
    pub instance_id: String,
    pub seq: u64,
    pub event_ids: Vec<Uuid>,
}

impl std::fmt::Display for SeqConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ids: Vec<String> = self.event_ids.iter().map(Uuid::to_string).collect();
        write!(
            f,
            "{} {}: seq {} is used by {} different events ({})",
            self.component,
            self.instance_id,
            self.seq,
            ids.len(),
            ids.join(", ")
        )
    }
}

/// The parts of an event the gap check needs.
#[derive(serde::Deserialize)]
struct EventSeq {
    event_id: Uuid,
    producer: Producer,
}

/// Who numbered an event: `seq` counts from 0 for each `(component, instance_id)`.
#[derive(serde::Deserialize)]
struct Producer {
    component: String,
    instance_id: String,
    seq: u64,
}

/// Distinct events, and the events seen per producer and `seq`.
#[derive(Default)]
struct Tally {
    ids: HashSet<Uuid>,
    seqs: BTreeMap<(String, String), BTreeMap<u64, BTreeSet<Uuid>>>,
}

impl Tally {
    fn add(&mut self, line: &str) -> Result<(), serde_json::Error> {
        let e: EventSeq = serde_json::from_str(line)?;
        self.ids.insert(e.event_id);
        self.seqs
            .entry((e.producer.component, e.producer.instance_id))
            .or_default()
            .entry(e.producer.seq)
            .or_default()
            .insert(e.event_id);
        Ok(())
    }

    fn gaps(&self) -> Vec<SeqGap> {
        let mut gaps = Vec::new();
        for ((component, instance_id), seqs) in &self.seqs {
            // Every instance starts at 0: anything below the lowest is lost.
            let mut next = 0;
            for &seq in seqs.keys() {
                if seq > next {
                    gaps.push(SeqGap {
                        component: component.clone(),
                        instance_id: instance_id.clone(),
                        missing_from: next,
                        missing_to: seq - 1,
                    });
                }
                // `seq` comes from the bucket, so it may be anything.
                next = seq.saturating_add(1);
            }
        }
        gaps
    }

    fn conflicts(&self) -> Vec<SeqConflict> {
        let mut out = Vec::new();
        for ((component, instance_id), seqs) in &self.seqs {
            for (&seq, ids) in seqs {
                if ids.len() > 1 {
                    out.push(SeqConflict {
                        component: component.clone(),
                        instance_id: instance_id.clone(),
                        seq,
                        event_ids: ids.iter().copied().collect(),
                    });
                }
            }
        }
        out
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
            let manifest: Manifest = match serde_json::from_str(&signed.manifest) {
                Ok(m) => m,
                Err(e) => {
                    report
                        .problems
                        .push(problem(format!("unreadable manifest body: {e}")));
                    break;
                }
            };
            // The signer's certificate lives about a day, so it is judged as of
            // the time the manifest records, not now. (A key stolen from an
            // expired certificate could backdate a manifest, but not make it
            // fit the chain: the previous manifest's hash is checked below.)
            let sealed_by = match time::OffsetDateTime::parse(
                &manifest.created_at,
                &time::format_description::well_known::Rfc3339,
            ) {
                Ok(at) => match verify_at(&envelope, Purpose::AuditManifest, internal_ca, at) {
                    Ok((by, _)) => Some(by),
                    Err(e) => {
                        report.problems.push(problem(format!("signature: {e}")));
                        None
                    }
                },
                Err(e) => {
                    report
                        .problems
                        .push(problem(format!("unreadable manifest time: {e}")));
                    None
                }
            };
            if manifest.seq != expected_seq {
                report.problems.push(problem(format!(
                    "sequence {} found where {expected_seq} was expected (a batch is missing)",
                    manifest.seq
                )));
            }
            // The signer is the writer's own control-plane certificate: another
            // component's valid signature doesn't make a manifest this writer's.
            if let Some(by) = &sealed_by
                && let Some(why) = crate::manifest::signer_problem(&by.id, &manifest.writer)
            {
                report.problems.push(problem(why));
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
    report.seq_conflicts = tally.conflicts();
    Ok(report)
}

/// What a check of the newest manifests found.
#[derive(Debug, Default)]
pub struct TailReport {
    pub writers: usize,
    /// Manifests whose signature, signer, sequence and chain link were read.
    pub manifests: usize,
    pub problems: Vec<String>,
}

impl TailReport {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Most problems a tail check reports before it stops describing them.
const MAX_TAIL_PROBLEMS: usize = 20;

/// Check the newest `last` manifests of every writer under `prefix`, and the
/// one before them as the anchor of the chain: each is signed by its own
/// control plane, numbered without a gap, and names the hash of the file
/// before it.
///
/// This reads **manifests only**. It never fetches a batch, so it can run
/// with the control plane's own write role (ADR-0053). It lists every manifest
/// key to find each writer's newest, so it grows with the number of manifests;
/// the reads are bounded to `last + 1` per writer. It therefore can't see a modified batch or a
/// gap in the events' own numbering; [`verify_bucket`] does, with read access
/// to the batches.
///
/// # Errors
/// If the bucket can't be listed or a manifest can't be read.
pub async fn verify_manifest_tail(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    prefix: &str,
    internal_ca: &CertificateDer<'_>,
    last: usize,
) -> anyhow::Result<TailReport> {
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
    let mut report = TailReport {
        writers: by_writer.len(),
        ..TailReport::default()
    };
    for (writer, mut keys) in by_writer {
        keys.sort();
        // One more than asked for: the oldest only anchors the chain.
        let start = keys.len().saturating_sub(last.saturating_add(1));
        let mut prev: Option<(u64, String)> = None;
        for (i, key) in keys.iter().enumerate().skip(start) {
            let problem = |what: String| format!("{writer} #{i} ({key}): {what}");
            let mut add = |what: String| {
                if report.problems.len() < MAX_TAIL_PROBLEMS {
                    report.problems.push(what);
                }
            };
            let file = get(client, bucket, key).await?;
            let file_sha = hex(&Sha256::digest(&file));
            let this = (|| -> Result<Manifest, String> {
                let signed: SignedManifest = serde_json::from_slice(&file)
                    .map_err(|e| format!("unreadable manifest: {e}"))?;
                let manifest: Manifest = serde_json::from_str(&signed.manifest)
                    .map_err(|e| format!("unreadable manifest body: {e}"))?;
                let envelope = Signed {
                    payload: signed.manifest.clone().into_bytes(),
                    signature: b64.decode(&signed.signature).unwrap_or_default(),
                    signer_cert_der: b64.decode(&signed.signer_cert).unwrap_or_default(),
                };
                let at = time::OffsetDateTime::parse(
                    &manifest.created_at,
                    &time::format_description::well_known::Rfc3339,
                )
                .map_err(|e| format!("unreadable manifest time: {e}"))?;
                let (by, _) = verify_at(&envelope, Purpose::AuditManifest, internal_ca, at)
                    .map_err(|e| format!("signature: {e}"))?;
                if let Some(why) = crate::manifest::signer_problem(&by.id, &manifest.writer) {
                    return Err(why);
                }
                Ok(manifest)
            })();
            let manifest = match this {
                Ok(m) => m,
                Err(e) => {
                    add(problem(e));
                    break;
                }
            };
            report.manifests += 1;
            if manifest.writer != writer {
                add(problem(format!(
                    "manifest names writer {}",
                    manifest.writer
                )));
            }
            // Keys are `<seq:012>.json` and the full check numbers manifests
            // by their place in the list: a manifest must sit at its own seq.
            if usize::try_from(manifest.seq).ok() != Some(i) {
                add(problem(format!(
                    "sequence {} found where {i} was expected (a batch is missing)",
                    manifest.seq
                )));
            }
            match &prev {
                Some((_, prev_sha)) => {
                    if manifest.prev_manifest_sha256 != *prev_sha {
                        add(problem(
                            "chain broken: previous manifest hash doesn't match".into(),
                        ));
                    }
                }
                // The very first manifest of a writer names no predecessor.
                None if i == 0 && !manifest.prev_manifest_sha256.is_empty() => {
                    add(problem("the first manifest names a predecessor".into()));
                }
                None => {}
            }
            prev = Some((manifest.seq, file_sha));
        }
    }
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
        for l in [
            line("p/a", 0),
            line("p/a", 1),
            two.clone(),
            two,
            line("p/a", 4),
        ] {
            t.add(&l).expect("event");
        }
        assert_eq!(t.ids.len(), 4);
        assert_eq!(t.conflicts(), vec![]);
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

    /// `seq` starts at 0 for every instance, so a missing head is a gap too.
    #[test]
    fn a_lost_head_is_a_gap_from_zero() {
        let mut t = Tally::default();
        for l in [line("p/a", 3), line("p/a", 4)] {
            t.add(&l).expect("event");
        }
        assert_eq!(
            t.gaps(),
            vec![SeqGap {
                component: "proxy".into(),
                instance_id: "p/a".into(),
                missing_from: 0,
                missing_to: 2,
            }]
        );
    }

    /// `seq` is read from the bucket, so a tampered or corrupt line can say
    /// anything, `u64::MAX` included: that is a gap, never a panic.
    #[test]
    fn the_largest_seq_is_a_gap_not_an_overflow() {
        let mut t = Tally::default();
        for l in [line("p/a", 0), line("p/a", u64::MAX)] {
            t.add(&l).expect("event");
        }
        assert_eq!(
            t.gaps(),
            vec![SeqGap {
                component: "proxy".into(),
                instance_id: "p/a".into(),
                missing_from: 1,
                missing_to: u64::MAX - 1,
            }]
        );
    }

    /// One producer can't give one `seq` to two events.
    #[test]
    fn a_seq_used_by_two_events_is_a_conflict() {
        let mut t = Tally::default();
        let (a, b) = (line("p/a", 0), line("p/a", 0));
        for l in [&a, &b, &a] {
            t.add(l).expect("event");
        }
        let conflicts = t.conflicts();
        assert_eq!(conflicts.len(), 1, "{conflicts:?}");
        assert_eq!((conflicts[0].seq, conflicts[0].event_ids.len()), (0, 2));
        assert_eq!(t.gaps(), vec![]);
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

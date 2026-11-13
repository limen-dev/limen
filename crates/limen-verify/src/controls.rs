//! The controls report (ADR-0053): what the scheduled self-test found, in the
//! same signed envelope as an evidence pack (`pack.rs`), under its own format
//! string and signature label.
//!
//! The control plane builds a report with [`Prepared`], and anyone checks one
//! offline with [`verify_report`] and the internal CA certificate. A report is
//! the control plane attesting to itself: it proves a control plane the CA
//! issued produced exactly these results, not that the checks were honest.
//! The signed `attestation` says so.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use limen_session::envelope::{EnvelopeSigner, Purpose};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::pack::{FileEntry, Manifest, Verification, sha, verify_signed};

pub const FORMAT: &str = "limen-controls/1";

/// Printed in every report, inside the signature.
/// The file name a downloaded report gets: `limen-controls-report-20261113T191502Z.json`.
/// The time is when the run started, in UTC, with no colons so every filesystem takes it, and it
/// sorts in the order the runs happened. The console and the CLI both use it.
#[must_use]
pub fn report_file_name(started_at_unix: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(started_at_unix) {
        Ok(t) => format!(
            "limen-controls-report-{:04}{:02}{:02}T{:02}{:02}{:02}Z.json",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        ),
        Err(_) => "limen-controls-report.json".to_owned(),
    }
}

pub const ATTESTATION: &str = "This report is the control plane attesting to itself. The signature shows that a control plane the internal CA issued produced exactly these results; it does not show that the checks ran honestly, and it does not replace verifying the audit trail offline with `limen audit verify`.";

/// Checks whose conditions are always met, so a report in which one was
/// skipped is not a report of a working self-test.
pub const NEVER_SKIPPED: &[&str] = &[
    "policy.engine",
    "cert.expired_refused",
    "cert.foreign_ca_refused",
    "lock.refused",
    "audit.sinks",
];

/// Most checks a report holds; a bound for the verifier, not a target.
const MAX_CHECKS: usize = 256;

/// How one check ended. A skipped check is not a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Passed,
    Failed,
    Skipped,
}

impl Status {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Passed => "passed",
            Status::Failed => "failed",
            Status::Skipped => "skipped",
        }
    }
}

/// One check's result. `id` and `title` name the path that was exercised;
/// `detail` says why it failed or was skipped, and holds no secret, no user
/// content, and only ids of the things it looked at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub title: String,
    pub status: Status,
    pub detail: String,
    pub duration_ms: u64,
}

/// Facts about the run, signed with the results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub run_id: String,
    /// `schedule` or `manual`.
    pub trigger: String,
    pub started_at: i64,
    pub finished_at: i64,
    pub control_plane: String,
    pub policy_version: i64,
    pub policy_digest: String,
    pub build: String,
    pub interval_secs: u64,
    /// Every check this run was meant to include. A check missing from
    /// `checks` but named here shows.
    pub expected_checks: Vec<String>,
    pub attestation: String,
}

/// A whole run: the facts and the results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    pub meta: Meta,
    pub checks: Vec<CheckResult>,
}

/// How many checks ended each way.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
}

impl Counts {
    #[must_use]
    pub fn of(checks: &[CheckResult]) -> Self {
        let mut c = Self::default();
        for check in checks {
            match check.status {
                Status::Passed => c.passed += 1,
                Status::Failed => c.failed += 1,
                Status::Skipped => c.skipped += 1,
            }
        }
        c
    }

    /// `passed` when nothing failed, `failed` otherwise. Skipped checks don't
    /// fail a run, and the counts say how many there were.
    #[must_use]
    pub fn verdict(self) -> &'static str {
        if self.failed == 0 { "passed" } else { "failed" }
    }
}

/// A report ready to sign. Its manifest hash is known before the signature,
/// so the control plane can anchor it in the audit trail first ("no event,
/// no report").
#[derive(Debug)]
pub struct Prepared {
    sections: BTreeMap<String, Value>,
    manifest_json: String,
    pub manifest_sha256: String,
}

impl Prepared {
    /// # Errors
    /// If the run can't be encoded.
    pub fn new(run: &Run, requested_by: &str) -> Result<Self, serde_json::Error> {
        let mut sections = BTreeMap::new();
        sections.insert("checks".to_owned(), serde_json::to_value(&run.checks)?);
        sections.insert("meta".to_owned(), serde_json::to_value(&run.meta)?);
        let mut files = BTreeMap::new();
        for (name, v) in &sections {
            let bytes = serde_json::to_vec(v)?;
            files.insert(
                name.clone(),
                FileEntry {
                    sha256: sha(&bytes),
                    bytes: bytes.len(),
                },
            );
        }
        let manifest = Manifest {
            format: FORMAT.to_owned(),
            generated_at: run.meta.finished_at,
            from: run.meta.started_at,
            to: run.meta.finished_at,
            requested_by: requested_by.to_owned(),
            control_plane: run.meta.control_plane.clone(),
            files,
        };
        let manifest_json = serde_json::to_string(&manifest)?;
        Ok(Self {
            sections,
            manifest_sha256: sha(manifest_json.as_bytes()),
            manifest_json,
        })
    }

    /// Sign the manifest and return the report's bytes.
    ///
    /// # Errors
    /// If signing or encoding fails.
    pub fn sign(self, key: &EnvelopeSigner) -> anyhow::Result<Vec<u8>> {
        let signed = key.sign(
            Purpose::ControlsReport,
            self.manifest_json.clone().into_bytes(),
        )?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let doc = json!({
            "format": FORMAT,
            "manifest_json": self.manifest_json,
            "manifest_sha256": self.manifest_sha256,
            "signature_b64": b64.encode(&signed.signature),
            "signer_cert_b64": b64.encode(&signed.signer_cert_der),
            "sections": self.sections,
        });
        Ok(serde_json::to_vec_pretty(&doc)?)
    }
}

/// What checking a report found.
#[derive(Debug, Default)]
pub struct Verified {
    pub verification: Verification,
    pub run: Option<Run>,
}

impl Verified {
    /// The report is intact. Says nothing about whether the checks passed.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.verification.ok() && self.run.is_some()
    }

    #[must_use]
    pub fn problems(&self) -> &[String] {
        &self.verification.problems
    }
}

/// Check a controls report offline: signed by a control plane the internal CA
/// issued under the controls-report label, every section as signed, and the
/// results complete (every expected check present once, nothing unlisted).
#[must_use]
pub fn verify_report(
    report: &[u8],
    internal_ca: &rustls_pki_types::CertificateDer<'_>,
) -> Verified {
    let mut out = Verified {
        verification: verify_signed(report, internal_ca, FORMAT, Purpose::ControlsReport),
        run: None,
    };
    if out.verification.manifest.is_none() {
        return out;
    }
    let Ok(doc) = serde_json::from_slice::<Value>(report) else {
        return out;
    };
    let section = |name: &str| doc["sections"].get(name).cloned();
    let (Some(checks), Some(meta)) = (section("checks"), section("meta")) else {
        out.verification
            .problems
            .push("the report has no checks or no meta section".into());
        return out;
    };
    let (Ok(checks), Ok(meta)) = (
        serde_json::from_value::<Vec<CheckResult>>(checks),
        serde_json::from_value::<Meta>(meta),
    ) else {
        out.verification
            .problems
            .push("the checks or meta section is unreadable".into());
        return out;
    };
    let problems = &mut out.verification.problems;
    if checks.is_empty() || checks.len() > MAX_CHECKS {
        problems.push(format!("a report holds 1 to {MAX_CHECKS} checks"));
    }
    if meta.attestation.is_empty() {
        problems.push("the report doesn't say it is a self-attestation".into());
    }
    let mut seen = BTreeSet::new();
    for c in &checks {
        if !seen.insert(c.id.as_str()) {
            problems.push(format!("check {} appears twice", c.id));
        }
    }
    // Checks every report must carry, whatever it says it expected.
    for id in NEVER_SKIPPED {
        if !seen.contains(id) {
            problems.push(format!("check {id} is required and absent"));
        }
    }
    // Checks that have no reason to be skipped: a report that skips one
    // didn't test what it claims to (ADR-0053).
    for c in &checks {
        if c.status == Status::Skipped && NEVER_SKIPPED.contains(&c.id.as_str()) {
            problems.push(format!("check {} was skipped but is never skippable", c.id));
        }
    }
    let expected: BTreeSet<&str> = meta.expected_checks.iter().map(String::as_str).collect();
    for id in expected.difference(&seen) {
        problems.push(format!("check {id} was expected but is missing"));
    }
    for id in seen.difference(&expected) {
        problems.push(format!("check {id} is present but was not expected"));
    }
    // The manifest's own facts are what the section says they are.
    if let Some(m) = &out.verification.manifest
        && (m.control_plane != meta.control_plane
            || m.from != meta.started_at
            || m.to != meta.finished_at
            || m.generated_at != meta.finished_at)
    {
        out.verification
            .problems
            .push("the manifest and the meta section disagree".into());
    }
    out.run = Some(Run { meta, checks });
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // assertions on JSON built in the test
mod tests {
    #[test]
    fn a_downloaded_report_is_named_for_when_its_run_started() {
        // 2026-11-13 19:15:02 UTC.
        assert_eq!(
            report_file_name(1_794_597_302),
            "limen-controls-report-20261113T191502Z.json"
        );
        // Earlier names sort first, and nothing in a name needs escaping.
        assert!(report_file_name(1_000_000_000) < report_file_name(1_794_597_302));
        assert!(
            report_file_name(1_794_597_302)
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        );
    }

    use std::sync::Arc;

    use limen_ca::{CaPurpose, CertificateAuthority, ComponentCertRequest, FileSigner};
    use limen_core::identity::ComponentKind;
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
    use rustls_pki_types::CertificateDer;

    use super::*;

    async fn signer() -> (EnvelopeSigner, Vec<u8>) {
        let ca = CertificateAuthority::create_self_signed(
            CaPurpose::Internal,
            Arc::new(FileSigner::generate().expect("key")),
        )
        .await
        .expect("ca");
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let csr = CertificateParams::default()
            .serialize_request(&key)
            .expect("csr");
        let cert = ca
            .issue_component(ComponentCertRequest {
                csr_der: csr.der().to_vec(),
                kind: ComponentKind::ControlPlane,
                id: "cp-1".into(),
                dns_names: vec![],
                labels: BTreeMap::new(),
                ttl: std::time::Duration::from_secs(3600),
            })
            .await
            .expect("issue");
        (
            EnvelopeSigner::new(&key.serialize_pem(), cert.der.to_vec()).expect("signer"),
            ca.cert_der().to_vec(),
        )
    }

    fn check(id: &str, status: Status) -> CheckResult {
        CheckResult {
            id: id.into(),
            title: format!("check {id}"),
            status,
            detail: String::new(),
            duration_ms: 3,
        }
    }

    fn run() -> Run {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        Run {
            meta: Meta {
                run_id: "r1".into(),
                trigger: "schedule".into(),
                started_at: now - 2,
                finished_at: now,
                control_plane: "cp-1".into(),
                policy_version: 7,
                policy_digest: "abc".into(),
                build: "test".into(),
                interval_secs: 86_400,
                expected_checks: ["a", "b", "c"]
                    .iter()
                    .chain(NEVER_SKIPPED)
                    .map(|id| (*id).to_owned())
                    .collect(),
                attestation: ATTESTATION.into(),
            },
            // The checks every report must carry passed; a, b and c vary.
            checks: [
                check("a", Status::Passed),
                check("b", Status::Failed),
                check("c", Status::Skipped),
            ]
            .into_iter()
            .chain(NEVER_SKIPPED.iter().map(|id| check(id, Status::Passed)))
            .collect(),
        }
    }

    async fn sealed() -> (Vec<u8>, Vec<u8>) {
        let (signer, ca) = signer().await;
        let bytes = Prepared::new(&run(), "admin@example.com")
            .unwrap()
            .sign(&signer)
            .unwrap();
        (bytes, ca)
    }

    fn problems(bytes: &[u8], ca: &[u8]) -> Vec<String> {
        verify_report(bytes, &CertificateDer::from(ca.to_vec()))
            .problems()
            .to_vec()
    }

    fn broken(bytes: &[u8], ca: &[u8]) -> bool {
        !verify_report(bytes, &CertificateDer::from(ca.to_vec())).ok()
    }

    fn edit(bytes: &[u8], f: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut v: Value = serde_json::from_slice(bytes).unwrap();
        f(&mut v);
        serde_json::to_vec(&v).unwrap()
    }

    #[tokio::test]
    async fn a_report_round_trips_and_keeps_its_skipped_and_failed_checks() {
        let (bytes, ca) = sealed().await;
        let v = verify_report(&bytes, &CertificateDer::from(ca));
        assert!(v.ok(), "{:?}", v.problems());
        let run = v.run.unwrap();
        let counts = Counts::of(&run.checks);
        assert_eq!(
            counts,
            Counts {
                passed: 1 + u32::try_from(NEVER_SKIPPED.len()).unwrap(),
                failed: 1,
                skipped: 1
            }
        );
        assert_eq!(counts.verdict(), "failed");
        assert!(run.meta.attestation.contains("attesting to itself"));
    }

    #[tokio::test]
    async fn the_manifest_hash_is_known_before_signing() {
        let (signer, ca) = signer().await;
        let prepared = Prepared::new(&run(), "x").unwrap();
        let hash = prepared.manifest_sha256.clone();
        let bytes = prepared.sign(&signer).unwrap();
        let v = verify_report(&bytes, &CertificateDer::from(ca));
        assert_eq!(v.verification.manifest_sha256, hash);
    }

    /// Every signed manifest field, changed alone, breaks the report.
    #[tokio::test]
    async fn changing_any_manifest_field_is_caught() {
        let (bytes, ca) = sealed().await;
        for field in [
            "format",
            "generated_at",
            "from",
            "to",
            "requested_by",
            "control_plane",
            "files",
        ] {
            let tampered = edit(&bytes, |v| {
                let m: String = v["manifest_json"].as_str().unwrap().to_owned();
                let mut manifest: Value = serde_json::from_str(&m).unwrap();
                manifest[field] = match field {
                    "files" => json!({}),
                    "generated_at" | "from" | "to" => json!(1),
                    _ => json!("changed"),
                };
                v["manifest_json"] = json!(serde_json::to_string(&manifest).unwrap());
            });
            assert!(
                !problems(&tampered, &ca).is_empty(),
                "{field} went unnoticed"
            );
        }
    }

    /// Every section, changed alone, breaks the report, and a section can
    /// be neither added nor removed.
    #[tokio::test]
    async fn changing_adding_or_dropping_a_section_is_caught() {
        let (bytes, ca) = sealed().await;
        let flipped = edit(&bytes, |v| {
            v["sections"]["checks"][1]["status"] = json!("passed");
        });
        assert!(
            problems(&flipped, &ca)
                .iter()
                .any(|p| p.contains("section checks was changed"))
        );
        let meta = edit(&bytes, |v| {
            v["sections"]["meta"]["policy_digest"] = json!("x");
        });
        assert!(
            problems(&meta, &ca)
                .iter()
                .any(|p| p.contains("section meta was changed"))
        );
        let extra = edit(&bytes, |v| v["sections"]["extra"] = json!([]));
        assert!(
            problems(&extra, &ca)
                .iter()
                .any(|p| p.contains("not in the signed manifest"))
        );
        let dropped = edit(&bytes, |v| {
            v["sections"].as_object_mut().unwrap().remove("checks");
        });
        assert!(broken(&dropped, &ca));
    }

    #[tokio::test]
    async fn the_signature_and_signer_are_checked() {
        let (bytes, ca) = sealed().await;
        let no_sig = edit(&bytes, |v| v["signature_b64"] = json!(""));
        assert!(broken(&no_sig, &ca));
        let (_, other_ca) = signer().await;
        assert!(
            broken(&bytes, &other_ca),
            "a report from another CA's control plane must not verify"
        );
    }

    /// A signature is good for one purpose.
    #[tokio::test]
    async fn an_evidence_pack_is_not_a_report_and_the_reverse() {
        let (signer, ca) = signer().await;
        let run = run();
        let prepared = Prepared::new(&run, "x").unwrap();
        let manifest_json = prepared.manifest_json.clone();
        // The same manifest, signed as an evidence pack, relabelled as a report.
        let as_pack = signer
            .sign(Purpose::EvidencePack, manifest_json.clone().into_bytes())
            .unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        let forged = json!({
            "format": FORMAT,
            "manifest_json": manifest_json,
            "manifest_sha256": prepared.manifest_sha256,
            "signature_b64": b64.encode(&as_pack.signature),
            "signer_cert_b64": b64.encode(&as_pack.signer_cert_der),
            "sections": prepared.sections,
        });
        let forged = serde_json::to_vec(&forged).unwrap();
        assert!(
            problems(&forged, &ca)
                .iter()
                .any(|p| p.contains("signature is not valid")),
            "{:?}",
            problems(&forged, &ca)
        );
        // And a real report is no evidence pack.
        let real = prepared.sign(&signer).unwrap();
        let pack = crate::pack::verify_pack(&real, &CertificateDer::from(ca));
        assert!(!pack.ok());
    }

    #[tokio::test]
    async fn a_dropped_or_extra_check_is_visible_even_when_the_sections_are_signed() {
        let (signer, ca) = signer().await;
        let mut dropped = run();
        dropped.checks.retain(|c| c.id != "b");
        let bytes = Prepared::new(&dropped, "x").unwrap().sign(&signer).unwrap();
        assert!(
            problems(&bytes, &ca)
                .iter()
                .any(|p| p.contains("check b was expected but is missing"))
        );

        let mut extra = run();
        extra.checks.push(check("zz", Status::Passed));
        let bytes = Prepared::new(&extra, "x").unwrap().sign(&signer).unwrap();
        assert!(
            problems(&bytes, &ca)
                .iter()
                .any(|p| p.contains("zz is present but was not expected"))
        );

        let mut twice = run();
        twice.checks.push(check("a", Status::Passed));
        let bytes = Prepared::new(&twice, "x").unwrap().sign(&signer).unwrap();
        assert!(
            problems(&bytes, &ca)
                .iter()
                .any(|p| p.contains("appears twice"))
        );
    }

    #[tokio::test]
    async fn a_check_that_may_never_be_skipped_is_a_problem_when_it_is() {
        let (signer, ca) = signer().await;
        let mut r = run();
        for c in &mut r.checks {
            if c.id == "lock.refused" {
                c.status = Status::Skipped;
            }
        }
        let bytes = Prepared::new(&r, "x").unwrap().sign(&signer).unwrap();
        assert!(
            problems(&bytes, &ca)
                .iter()
                .any(|p| p.contains("never skippable"))
        );
    }

    #[tokio::test]
    async fn a_report_must_say_it_is_a_self_attestation() {
        let (signer, ca) = signer().await;
        let mut r = run();
        r.meta.attestation.clear();
        let bytes = Prepared::new(&r, "x").unwrap().sign(&signer).unwrap();
        assert!(
            problems(&bytes, &ca)
                .iter()
                .any(|p| p.contains("self-attestation"))
        );
    }

    #[tokio::test]
    async fn junk_is_not_a_report() {
        let ca = CertificateDer::from(vec![0u8]);
        for junk in [
            &b"not json"[..],
            b"{}",
            b"{\"format\":\"limen-controls/1\"}",
        ] {
            assert!(!verify_report(junk, &ca).ok());
        }
    }
}

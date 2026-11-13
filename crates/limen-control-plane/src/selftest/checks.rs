//! The checks of the scheduled self-test (ADR-0053).
//!
//! Every check names the path it exercised and claims nothing wider. None of
//! them mints a credential for a real identity, writes a row that outlives
//! the check, or touches a real resource: certificate probes use throwaway
//! in-memory CAs, the lock probe runs in a transaction that is always rolled
//! back, and policy probes only evaluate.

use std::sync::Arc;
use std::time::{Duration, Instant};

use limen_ca::{CaPurpose, CertificateAuthority, FileSigner, UserCertRequest};
use limen_policy::{AccessRequest, Decision, DenyReason, Policy, Principal};
use limen_verify::controls::{CheckResult, Status};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use sqlx::Row as _;
use time::OffsetDateTime;

use crate::state::AppState;

/// A check and what it is called in a report. The order is the report's.
pub const CHECKS: &[(&str, &str)] = &[
    ("policy.declared_tests", "Your policy tests pass"),
    (
        "policy.engine",
        "The policy engine denies by default and lets a deny win",
    ),
    ("cert.expired_refused", "Expired certificates are refused"),
    (
        "cert.foreign_ca_refused",
        "Certificates from another CA are refused",
    ),
    (
        "lock.refused",
        "Locked accounts and ended logins are refused",
    ),
    ("audit.sinks", "Audit events are being shipped"),
    (
        "audit.manifest_tail",
        "Recent audit manifests are signed and in order",
    ),
    ("recording.integrity", "Session recordings are unchanged"),
];

/// Longest any one check may run.
const CHECK_TIMEOUT: Duration = Duration::from_secs(90);
/// Manifests per writer the tail check reads (and one more as the anchor).
const MANIFEST_TAIL: usize = 20;
/// Recordings re-hashed per run, and the most bytes read for them.
const RECORDING_SAMPLE: i64 = 5;
const RECORDING_BUDGET: usize = 128 * 1024 * 1024;
/// A sink with a backlog must have accepted a batch this recently.
const SINK_STALE_SECS: i64 = 15 * 60;

/// What one check found: its status and one line of detail.
type Verdict = (Status, String);

fn pass(detail: impl Into<String>) -> Verdict {
    (Status::Passed, detail.into())
}
fn fail(detail: impl Into<String>) -> Verdict {
    (Status::Failed, detail.into())
}
fn skip(detail: impl Into<String>) -> Verdict {
    (Status::Skipped, detail.into())
}

fn plural(n: usize, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 { one } else { many }
}

/// Keep a detail to one short line: it is free text from a policy author or
/// an error, and goes into a signed report and a log.
fn tidy(text: &str) -> String {
    let one_line: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    one_line.chars().take(300).collect()
}

/// Run every check, in the report's order. A check that panics or runs past
/// its timeout is a failed check, never a missing one.
pub async fn run_all(state: &AppState) -> Vec<CheckResult> {
    let mut out = Vec::with_capacity(CHECKS.len());
    for (id, title) in CHECKS {
        let started = Instant::now();
        // Its own task, so a panic is a failed check and not a lost run.
        let task = {
            let state = state.clone();
            let id = (*id).to_owned();
            tokio::spawn(async move { run_one(&state, &id).await })
        };
        let abort = task.abort_handle();
        let (status, detail) = match tokio::time::timeout(CHECK_TIMEOUT, task).await {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => fail("the check stopped unexpectedly"),
            Err(_) => {
                abort.abort();
                fail(format!(
                    "did not finish within {}s",
                    CHECK_TIMEOUT.as_secs()
                ))
            }
        };
        out.push(CheckResult {
            id: (*id).to_owned(),
            title: (*title).to_owned(),
            status,
            detail: tidy(&detail),
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        });
    }
    out
}

async fn run_one(state: &AppState, id: &str) -> Verdict {
    match id {
        "policy.declared_tests" => declared_tests(state),
        "policy.engine" => engine(),
        "cert.expired_refused" => cert_expired_refused().await,
        "cert.foreign_ca_refused" => cert_foreign_ca_refused().await,
        "lock.refused" => lock_refused(state).await,
        "audit.sinks" => audit_sinks(state).await,
        "audit.manifest_tail" => manifest_tail(state).await,
        "recording.integrity" => recording_integrity(state).await,
        other => fail(format!("no such check: {other}")),
    }
}

// ---- policy ----

/// The operator's own `policy_test` documents, against the policy in force
/// now: applied policy plus accepted discovered resources, which apply-time
/// tests never see.
fn declared_tests(state: &AppState) -> Verdict {
    let loaded = state.policy.current();
    let report = loaded.policy.run_tests();
    if report.results.is_empty() {
        return skip("No policy tests are defined, so nothing was checked.");
    }
    let total = report.results.len();
    let failed: Vec<&str> = report
        .results
        .iter()
        .filter(|r| !r.passed)
        .map(|r| r.name.as_str())
        .collect();
    if failed.is_empty() {
        pass(format!(
            "{total} policy {} passed (policy version {}).",
            plural(total, "test", "tests"),
            loaded.version
        ))
    } else {
        let names: Vec<String> = failed.iter().take(3).map(|n| tidy(n)).collect();
        fail(format!(
            "{} of {total} policy tests failed: {}.",
            failed.len(),
            names.join("; ")
        ))
    }
}

const ENGINE_POLICY: &str = r"
kind: role
version: v1
metadata: { name: probe-reader }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [staging, prod] } }
      ssh: { logins: [probe] }
  deny:
    - resources: { kind: [ssh], labels: { tier: [bastion] } }
---
kind: role
version: v1
metadata: { name: probe-requestable }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [probe] }
  request:
    who: [probe-people]
    approvers: [probe-approvers]
    approvals_required: 1
    max_duration: 1h
---
kind: resource
version: v1
metadata: { name: probe-staging, labels: { env: staging } }
spec: { ssh: { address: 'probe-staging:22' }, worker_selector: { pool: probe } }
---
kind: resource
version: v1
metadata: { name: probe-prod, labels: { env: prod } }
spec: { ssh: { address: 'probe-prod:22' }, worker_selector: { pool: probe } }
---
kind: resource
version: v1
metadata: { name: probe-bastion, labels: { env: staging, tier: bastion } }
spec: { ssh: { address: 'probe-bastion:22' }, worker_selector: { pool: probe } }
---
kind: resource
version: v1
metadata: { name: probe-dev, labels: { env: dev } }
spec: { ssh: { address: 'probe-dev:22' }, worker_selector: { pool: probe } }
";

/// The deployed policy engine on a fixed in-memory policy. It says nothing
/// about the operator's policy: it says the code that decides still decides
/// the way the design says it must.
fn engine() -> Verdict {
    let policy = match Policy::parse_yaml([("selftest", ENGINE_POLICY)]) {
        Ok(p) => p,
        Err(e) => return fail(format!("the probe policy did not load: {e}")),
    };
    let reader = vec!["probe-reader".to_owned()];
    let nobody: Vec<String> = Vec::new();
    let unknown_role = vec!["no-such-role".to_owned()];
    let login = |l: &str| Principal::SshLogin(l.to_owned());
    let decide = |roles: &[String], resource: &str, who: Principal| {
        policy.evaluate(&AccessRequest {
            roles,
            resource,
            principal: who,
        })
    };
    // (what is expected, what happened)
    let cases: Vec<(&str, bool)> = vec![
        (
            "a matching role allows",
            decide(&reader, "probe-staging", login("probe")).is_allowed(),
        ),
        (
            "a deny rule beats an allow",
            matches!(
                decide(&reader, "probe-bastion", login("probe")),
                Decision::Deny {
                    reason: DenyReason::ExplicitDeny
                }
            ),
        ),
        (
            "a label mismatch denies",
            matches!(
                decide(&reader, "probe-dev", login("probe")),
                Decision::Deny {
                    reason: DenyReason::NoMatchingRole
                }
            ),
        ),
        (
            "an unlisted login denies",
            !decide(&reader, "probe-staging", login("root")).is_allowed(),
        ),
        (
            "an unknown resource denies",
            matches!(
                decide(&reader, "probe-missing", login("probe")),
                Decision::Deny {
                    reason: DenyReason::UnknownResource
                }
            ),
        ),
        (
            "no roles deny",
            !decide(&nobody, "probe-staging", login("probe")).is_allowed(),
        ),
        (
            "an unknown role denies",
            !decide(&unknown_role, "probe-staging", login("probe")).is_allowed(),
        ),
        (
            "a role that may only be requested is no access, and is offered as a request",
            {
                let req = AccessRequest {
                    roles: &nobody,
                    resource: "probe-prod",
                    principal: login("probe"),
                };
                let eligible = vec!["probe-requestable".to_owned()];
                !policy.evaluate(&req).is_allowed()
                    && matches!(
                        policy.evaluate_eligible(&req, &eligible),
                        Decision::RequiresApproval { .. }
                    )
                    && !policy.evaluate_eligible(&req, &eligible).is_allowed()
            },
        ),
    ];
    let wrong: Vec<&str> = cases
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(w, _)| *w)
        .collect();
    if wrong.is_empty() {
        pass(format!(
            "All {} test decisions came out as designed.",
            cases.len()
        ))
    } else {
        fail(format!("decided wrongly: {}", wrong.join("; ")))
    }
}

// ---- certificates ----

/// A throwaway user CA, and a certificate it issued to a name no real
/// identity has. Nothing here uses a real CA key.
async fn probe_cert() -> Result<
    (
        CertificateAuthority,
        rustls_pki_types::CertificateDer<'static>,
    ),
    String,
> {
    let ca = CertificateAuthority::create_self_signed(
        CaPurpose::UserX509,
        Arc::new(FileSigner::generate().map_err(|e| e.to_string())?),
    )
    .await
    .map_err(|e| e.to_string())?;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let csr = CertificateParams::default()
        .serialize_request(&key)
        .map_err(|e| e.to_string())?;
    let issued = ca
        .issue_user(UserCertRequest {
            csr_der: csr.der().to_vec(),
            username: "probe-person".to_owned(),
            roles: Vec::new(),
            login_id: uuid::Uuid::now_v7(),
            ttl: Duration::from_secs(60),
            ci: None,
        })
        .await
        .map_err(|e| e.to_string())?;
    Ok((ca, issued.der))
}

/// The production verifier accepts the probe certificate now (so a refusal
/// later is about the end date and not a broken probe) and refuses it after.
async fn cert_expired_refused() -> Verdict {
    let (ca, cert) = match probe_cert().await {
        Ok(v) => v,
        Err(e) => return fail(format!("could not make a probe certificate: {e}")),
    };
    let now = OffsetDateTime::now_utc();
    if let Err(e) = limen_ca::verify::verify_user_at(&cert, ca.cert_der(), now) {
        return fail(format!(
            "the probe certificate was refused while valid: {e}"
        ));
    }
    match limen_ca::verify::verify_user_at(&cert, ca.cert_der(), now + time::Duration::hours(2)) {
        Err(_) => pass("A test certificate was accepted while valid and refused after it expired."),
        Ok(_) => fail("a certificate past its end date was accepted"),
    }
}

/// The production verifier refuses a certificate that chains to some other CA.
async fn cert_foreign_ca_refused() -> Verdict {
    let (ca, cert) = match probe_cert().await {
        Ok(v) => v,
        Err(e) => return fail(format!("could not make a probe certificate: {e}")),
    };
    let (other, _) = match probe_cert().await {
        Ok(v) => v,
        Err(e) => return fail(format!("could not make a second probe CA: {e}")),
    };
    if limen_ca::verify::verify_user(&cert, ca.cert_der()).is_err() {
        return fail("the probe certificate was refused by its own CA");
    }
    match limen_ca::verify::verify_user(&cert, other.cert_der()) {
        Err(_) => pass("A test certificate was accepted by its own CA and refused by another."),
        Ok(_) => fail("a certificate from another CA was accepted"),
    }
}

// ---- locks ----

/// The two SQL checks the API and the grant and certificate paths use, and
/// the function that turns their answer into a refusal, against a lock and an
/// ended login that exist only inside a transaction. It never opens a
/// session. The transaction is rolled back, so no other replica, the console
/// or an evidence pack ever sees the probe.
async fn lock_refused(state: &AppState) -> Verdict {
    match lock_probe(state).await {
        Ok(v) => v,
        Err(e) => fail(format!("the probe could not run: {e}")),
    }
}

async fn lock_probe(state: &AppState) -> Result<Verdict, sqlx::Error> {
    // Mixed case on purpose: the database compares names case-insensitively.
    const LOCKED: &str = "selftest:Lock-Probe";
    const OTHER: &str = "selftest:other-probe";
    let login = uuid::Uuid::now_v7().to_string();
    let other_login = uuid::Uuid::now_v7().to_string();
    let mut tx = state.db.begin().await?;
    sqlx::query("SET LOCAL statement_timeout = '5s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO user_locks (id, username, reason, locked_by) VALUES ($1, $2, 'self-test probe, rolled back', 'selftest:runner')",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(LOCKED)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO login_revocations (login_id, username) VALUES ($1, $2)")
        .bind(&login)
        .bind(OTHER)
        .execute(&mut *tx)
        .await?;

    let (locked, ended) =
        crate::db::lock_and_logout(&mut *tx, &LOCKED.to_lowercase(), &other_login).await?;
    let (other_locked, other_ended) =
        crate::db::lock_and_logout(&mut *tx, OTHER, &other_login).await?;
    let (_, revoked_login) = crate::db::lock_and_logout(&mut *tx, OTHER, &login).await?;
    let grant_path_locked = crate::db::is_locked(&mut *tx, &LOCKED.to_uppercase()).await?;
    let grant_path_other = crate::db::is_locked(&mut *tx, OTHER).await?;
    tx.rollback().await?;

    let mut wrong = Vec::new();
    if !locked || ended {
        wrong.push("the API path did not see the lock");
    }
    if other_locked || other_ended {
        wrong.push("the API path saw a lock on another name");
    }
    if !revoked_login {
        wrong.push("the API path did not see the ended login");
    }
    if !grant_path_locked {
        wrong.push("the grant and certificate path did not see the lock");
    }
    if grant_path_other {
        wrong.push("the grant and certificate path saw a lock on another name");
    }
    if crate::caller::refusal(locked, ended).is_none() {
        wrong.push("a locked account would not be refused");
    }
    if crate::caller::refusal(false, revoked_login).is_none() {
        wrong.push("an ended login would not be refused");
    }
    if crate::caller::refusal(false, false).is_some() {
        wrong.push("an ordinary account would be refused");
    }
    Ok(if wrong.is_empty() {
        pass("A lock and an ended login were seen and refused. The test left nothing behind.")
    } else {
        fail(wrong.join("; "))
    })
}

// ---- audit ----

async fn audit_sinks(state: &AppState) -> Verdict {
    // A sink that is mid-batch looks stuck for a moment: look twice.
    let first = sink_problems(state);
    if first.is_empty() {
        return pass(sink_summary(state));
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let second = sink_problems(state);
    if second.is_empty() {
        pass(sink_summary(state))
    } else {
        fail(second.join("; "))
    }
}

fn sink_summary(state: &AppState) -> String {
    let n = state.pipeline.sink_snapshots().len();
    format!(
        "{n} audit {} on this control plane {} up to date.",
        plural(n, "sink", "sinks"),
        if n == 1 { "is" } else { "are" }
    )
}

fn sink_problems(state: &AppState) -> Vec<String> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut problems = Vec::new();
    if state.pipeline.is_fenced() {
        problems
            .push("S3 shipping is paused: this replica can't confirm it owns its id".to_owned());
    }
    for (name, snap) in state.pipeline.sink_snapshots() {
        if snap.pending == 0 {
            continue;
        }
        match snap.last_ok_unix {
            Some(at) if now - at <= SINK_STALE_SECS => {}
            Some(at) => problems.push(format!(
                "{name} has {} events waiting and last accepted a batch {} minutes ago",
                snap.pending,
                (now - at) / 60
            )),
            None => problems.push(format!(
                "{name} has {} events waiting and has accepted nothing since this process started",
                snap.pending
            )),
        }
    }
    problems
}

/// Signatures, signer, sequence and hash chain of the newest manifests. It
/// reads manifests only: the control plane's role can't read event batches,
/// so a modified batch or a gap in an event sequence is `limen audit verify`'s
/// to find, not this check's.
async fn manifest_tail(state: &AppState) -> Verdict {
    let Some(sink) = state.pipeline.s3_sink() else {
        return skip("This control plane has no S3 audit store.");
    };
    let ca = state.cas.internal.cert_der();
    match limen_verify::bucket::verify_manifest_tail(
        &sink.client,
        &sink.bucket,
        &sink.prefix,
        ca,
        MANIFEST_TAIL,
    )
    .await
    {
        Err(e) => fail(format!("the manifests could not be read: {e}")),
        Ok(r) if r.writers == 0 => skip("The audit store has no manifests yet."),
        Ok(r) if r.ok() => pass(format!(
            "The newest {} {} of {} {} are signed, in order and chained. Event batches are not read: use `limen audit verify` for those.",
            r.manifests,
            plural(r.manifests, "manifest", "manifests"),
            r.writers,
            plural(r.writers, "writer", "writers")
        )),
        Ok(r) => fail(r.problems.join("; ")),
    }
}

// ---- recordings ----

/// The newest few recordings, re-hashed and compared with the hash the worker
/// reported when the session ended. The detail holds session ids only.
async fn recording_integrity(state: &AppState) -> Verdict {
    // Recent enough to be a live concern, old enough to be fully stored.
    let rows = match sqlx::query(
        "SELECT session_id::text AS id, recording_uri, recording_sha256 FROM sessions
         WHERE recording_uri IS NOT NULL AND recording_sha256 IS NOT NULL
           AND ended_at IS NOT NULL AND ended_at < now() - interval '2 minutes'
         ORDER BY ended_at DESC LIMIT $1",
    )
    .bind(RECORDING_SAMPLE)
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => return fail(format!("the sessions could not be listed: {e}")),
    };
    if rows.is_empty() {
        return skip("No ended session has a recording yet.");
    }
    let mut read = 0usize;
    let mut checked = 0usize;
    let mut oversized = 0usize;
    let mut bad: Vec<String> = Vec::new();
    for row in &rows {
        let (Ok(id), Ok(uri), Ok(expected)) = (
            row.try_get::<String, _>("id"),
            row.try_get::<String, _>("recording_uri"),
            row.try_get::<String, _>("recording_sha256"),
        ) else {
            return fail("a session row could not be read");
        };
        if read >= RECORDING_BUDGET {
            break;
        }
        match state.pipeline.recordings.get(&uri).await {
            Ok(bytes) => {
                read += bytes.len();
                checked += 1;
                if limen_verify::pack::sha(&bytes) != expected {
                    bad.push(format!("{id}: does not match its recorded hash"));
                }
            }
            // The store refuses what it would not play (over its size cap):
            // a limit of this check, not a damaged recording.
            Err(e) if e.downcast_ref::<crate::pipeline::TooLarge>().is_some() => oversized += 1,
            Err(_) => bad.push(format!("{id}: could not be read from storage")),
        }
    }
    if bad.is_empty() && checked == 0 {
        skip(format!(
            "{oversized} recent {} are too large for this check to read.",
            plural(oversized, "recording", "recordings")
        ))
    } else if bad.is_empty() {
        let extra = if oversized > 0 {
            format!(
                " {oversized} too large to read {} skipped.",
                if oversized == 1 { "was" } else { "were" }
            )
        } else {
            String::new()
        };
        pass(format!(
            "{checked} recent {} still {} the hash recorded when the session ended.{extra}",
            plural(checked, "recording", "recordings"),
            if checked == 1 { "matches" } else { "match" }
        ))
    } else {
        fail(bad.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_the_engine_check_holds() {
        let mut ids: Vec<&str> = CHECKS.iter().map(|(id, _)| *id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), CHECKS.len());
        assert_eq!(engine().0, Status::Passed, "{}", engine().1);
    }

    #[tokio::test]
    async fn the_certificate_checks_pass_without_a_real_ca() {
        assert_eq!(
            cert_expired_refused().await.0,
            Status::Passed,
            "{}",
            cert_expired_refused().await.1
        );
        assert_eq!(cert_foreign_ca_refused().await.0, Status::Passed);
    }

    #[test]
    fn details_are_one_short_line() {
        assert_eq!(tidy("a\nb\tc"), "a b c");
        assert_eq!(tidy(&"x".repeat(1000)).len(), 300);
    }
}

//! The scheduled self-test and controls report (ADR-0053) against a real
//! PostgreSQL. Set `LIMEN_TEST_DATABASE_URL` to run them.

#![allow(clippy::large_futures)]

mod common;

use common::{Harness, forwarded};
use limen_audit::EventKind;
use limen_proto::v1::controls_client::ControlsClient;
use limen_proto::v1::reviews_client::ReviewsClient;
use limen_proto::v1::{
    ExportEvidenceRequest, GetControlsReportRequest, ListSelfTestRunsRequest, RunSelfTestRequest,
    SelfTestRunInfo,
};
use limen_testkit::users::{ADMIN, AUDITOR, DEVELOPER};
use limen_tunnel::connect::TracedChannel as Channel;
use limen_verify::controls::{Status, verify_report};
use rustls_pki_types::CertificateDer;
use tonic::Code;

const POLICY: &str = r"
kind: resource
version: v1
metadata: { name: web-1, labels: { env: prod } }
spec: { ssh: { address: '10.0.0.1:22', host_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' } }
---
kind: role
version: v1
metadata: { name: ops }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [ubuntu] }
---
kind: role_mapping
version: v1
metadata: { name: m }
spec:
  - { idp_group: ops-group, roles: [ops] }
  - { idp_group: auditors, roles: ['limen:auditor'] }
---
kind: policy_test
version: v1
metadata: { name: t }
spec:
  cases:
    - name: ops reach web-1
      who: { groups: [ops-group] }
      resource: web-1
      principal: { login: ubuntu }
      expect: allow
";

struct Rig {
    h: Harness,
    ch: Channel,
    admin: CertificateDer<'static>,
    dev: CertificateDer<'static>,
    auditor: CertificateDer<'static>,
}

async fn rig_with(extra: &[String]) -> Option<Rig> {
    let h = Harness::start_with(extra).await?;
    h.set_policy(&[("p.yaml", POLICY)]);
    let (_, proxy) = h.enroll_proxy().await;
    let ch = h.channel(Some(proxy));
    let (_, admin) = h.login(ADMIN, &["admins"]).await.expect("admin");
    let (_, dev) = h.login(DEVELOPER, &["ops-group"]).await.expect("dev");
    let (_, auditor) = h.login(AUDITOR, &["auditors"]).await.expect("auditor");
    Some(Rig {
        h,
        ch,
        admin,
        dev,
        auditor,
    })
}

async fn rig() -> Option<Rig> {
    rig_with(&[]).await
}

impl Rig {
    fn c(&self) -> ControlsClient<Channel> {
        ControlsClient::new(self.ch.clone())
    }

    async fn run(&self) -> Result<SelfTestRunInfo, tonic::Status> {
        self.c()
            .run_self_test(forwarded(RunSelfTestRequest {}, Some(&self.admin)))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn runs(&self) -> Vec<SelfTestRunInfo> {
        self.c()
            .list_self_test_runs(forwarded(
                ListSelfTestRunsRequest { limit: 50 },
                Some(&self.auditor),
            ))
            .await
            .expect("list")
            .into_inner()
            .runs
    }

    /// Wait for a run to leave `running`.
    async fn finished(&self, id: &str) -> SelfTestRunInfo {
        for _ in 0..200 {
            if let Some(r) = self
                .runs()
                .await
                .into_iter()
                .find(|r| r.id == id && r.status != "running")
            {
                return r;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        panic!("the self-test did not finish");
    }

    async fn count(&self, sql: &'static str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(&self.h.state.db)
            .await
            .expect("count")
    }
}

#[tokio::test]
async fn a_run_produces_a_signed_report_anchored_in_the_audit_trail() {
    let Some(r) = rig().await else { return };
    let started = r.run().await.expect("run");
    assert!(!started.already_running);
    let done = r.finished(&started.id).await;
    assert_eq!(done.status, "passed", "{done:?}");
    assert_eq!(done.failed, 0);
    // Without an S3 sink or recordings these are skipped, and counted apart.
    assert!(done.skipped >= 2, "{done:?}");
    assert!(done.passed >= 5, "{done:?}");

    let rep = r
        .c()
        .get_controls_report(forwarded(
            GetControlsReportRequest {
                id: done.id.clone(),
            },
            Some(&r.auditor),
        ))
        .await
        .expect("report")
        .into_inner();
    let v = verify_report(&rep.report, r.h.state.cas.internal.cert_der());
    assert!(v.ok(), "{:?}", v.problems());
    assert_eq!(v.verification.manifest_sha256, done.manifest_sha256);
    let run = v.run.expect("run");
    let by = |id: &str| run.checks.iter().find(|c| c.id == id).expect(id).status;
    assert_eq!(by("policy.declared_tests"), Status::Passed);
    assert_eq!(by("policy.engine"), Status::Passed);
    assert_eq!(by("cert.expired_refused"), Status::Passed);
    assert_eq!(by("cert.foreign_ca_refused"), Status::Passed);
    assert_eq!(by("lock.refused"), Status::Passed);
    assert_eq!(by("audit.manifest_tail"), Status::Skipped);
    assert!(run.meta.attestation.contains("attesting to itself"));

    // The demo checks this very report with the CLI, offline.
    if let Some(dir) = std::env::var_os("LIMEN_TEST_REPORT_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::write(dir.join("limen-controls.json"), &rep.report).expect("write report");
        std::fs::write(
            dir.join("internal-ca.pem"),
            r.h.state.cas.internal.cert_pem(),
        )
        .expect("write ca");
        let lines: Vec<String> =
            r.h.audit_events()
                .await
                .iter()
                .map(|e| serde_json::to_string(e).expect("event"))
                .collect();
        std::fs::write(dir.join("audit.jsonl"), lines.join("\n")).expect("write events");
    }

    // Anchored: the event carries the same manifest hash.
    let events = r.h.audit_events().await;
    let anchored = events.iter().any(|e| {
        e.kind == EventKind::SelftestRun && e.data["manifest_sha256"] == done.manifest_sha256
    });
    assert!(anchored, "no selftest.run event for the report");

    // The lock probe left nothing behind, and the test principal has no row.
    assert_eq!(r.count("SELECT count(*) FROM user_locks").await, 0);
    assert_eq!(r.count("SELECT count(*) FROM login_revocations").await, 0);
    assert_eq!(
        r.count("SELECT count(*) FROM users WHERE username ILIKE 'selftest:%'")
            .await,
        0
    );
}

#[tokio::test]
async fn only_admins_start_a_run_and_only_readers_see_one() {
    let Some(r) = rig().await else { return };
    let dev_run = r
        .c()
        .run_self_test(forwarded(RunSelfTestRequest {}, Some(&r.dev)))
        .await
        .expect_err("developer");
    assert_eq!(dev_run.code(), Code::PermissionDenied);
    let aud_run = r
        .c()
        .run_self_test(forwarded(RunSelfTestRequest {}, Some(&r.auditor)))
        .await
        .expect_err("auditor starts");
    assert_eq!(aud_run.code(), Code::PermissionDenied);
    let list = r
        .c()
        .list_self_test_runs(forwarded(
            ListSelfTestRunsRequest { limit: 5 },
            Some(&r.dev),
        ))
        .await
        .expect_err("developer lists");
    assert_eq!(list.code(), Code::PermissionDenied);
    let get = r
        .c()
        .get_controls_report(forwarded(
            GetControlsReportRequest { id: "x".into() },
            Some(&r.dev),
        ))
        .await
        .expect_err("developer reads");
    assert_eq!(get.code(), Code::PermissionDenied);
    assert_eq!(r.count("SELECT count(*) FROM selftest_runs").await, 0);
}

#[tokio::test]
async fn a_second_click_gets_the_run_in_progress_and_a_third_is_rate_limited() {
    let Some(r) = rig().await else { return };
    let (a, b) = tokio::join!(r.run(), r.run());
    let (a, b) = (a.expect("a"), b.expect("b"));
    assert_eq!(a.id, b.id, "one run, shared");
    assert_ne!(a.already_running, b.already_running);
    r.finished(&a.id).await;
    let again = r.run().await.expect_err("too soon");
    assert_eq!(again.code(), Code::ResourceExhausted);
}

#[tokio::test]
async fn a_failing_declared_test_fails_the_run() {
    let Some(r) = rig().await else { return };
    // The policy now says ops must be denied what the role allows.
    let broken = POLICY.replace("expect: allow", "expect: deny");
    r.h.set_policy(&[("p.yaml", &broken)]);
    let started = r.run().await.expect("run");
    let done = r.finished(&started.id).await;
    assert_eq!(done.status, "failed", "{done:?}");
    assert_eq!(done.failed, 1);
    let rep = r
        .c()
        .get_controls_report(forwarded(
            GetControlsReportRequest { id: done.id },
            Some(&r.admin),
        ))
        .await
        .expect("report")
        .into_inner();
    let v = verify_report(&rep.report, r.h.state.cas.internal.cert_der());
    assert!(v.ok(), "a failed run is still an intact report");
    let c = v
        .run
        .expect("run")
        .checks
        .into_iter()
        .find(|c| c.id == "policy.declared_tests")
        .expect("check");
    assert_eq!(c.status, Status::Failed);
    let failed =
        r.h.audit_events()
            .await
            .into_iter()
            .any(|e| e.kind == EventKind::SelftestRun && e.data["status"] == "failed");
    assert!(failed, "a failure is in the audit trail");
}

#[tokio::test]
async fn the_self_test_name_cannot_log_in() {
    let Some(r) = rig().await else { return };
    for name in ["selftest:probe", "SelfTest:probe"] {
        let refused = r.h.login(name, &["admins"]).await;
        assert!(refused.is_err(), "{name} must not get a certificate");
    }
    assert_eq!(
        r.count("SELECT count(*) FROM users WHERE username ILIKE 'selftest:%'")
            .await,
        0
    );
}

#[tokio::test]
async fn evidence_packs_list_the_runs_of_the_period() {
    let Some(r) = rig().await else { return };
    let started = r.run().await.expect("run");
    let done = r.finished(&started.id).await;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let pack = ReviewsClient::new(r.ch.clone())
        .export_evidence(forwarded(
            ExportEvidenceRequest {
                from_unix: now - 3600,
                to_unix: now + 3600,
            },
            Some(&r.auditor),
        ))
        .await
        .expect("evidence")
        .into_inner();
    assert!(limen_verify::pack::verify_pack(&pack.pack, r.h.state.cas.internal.cert_der()).ok());
    let doc: serde_json::Value = serde_json::from_slice(&pack.pack).expect("json");
    let runs = doc["sections"]["controls"].as_array().expect("controls");
    assert!(
        runs.iter()
            .any(|x| x["manifest_sha256"] == done.manifest_sha256 && x["status"] == "passed"),
        "{runs:?}"
    );
}

#[tokio::test]
async fn the_schedule_runs_by_itself_once_across_replicas() {
    let flags = ["--selftest-interval=4s".to_owned()];
    let Some(r) = rig_with(&flags).await else {
        return;
    };
    let peer =
        r.h.start_peer(&["--id=cp-peer".to_owned(), flags[0].clone()])
            .await;
    // Both replicas tick; within one interval only one run is scheduled.
    for _ in 0..60 {
        if r.count("SELECT count(*) FROM selftest_runs WHERE trigger = 'schedule'")
            .await
            >= 1
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let scheduled = r
        .count("SELECT count(*) FROM selftest_runs WHERE trigger = 'schedule'")
        .await;
    assert_eq!(scheduled, 1, "two replicas ran the same slot");
    let by: String = sqlx::query_scalar("SELECT requested_by FROM selftest_runs LIMIT 1")
        .fetch_one(&r.h.state.db)
        .await
        .expect("by");
    assert_eq!(by, "selftest:scheduler");
    peer.begin_shutdown();
    let _ = peer.finish().await;
}

#[tokio::test]
async fn a_restart_abandons_its_own_stale_runs_and_only_those() {
    let Some(r) = rig().await else { return };
    for (id, plane) in [
        (uuid::Uuid::now_v7(), "cp-test"),
        (uuid::Uuid::now_v7(), "cp-other"),
    ] {
        sqlx::query(
            "INSERT INTO selftest_runs (id, trigger, requested_by, control_plane, status, started_at)
             VALUES ($1, 'manual', 'x', $2, 'abandoned', now() - interval '1 hour')",
        )
        .bind(id)
        .bind(plane)
        .execute(&r.h.state.db)
        .await
        .expect("insert");
    }
    // One running row of this control plane (the abandoned ones don't count).
    sqlx::query(
        "INSERT INTO selftest_runs (id, trigger, requested_by, control_plane, status)
         VALUES ($1, 'manual', 'x', 'cp-test', 'running')",
    )
    .bind(uuid::Uuid::now_v7())
    .execute(&r.h.state.db)
    .await
    .expect("running");
    limen_control_plane::selftest::abandon_own_stale(&r.h.state).await;
    assert_eq!(
        r.count("SELECT count(*) FROM selftest_runs WHERE status = 'running'")
            .await,
        0
    );
    assert_eq!(
        r.count(
            "SELECT count(*) FROM selftest_runs WHERE status = 'abandoned' AND error LIKE '%restarted%'"
        )
        .await,
        1
    );
}

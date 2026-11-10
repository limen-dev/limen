//! Replay of recorded sessions against a policy change (ADR-0049). Set
//! `LIMEN_TEST_DATABASE_URL` to run them.

mod common;

use common::{Harness, forwarded};
use limen_audit::EventKind;
use limen_policy::replay::ReplayReport;
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, ApplyPolicyResponse, PolicySource};
use limen_testkit::users::{ADMIN, DEVELOPER};
use rustls_pki_types::CertificateDer;

const BASE: &str = r"
kind: resource
version: v1
metadata: { name: web-prod, labels: { env: prod } }
spec: { ssh: { address: 'h:22' } }
---
kind: resource
version: v1
metadata: { name: orders-prod, labels: { env: prod } }
spec: { postgres: { endpoint: 'db.internal:5432' } }
---
kind: role_mapping
version: v1
metadata: { name: replay-test }
spec:
  - { idp_group: admins, roles: ['limen:admin'] }
  - { idp_group: developers, roles: [dev] }
---
kind: role
version: v1
metadata: { name: dev }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [ubuntu] }
    - resources: { kind: [postgres], labels: { env: [prod] } }
      db: { roles: [limen_read], databases: [orders] }
---
kind: bot
version: v1
metadata: { name: nightly }
spec:
  roles: [dev]
  join:
    method: github_actions
    match: { repository: acme/infra, ref: refs/heads/main }
";

/// Developers lose SSH to production.
fn tightened() -> String {
    BASE.replace(
        "labels: { env: [prod] } }\n      ssh: { logins: [ubuntu] }",
        "labels: { env: [staging] } }\n      ssh: { logins: [ubuntu] }",
    )
}

struct Fixture {
    h: Harness,
    admin: CertificateDer<'static>,
    proxy: limen_tunnel::tls::Identity,
}

async fn start() -> Option<Fixture> {
    let h = Harness::start_with(&[]).await?;
    let (_, admin) = h.login(ADMIN, &["admins"]).await.expect("admin");
    let (_, proxy) = h.enroll_proxy().await;
    Some(Fixture { h, admin, proxy })
}

impl Fixture {
    async fn call(
        &self,
        who: &CertificateDer<'static>,
        content: String,
        dry_run: bool,
        replay_days: u32,
    ) -> Result<ApplyPolicyResponse, tonic::Status> {
        AdminClient::new(self.h.channel(Some(self.proxy.clone())))
            .apply_policy(forwarded(
                ApplyPolicyRequest {
                    source: String::new(),
                    sources: vec![PolicySource {
                        name: "policy.yaml".into(),
                        content,
                    }],
                    dry_run,
                    source_ref: String::new(),
                    require_tests: false,
                    replay_days,
                },
                Some(who),
            ))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn session(&self, user: &str, kind: &str, resource: &str, login: &str, age_days: i64) {
        sqlx::query(
            "INSERT INTO sessions (session_id, username, kind, resource, login, client_addr, started_at, actor_type)
             VALUES ($1, $2, $3, $4, $5, '203.0.113.9:5555', now() - make_interval(days => $6::int), $7)",
        )
        .bind(uuid::Uuid::now_v7())
        .bind(user)
        .bind(kind)
        .bind(resource)
        .bind(login)
        .bind(i32::try_from(age_days).expect("small"))
        .bind(if user.starts_with("bot:") { "bot" } else { "user" })
        .execute(&self.h.state.db)
        .await
        .expect("insert session");
    }

    async fn known_person(&self, user: &str, groups: &[&str]) {
        sqlx::query(
            "INSERT INTO users (username, subject, roles, groups) VALUES ($1, $1, '{}', $2)
             ON CONFLICT (username) DO UPDATE SET groups = EXCLUDED.groups",
        )
        .bind(user)
        .bind(groups.iter().map(|g| (*g).to_owned()).collect::<Vec<_>>())
        .execute(&self.h.state.db)
        .await
        .expect("insert user");
    }
}

fn report(resp: &ApplyPolicyResponse) -> ReplayReport {
    serde_json::from_str(&resp.replay_json).expect("a replay report")
}

#[tokio::test]
async fn a_dry_run_replays_recorded_sessions_through_the_change() {
    let Some(f) = Box::pin(start()).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    f.call(&f.admin, BASE.into(), false, 0)
        .await
        .expect("apply base");
    f.known_person("alice@example.com", &["developers"]).await;
    for _ in 0..3 {
        f.session("alice@example.com", "ssh", "web-prod", "ubuntu", 1)
            .await;
    }
    f.session("bot:nightly", "ssh", "web-prod", "ubuntu", 2)
        .await;
    // Not replayed, and said so: Kubernetes, a database that wasn't recorded,
    // and someone Limen no longer knows.
    f.session("alice@example.com", "kube", "web-prod", "", 1)
        .await;
    f.session(
        "alice@example.com",
        "postgres",
        "orders-prod",
        "limen_read",
        1,
    )
    .await;
    f.session("ghost@example.com", "ssh", "web-prod", "ubuntu", 1)
        .await;
    // Outside the window.
    f.session("alice@example.com", "ssh", "web-prod", "ubuntu", 40)
        .await;
    // Already refused today (no groups).
    f.known_person("dave@example.com", &[]).await;
    f.session("dave@example.com", "ssh", "web-prod", "ubuntu", 1)
        .await;

    // Replaying the policy against itself changes nothing.
    let same = f.call(&f.admin, BASE.into(), true, 30).await.expect("same");
    let same = report(&same);
    assert_eq!(same.affected_sessions, 0, "{same:?}");
    assert_eq!(same.unchanged, 4);
    assert_eq!(same.already_refused, 1);

    let before = f.h.state.policy.base().version;
    let resp = f
        .call(&f.admin, tightened(), true, 30)
        .await
        .expect("replay");
    let r = report(&resp);
    assert!(!resp.applied, "a replay applies nothing");
    assert_eq!(f.h.state.policy.base().version, before);
    assert_eq!(r.window_days, 30);
    assert_eq!(r.affected_sessions, 4, "{r:?}");
    assert_eq!(r.affected_users(), (1, 1));
    assert_eq!(r.already_refused, 1);
    assert_eq!(r.skipped.len(), 3, "{:?}", r.skipped);
    assert!(
        r.skipped.keys().any(|k| k.contains("Kubernetes")),
        "{:?}",
        r.skipped
    );
    assert!(
        r.skipped.keys().any(|k| k.contains("no longer known")),
        "{:?}",
        r.skipped
    );
    // The report names no session, client address, or id.
    assert!(!resp.replay_json.contains("203.0.113.9"));
    assert!(!resp.replay_json.contains("session_id"));

    // Audited: before it ran, and with counts after, never with rows.
    let events: Vec<_> =
        f.h.audit_events()
            .await
            .into_iter()
            .filter(|e| e.kind == EventKind::PolicyReplay)
            .collect();
    assert!(events.len() >= 4, "{events:?}");
    let start = events
        .iter()
        .find(|e| e.data["phase"] == "start")
        .expect("start event");
    assert_eq!(start.user.as_deref(), Some(ADMIN));
    assert_eq!(start.data["window_days"], 30);
    assert!(
        events
            .iter()
            .any(|e| e.data["phase"] == "done" && e.data["affected_sessions"] == 4)
    );
    let raw = serde_json::to_string(&events).expect("json");
    assert!(!raw.contains("alice"), "{raw}");
}

#[tokio::test]
async fn replay_is_for_admins_dry_runs_and_a_sane_window() {
    let Some(f) = Box::pin(start()).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    f.call(&f.admin, BASE.into(), false, 0)
        .await
        .expect("apply base");
    // A developer can't ask.
    let (_, developer) =
        f.h.login(DEVELOPER, &["developers"])
            .await
            .expect("developer");
    let err = f
        .call(&developer, tightened(), true, 7)
        .await
        .expect_err("not an admin");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(
        f.h.audit_kinds()
            .await
            .iter()
            .all(|k| *k != EventKind::PolicyReplay),
        "a refused caller leaves no replay"
    );
    // It is a dry-run feature: a real apply with a window is refused, untouched.
    let err = f
        .call(&f.admin, tightened(), false, 7)
        .await
        .expect_err("needs dry_run");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(f.h.state.policy.base().policy.digest(), {
        limen_policy::Policy::parse_yaml([("p", BASE)])
            .expect("base")
            .digest()
    });
    // The window is 1 to 30 days.
    let err = f
        .call(&f.admin, tightened(), true, 31)
        .await
        .expect_err("too long");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    // No window, no replay.
    let none = f
        .call(&f.admin, tightened(), true, 0)
        .await
        .expect("plain dry run");
    assert_eq!(none.replay_json, "");
}

#[tokio::test]
async fn replays_are_rate_limited_per_person() {
    let Some(f) = Box::pin(start()).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    f.call(&f.admin, BASE.into(), false, 0)
        .await
        .expect("apply base");
    let mut refused = 0;
    for _ in 0..12 {
        match f.call(&f.admin, tightened(), true, 7).await {
            Ok(_) => {}
            Err(e) if e.code() == tonic::Code::ResourceExhausted => refused += 1,
            Err(e) => panic!("unexpected: {e}"),
        }
    }
    assert!(refused > 0, "a burst of replays is slowed down");
}

/// A replay that can't be audited doesn't happen (the audit fails closed).
#[tokio::test(flavor = "multi_thread")]
async fn a_replay_that_cannot_be_audited_does_not_run() {
    let Some(_) = limen_testkit::s3_endpoint() else {
        eprintln!("SKIPPED: set LIMEN_TEST_S3_ENDPOINT");
        return;
    };
    // S3 pointed at a closed port: nothing drains the spool, so it fills.
    let dead =
        limen_testkit::toggle_proxy::ToggleProxy::start("127.0.0.1:9".parse().expect("addr")).await;
    dead.set_up(false);
    let Some(h) = Harness::start_with(&[
        "--audit-s3-bucket=never".into(),
        format!("--audit-s3-endpoint=http://{}", dead.addr),
        "--audit-s3-path-style".into(),
        "--audit-spool-max-bytes=6000".into(),
    ])
    .await
    else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let (_, admin) = h.login(ADMIN, &["admins"]).await.expect("admin");
    let (_, proxy) = h.enroll_proxy().await;
    let f = Fixture { h, admin, proxy };
    f.call(&f.admin, BASE.into(), false, 0)
        .await
        .expect("apply base");
    // Fill the spool until audited actions are refused.
    for i in 0..40 {
        if f.h
            .login(&format!("user{i}@example.com"), &["admins"])
            .await
            .is_err()
        {
            break;
        }
    }
    // The same dry run without a replay still works: it is the replay, which
    // reads who used what, that needs the audit trail.
    f.call(&f.admin, tightened(), true, 0)
        .await
        .expect("a plain dry run needs no audit");
    let err = f
        .call(&f.admin, tightened(), true, 7)
        .await
        .expect_err("refused while audit is down");
    assert_eq!(err.code(), tonic::Code::Unavailable, "{err}");
    assert!(err.message().contains("audit"), "{err}");
    assert!(
        f.h.audit_kinds()
            .await
            .iter()
            .all(|k| *k != EventKind::PolicyReplay)
    );
}

//! `limen policy suggest` (ADR-0050) against a real PostgreSQL. Set
//! `LIMEN_TEST_DATABASE_URL` to run them.

#![allow(clippy::large_futures)]

mod common;

use common::{Harness, forwarded};
use limen_audit::EventKind;
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{GetPolicyRequest, SuggestPolicyRequest, SuggestPolicyResponse};
use limen_testkit::users::{ADMIN, AUDITOR, DEVELOPER, ONCALL};
use limen_tunnel::connect::TracedChannel as Channel;
use rustls_pki_types::CertificateDer;
use tonic::Code;

const POLICY: &str = r"
kind: resource
version: v1
metadata: { name: web-1, labels: { env: prod } }
spec: { ssh: { address: '10.0.0.1:22', host_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' } }
---
kind: resource
version: v1
metadata: { name: db-1, labels: { env: prod } }
spec: { postgres: { endpoint: 'db.internal:5432' } }
---
kind: role
version: v1
metadata: { name: ops }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [ubuntu, root] }
---
kind: role
version: v1
metadata: { name: dba }
spec:
  allow:
    - resources: { kind: [postgres], labels: { env: [prod] } }
      db: { roles: [limen_read, limen_write], databases: ['*'] }
---
kind: role
version: v1
metadata: { name: keeper, labels: { suggest: keep } }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [batch] }
---
kind: role_mapping
version: v1
metadata: { name: m }
spec:
  - { idp_group: ops-group, roles: [ops, keeper] }
  - { idp_group: dba-group, roles: [dba] }
  - { idp_group: auditors, roles: ['limen:auditor'] }
";

struct Rig {
    h: Harness,
    ch: Channel,
    admin: CertificateDer<'static>,
    oncall: CertificateDer<'static>,
    auditor: CertificateDer<'static>,
}

async fn rig() -> Option<Rig> {
    let h = Harness::start().await?;
    h.set_policy(&[("p.yaml", POLICY)]);
    let (_, proxy) = h.enroll_proxy().await;
    let ch = h.channel(Some(proxy));
    let (_, admin) = h.login(ADMIN, &["admins"]).await.expect("admin");
    let (_, oncall) = h.login(ONCALL, &["ops-group"]).await.expect("oncall");
    let (_, _dev) = h.login(DEVELOPER, &["dba-group"]).await.expect("dev");
    let (_, auditor) = h.login(AUDITOR, &["auditors"]).await.expect("auditor");
    let r = Rig {
        h,
        ch,
        admin,
        oncall,
        auditor,
    };
    // Limen has been watching for a year, and every document is old.
    sqlx::query("UPDATE users SET first_login_at = now() - interval '400 days'")
        .execute(&r.h.state.db)
        .await
        .expect("users");
    for (kind, name) in [
        ("role", "ops"),
        ("role", "dba"),
        ("role", "keeper"),
        ("resource", "web-1"),
        ("resource", "db-1"),
    ] {
        sqlx::query(
            "INSERT INTO policy_document_heads (kind, name, channel, source, namespace, input, etag, policy_version, created_at, updated_at, updated_by)
             VALUES ($1, $2, 'git', 'default', 'default', '{}', 'x', 1, now() - interval '400 days', now() - interval '400 days', 'test')
             ON CONFLICT (kind, name) DO UPDATE SET created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at",
        )
        .bind(kind)
        .bind(name)
        .execute(&r.h.state.db)
        .await
        .expect("head");
    }
    Some(r)
}

impl Rig {
    async fn session(&self, user: &str, resource: &str, login: &str, days_ago: i32) {
        sqlx::query(
            "INSERT INTO sessions (session_id, username, kind, resource, login, started_at)
             VALUES (gen_random_uuid(), $1, 'x', $2, $3, now() - make_interval(days => $4))",
        )
        .bind(user)
        .bind(resource)
        .bind(login)
        .bind(days_ago)
        .execute(&self.h.state.db)
        .await
        .expect("session");
    }

    async fn apply(&self, yaml: &str) {
        AdminClient::new(self.ch.clone())
            .apply_policy(forwarded(
                limen_proto::v1::ApplyPolicyRequest {
                    source: String::new(),
                    require_tests: false,
                    replay_days: 0,
                    sources: vec![limen_proto::v1::PolicySource {
                        name: "p.yaml".into(),
                        content: yaml.into(),
                    }],
                    dry_run: false,
                    source_ref: String::new(),
                },
                Some(&self.admin),
            ))
            .await
            .expect("apply");
    }

    async fn suggest(
        &self,
        who: &CertificateDer<'static>,
        window_days: u32,
    ) -> Result<SuggestPolicyResponse, tonic::Status> {
        AdminClient::new(self.ch.clone())
            .suggest_policy(forwarded(SuggestPolicyRequest { window_days }, Some(who)))
            .await
            .map(tonic::Response::into_inner)
    }
}

#[tokio::test]
async fn suggests_removals_from_real_sessions_and_audits_the_call() {
    let Some(r) = rig().await else { return };
    r.session(ONCALL, "web-1", "ubuntu", 3).await;
    r.session(DEVELOPER, "db-1", "limen_read", 3).await;
    // Older than the window: does not count.
    r.session(ONCALL, "web-1", "root", 200).await;

    let before = AdminClient::new(r.ch.clone())
        .get_policy(forwarded(GetPolicyRequest {}, Some(&r.admin)))
        .await
        .expect("policy")
        .into_inner();
    let s = r.suggest(&r.admin, 0).await.expect("suggest");
    assert!(s.yaml.contains("name: ops"), "{}", s.yaml);
    assert!(s.yaml.contains("name: dba"), "{}", s.yaml);
    assert!(!s.yaml.contains("root"), "root was unused: {}", s.yaml);
    assert!(!s.yaml.contains("limen_write"), "{}", s.yaml);
    assert!(s.yaml.contains("limen_read"), "{}", s.yaml);
    // The opt-out label keeps its role out entirely.
    assert!(!s.yaml.contains("keeper"), "{}", s.yaml);
    assert!(
        s.text.contains("keeper"),
        "listed as left alone: {}",
        s.text
    );
    assert!(s.diff.contains("loses"), "{}", s.diff);
    assert!(!s.diff.contains("gains"), "{}", s.diff);

    // Nothing was applied.
    let after = AdminClient::new(r.ch.clone())
        .get_policy(forwarded(GetPolicyRequest {}, Some(&r.admin)))
        .await
        .expect("policy")
        .into_inner();
    assert_eq!(before.digest, after.digest);

    // The call is audited, without names.
    let events = r.h.audit_events().await;
    let ev = events
        .iter()
        .find(|e| e.kind == EventKind::PolicySuggest)
        .expect("a policy.suggest event");
    assert_eq!(ev.data["window_days"], 90);
    assert_eq!(ev.data["roles_to_tighten"], 2);
    let text = ev.data.to_string();
    assert!(
        !text.contains(ONCALL) && !text.contains(DEVELOPER),
        "{text}"
    );

    // A longer window sees the old `root` session: `ops` needs no change.
    let s = r.suggest(&r.admin, 365).await.expect("suggest");
    assert!(!s.yaml.contains("name: ops"), "{}", s.yaml);
    assert!(s.yaml.contains("name: dba"), "{}", s.yaml);
}

#[tokio::test]
async fn only_admins_may_ask_and_a_refusal_leaves_no_event() {
    let Some(r) = rig().await else { return };
    for who in [&r.oncall, &r.auditor] {
        let err = r.suggest(who, 90).await.expect_err("not an admin");
        assert_eq!(err.code(), Code::PermissionDenied, "{err}");
    }
    assert!(
        !r.h.audit_kinds().await.contains(&EventKind::PolicySuggest),
        "a refused call is not a suggestion"
    );
}

#[tokio::test]
async fn short_history_and_bad_windows_are_refused() {
    let Some(r) = rig().await else { return };
    r.session(ONCALL, "web-1", "ubuntu", 3).await;
    sqlx::query("UPDATE users SET first_login_at = now() - interval '20 days'")
        .execute(&r.h.state.db)
        .await
        .expect("users");
    let err = r.suggest(&r.admin, 90).await.expect_err("short history");
    assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
    assert!(err.message().contains("20 days"), "{err}");
    // A window it can honour works.
    r.suggest(&r.admin, 14).await.expect("14 days");
    for bad in [3, 366, 4_000_000_000] {
        let err = r.suggest(&r.admin, bad).await.expect_err("bad window");
        assert_eq!(err.code(), Code::InvalidArgument, "{bad}: {err}");
    }
}

#[tokio::test]
async fn a_role_changed_recently_is_not_judged() {
    let Some(r) = rig().await else { return };
    r.session(ONCALL, "web-1", "ubuntu", 3).await;
    sqlx::query("UPDATE policy_document_heads SET updated_at = now() - interval '5 days' WHERE name = 'ops'")
        .execute(&r.h.state.db)
        .await
        .expect("head");
    let s = r.suggest(&r.admin, 90).await.expect("suggest");
    assert!(!s.yaml.contains("name: ops"), "{}", s.yaml);
    assert!(s.text.contains("ops"), "{}", s.text);
    // A document with no recorded age is treated as new, not old.
    sqlx::query("DELETE FROM policy_document_heads WHERE name = 'dba'")
        .execute(&r.h.state.db)
        .await
        .expect("delete");
    let s = r.suggest(&r.admin, 90).await.expect("suggest");
    assert!(!s.yaml.contains("name: dba"), "{}", s.yaml);
}

#[tokio::test]
async fn a_resource_with_no_recorded_age_blocks_the_rules_that_reach_it() {
    // Accepted discovered resources have no document head (ADR-0027): a rule
    // that reaches one is not judged, because its age is not known.
    let Some(r) = rig().await else { return };
    r.session(ONCALL, "web-1", "ubuntu", 3).await;
    r.session(DEVELOPER, "db-1", "limen_read", 3).await;
    sqlx::query("DELETE FROM policy_document_heads WHERE kind = 'resource' AND name = 'db-1'")
        .execute(&r.h.state.db)
        .await
        .expect("delete");
    let s = r.suggest(&r.admin, 90).await.expect("suggest");
    assert!(!s.yaml.contains("name: dba"), "{}", s.yaml);
    assert!(s.yaml.contains("name: ops"), "{}", s.yaml);
}

#[tokio::test]
async fn applying_again_does_not_make_unchanged_roles_look_new() {
    // Through the real ApplyPolicy path: only the document that changed gets
    // a new age.
    let Some(r) = rig().await else { return };
    r.session(ONCALL, "web-1", "ubuntu", 3).await;
    r.session(DEVELOPER, "db-1", "limen_read", 3).await;
    r.apply(POLICY).await;
    sqlx::query("UPDATE policy_document_heads SET created_at = now() - interval '400 days', updated_at = now() - interval '400 days'")
        .execute(&r.h.state.db)
        .await
        .expect("backdate");
    sqlx::query("UPDATE users SET first_login_at = now() - interval '400 days'")
        .execute(&r.h.state.db)
        .await
        .expect("users");
    // The same policy again, then a change to `ops` alone.
    r.apply(POLICY).await;
    let changed = POLICY.replace("logins: [ubuntu, root]", "logins: [ubuntu, root, deploy]");
    assert_ne!(changed, POLICY);
    r.apply(&changed).await;
    let s = r.suggest(&r.admin, 90).await.expect("suggest");
    assert!(
        s.yaml.contains("name: dba"),
        "dba never changed: {}",
        s.yaml
    );
    assert!(
        !s.yaml.contains("name: ops"),
        "ops just changed: {}",
        s.yaml
    );
}

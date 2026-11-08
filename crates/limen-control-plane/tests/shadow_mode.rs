//! Shadow mode on the write path (ADR-0046). Set `LIMEN_TEST_DATABASE_URL`
//! to run them.
//!
//! Moving a deny rule to shadow, or giving a shadow rule more time, is
//! loosening: it waits for a second admin whatever `--widening-approval`
//! says (here the default). Dates that have passed or are too far ahead are
//! refused. Tightening applies at once.

mod common;

use common::{Harness, forwarded};
use limen_policy::shadow::ShadowDate;
use limen_proto::manage::v1 as pb;
use limen_proto::manage::v1::management_service_client::ManagementServiceClient;
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, ApplyPolicyResponse, PolicySource};
use limen_testkit::users::{ADMIN, ONCALL};
use rustls_pki_types::CertificateDer;
use time::{Duration, OffsetDateTime};

const BASE: &str = r"
kind: resource
version: v1
metadata: { name: web-prod, labels: { env: prod } }
spec: { ssh: { address: 'h:22' } }
---
kind: role_mapping
version: v1
metadata: { name: shadow-test }
spec:
  - { idp_group: admins, roles: ['limen:admin'] }
  - { idp_group: developers, roles: [shadow-dev] }
---
kind: role
version: v1
metadata: { name: shadow-dev }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [ubuntu, root] }
  deny:
    - name: no-root
      MODE
      resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [root] }
";

/// The policy with the deny rule enforced (`None`) or in shadow until `until`.
fn policy(until: Option<time::Date>) -> String {
    let mode = until.map_or(String::new(), |d| {
        format!("mode: shadow\n      shadow_until: {}", ShadowDate(d))
    });
    BASE.replace("MODE", &mode)
}

fn in_days(n: i64) -> time::Date {
    (OffsetDateTime::now_utc() + Duration::days(n)).date()
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
    async fn apply(&self, content: String) -> Result<ApplyPolicyResponse, tonic::Status> {
        AdminClient::new(self.h.channel(Some(self.proxy.clone())))
            .apply_policy(forwarded(
                ApplyPolicyRequest {
                    source: String::new(),
                    sources: vec![PolicySource {
                        name: "policy.yaml".into(),
                        content,
                    }],
                    dry_run: false,
                    source_ref: String::new(),
                    require_tests: false,
                },
                Some(&self.admin),
            ))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn approve(&self, id: &str) -> pb::PolicyChange {
        let (_, second) = self
            .h
            .login(ONCALL, &["admins"])
            .await
            .expect("second admin");
        ManagementServiceClient::new(self.h.channel(Some(self.proxy.clone())))
            .approve_change(forwarded(
                pb::ApproveChangeRequest {
                    id: id.into(),
                    note: "looked at it".into(),
                },
                Some(&second),
            ))
            .await
            .expect("approve")
            .into_inner()
            .change
            .expect("change")
    }

    async fn shadow_rules(&self) -> usize {
        self.h
            .state
            .policy
            .refresh(&self.h.state.db)
            .await
            .expect("refresh");
        self.h.state.policy.base().policy.shadow_rules().len()
    }
}

#[tokio::test]
async fn shadow_mode_loosens_only_with_a_second_admin() {
    let Some(f) = Box::pin(start()).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let first = f.apply(policy(None)).await.expect("enforced policy");
    assert!(first.applied);
    assert_eq!(f.shadow_rules().await, 0);

    // Enforce to shadow: held, nothing applied.
    let held = f
        .apply(policy(Some(in_days(30))))
        .await
        .expect("held, not refused");
    assert!(!held.applied, "loosening waits");
    assert_ne!(held.pending_change_id, "");
    assert_eq!(f.shadow_rules().await, 0, "still enforced");

    // A second admin approves it, and the rule is in shadow.
    let applied = f.approve(&held.pending_change_id).await;
    assert_eq!(applied.state, i32::from(pb::policy_change::State::Applied));
    assert_eq!(f.shadow_rules().await, 1);

    // More time is loosening too.
    let longer = f
        .apply(policy(Some(in_days(45))))
        .await
        .expect("held, not refused");
    assert!(!longer.applied);
    assert_ne!(longer.pending_change_id, "");

    // The same date again changes nothing; a shorter one tightens at once.
    let same = f.apply(policy(Some(in_days(30)))).await.expect("same");
    assert_eq!(same.pending_change_id, "");
    let shorter = f.apply(policy(Some(in_days(10)))).await.expect("shorter");
    assert!(shorter.applied);
    assert_eq!(shorter.pending_change_id, "");

    // Back to enforced: tightening applies at once.
    let back = f.apply(policy(None)).await.expect("enforce again");
    assert!(back.applied);
    assert_eq!(back.pending_change_id, "");
    assert_eq!(f.shadow_rules().await, 0);
}

#[tokio::test]
async fn dates_that_have_passed_or_are_too_far_off_are_refused() {
    let Some(f) = Box::pin(start()).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    f.apply(policy(None)).await.expect("enforced policy");
    for (days, why) in [(-1, "has passed"), (91, "days away")] {
        let err = f
            .apply(policy(Some(in_days(days))))
            .await
            .expect_err("refused");
        assert!(err.message().contains(why), "{days}: {}", err.message());
    }
    // The last allowed day is fine (and held, being loosening).
    let edge = f.apply(policy(Some(in_days(90)))).await.expect("90 days");
    assert_ne!(edge.pending_change_id, "");
}

//! Discovered resources (ADR-0027) against a real PostgreSQL. Set
//! `LIMEN_TEST_DATABASE_URL` to run them.

// A whole control plane is started in each test.
#![allow(clippy::large_futures, clippy::assert_is_empty)]

mod common;

use std::collections::HashMap;

use common::{Harness, csr, forwarded, new_key};
use limen_audit::EventKind;
use limen_control_plane::discovery;
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::discovery_client::DiscoveryClient;
use limen_proto::v1::enrollment_client::EnrollmentClient;
use limen_proto::v1::resources_client::ResourcesClient;
use limen_proto::v1::{
    DiscoveredItem, EnrollRequest, ListDiscoveredRequest, ListResourcesRequest,
    ReportDiscoveryRequest, ReviewDiscoveredRequest, ScanScope,
};
use limen_testkit::users::{ADMIN, ONCALL};
use limen_tunnel::tls::Identity;
use rustls_pki_types::CertificateDer;
use tonic::{Code, transport::Channel};

const WORKER_TOKEN: &str = "static-worker-token-0123456789abcdef0123456789";
const HOST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

const POLICY: &str = r"
kind: discovery
version: v1
metadata: { name: aws-prod }
spec:
  provider: aws
  accounts: [{ role_arn: 'arn:aws:iam::111122223333:role/limen-discovery' }]
  regions: [eu-west-1]
  worker_selector: { pool: prod }
  auto_accept: [team]
  stale_after_cycles: 2
  match:
    - type: ec2
      tags: { limen/managed: ['true'] }
      labels_from_tags: [env, team]
---
kind: resource
version: v1
metadata: { name: taken, labels: { env: ops } }
spec: { ssh: { address: '10.9.9.9:22', host_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' } }
---
kind: role
version: v1
metadata: { name: sre }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [ubuntu] }
---
kind: role_mapping
version: v1
metadata: { name: m }
spec:
  - { idp_group: sre-group, roles: [sre] }
";

struct Rig {
    h: Harness,
    proxy_ch: Channel,
    worker_ch: Channel,
    admin: CertificateDer<'static>,
    sre: CertificateDer<'static>,
}

async fn rig() -> Option<Rig> {
    let h = Harness::start_with(&[format!(
        "--static-join-token=proxy:{},worker:{WORKER_TOKEN}:pool=prod",
        common::STATIC_PROXY_TOKEN
    )])
    .await?;
    h.set_policy(&[("p.yaml", POLICY)]);
    let (_, proxy) = h.enroll_proxy().await;
    let proxy_ch = h.channel(Some(proxy));
    // A worker in the `prod` pool.
    let key = new_key();
    let resp = EnrollmentClient::new(h.channel(None))
        .enroll(EnrollRequest {
            join_token: WORKER_TOKEN.into(),
            csr_der: csr(&key),
            kind: "worker".into(),
            dns_names: vec![],
            name: String::new(),
        })
        .await
        .expect("enroll worker")
        .into_inner();
    let worker = Identity::from_pem(&resp.cert_pem, &key.serialize_pem()).expect("identity");
    let worker_ch = h.channel(Some(worker));
    let (_, admin) = h.login(ADMIN, &["admins"]).await.expect("admin");
    let (_, sre) = h.login(ONCALL, &["sre-group"]).await.expect("sre");
    Some(Rig {
        h,
        proxy_ch,
        worker_ch,
        admin,
        sre,
    })
}

fn item(id: &str, tags: &[(&str, &str)], host_key: bool) -> DiscoveredItem {
    let mut t: HashMap<String, String> =
        HashMap::from([("limen/managed".to_owned(), "true".to_owned())]);
    t.extend(tags.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())));
    DiscoveredItem {
        matcher: 0,
        source: "ec2".into(),
        account: "111122223333".into(),
        region: "eu-west-1".into(),
        provider_id: id.into(),
        target: format!("10.0.1.{}:22", id.len()),
        tags: t,
        facts: if host_key {
            HashMap::from([("host_key".to_owned(), HOST_KEY.to_owned())])
        } else {
            HashMap::new()
        },
    }
}

fn scope() -> ScanScope {
    ScanScope {
        matcher: 0,
        account: "111122223333".into(),
        region: "eu-west-1".into(),
    }
}

impl Rig {
    async fn report(
        &self,
        items: Vec<DiscoveredItem>,
        complete: bool,
    ) -> Result<limen_proto::v1::ReportDiscoveryResponse, tonic::Status> {
        DiscoveryClient::new(self.worker_ch.clone())
            .report(ReportDiscoveryRequest {
                document: "aws-prod".into(),
                items,
                complete: if complete { vec![scope()] } else { vec![] },
            })
            .await
            .map(tonic::Response::into_inner)
    }

    async fn list(&self, state: &str) -> Vec<limen_proto::v1::DiscoveredInfo> {
        AdminClient::new(self.proxy_ch.clone())
            .list_discovered(forwarded(
                ListDiscoveredRequest {
                    state: state.into(),
                },
                Some(&self.admin),
            ))
            .await
            .expect("list")
            .into_inner()
            .items
    }

    async fn review(
        &self,
        key: &str,
        accept: bool,
    ) -> Result<limen_proto::v1::DiscoveredInfo, tonic::Status> {
        AdminClient::new(self.proxy_ch.clone())
            .review_discovered(forwarded(
                ReviewDiscoveredRequest {
                    key: key.into(),
                    accept,
                    note: "checked".into(),
                },
                Some(&self.admin),
            ))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn visible_to_sre(&self) -> Vec<String> {
        ResourcesClient::new(self.proxy_ch.clone())
            .list_resources(forwarded(ListResourcesRequest {}, Some(&self.sre)))
            .await
            .expect("ls")
            .into_inner()
            .resources
            .into_iter()
            .map(|r| r.name)
            .collect()
    }
}

#[tokio::test]
async fn a_new_resource_waits_for_an_admin_and_reaches_nobody_until_accepted() {
    let Some(r) = rig().await else { return };
    let kept = r
        .report(
            vec![item("i-0aaa", &[("Name", "Web 1"), ("env", "prod")], true)],
            true,
        )
        .await
        .expect("report");
    assert_eq!((kept.accepted, kept.dropped), (1, 0));

    // Pending: known to admins, in nobody's policy, reachable by no one.
    let listed = r.list("").await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].state, "pending");
    assert_eq!(listed[0].name, "web-1");
    assert_eq!(listed[0].labels["env"], "prod");
    assert_eq!(listed[0].labels["limen.io/discovered"], "true");
    assert!(
        r.h.state
            .policy
            .current()
            .policy
            .resource("web-1")
            .is_none()
    );
    assert!(
        r.visible_to_sre().await.is_empty(),
        "the role selects env=prod, but it isn't accepted"
    );

    // An admin accepts it. Now policy has it, and the role selects it as usual.
    let accepted = r.review(&listed[0].key, true).await.expect("accept");
    assert_eq!(accepted.state, "accepted");
    assert_eq!(accepted.accepted_by, ADMIN);
    assert!(
        r.h.state
            .policy
            .current()
            .policy
            .resource("web-1")
            .is_some()
    );
    assert!(
        r.h.state.policy.base().policy.resource("web-1").is_none(),
        "applied policy is untouched"
    );
    assert_eq!(r.visible_to_sre().await, ["web-1"]);

    // Its worker selector is the document's: only prod-pool workers serve it.
    let res = r.h.state.policy.current();
    let doc = res.policy.resource("web-1").expect("resource");
    assert_eq!(doc.spec.worker_selector.get("pool"), Some("prod"));

    let kinds = r.h.audit_kinds().await;
    assert!(kinds.contains(&EventKind::ResourceDiscovered), "{kinds:?}");
    assert!(kinds.contains(&EventKind::ResourceReview));
}

#[tokio::test]
async fn a_changed_label_waits_and_the_old_ones_stay_in_force() {
    let Some(r) = rig().await else { return };
    r.report(
        vec![item(
            "i-0aaa",
            &[("Name", "Web 1"), ("env", "prod"), ("team", "a")],
            true,
        )],
        true,
    )
    .await
    .expect("report");
    let key = r.list("").await[0].key.clone();
    r.review(&key, true).await.expect("accept");
    assert_eq!(r.visible_to_sre().await, ["web-1"]);

    // Someone retags the instance env=staging: the role no longer matches it,
    // but only once an admin accepts. Until then it is as accepted.
    r.report(
        vec![item(
            "i-0aaa",
            &[("Name", "Web 1"), ("env", "staging"), ("team", "a")],
            true,
        )],
        true,
    )
    .await
    .expect("retag");
    let info = &r.list("").await[0];
    assert!(info.change_pending);
    assert!(
        info.changes
            .iter()
            .any(|c| c.contains("env: prod → staging")),
        "{:?}",
        info.changes
    );
    assert_eq!(
        r.visible_to_sre().await,
        ["web-1"],
        "the accepted labels are in force"
    );
    assert_eq!(
        r.h.state
            .policy
            .current()
            .policy
            .resource("web-1")
            .expect("r")
            .metadata
            .labels
            .get("env"),
        Some("prod")
    );
    // The same report again says nothing new.
    r.report(
        vec![item(
            "i-0aaa",
            &[("Name", "Web 1"), ("env", "staging"), ("team", "a")],
            true,
        )],
        true,
    )
    .await
    .expect("again");
    let relabels =
        r.h.audit_events()
            .await
            .into_iter()
            .filter(|e| e.kind == EventKind::ResourceRelabel)
            .count();
    assert_eq!(relabels, 1, "announced once");
    // The admin accepts the change.
    r.review(&key, true).await.expect("accept the change");
    assert!(r.visible_to_sre().await.is_empty(), "now it's env=staging");
    assert!(!r.list("").await[0].change_pending);
}

#[tokio::test]
async fn only_keys_the_document_auto_accepts_change_without_an_admin() {
    let Some(r) = rig().await else { return };
    r.report(
        vec![item(
            "i-0aaa",
            &[("Name", "Web 1"), ("env", "prod"), ("team", "a")],
            true,
        )],
        true,
    )
    .await
    .expect("report");
    let key = r.list("").await[0].key.clone();
    r.review(&key, true).await.expect("accept");
    r.report(
        vec![item(
            "i-0aaa",
            &[("Name", "Web 1"), ("env", "prod"), ("team", "b")],
            true,
        )],
        true,
    )
    .await
    .expect("team changes");
    assert!(!r.list("").await[0].change_pending, "team is auto_accept");
    assert_eq!(
        r.h.state
            .policy
            .current()
            .policy
            .resource("web-1")
            .expect("r")
            .metadata
            .labels
            .get("team"),
        Some("b")
    );
    let auto =
        r.h.audit_events()
            .await
            .into_iter()
            .find(|e| e.kind == EventKind::ResourceRelabel)
            .expect("still audited");
    assert_eq!(auto.data["auto"], true);
    // A new address is never automatic.
    let mut moved = item(
        "i-0aaa",
        &[("Name", "Web 1"), ("env", "prod"), ("team", "b")],
        true,
    );
    moved.target = "10.66.6.6:22".into();
    r.report(vec![moved], true).await.expect("moved");
    assert!(r.list("").await[0].change_pending);
    assert_eq!(
        r.h.state
            .policy
            .current()
            .policy
            .resource("web-1")
            .expect("r")
            .spec
            .ssh
            .as_ref()
            .expect("ssh")
            .address,
        "10.0.1.6:22",
        "the accepted address stays until an admin agrees"
    );
}

#[tokio::test]
async fn a_report_can_only_say_what_the_document_asks_for() {
    let Some(r) = rig().await else { return };
    let mut wrong_region = item("i-1", &[("Name", "a")], true);
    wrong_region.region = "us-east-1".into();
    let mut wrong_account = item("i-2", &[("Name", "b")], true);
    wrong_account.account = "999999999999".into();
    let mut untagged = item("i-3", &[("Name", "c")], true);
    untagged.tags.remove("limen/managed");
    let mut wrong_source = item("i-4", &[("Name", "d")], true);
    wrong_source.source = "rds".into();
    let mut unknown_source = item("i-5", &[], true);
    unknown_source.source = "lambda".into();
    let good = item("i-6", &[("Name", "e")], true);
    let resp = r
        .report(
            vec![
                wrong_region,
                wrong_account,
                untagged,
                wrong_source,
                unknown_source,
                good,
            ],
            false,
        )
        .await
        .expect("report");
    assert_eq!((resp.accepted, resp.dropped), (1, 5));
    assert_eq!(r.list("").await.len(), 1);
    // A worker outside the document's pool can't report for it.
    let key = new_key();
    let other = EnrollmentClient::new(r.h.channel(None))
        .enroll(EnrollRequest {
            join_token: common::STATIC_PROXY_TOKEN.into(),
            csr_der: csr(&key),
            kind: "proxy".into(),
            dns_names: vec!["localhost".into()],
            name: String::new(),
        })
        .await
        .expect("a proxy");
    let proxy =
        Identity::from_pem(&other.into_inner().cert_pem, &key.serialize_pem()).expect("identity");
    // A proxy isn't a worker.
    let err = DiscoveryClient::new(r.h.channel(Some(proxy)))
        .report(ReportDiscoveryRequest {
            document: "aws-prod".into(),
            items: vec![],
            complete: vec![],
        })
        .await
        .expect_err("proxy");
    assert_eq!(err.code(), Code::PermissionDenied);
    // Unknown documents and anonymous callers are refused.
    let err = DiscoveryClient::new(r.worker_ch.clone())
        .report(ReportDiscoveryRequest {
            document: "nope".into(),
            items: vec![],
            complete: vec![],
        })
        .await
        .expect_err("unknown");
    assert_eq!(err.code(), Code::NotFound);
    let err = DiscoveryClient::new(r.h.channel(None))
        .report(ReportDiscoveryRequest {
            document: "aws-prod".into(),
            items: vec![],
            complete: vec![],
        })
        .await
        .expect_err("anonymous");
    assert_eq!(err.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn only_admins_review() {
    let Some(r) = rig().await else { return };
    r.report(
        vec![item("i-0aaa", &[("Name", "Web 1"), ("env", "prod")], true)],
        true,
    )
    .await
    .expect("report");
    let key = r.list("").await[0].key.clone();
    let err = AdminClient::new(r.proxy_ch.clone())
        .review_discovered(forwarded(
            ReviewDiscoveredRequest {
                key,
                accept: true,
                note: String::new(),
            },
            Some(&r.sre),
        ))
        .await
        .expect_err("not an admin");
    assert_eq!(err.code(), Code::PermissionDenied);
    let err = r
        .review("aws:1:x:ec2:nope", true)
        .await
        .expect_err("unknown");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn names_never_collide_and_an_instance_without_a_host_key_cannot_be_accepted() {
    let Some(r) = rig().await else { return };
    // Two instances called "Web 1", and one called like a static resource.
    r.report(
        vec![
            item("i-0aaa111", &[("Name", "Web 1"), ("env", "prod")], true),
            item("i-0bbb222", &[("Name", "Web 1"), ("env", "prod")], true),
            item("i-0ccc333", &[("Name", "taken"), ("env", "prod")], true),
            item("i-0ddd444", &[("Name", "No Key"), ("env", "prod")], false),
        ],
        true,
    )
    .await
    .expect("report");
    let names: std::collections::BTreeSet<String> =
        r.list("").await.into_iter().map(|i| i.name).collect();
    assert_eq!(names.len(), 4, "{names:?}");
    assert!(names.contains("web-1"));
    assert!(names.iter().any(|n| n.starts_with("web-1-")));
    assert!(
        names.iter().any(|n| n.starts_with("taken-")),
        "the static name is left alone: {names:?}"
    );
    let blocked = r
        .list("")
        .await
        .into_iter()
        .find(|i| !i.blockers.is_empty())
        .expect("blocked");
    let err = r.review(&blocked.key, true).await.expect_err("blocked");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err.message().contains("host key"), "{}", err.message());
}

#[tokio::test]
async fn rejecting_keeps_it_out_and_it_stays_rejected_when_seen_again() {
    let Some(r) = rig().await else { return };
    r.report(
        vec![item("i-0aaa", &[("Name", "Web 1"), ("env", "prod")], true)],
        true,
    )
    .await
    .expect("report");
    let key = r.list("").await[0].key.clone();
    assert_eq!(
        r.review(&key, false).await.expect("reject").state,
        "rejected"
    );
    r.report(
        vec![item("i-0aaa", &[("Name", "Web 1"), ("env", "prod")], true)],
        true,
    )
    .await
    .expect("again");
    assert_eq!(r.list("").await[0].state, "rejected");
    assert!(r.visible_to_sre().await.is_empty());
}

#[tokio::test]
async fn what_stops_being_seen_goes_stale_fails_closed_and_is_removed_after_a_while() {
    let Some(r) = rig().await else { return };
    r.report(
        vec![item("i-0aaa", &[("Name", "Web 1"), ("env", "prod")], true)],
        true,
    )
    .await
    .expect("report");
    let key = r.list("").await[0].key.clone();
    r.review(&key, true).await.expect("accept");
    assert_eq!(r.visible_to_sre().await, ["web-1"]);

    // A scan that did not finish proves nothing about what is missing.
    r.report(vec![], false).await.expect("partial scan");
    r.report(vec![], false).await.expect("partial scan");
    assert_eq!(r.list("").await[0].missed_cycles, 0);
    assert_eq!(r.visible_to_sre().await, ["web-1"]);

    // Two complete scans without it (stale_after_cycles: 2).
    r.report(vec![], true).await.expect("scan 1");
    assert_eq!(r.list("").await[0].state, "accepted", "once is not enough");
    r.report(vec![], true).await.expect("scan 2");
    assert_eq!(r.list("").await[0].state, "stale");
    assert!(r.visible_to_sre().await.is_empty(), "stale means refused");
    assert!(
        r.h.state
            .policy
            .current()
            .policy
            .resource("web-1")
            .is_none()
    );
    assert!(r.h.audit_kinds().await.contains(&EventKind::ResourceStale));

    // Seen again: back, as it was accepted.
    r.report(
        vec![item("i-0aaa", &[("Name", "Web 1"), ("env", "prod")], true)],
        true,
    )
    .await
    .expect("back");
    assert_eq!(r.list("").await[0].state, "accepted");
    assert_eq!(r.visible_to_sre().await, ["web-1"]);

    // Stale again, and past its time: kept while a session is open, then removed.
    r.report(vec![], true).await.expect("scan 1");
    r.report(vec![], true).await.expect("scan 2");
    sqlx::query("UPDATE discovered_resources SET stale_since = now() - interval '8 days'")
        .execute(&r.h.state.db)
        .await
        .expect("age it");
    let session = uuid::Uuid::now_v7();
    sqlx::query("INSERT INTO sessions (session_id, username, resource, started_at) VALUES ($1, $2, 'web-1', now())")
        .bind(session)
        .bind(ONCALL)
        .execute(&r.h.state.db)
        .await
        .expect("an open session");
    discovery::sweep(&r.h.state).await.expect("sweep");
    assert_eq!(
        r.list("").await.len(),
        1,
        "never removed from under an open session"
    );
    sqlx::query("UPDATE sessions SET ended_at = now() WHERE session_id = $1")
        .bind(session)
        .execute(&r.h.state.db)
        .await
        .expect("end it");
    discovery::sweep(&r.h.state).await.expect("sweep");
    assert!(r.list("").await.is_empty());
}

#[tokio::test]
async fn removing_the_document_takes_its_resources_out_of_policy() {
    let Some(r) = rig().await else { return };
    r.report(
        vec![item("i-0aaa", &[("Name", "Web 1"), ("env", "prod")], true)],
        true,
    )
    .await
    .expect("report");
    let key = r.list("").await[0].key.clone();
    r.review(&key, true).await.expect("accept");
    assert_eq!(r.visible_to_sre().await, ["web-1"]);
    // Policy no longer has the discovery document.
    let without = POLICY.split("---").skip(1).collect::<Vec<_>>().join("---");
    r.h.set_policy(&[("p.yaml", &without)]);
    discovery::refresh_overlay(&r.h.state)
        .await
        .expect("refresh");
    assert!(
        r.visible_to_sre().await.is_empty(),
        "no document, no discovered resources"
    );
}

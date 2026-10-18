//! Optional names for proxies and workers (Phase 5, Task 8b): approved by
//! the join token, validated and unique among live components, and recorded
//! in the certificate as the `limen.io/name` label.
//! Set `LIMEN_TEST_DATABASE_URL` to run them.

mod common;

use std::collections::{BTreeMap, HashMap};

use common::{Harness, csr, forwarded, new_key};
use limen_audit::EventKind;
use limen_ca::verify::verify_component;
use limen_core::names::NAME_LABEL;
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::enrollment_client::EnrollmentClient;
use limen_proto::v1::registry_client::RegistryClient;
use limen_proto::v1::{
    CreateJoinTokenRequest, EnrollRequest, EnrollResponse, ListComponentsRequest,
    ListTunnelsRequest, RenewCertificateRequest, ReportTunnelsRequest, RevokeComponentRequest,
    TunnelReport,
};
use limen_testkit::users::ADMIN;
use limen_tunnel::tls::Identity;
use rustls_pki_types::CertificateDer;
use tonic::Code;

const STATIC_WORKER_TOKEN: &str = "static-worker-token-0123456789abcdef0123456789";

/// A deployment with an enrolled proxy (to relay) and an admin.
struct Fixture {
    h: Harness,
    proxy: Identity,
    admin: CertificateDer<'static>,
}

impl Fixture {
    async fn start(extra: &[String]) -> Option<Self> {
        let h = Harness::start_with(extra).await?;
        let (_, proxy) = h.enroll_proxy().await;
        let (_, admin) = h.login(ADMIN, &["admins"]).await.expect("admin");
        Some(Self { h, proxy, admin })
    }

    fn admin_client(&self) -> AdminClient<tonic::transport::Channel> {
        AdminClient::new(self.h.channel(Some(self.proxy.clone())))
    }

    async fn try_token(&self, name: &str) -> Result<String, tonic::Status> {
        self.admin_client()
            .create_join_token(forwarded(
                CreateJoinTokenRequest {
                    kind: "worker".into(),
                    ttl_seconds: 300,
                    labels: HashMap::from([("pool".to_owned(), "dev".to_owned())]),
                    dns_names: vec![],
                    name: name.into(),
                },
                Some(&self.admin),
            ))
            .await
            .map(|r| r.into_inner().token)
    }

    async fn token(&self, name: &str) -> String {
        self.try_token(name).await.expect("token")
    }

    async fn enroll(&self, token: &str, name: &str) -> Result<EnrollResponse, tonic::Status> {
        EnrollmentClient::new(self.h.channel(Some(self.proxy.clone())))
            .enroll(forwarded(
                EnrollRequest {
                    join_token: token.into(),
                    csr_der: csr(&new_key()),
                    kind: "worker".into(),
                    dns_names: vec![],
                    name: name.into(),
                },
                None,
            ))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn components(&self) -> Vec<limen_proto::v1::Component> {
        self.admin_client()
            .list_components(forwarded(ListComponentsRequest {}, Some(&self.admin)))
            .await
            .expect("list")
            .into_inner()
            .components
    }

    async fn revoke(&self, id: &str) {
        self.admin_client()
            .revoke_component(forwarded(
                RevokeComponentRequest {
                    component_id: id.into(),
                    reason: "test".into(),
                },
                Some(&self.admin),
            ))
            .await
            .expect("revoke");
    }

    /// The `auth.denied` events for enrollment, as their `data`.
    async fn enroll_denials(&self) -> Vec<serde_json::Value> {
        self.h
            .audit_events()
            .await
            .into_iter()
            .filter(|e| e.kind == EventKind::AuthDenied && e.data["action"] == "enroll")
            .map(|e| e.data)
            .collect()
    }

    fn cert_labels(&self, resp: &EnrollResponse) -> BTreeMap<String, String> {
        let der = limen_tunnel::tls::certs_from_pem(&resp.cert_pem)
            .expect("cert")
            .remove(0);
        verify_component(&der, self.h.state.cas.internal.cert_der(), false)
            .expect("component cert")
            .labels
    }
}

#[tokio::test]
async fn exact_name_is_certified_listed_and_audited() {
    let Some(f) = Box::pin(Fixture::start(&[])).await else {
        return;
    };
    let token = f.token("prod-a-worker-1").await;
    let resp = f
        .enroll(&token, "prod-a-worker-1")
        .await
        .expect("enroll with the approved name");
    assert_eq!(resp.name, "prod-a-worker-1");
    assert_eq!(
        resp.labels.get(NAME_LABEL).map(String::as_str),
        Some("prod-a-worker-1")
    );
    // Certified: in the certificate, as a label, next to the token's labels.
    let labels = f.cert_labels(&resp);
    assert_eq!(
        labels.get(NAME_LABEL).map(String::as_str),
        Some("prod-a-worker-1")
    );
    assert_eq!(labels.get("pool").map(String::as_str), Some("dev"));

    // The name is a certified label but never an access decision: policy
    // refuses a selector on it, and the matcher ignores it even if one gets
    // through (an older stored policy).
    let err = limen_policy::Policy::parse_yaml([(
        "p.yaml",
        r#"
kind: resource
version: v1
metadata: { name: by-name }
spec:
  ssh: { address: "10.0.0.1:22" }
  worker_selector: { limen.io/name: prod-a-worker-1 }
"#,
    )])
    .expect_err("policy can't select on a name");
    assert!(err.to_string().contains("limen.io/name"), "{err}");
    let policy = limen_policy::Policy::parse_yaml([(
        "p.yaml",
        r#"
kind: resource
version: v1
metadata: { name: by-pool }
spec:
  ssh: { address: "10.0.0.1:22" }
  worker_selector: { pool: dev }
"#,
    )])
    .expect("policy");
    assert!(policy.worker_may_serve("by-pool", &labels));

    let listed = f.components().await;
    let w = listed
        .iter()
        .find(|c| c.id == resp.component_id)
        .expect("listed");
    assert_eq!(w.name, "prod-a-worker-1");

    let enroll = f
        .h
        .audit_events()
        .await
        .into_iter()
        .find(|e| e.kind == EventKind::WorkerEnroll && e.data["component_id"] == resp.component_id)
        .expect("enroll audited");
    assert_eq!(enroll.data["component_name"], "prod-a-worker-1");

    // Renewal keeps the name in the certificate.
    let der = limen_tunnel::tls::certs_from_pem(&resp.cert_pem)
        .expect("cert")
        .remove(0);
    let renewed = EnrollmentClient::new(f.h.channel(Some(f.proxy.clone())))
        .renew_certificate(forwarded(
            RenewCertificateRequest {
                csr_der: csr(&new_key()),
            },
            Some(&der),
        ))
        .await
        .expect("renew")
        .into_inner();
    let renewed_der = limen_tunnel::tls::certs_from_pem(&renewed.cert_pem)
        .expect("cert")
        .remove(0);
    let renewed_id = verify_component(&renewed_der, f.h.state.cas.internal.cert_der(), false)
        .expect("renewed cert");
    assert_eq!(
        renewed_id.labels.get(NAME_LABEL).map(String::as_str),
        Some("prod-a-worker-1")
    );
}

#[tokio::test]
async fn exact_single_use_name_is_given_without_asking() {
    let Some(f) = Box::pin(Fixture::start(&[])).await else {
        return;
    };
    let token = f.token("edge-7").await;
    let resp = f.enroll(&token, "").await.expect("enroll");
    assert_eq!(resp.name, "edge-7");
    assert_eq!(
        f.cert_labels(&resp).get(NAME_LABEL).map(String::as_str),
        Some("edge-7")
    );
}

#[tokio::test]
async fn pattern_approves_matching_names_only() {
    let Some(f) = Box::pin(Fixture::start(&[])).await else {
        return;
    };
    let token = f.token("prod-a-*").await;
    for bad in ["prod-b-1", "prod-a"] {
        let err = f.enroll(&token, bad).await.expect_err("not approved");
        assert_eq!(err.code(), Code::PermissionDenied, "{bad}: {err:?}");
        assert!(err.message().contains("not approved"), "{err:?}");
    }
    let denials = f.enroll_denials().await;
    assert_eq!(denials.len(), 2, "both refusals are audited: {denials:?}");
    assert!(
        denials
            .iter()
            .all(|d| d["reason"] == "name not approved by join token")
    );
    assert_eq!(denials[0]["name"], "prod-b-1");

    // The refusals did not use up the single-use token.
    let resp = f.enroll(&token, "prod-a-1").await.expect("matching name");
    assert_eq!(resp.name, "prod-a-1");

    // With a pattern, no name asked for means no name.
    let resp = f
        .enroll(&f.token("prod-a-*").await, "")
        .await
        .expect("no name");
    assert_eq!(resp.name, "");
    assert!(!resp.labels.contains_key(NAME_LABEL));
}

#[tokio::test]
async fn name_without_approval_is_refused_and_audited() {
    let Some(f) = Box::pin(Fixture::start(&[])).await else {
        return;
    };
    let token = f.token("").await;
    let err = f
        .enroll(&token, "sneaky-1")
        .await
        .expect_err("no name approved");
    assert_eq!(err.code(), Code::PermissionDenied);
    let denials = f.enroll_denials().await;
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0]["reason"], "name not approved by join token");
    assert_eq!(denials[0]["name"], "sneaky-1");
    // An exact token refuses another name too.
    let exact = f.token("edge-1").await;
    let err = f.enroll(&exact, "edge-2").await.expect_err("other name");
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn no_name_enrollment_is_unchanged() {
    let Some(f) = Box::pin(Fixture::start(&[])).await else {
        return;
    };
    let resp = f.enroll(&f.token("").await, "").await.expect("enroll");
    assert_eq!(resp.name, "");
    assert_eq!(
        resp.labels.into_iter().collect::<BTreeMap<_, _>>(),
        BTreeMap::from([("pool".to_owned(), "dev".to_owned())])
    );
    let w = f
        .components()
        .await
        .into_iter()
        .find(|c| c.id == resp.component_id)
        .expect("listed");
    assert_eq!(w.name, "");
    // Several nameless components coexist (NULL names are never unique-checked).
    f.enroll(&f.token("").await, "").await.expect("second");
}

#[tokio::test]
async fn invalid_names_are_refused() {
    let Some(f) = Box::pin(Fixture::start(&[])).await else {
        return;
    };
    let token = f.token("*").await;
    for bad in [
        "Prod-1",
        &"a".repeat(64),
        "-lead",
        "trail-",
        " ",
        "w\u{f6}rker",
        "a_b",
    ] {
        let err = f.enroll(&token, bad).await.expect_err("invalid");
        assert_eq!(err.code(), Code::InvalidArgument, "{bad:?}: {err:?}");
    }
    // The token is still good.
    f.enroll(&token, "fine-1").await.expect("valid name");

    // Tokens with invalid patterns, or the name set as a label, are refused.
    for bad in ["Prod-*", "a*b*", "-x", "a_*"] {
        let err = f.try_token(bad).await.expect_err("invalid pattern");
        assert_eq!(err.code(), Code::InvalidArgument, "{bad:?}");
    }
    let err = f
        .admin_client()
        .create_join_token(forwarded(
            CreateJoinTokenRequest {
                kind: "worker".into(),
                ttl_seconds: 300,
                labels: HashMap::from([(NAME_LABEL.to_owned(), "x".to_owned())]),
                dns_names: vec![],
                name: String::new(),
            },
            Some(&f.admin),
        ))
        .await
        .expect_err("reserved label");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn duplicate_live_name_is_refused_without_using_the_token_and_freed_by_revoke() {
    let Some(f) = Box::pin(Fixture::start(&[format!(
        "--static-join-token=proxy:{}:limen.io/name=*",
        common::STATIC_PROXY_TOKEN
    )]))
    .await
    else {
        return;
    };
    let first = f
        .enroll(&f.token("dup-*").await, "dup-1")
        .await
        .expect("first");
    let second_token = f.token("dup-*").await;
    let err = f
        .enroll(&second_token, "dup-1")
        .await
        .expect_err("name in use");
    assert_eq!(err.code(), Code::AlreadyExists, "{err:?}");
    assert!(err.message().contains("dup-1"), "{err:?}");
    // Proxies and workers share the namespace.
    let err = EnrollmentClient::new(f.h.channel(None))
        .enroll(EnrollRequest {
            join_token: common::STATIC_PROXY_TOKEN.into(),
            csr_der: csr(&new_key()),
            kind: "proxy".into(),
            dns_names: vec!["localhost".into()],
            name: "dup-1".into(),
        })
        .await
        .expect_err("a proxy can't take a worker's name");
    assert_eq!(err.code(), Code::AlreadyExists, "{err:?}");
    // Both attempts on a live name are on the record, like any other
    // refused enrollment.
    let denials = f.enroll_denials().await;
    let in_use = denials
        .iter()
        .filter(|d| d["reason"] == "name already in use" && d["name"] == "dup-1")
        .count();
    assert_eq!(in_use, 2, "both conflicts are audited: {denials:?}");

    // The conflict rolled back: the single-use token still works.
    let other = f
        .enroll(&second_token, "dup-2")
        .await
        .expect("token not consumed by the conflict");
    assert_eq!(other.name, "dup-2");

    // Revoking frees the name.
    f.revoke(&first.component_id).await;
    let again = f
        .enroll(&f.token("dup-*").await, "dup-1")
        .await
        .expect("name reusable after revoke");
    assert_eq!(again.name, "dup-1");
    // Both rows keep their name for history.
    let listed = f.components().await;
    assert_eq!(listed.iter().filter(|c| c.name == "dup-1").count(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_enrollments_with_one_name_have_one_winner() {
    let Some(f) = Box::pin(Fixture::start(&[])).await else {
        return;
    };
    let mut tokens = Vec::new();
    for _ in 0..6 {
        tokens.push(f.token("race-*").await);
    }
    let results = futures::future::join_all(tokens.iter().map(|t| f.enroll(t, "race-1"))).await;
    let ok = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(ok, 1, "exactly one wins: {results:?}");
    for r in results.iter().filter_map(|r| r.as_ref().err()) {
        assert_eq!(r.code(), Code::AlreadyExists, "{r:?}");
    }
    // Every loser's token is still unused.
    let pending = limen_control_plane::db::list_pending_join_tokens(&f.h.state.db)
        .await
        .expect("pending");
    assert_eq!(pending.len(), 5);
    assert!(pending.iter().all(|t| t.name.as_deref() == Some("race-*")));
}

#[tokio::test]
async fn static_tokens_approve_patterns_and_registry_lists_names() {
    let Some(f) = Box::pin(Fixture::start(&[
        format!("--static-join-token=worker:{STATIC_WORKER_TOKEN}:pool=dev;limen.io/name=edge-*"),
        format!(
            "--static-join-token=proxy:{}:limen.io/name=gw-*",
            common::STATIC_PROXY_TOKEN
        ),
    ]))
    .await
    else {
        return;
    };
    let edge1 = f
        .enroll(STATIC_WORKER_TOKEN, "edge-1")
        .await
        .expect("edge-1");
    let edge2 = f
        .enroll(STATIC_WORKER_TOKEN, "edge-2")
        .await
        .expect("edge-2");
    assert_eq!(
        (edge1.name.as_str(), edge2.name.as_str()),
        ("edge-1", "edge-2")
    );
    let none = f.enroll(STATIC_WORKER_TOKEN, "").await.expect("no name");
    assert_eq!(none.name, "");
    // The pattern is not a label.
    assert_eq!(
        f.cert_labels(&none).into_iter().collect::<Vec<_>>(),
        vec![("pool".to_owned(), "dev".to_owned())]
    );
    let err = f
        .enroll(STATIC_WORKER_TOKEN, "core-1")
        .await
        .expect_err("not approved");
    assert_eq!(err.code(), Code::PermissionDenied);
    let err = f
        .enroll(STATIC_WORKER_TOKEN, "edge-1")
        .await
        .expect_err("in use");
    assert_eq!(err.code(), Code::AlreadyExists);

    // A named proxy reports a tunnel to a named worker: listings carry both names.
    let key = new_key();
    let resp = EnrollmentClient::new(f.h.channel(None))
        .enroll(EnrollRequest {
            join_token: common::STATIC_PROXY_TOKEN.into(),
            csr_der: csr(&key),
            kind: "proxy".into(),
            dns_names: vec!["localhost".into()],
            name: "gw-1".into(),
        })
        .await
        .expect("named proxy")
        .into_inner();
    assert_eq!(resp.name, "gw-1");
    let named_proxy = Identity::from_pem(&resp.cert_pem, &key.serialize_pem()).expect("identity");
    RegistryClient::new(f.h.channel(Some(named_proxy)))
        .report_tunnels(tonic::Request::new(ReportTunnelsRequest {
            tunnels: vec![TunnelReport {
                worker_id: edge1.component_id.clone(),
                tunnel_id: "t1".into(),
                active_sessions: 0,
                max_sessions: 0,
            }],
            peer_address: "10.0.0.9:3443".into(),
        }))
        .await
        .expect("report");
    let listed = RegistryClient::new(f.h.channel(Some(f.proxy.clone())))
        .list_tunnels(tonic::Request::new(ListTunnelsRequest {}))
        .await
        .expect("list tunnels")
        .into_inner()
        .tunnels;
    let tunnel = listed
        .iter()
        .find(|t| t.worker_id == edge1.component_id)
        .expect("tunnel listed");
    assert_eq!(
        (tunnel.worker_name.as_str(), tunnel.proxy_name.as_str()),
        ("edge-1", "gw-1")
    );
    let worker = f
        .components()
        .await
        .into_iter()
        .find(|c| c.id == edge1.component_id)
        .expect("worker");
    assert_eq!(worker.tunnels.len(), 1);
    assert_eq!(worker.tunnels[0].proxy_name, "gw-1");
}

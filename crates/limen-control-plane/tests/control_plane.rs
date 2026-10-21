//! Control plane integration tests against a real PostgreSQL and a mock IdP.
//! Set `LIMEN_TEST_DATABASE_URL` to run them.

mod common;

use common::{Harness, csr, forwarded, new_key};
use limen_audit::EventKind;
use limen_ca::verify::{verify_component, verify_user};
use limen_core::identity::ComponentKind;
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::auth_client::AuthClient;
use limen_proto::v1::enrollment_client::EnrollmentClient;
use limen_proto::v1::registry_client::RegistryClient;
use limen_proto::v1::resources_client::ResourcesClient;
use limen_proto::v1::{
    ApplyPolicyRequest, CreateJoinTokenRequest, EnrollRequest, ListComponentsRequest,
    ListResourcesRequest, ListTunnelsRequest, LoginFlow, PolicySource, RenewCertificateRequest,
    ReportTunnelsRequest, TunnelReport, WhoAmIRequest,
};
use limen_testkit::idp::Claims;
use limen_testkit::users::{ADMIN, DEVELOPER, GUEST};
use limen_tunnel::tls::Identity;
use tonic::Code;

const ROLES: &str = include_str!("../../../examples/policy/roles.yaml");
const MAPPINGS: &str = include_str!("../../../examples/policy/mappings.yaml");
const RESOURCES: &str = include_str!("../../../examples/policy/resources.yaml");

fn sources() -> Vec<PolicySource> {
    [
        ("roles.yaml", ROLES),
        ("mappings.yaml", MAPPINGS),
        ("resources.yaml", RESOURCES),
    ]
    .into_iter()
    .map(|(name, content)| PolicySource {
        name: name.into(),
        content: content.into(),
    })
    .collect()
}

#[tokio::test]
async fn pkce_login_issues_verified_short_lived_cert() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let (resp, der) = h.login(ADMIN, &["admins"]).await.expect("login");
    assert_eq!(resp.username, ADMIN);
    assert_eq!(resp.roles, ["limen:admin"]);
    let id =
        verify_user(&der, h.state.cas.user.cert_der()).expect("cert verifies against the user CA");
    assert_eq!(id.username, ADMIN);
    let ttl = resp.expires_at_unix - time::OffsetDateTime::now_utc().unix_timestamp();
    assert!(
        (540..=600).contains(&ttl),
        "default TTL is 10 minutes, got {ttl}s"
    );
    let login = h
        .audit_events()
        .await
        .into_iter()
        .find(|e| e.kind == EventKind::AuthLogin)
        .expect("auth.login event");
    assert_eq!(login.user.as_deref(), Some(ADMIN));
}

#[tokio::test]
async fn login_rejects_replay_wrong_nonce_and_bad_tokens() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let key = new_key();
    let salt = vec![9u8; 32];
    let nonce = limen_control_plane::services::auth::expected_nonce(
        &rcgen::PublicKeyData::subject_public_key_info(&key),
        &salt,
    );
    let token = h
        .idp
        .id_token(&Claims::user(ADMIN, &["admins"]).with_nonce(&nonce));

    h.login_raw(token.clone(), csr(&key), salt.clone(), LoginFlow::Pkce)
        .await
        .expect("first use");
    let replay = h
        .login_raw(token, csr(&key), salt.clone(), LoginFlow::Pkce)
        .await
        .expect_err("replay");
    assert_eq!(replay.code(), Code::PermissionDenied);

    // A token whose nonce binds a different key: what a relaying attacker would try.
    let other_key = new_key();
    let token = h
        .idp
        .id_token(&Claims::user(ADMIN, &["admins"]).with_nonce(&nonce));
    let swapped = h
        .login_raw(token, csr(&other_key), salt.clone(), LoginFlow::Pkce)
        .await
        .expect_err("key swap");
    assert_eq!(swapped.code(), Code::PermissionDenied);

    for (what, claims) in [
        (
            "expired",
            Claims {
                ttl_secs: -60,
                ..Claims::user("a@example.com", &["admins"])
            },
        ),
        (
            "wrong audience",
            Claims {
                audience: Some("someone-else".into()),
                ..Claims::user("a@example.com", &["admins"])
            },
        ),
        (
            "wrong issuer",
            Claims {
                issuer: Some("https://evil.example".into()),
                ..Claims::user("a@example.com", &["admins"])
            },
        ),
        (
            "unverified email",
            Claims {
                email_verified: Some(false),
                ..Claims::user("a@example.com", &["admins"])
            },
        ),
    ] {
        let key = new_key();
        let salt = vec![1u8; 32];
        let nonce = limen_control_plane::services::auth::expected_nonce(
            &rcgen::PublicKeyData::subject_public_key_info(&key),
            &salt,
        );
        let token = h.idp.id_token(&claims.with_nonce(&nonce));
        let err = h
            .login_raw(token, csr(&key), salt, LoginFlow::Pkce)
            .await
            .expect_err(what);
        assert_eq!(err.code(), Code::PermissionDenied, "{what}: {err}");
    }
    let forged = h
        .login_raw(
            "eyJhbGciOiJub25lIn0.e30.".into(),
            csr(&new_key()),
            vec![1u8; 32],
            LoginFlow::Pkce,
        )
        .await
        .expect_err("alg none");
    assert_ne!(forged.code(), Code::Ok);
}

#[tokio::test]
async fn login_without_roles_is_denied_and_audited() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let err = h.login(GUEST, &["marketing"]).await.expect_err("no roles");
    assert_eq!(err.code(), Code::PermissionDenied);
    let denied = h
        .audit_events()
        .await
        .into_iter()
        .find(|e| e.kind == EventKind::AuthDenied)
        .expect("auth.denied event");
    assert_eq!(denied.user.as_deref(), Some(GUEST));
}

#[tokio::test]
async fn device_flow_login_works_without_nonce_and_is_single_use() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let key = new_key();
    let token = h.idp.id_token(&Claims::user(ADMIN, &["admins"]));
    h.login_raw(token.clone(), csr(&key), vec![2u8; 32], LoginFlow::Device)
        .await
        .expect("device login");
    let replay = h
        .login_raw(token, csr(&key), vec![2u8; 32], LoginFlow::Device)
        .await
        .expect_err("replay");
    assert_eq!(replay.code(), Code::PermissionDenied);
    // PKCE without a nonce in the token is refused.
    let token = h.idp.id_token(&Claims::user(ADMIN, &["admins"]));
    let err = h
        .login_raw(token, csr(&key), vec![3u8; 32], LoginFlow::Pkce)
        .await
        .expect_err("pkce without nonce");
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn admin_apply_policy_then_users_see_only_their_resources() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let (proxy_id, proxy) = h.enroll_proxy().await;
    assert!(proxy_id.starts_with("proxy-"));
    let (_, admin_user) = h.login(ADMIN, &["admins"]).await.expect("admin");
    let ch = h.channel(Some(proxy));

    // Dry run changes nothing.
    let mut admin = AdminClient::new(ch.clone());
    let dry = admin
        .apply_policy(forwarded(
            ApplyPolicyRequest {
                sources: sources(),
                dry_run: true,
                source_ref: String::new(),
            },
            Some(&admin_user),
        ))
        .await
        .expect("dry run")
        .into_inner();
    assert!(!dry.applied);
    assert_eq!(dry.diff.as_ref().expect("diff").added.len(), 20);
    assert_eq!(dry.version, 0);

    let applied = admin
        .apply_policy(forwarded(
            ApplyPolicyRequest {
                sources: sources(),
                dry_run: false,
                source_ref: "abc123".into(),
            },
            Some(&admin_user),
        ))
        .await
        .expect("apply")
        .into_inner();
    assert!(applied.applied);
    assert!(applied.version > 0);
    let change = h
        .audit_events()
        .await
        .into_iter()
        .find(|e| e.kind == EventKind::PolicyChange)
        .expect("policy.change event");
    assert_eq!(change.data["source_ref"], "abc123");

    // Reapplying the same policy is a no-op.
    let again = admin
        .apply_policy(forwarded(
            ApplyPolicyRequest {
                sources: sources(),
                dry_run: false,
                source_ref: String::new(),
            },
            Some(&admin_user),
        ))
        .await
        .expect("reapply")
        .into_inner();
    assert!(!again.applied);

    // The developer (developers → dev-readonly) sees the staging DB and host.
    let (developer_resp, dev_user) = h
        .login(DEVELOPER, &["developers"])
        .await
        .expect("developer");
    assert_eq!(developer_resp.roles, ["dev-readonly"]);
    let mut resources = ResourcesClient::new(ch.clone());
    let listed = resources
        .list_resources(forwarded(ListResourcesRequest {}, Some(&dev_user)))
        .await
        .expect("ls")
        .into_inner();
    let names: Vec<_> = listed.resources.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "cache-staging",
            "cache-valkey",
            "catalog-staging",
            "catalog-x509",
            "events-kafka-scram",
            "events-kafka-staging",
            "events-rabbit-staging",
            "orders-mysql-staging",
            "orders-staging",
            "search-opensearch",
            "search-staging",
            "web-staging-1"
        ]
    );
    // SQL resources say which database `limen db connect` uses by default.
    let default_of = |name: &str| {
        listed
            .resources
            .iter()
            .find(|r| r.name == name)
            .map(|r| r.default_database.as_str())
    };
    assert_eq!(default_of("orders-staging"), Some("orders"));
    assert_eq!(default_of("web-staging-1"), Some(""));

    // The developer is not an admin.
    let err = admin
        .apply_policy(forwarded(
            ApplyPolicyRequest {
                sources: sources(),
                dry_run: true,
                source_ref: String::new(),
            },
            Some(&dev_user),
        ))
        .await
        .expect_err("not admin");
    assert_eq!(err.code(), Code::PermissionDenied);

    let who = AuthClient::new(ch)
        .who_am_i(forwarded(WhoAmIRequest {}, Some(&dev_user)))
        .await
        .expect("whoami")
        .into_inner();
    assert_eq!(who.username, DEVELOPER);
}

#[tokio::test]
async fn invalid_policy_is_rejected() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let (_, proxy) = h.enroll_proxy().await;
    let (_, admin_user) = h.login(ADMIN, &["admins"]).await.expect("admin");
    let bad = vec![PolicySource {
        name: "bad.yaml".into(),
        content: "kind: role\nversion: v1\nmetadata: {name: x}\nspec: {bogus: true}".into(),
    }];
    let err = AdminClient::new(h.channel(Some(proxy)))
        .apply_policy(forwarded(
            ApplyPolicyRequest {
                sources: bad,
                dry_run: false,
                source_ref: String::new(),
            },
            Some(&admin_user),
        ))
        .await
        .expect_err("invalid");
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(!h.audit_kinds().await.contains(&EventKind::PolicyChange));
}

#[tokio::test]
async fn worker_enrolls_once_with_single_use_token_and_renews() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let (proxy_id, proxy) = h.enroll_proxy().await;
    let (_, admin_user) = h.login(ADMIN, &["admins"]).await.expect("admin");
    let ch = h.channel(Some(proxy.clone()));

    let token = AdminClient::new(ch.clone())
        .create_join_token(forwarded(
            CreateJoinTokenRequest {
                kind: "worker".into(),
                ttl_seconds: 300,
                labels: [("pool".to_owned(), "dev".to_owned())].into(),
                dns_names: vec![],
                name: String::new(),
            },
            Some(&admin_user),
        ))
        .await
        .expect("token")
        .into_inner()
        .token;
    assert!(token.starts_with("lmn_join_"));

    // Workers enroll through the proxy, anonymously.
    let key = new_key();
    let mut enroll = EnrollmentClient::new(ch.clone());
    let req = || EnrollRequest {
        join_token: token.clone(),
        csr_der: csr(&key),
        kind: "worker".into(),
        dns_names: vec![],
        name: String::new(),
    };
    let resp = enroll
        .enroll(forwarded(req(), None))
        .await
        .expect("enroll")
        .into_inner();
    assert_eq!(resp.labels.get("pool").map(String::as_str), Some("dev"));
    let worker_der = limen_tunnel::tls::certs_from_pem(&resp.cert_pem)
        .expect("cert")
        .remove(0);
    let worker =
        verify_component(&worker_der, h.state.cas.internal.cert_der(), false).expect("worker cert");
    assert_eq!(worker.kind, ComponentKind::Worker);

    let reuse = enroll
        .enroll(forwarded(req(), None))
        .await
        .expect_err("second use");
    assert_eq!(reuse.code(), Code::PermissionDenied);
    let wrong_kind = enroll
        .enroll(forwarded(
            EnrollRequest {
                kind: "proxy".into(),
                ..req()
            },
            None,
        ))
        .await
        .expect_err("kind");
    assert_eq!(wrong_kind.code(), Code::PermissionDenied);
    let kinds = h.audit_kinds().await;
    assert!(kinds.contains(&EventKind::WorkerEnroll));
    assert!(kinds.contains(&EventKind::JoinTokenCreate));
    assert!(kinds.contains(&EventKind::AuthDenied));

    // Renewal through the proxy, presenting the worker cert.
    let renewed = enroll
        .renew_certificate(forwarded(
            RenewCertificateRequest {
                csr_der: csr(&new_key()),
            },
            Some(&worker_der),
        ))
        .await
        .expect("renew")
        .into_inner();
    let renewed_der = limen_tunnel::tls::certs_from_pem(&renewed.cert_pem)
        .expect("cert")
        .remove(0);
    assert_eq!(
        verify_component(&renewed_der, h.state.cas.internal.cert_der(), false)
            .expect("renewed")
            .id,
        worker.id
    );

    // The proxy reports a tunnel to the worker; admins see it.
    RegistryClient::new(ch.clone())
        .report_tunnels(tonic::Request::new(ReportTunnelsRequest {
            tunnels: vec![TunnelReport {
                worker_id: worker.id.clone(),
                tunnel_id: "t1".into(),
                active_sessions: 3,
                max_sessions: 200,
            }],
            peer_address: "10.0.0.5:3024".into(),
        }))
        .await
        .expect("report");
    let components = AdminClient::new(ch)
        .list_components(forwarded(ListComponentsRequest {}, Some(&admin_user)))
        .await
        .expect("list")
        .into_inner()
        .components;
    let w = components
        .iter()
        .find(|c| c.id == worker.id)
        .expect("worker listed");
    assert_eq!(w.tunnels.len(), 1);
    assert_eq!(w.tunnels[0].proxy_id, proxy_id);

    // Another proxy finds the worker through the registry, with the load the
    // first one reported, for its least-loaded choice.
    let (_, other) = h.enroll_proxy().await;
    let listed = RegistryClient::new(h.channel(Some(other)))
        .list_tunnels(tonic::Request::new(ListTunnelsRequest {}))
        .await
        .expect("list tunnels")
        .into_inner()
        .tunnels;
    let t = listed
        .iter()
        .find(|t| t.worker_id == worker.id)
        .expect("the worker is listed to other proxies");
    assert_eq!(t.peer_address, "10.0.0.5:3024");
    assert_eq!((t.active_sessions, t.max_sessions), (3, 200));
}

#[tokio::test]
async fn only_proxies_may_forward_or_report() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let (_, proxy) = h.enroll_proxy().await;
    let (_, admin_user) = h.login(ADMIN, &["admins"]).await.expect("admin");

    // Anonymous caller claiming to forward a user's cert.
    let err = ResourcesClient::new(h.channel(None))
        .list_resources(forwarded(ListResourcesRequest {}, Some(&admin_user)))
        .await
        .expect_err("anon forward");
    assert_eq!(err.code(), Code::PermissionDenied);

    // A worker connecting directly may not forward or report tunnels.
    let token = AdminClient::new(h.channel(Some(proxy.clone())))
        .create_join_token(forwarded(
            CreateJoinTokenRequest {
                kind: "worker".into(),
                ttl_seconds: 0,
                labels: std::collections::HashMap::default(),
                dns_names: vec![],
                name: String::new(),
            },
            Some(&admin_user),
        ))
        .await
        .expect("token")
        .into_inner()
        .token;
    let key = new_key();
    let resp = EnrollmentClient::new(h.channel(Some(proxy)))
        .enroll(forwarded(
            EnrollRequest {
                join_token: token,
                csr_der: csr(&key),
                kind: "worker".into(),
                dns_names: vec![],
                name: String::new(),
            },
            None,
        ))
        .await
        .expect("enroll")
        .into_inner();
    let worker = Identity::from_pem(&resp.cert_pem, &key.serialize_pem()).expect("identity");
    let worker_ch = h.channel(Some(worker));
    let err = ResourcesClient::new(worker_ch.clone())
        .list_resources(forwarded(ListResourcesRequest {}, Some(&admin_user)))
        .await
        .expect_err("worker forward");
    assert_eq!(err.code(), Code::PermissionDenied);
    let err = RegistryClient::new(worker_ch.clone())
        .report_tunnels(tonic::Request::new(ReportTunnelsRequest {
            tunnels: vec![],
            peer_address: String::new(),
        }))
        .await
        .expect_err("worker report");
    assert_eq!(err.code(), Code::PermissionDenied);

    // Users can't reach user APIs without a forwarded cert.
    let err = ResourcesClient::new(worker_ch)
        .list_resources(tonic::Request::new(ListResourcesRequest {}))
        .await
        .expect_err("no user");
    assert_eq!(err.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn proxy_cannot_request_unapproved_dns_names() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let err = EnrollmentClient::new(h.channel(None))
        .enroll(EnrollRequest {
            join_token: common::STATIC_PROXY_TOKEN.into(),
            csr_der: csr(&new_key()),
            kind: "proxy".into(),
            dns_names: vec!["bank.example.com".into()],
            name: String::new(),
        })
        .await
        .expect_err("unapproved DNS name");
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn ingest_accepts_own_events_and_rejects_forgery_and_bad_recordings() {
    use limen_proto::v1::audit_ingest_client::AuditIngestClient;
    use limen_proto::v1::{IngestRequest, RecordingChunk};
    let Some(h) = Harness::start().await else {
        return;
    };
    let (proxy_id, proxy) = h.enroll_proxy().await;
    let mut ingest = AuditIngestClient::new(h.channel(Some(proxy)));
    let event = |component: &str, instance: &str| {
        let producer = limen_audit::Producer {
            component: component.into(),
            instance_id: instance.into(),
            seq: 0,
        };
        serde_json::to_vec(&limen_audit::Event::new(
            EventKind::SessionStart,
            producer,
            serde_json::json!({"resource": "web-1"}),
        ))
        .expect("json")
    };

    // A proxy may submit its own events; they reach the sinks.
    let own = event("proxy", &format!("{proxy_id}/boot1"));
    let accepted = ingest
        .ingest(IngestRequest { events: vec![own] })
        .await
        .expect("own events")
        .into_inner()
        .accepted;
    assert_eq!(accepted, 1);
    assert!(
        h.audit_events()
            .await
            .iter()
            .any(|e| e.kind == EventKind::SessionStart)
    );

    // ...but not events claiming to come from another component or instance.
    for (component, instance) in [
        ("worker", format!("{proxy_id}/boot1")),
        ("proxy", "proxy-someone-else/boot1".to_owned()),
        ("control-plane", "cp/1".to_owned()),
    ] {
        let err = ingest
            .ingest(IngestRequest {
                events: vec![event(component, &instance)],
            })
            .await
            .expect_err("forged");
        assert_eq!(err.code(), Code::PermissionDenied, "{component} {instance}");
    }
    let err = ingest
        .ingest(IngestRequest {
            events: vec![b"not json".to_vec()],
        })
        .await
        .expect_err("garbage");
    assert_eq!(err.code(), Code::InvalidArgument);

    // Only workers upload recordings.
    let chunk = RecordingChunk {
        session_id: uuid::Uuid::now_v7().to_string(),
        data: b"{}".to_vec(),
        sha256: "00".into(),
    };
    let err = ingest
        .upload_recording(tokio_stream::iter(vec![chunk]))
        .await
        .expect_err("proxy upload");
    assert_eq!(err.code(), Code::PermissionDenied);
}

/// Shutdown ships the spool: after `drain`, every sink has every record and
/// the report says so.
#[tokio::test]
async fn drain_ships_the_spool_to_every_sink() {
    let Some(h) = common::Harness::start().await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let before = h.audit_events().await.len();
    for i in 0..40 {
        let event = limen_audit::Event::new(
            limen_audit::EventKind::SessionRecording,
            limen_audit::Producer {
                component: "control-plane".into(),
                instance_id: "cp-test".into(),
                seq: i,
            },
            serde_json::json!({ "n": i }),
        );
        h.state
            .pipeline
            .spool
            .append(&serde_json::to_vec(&event).expect("json"))
            .await
            .expect("append");
    }
    let report = h
        .state
        .pipeline
        .drain(std::time::Duration::from_secs(10))
        .await;
    assert!(report.is_clean(), "left behind: {:?}", report.pending);
    let text = std::fs::read_to_string(&h.audit_file).expect("audit file");
    assert!(text.lines().count() >= before + 40);
}

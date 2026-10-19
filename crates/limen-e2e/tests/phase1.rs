//! Phase 1 end to end, everything through the proxy:
//! login → policy → ls → worker enrollment → tunnels → proxy restart.

use std::collections::HashMap;
use std::time::Duration;

use limen_e2e::{Deployment, eventually};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::enrollment_client::EnrollmentClient;
use limen_proto::v1::resources_client::ResourcesClient;
use limen_proto::v1::{
    ApplyPolicyRequest, CreateJoinTokenRequest, EnrollRequest, ListComponentsRequest,
    ListResourcesRequest, PolicySource,
};
use limen_testkit::users::{ADMIN, DEVELOPER, GUEST};
use tonic::Code;

const POLICY: [(&str, &str); 3] = [
    (
        "roles.yaml",
        include_str!("../../../examples/policy/roles.yaml"),
    ),
    (
        "mappings.yaml",
        include_str!("../../../examples/policy/mappings.yaml"),
    ),
    (
        "resources.yaml",
        include_str!("../../../examples/policy/resources.yaml"),
    ),
];

// One scenario on purpose: each step depends on the previous one.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread")]
async fn login_policy_enrollment_tunnels_and_proxy_restart() {
    let Some(mut d) = Deployment::start().await else {
        return;
    };

    // Admin logs in through the proxy and applies policy.
    let admin_user = d.login(ADMIN, &["admins"]).await.expect("admin login");
    let admin_ch = d.proxy_channel(Some(admin_user));
    let sources = POLICY
        .iter()
        .map(|(n, c)| PolicySource {
            name: (*n).into(),
            content: (*c).into(),
        })
        .collect();
    let applied = AdminClient::new(admin_ch.clone())
        .apply_policy(ApplyPolicyRequest {
            sources,
            dry_run: false,
            source_ref: "e2e".into(),
        })
        .await
        .expect("apply policy")
        .into_inner();
    assert!(applied.applied);

    // A developer sees only what policy allows.
    let dev_user = d
        .login(DEVELOPER, &["developers"])
        .await
        .expect("developer login");
    let listed = ResourcesClient::new(d.proxy_channel(Some(dev_user)))
        .list_resources(ListResourcesRequest {})
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
            "orders-mysql-staging",
            "orders-staging",
            "search-opensearch",
            "search-staging",
            "web-staging-1"
        ]
    );

    // A user with no mapped roles can't log in.
    let err = d
        .login(GUEST, &["marketing"])
        .await
        .expect_err("guest denied");
    assert_eq!(err.code(), Code::PermissionDenied);

    // A single-use join token enrolls a worker through the proxy.
    let token = AdminClient::new(admin_ch.clone())
        .create_join_token(CreateJoinTokenRequest {
            kind: "worker".into(),
            ttl_seconds: 600,
            labels: HashMap::from([("pool".to_owned(), "dev".to_owned())]),
            dns_names: vec![],
            name: String::new(),
        })
        .await
        .expect("token")
        .into_inner()
        .token;
    let worker = d.start_worker(&token, "worker-a").await;
    let worker_id = worker.worker.id();

    // Both tunnels come up and the control plane learns about them.
    eventually(
        Duration::from_secs(15),
        "two tunnels on the proxy",
        || async {
            d.proxy()
                .tunnels
                .summaries()
                .iter()
                .filter(|t| t.worker_id == worker_id)
                .count()
                == 2
        },
    )
    .await;
    let admin = AdminClient::new(admin_ch.clone());
    eventually(
        Duration::from_secs(20),
        "control plane registry shows two tunnels",
        || {
            let mut admin = admin.clone();
            let worker_id = worker_id.clone();
            async move {
                let components = admin
                    .list_components(ListComponentsRequest {})
                    .await
                    .expect("list")
                    .into_inner()
                    .components;
                components
                    .iter()
                    .any(|c| c.id == worker_id && c.tunnels.len() == 2)
            }
        },
    )
    .await;

    // The token can't be used again.
    let reuse = EnrollmentClient::new(d.proxy_channel(None))
        .enroll(EnrollRequest {
            join_token: token.clone(),
            csr_der: vec![],
            kind: "worker".into(),
            dns_names: vec![],
            name: String::new(),
        })
        .await
        .expect_err("reuse");
    assert!(
        matches!(reuse.code(), Code::PermissionDenied | Code::InvalidArgument),
        "{reuse}"
    );

    // Restart the proxy. The worker reconnects on its own, with backoff and jitter.
    d.restart_proxy().await;
    eventually(
        Duration::from_secs(30),
        "worker tunnels back after proxy restart",
        || async {
            d.proxy()
                .tunnels
                .summaries()
                .iter()
                .filter(|t| t.worker_id == worker_id)
                .count()
                == 2
        },
    )
    .await;
    assert_eq!(worker.worker.tunnels_up(), 2);

    // The restarted proxy reused its identity rather than enrolling again.
    let components =
        AdminClient::new(d.proxy_channel(Some(d.login(ADMIN, &["admins"]).await.expect("login"))))
            .list_components(ListComponentsRequest {})
            .await
            .expect("list")
            .into_inner()
            .components;
    assert_eq!(components.iter().filter(|c| c.kind == "proxy").count(), 1);

    worker.stop().await;
    eventually(
        Duration::from_secs(10),
        "tunnels gone after worker stops",
        || async { d.proxy().tunnels.summaries().is_empty() },
    )
    .await;

    // The audit trail has the whole story.
    let audit = std::fs::read_to_string(d.dir.path().join("audit/control-plane.jsonl"))
        .expect("audit file");
    for kind in [
        "auth.login",
        "auth.denied",
        "policy.change",
        "join_token.create",
        "worker.enroll",
    ] {
        assert!(
            audit.contains(&format!("\"kind\":\"{kind}\"")),
            "audit trail is missing {kind}"
        );
    }
}

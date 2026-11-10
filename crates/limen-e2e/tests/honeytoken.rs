//! Honeytoken resources end to end (ADR-0050): a decoy is listed for the
//! role it is exposed to, every attempt to use it is refused like any other
//! name and audited as `detect.honeytoken`, and nothing a wildcard role says
//! reaches it.

#![allow(clippy::assert_is_empty, clippy::too_many_lines)]

use std::collections::HashMap;
use std::time::Duration;

use limen_e2e::{Deployment, eventually, ssh_client};
use limen_proto::v1::access_client::AccessClient;
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::resources_client::ResourcesClient;
use limen_proto::v1::{
    ApplyPolicyRequest, CreateJoinTokenRequest, ExplainRequest, ListResourcesRequest, PolicySource,
    RequestAccessRequest,
};
use limen_testkit::ssh_target::SshTarget;
use limen_testkit::users::{ADMIN, DEVELOPER};

fn policy(addr: &str, host_key: &str) -> Vec<PolicySource> {
    let yaml = format!(
        r#"
kind: resource
version: v1
metadata: {{ name: web-prod, labels: {{ env: prod }} }}
spec:
  ssh: {{ address: "{addr}", host_key: "{host_key}" }}
  worker_selector: {{ pool: dev }}
---
kind: resource
version: v1
metadata: {{ name: prod-backup-db, labels: {{ env: prod }} }}
spec:
  honeytoken:
    kind: ssh
    principals: [ubuntu]
    exposed_to: [dev]
---
kind: role
version: v1
metadata: {{ name: dev }}
spec:
  allow:
    # Matches every label on purpose: a decoy must still be out of reach.
    - resources: {{ kind: [ssh], labels: {{ "*": ["*"] }} }}
      ssh: {{ logins: [ubuntu] }}
---
kind: role_mapping
version: v1
metadata: {{ name: idp }}
spec:
  - {{ idp_group: developers, roles: [dev] }}
"#
    );
    vec![PolicySource {
        name: "policy.yaml".into(),
        content: yaml,
    }]
}

fn events(d: &Deployment, kind: &str) -> Vec<serde_json::Value> {
    std::fs::read_to_string(d.dir.path().join("audit/control-plane.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("json"))
        .filter(|e| e["kind"] == kind)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_decoy_is_listed_refused_like_any_name_and_reported() {
    let Some(d) = Box::pin(Deployment::start()).await else {
        return;
    };
    let target = SshTarget::start(&d.public_ca("ssh-user-ca.pub")).await;
    let host_ca = d.public_ca("ssh-host-ca.pub");
    let ca_pem = std::fs::read_to_string(d.ca_file()).expect("ca");
    let proxy_addr = d.proxy_addr.to_string();
    let admin_user = d.login(ADMIN, &["admins"]).await.expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(admin_user)));

    let applied = admin
        .apply_policy(ApplyPolicyRequest {
            source: String::new(),
            require_tests: false,
            sources: policy(&target.addr.to_string(), &target.host_key),
            dry_run: false,
            source_ref: String::new(),
        })
        .await
        .expect("apply")
        .into_inner();
    assert!(applied.applied);
    let token = admin
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
    let worker = d.start_worker_with(&token, "worker", &[]).await;
    eventually(Duration::from_secs(15), "policy everywhere", || async {
        d.proxy().tunnels.summaries().len() == 2
            && d.proxy().policy_version() == Some(applied.version)
            && worker.worker.policy_version() == Some(applied.version)
    })
    .await;

    let dev = d.login(DEVELOPER, &["developers"]).await.expect("dev");
    let (cert, key) = d
        .login_pem(DEVELOPER, &["developers"])
        .await
        .expect("login");

    // Listed like a real resource, in name order, for the exposed role only.
    let listed = ResourcesClient::new(d.proxy_channel(Some(dev.clone())))
        .list_resources(ListResourcesRequest {})
        .await
        .expect("list")
        .into_inner();
    let names: Vec<&str> = listed.resources.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["prod-backup-db", "web-prod"]);
    let decoy = &listed.resources[0];
    let real = &listed.resources[1];
    assert_eq!(decoy.kind, real.kind);
    assert_eq!(decoy.principals, ["ubuntu"]);
    assert_eq!(decoy.labels, real.labels);
    assert_eq!(decoy.grant_expires_at_unix, real.grant_expires_at_unix);
    assert!(
        events(&d, "detect.honeytoken").is_empty(),
        "listing is exposure, not an alert"
    );

    // The real resource still works and raises nothing.
    let connect = |resource: &'static str| {
        let (cert, key, ca_pem, host_ca, proxy_addr) = (
            cert.clone(),
            key.clone(),
            ca_pem.clone(),
            host_ca.clone(),
            proxy_addr.clone(),
        );
        async move {
            let id = limen_tunnel::tls::Identity::from_pem(&cert, &key).expect("identity");
            ssh_client::connect(&proxy_addr, &ca_pem, id, &host_ca, resource, "ubuntu").await
        }
    };
    let session = connect("web-prod").await.expect("the real resource opens");
    let (_, status) = ssh_client::exec(&session, "true").await.expect("exec");
    assert_eq!(status, Some(0));
    drop(session);
    assert!(events(&d, "detect.honeytoken").is_empty());

    // Connecting to the decoy reads exactly like connecting to a name that
    // doesn't exist, and is reported.
    let from_decoy = connect("prod-backup-db").await.err().expect("refused");
    let from_nothing = connect("no-such-db").await.err().expect("refused");
    assert!(from_decoy.contains("denied"), "{from_decoy}");
    assert_eq!(
        from_decoy.replace("prod-backup-db", "X"),
        from_nothing.replace("no-such-db", "X"),
        "the refusal must not tell a decoy from an unknown name"
    );
    eventually(Duration::from_secs(15), "the touch", || async {
        !events(&d, "detect.honeytoken").is_empty()
    })
    .await;
    let hits = events(&d, "detect.honeytoken");
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0]["user"], DEVELOPER);
    assert_eq!(hits[0]["data"]["resource"], "prod-backup-db");
    assert_eq!(hits[0]["data"]["action"], "ssh");
    assert_eq!(hits[0]["data"]["principal"], "ubuntu");
    assert_eq!(hits[0]["data"]["roles"], serde_json::json!(["dev"]));
    assert!(hits[0]["data"]["client_addr"].is_string(), "{hits:?}");
    assert!(
        hits[0]["data"].get("ci").is_none(),
        "a person has no CI run"
    );
    assert_eq!(
        events(&d, "session.start").len(),
        1,
        "the decoy never opened a session"
    );

    // Asking for it, or for an explanation of it, is a touch too, and the
    // answers are those of a name that doesn't exist.
    let mut access = AccessClient::new(d.proxy_channel(Some(dev)));
    let ask = |resource: &str| RequestAccessRequest {
        resource: resource.into(),
        role: String::new(),
        duration_seconds: 600,
        reason: "need it".into(),
        break_glass: false,
    };
    let asked_decoy = access
        .request_access(ask("prod-backup-db"))
        .await
        .expect_err("refused");
    let asked_nothing = access
        .request_access(ask("no-such-db"))
        .await
        .expect_err("refused");
    assert_eq!(asked_decoy.code(), asked_nothing.code());
    assert_eq!(
        asked_decoy.message().replace("prod-backup-db", "X"),
        asked_nothing.message().replace("no-such-db", "X")
    );
    let explain = |resource: &str| ExplainRequest {
        resource: resource.into(),
        ..Default::default()
    };
    let explained_decoy = access
        .explain(explain("prod-backup-db"))
        .await
        .expect("explain")
        .into_inner();
    let explained_nothing = access
        .explain(explain("no-such-db"))
        .await
        .expect("explain")
        .into_inner();
    let flat = |lines: &[String], name: &str| lines.join("\n").replace(name, "X");
    assert_eq!(
        flat(&explained_decoy.lines, "prod-backup-db"),
        flat(&explained_nothing.lines, "no-such-db")
    );
    assert_eq!(
        explained_decoy.worker_connected,
        explained_nothing.worker_connected
    );
    eventually(Duration::from_secs(15), "the other touches", || async {
        events(&d, "detect.honeytoken").len() == 3
    })
    .await;
    let actions: Vec<String> = events(&d, "detect.honeytoken")
        .iter()
        .map(|e| e["data"]["action"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(actions.contains(&"request".to_owned()), "{actions:?}");
    assert!(actions.contains(&"explain".to_owned()), "{actions:?}");

    // An admin explaining a name for someone else is not a touch.
    let mut admin_access =
        AccessClient::new(d.proxy_channel(Some(d.login(ADMIN, &["admins"]).await.expect("admin"))));
    admin_access
        .explain(ExplainRequest {
            resource: "prod-backup-db".into(),
            user: DEVELOPER.into(),
            ..Default::default()
        })
        .await
        .expect("admin explain");
    assert_eq!(events(&d, "detect.honeytoken").len(), 3);
}

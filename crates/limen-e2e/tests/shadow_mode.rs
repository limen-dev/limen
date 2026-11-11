//! Shadow mode end to end (ADR-0046): a real SSH session goes through a
//! deny rule that is only reported, the proxy audits `policy.shadow_deny`,
//! and once the rule is enforced the same session is refused.

use std::collections::HashMap;
use std::time::Duration;

use limen_e2e::{Deployment, eventually, ssh_client};
use limen_policy::shadow::ShadowDate;
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, CreateJoinTokenRequest, PolicySource};
use limen_testkit::ssh_target::SshTarget;
use limen_testkit::users::{ADMIN, DEVELOPER};
use time::{Duration as Days, OffsetDateTime};

fn policy(addr: &str, host_key: &str, mode: &str) -> Vec<PolicySource> {
    let yaml = format!(
        r#"
kind: resource
version: v1
metadata: {{ name: web-prod, labels: {{ env: prod }} }}
spec:
  ssh: {{ address: "{addr}", host_key: "{host_key}" }}
  worker_selector: {{ pool: dev }}
---
kind: role
version: v1
metadata: {{ name: dev }}
spec:
  allow:
    - resources: {{ kind: [ssh], labels: {{ env: [prod] }} }}
      ssh: {{ logins: [ubuntu] }}
  deny:
    - name: no-ubuntu-in-prod
      {mode}
      resources: {{ kind: [ssh], labels: {{ env: [prod] }} }}
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
async fn a_shadow_deny_is_reported_and_an_enforced_one_refuses() {
    let Some(d) = Box::pin(Deployment::start()).await else {
        return;
    };
    let target = SshTarget::start(&d.public_ca("ssh-user-ca.pub")).await;
    let host_ca = d.public_ca("ssh-host-ca.pub");
    let ca_pem = std::fs::read_to_string(d.ca_file()).expect("ca");
    let proxy_addr = d.proxy_addr.to_string();
    let admin_user = d.login(ADMIN, &["admins"]).await.expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(admin_user)));

    let until = ShadowDate((OffsetDateTime::now_utc() + Days::days(30)).date());
    let shadow = format!("mode: shadow\n      shadow_until: {until}");
    let applied = admin
        .apply_policy(ApplyPolicyRequest {
            source: String::new(),
            require_tests: false,
            sources: policy(&target.addr.to_string(), &target.host_key, &shadow),
            dry_run: false,
            source_ref: String::new(),
            replay_days: 0,
        })
        .await
        .expect("apply")
        .into_inner();
    assert!(applied.applied, "a new shadow rule is not loosening");
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

    let (cert, key) = d
        .login_pem(DEVELOPER, &["developers"])
        .await
        .expect("login");
    let connect = || async {
        let id = limen_tunnel::tls::Identity::from_pem(&cert, &key).expect("identity");
        ssh_client::connect(&proxy_addr, &ca_pem, id, &host_ca, "web-prod", "ubuntu").await
    };

    // The rule would refuse this, but it only reports: the session opens.
    let session = connect().await.expect("a shadow rule never refuses");
    let (_, status) = ssh_client::exec(&session, "true").await.expect("exec");
    assert_eq!(status, Some(0));
    drop(session);
    eventually(Duration::from_secs(15), "the shadow report", || async {
        !events(&d, "policy.shadow_deny").is_empty()
    })
    .await;
    let hits = events(&d, "policy.shadow_deny");
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0]["user"], DEVELOPER);
    assert_eq!(hits[0]["data"]["role"], "dev");
    assert_eq!(hits[0]["data"]["rule"], "no-ubuntu-in-prod");
    assert_eq!(hits[0]["data"]["resource"], "web-prod");
    assert_eq!(hits[0]["data"]["login"], "ubuntu");
    assert_eq!(hits[0]["data"]["policy_version"], applied.version);
    assert_eq!(
        events(&d, "session.start").len(),
        1,
        "the session itself is audited as usual"
    );

    // Enforcing it is tightening: applied at once, and the same login is refused.
    let enforced = admin
        .apply_policy(ApplyPolicyRequest {
            source: String::new(),
            require_tests: false,
            sources: policy(&target.addr.to_string(), &target.host_key, ""),
            dry_run: false,
            source_ref: String::new(),
            replay_days: 0,
        })
        .await
        .expect("apply")
        .into_inner();
    assert!(enforced.applied);
    eventually(Duration::from_secs(15), "enforced everywhere", || async {
        d.proxy().policy_version() == Some(enforced.version)
    })
    .await;
    let err = connect().await.err().expect("enforced now");
    assert!(err.contains("denied"), "{err}");
    assert_eq!(
        events(&d, "policy.shadow_deny").len(),
        1,
        "an enforced rule reports nothing"
    );
}

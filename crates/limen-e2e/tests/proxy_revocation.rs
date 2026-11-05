//! Pentest regression (#66): a revoked proxy's grants are refused. The grant
//! still verifies (its certificate has not expired), so the worker and the
//! control plane must check the revocation themselves (threat model TB2).

use std::collections::HashMap;
use std::time::Duration;

use limen_e2e::{Deployment, eventually, ssh_client};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{
    ApplyPolicyRequest, CreateJoinTokenRequest, PolicySource, RevokeComponentRequest,
};
use limen_testkit::ssh_target::SshTarget;
use limen_testkit::users::{ADMIN, DEVELOPER};

fn policy(target_addr: &str, host_key: &str) -> Vec<PolicySource> {
    let yaml = format!(
        r#"
kind: role
version: v1
metadata: {{ name: ops }}
spec:
  allow:
    - resources: {{ kind: [ssh], labels: {{ env: [test] }} }}
      ssh: {{ logins: [ubuntu] }}
---
kind: role_mapping
version: v1
metadata: {{ name: idp }}
spec:
  - {{ idp_group: ops, roles: [ops] }}
---
kind: resource
version: v1
metadata: {{ name: web-1, labels: {{ env: test }} }}
spec:
  ssh: {{ address: "{target_addr}", host_key: "{host_key}" }}
  worker_selector: {{ pool: dev }}
---
kind: resource
version: v1
metadata: {{ name: web-unpinned, labels: {{ env: test }} }}
spec:
  ssh: {{ address: "{target_addr}" }}
  worker_selector: {{ pool: dev }}
"#
    );
    vec![PolicySource {
        name: "policy.yaml".into(),
        content: yaml,
    }]
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_proxys_grants_are_refused() {
    let Some(d) = Deployment::start().await else {
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
    let worker = d.start_worker(&token, "worker").await;
    eventually(Duration::from_secs(15), "worker tunnels", || async {
        d.proxy().tunnels.summaries().len() == 2
    })
    .await;
    eventually(
        Duration::from_secs(15),
        "proxy and worker have the policy",
        || async {
            d.proxy().policy_version() == Some(applied.version)
                && worker.worker.policy_version() == Some(applied.version)
        },
    )
    .await;

    let dev_user = || async { d.login(DEVELOPER, &["ops"]).await.expect("developer") };
    let conn = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        dev_user().await,
        &host_ca,
        "web-1",
        "ubuntu",
    )
    .await
    .expect("a session before the revocation");
    drop(conn);

    let revoked = admin
        .revoke_component(RevokeComponentRequest {
            component_id: d.proxy().id(),
            reason: "pentest regression".into(),
        })
        .await
        .expect("revoke the proxy")
        .into_inner();
    assert!(revoked.revoked);

    // The revoked proxy still holds a certificate that has not expired. Once
    // the worker has the new restrictions it must refuse the proxy's grants,
    // and say why. (One login per attempt, spaced out, to stay under the
    // login rate limit.)
    let mut last = String::from("no attempt was refused");
    for _ in 0..15 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let Ok(identity) = d.login(DEVELOPER, &["ops"]).await else {
            continue;
        };
        match ssh_client::connect(&proxy_addr, &ca_pem, identity, &host_ca, "web-1", "ubuntu").await
        {
            Err(e) if e.contains("revoked") => return,
            Err(e) => last = e,
            Ok(conn) => drop(conn),
        }
    }
    panic!("the worker never refused the revoked proxy's grants (last error: {last})");
}

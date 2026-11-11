//! Policy suggest end to end (ADR-0050): a real SSH session through a real
//! proxy and worker is projected into `sessions` with its login, and
//! `SuggestPolicy` proposes dropping the login nobody used.

use std::collections::HashMap;
use std::time::Duration;

use limen_e2e::{Deployment, eventually, ssh_client};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{
    ApplyPolicyRequest, CreateJoinTokenRequest, PolicySource, SuggestPolicyRequest,
};
use limen_testkit::ssh_target::SshTarget;
use limen_testkit::users::{ADMIN, DEVELOPER};
use sqlx::Connection as _;

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
kind: role
version: v1
metadata: {{ name: dev }}
spec:
  allow:
    - resources: {{ kind: [ssh], labels: {{ env: [prod] }} }}
      ssh: {{ logins: [ubuntu, root] }}
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

#[tokio::test(flavor = "multi_thread")]
async fn an_ssh_session_is_the_use_that_keeps_its_login() {
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

    // A real session as `ubuntu`.
    let (cert, key) = d
        .login_pem(DEVELOPER, &["developers"])
        .await
        .expect("login");
    let id = limen_tunnel::tls::Identity::from_pem(&cert, &key).expect("identity");
    let session = ssh_client::connect(&proxy_addr, &ca_pem, id, &host_ca, "web-prod", "ubuntu")
        .await
        .expect("connect");
    let (_, status) = ssh_client::exec(&session, "true").await.expect("exec");
    assert_eq!(status, Some(0));
    drop(session);

    let mut db = sqlx::PgConnection::connect(&d.db_url).await.expect("db");
    // The projection records the login the proxy audited, and that is what
    // policy suggest reads.
    eventually(Duration::from_secs(15), "the session row", || async {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sessions WHERE username = $1 AND resource = 'web-prod' AND login = 'ubuntu'",
        )
        .bind(DEVELOPER)
        .fetch_one(&mut sqlx::PgConnection::connect(&d.db_url).await.expect("db"))
        .await
        .expect("count");
        n == 1
    })
    .await;

    // A deployment this new has not been watched for a window.
    let err = admin
        .suggest_policy(SuggestPolicyRequest { window_days: 90 })
        .await
        .expect_err("not enough history yet");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");

    // Make it look a year old, documents included.
    sqlx::query("UPDATE users SET first_login_at = now() - interval '400 days'")
        .execute(&mut db)
        .await
        .expect("users");
    sqlx::query(
        "UPDATE policy_document_heads SET created_at = now() - interval '400 days', updated_at = now() - interval '400 days'",
    )
    .execute(&mut db)
    .await
    .expect("heads");

    let s = admin
        .suggest_policy(SuggestPolicyRequest { window_days: 90 })
        .await
        .expect("suggest")
        .into_inner();
    assert!(s.yaml.contains("ubuntu"), "{}", s.yaml);
    assert!(!s.yaml.contains("root"), "root was never used: {}", s.yaml);
    assert!(s.diff.contains("loses"), "{}", s.diff);
    assert_eq!(s.policy_version, applied.version);
    // Nothing was applied.
    assert_eq!(d.proxy().policy_version(), Some(applied.version));
}

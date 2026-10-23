//! Phase 12 raw TCP forwarding through the proxy and worker.
//!
//! The target is a loopback echo stand-in. This verifies the transport and
//! policy path, not a real TCP service integration.

use std::collections::HashMap;
use std::time::Duration;

use limen_e2e::{Deployment, db_client, eventually};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, CreateJoinTokenRequest, PolicySource};
use limen_testkit::users::{ADMIN, DEVELOPER};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn echo_target() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let address = listener.local_addr().expect("echo address").to_string();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) if stream.write_all(&buffer[..n]).await.is_err() => return,
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    address
}

fn policy(address: &str) -> Vec<PolicySource> {
    let yaml = format!(
        r#"
kind: role
version: v1
metadata: {{ name: tcp-operators }}
spec:
  allow:
    - resources: {{ kind: [tcp], labels: {{ env: [test] }} }}
      tcp: {{}}
  deny:
    - resources: {{ kind: [tcp], labels: {{ team: [blocked] }} }}
---
kind: role_mapping
version: v1
metadata: {{ name: idp }}
spec:
  - {{ idp_group: tcp-users, roles: [tcp-operators] }}
---
kind: resource
version: v1
metadata: {{ name: tcp-echo, labels: {{ env: test, team: platform }} }}
spec:
  tcp: {{ address: "{address}" }}
  worker_selector: {{ pool: dev }}
---
kind: resource
version: v1
metadata: {{ name: tcp-blocked, labels: {{ env: test, team: blocked }} }}
spec:
  tcp: {{ address: "{address}" }}
  worker_selector: {{ pool: dev }}
"#
    );
    vec![PolicySource {
        name: "phase12-tcp.yaml".into(),
        content: yaml,
    }]
}

fn events(deployment: &Deployment) -> Vec<serde_json::Value> {
    std::fs::read_to_string(deployment.dir.path().join("audit/control-plane.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit JSON"))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_is_fixed_destination_policy_checked_and_audited() {
    let Some(deployment) = Deployment::start().await else {
        return;
    };
    let target = echo_target().await;
    let admin_user = deployment
        .login(ADMIN, &["admins"])
        .await
        .expect("admin login");
    let mut admin = AdminClient::new(deployment.proxy_channel(Some(admin_user)));
    let applied = admin
        .apply_policy(ApplyPolicyRequest {
            sources: policy(&target),
            dry_run: false,
            source_ref: String::new(),
        })
        .await
        .expect("apply policy")
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
        .expect("worker token")
        .into_inner()
        .token;
    let worker = deployment.start_worker_with(&token, "worker", &[]).await;
    eventually(Duration::from_secs(15), "worker tunnels", || async {
        deployment.proxy().tunnels.summaries().len() == 2
    })
    .await;
    eventually(Duration::from_secs(15), "policy on components", || async {
        deployment.proxy().policy_version() == Some(applied.version)
            && worker.worker.policy_version() == Some(applied.version)
    })
    .await;

    let ca = std::fs::read_to_string(deployment.ca_file()).expect("CA");
    let developer = deployment
        .login(DEVELOPER, &["tcp-users"])
        .await
        .expect("developer login");
    let (listener, refused) = db_client::listen_on(
        &deployment.proxy_addr.to_string(),
        &ca,
        developer.clone(),
        limen_tunnel::alpn::TCP,
        "tcp-echo",
        "access",
        "",
    )
    .await;
    let mut client = TcpStream::connect(listener).await.expect("local listener");
    client
        .write_all(b"phase12-tcp-roundtrip")
        .await
        .expect("send payload");
    client.shutdown().await.expect("half close");
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.expect("read echo");
    assert_eq!(response, b"phase12-tcp-roundtrip");
    assert!(refused.lock().expect("refusal list").is_empty());

    let (blocked_listener, blocked_refused) = db_client::listen_on(
        &deployment.proxy_addr.to_string(),
        &ca,
        developer,
        limen_tunnel::alpn::TCP,
        "tcp-blocked",
        "access",
        "",
    )
    .await;
    let _ = TcpStream::connect(blocked_listener)
        .await
        .expect("blocked local listener");
    eventually(Duration::from_secs(5), "policy denial", || async {
        !blocked_refused.lock().expect("refusal list").is_empty()
    })
    .await;
    assert!(
        blocked_refused.lock().expect("refusal list")[0].contains("access denied"),
        "the deny rule should win"
    );

    eventually(Duration::from_secs(10), "TCP session audit", || async {
        events(&deployment)
            .iter()
            .any(|event| event["kind"] == "session.end" && event["data"]["kind"] == "tcp")
    })
    .await;
    let trail = events(&deployment);
    let started = trail
        .iter()
        .find(|event| event["kind"] == "session.start" && event["data"]["kind"] == "tcp")
        .expect("TCP session.start");
    let ended = trail
        .iter()
        .find(|event| {
            event["kind"] == "session.end" && event["session_id"] == started["session_id"]
        })
        .expect("matching TCP session.end");
    assert_eq!(started["user"], DEVELOPER);
    assert_eq!(started["data"]["resource"], "tcp-echo");
    assert!(ended["data"]["bytes_in"].as_u64().unwrap_or_default() > 0);
    assert!(ended["data"]["bytes_out"].as_u64().unwrap_or_default() > 0);
    assert!(
        trail.iter().any(|event| {
            event["kind"] == "auth.denied"
                && event["data"]["action"] == "tcp"
                && event["data"]["resource"] == "tcp-blocked"
        }),
        "the denied connection should be audited"
    );
    assert!(
        !serde_json::to_string(&trail)
            .expect("serialize audit")
            .contains("phase12-tcp-roundtrip"),
        "TCP payloads must not appear in audit events"
    );
    worker.stop().await;
}

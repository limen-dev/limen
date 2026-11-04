//! ADR-0011 for the worker path: while the control plane is down, a new session is allowed
//! inside the policy grace period and refused after it, and a session that is already open
//! keeps working throughout. (The SSH half of the ADR is in `phase2.rs`.)
//!
//! The target is a loopback echo stand-in over raw TCP. DB, Redis and Kubernetes sessions go
//! through the same proxy and worker policy-snapshot check, but only TCP is exercised here.

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
---
kind: role_mapping
version: v1
metadata: {{ name: idp }}
spec:
  - {{ idp_group: tcp-users, roles: [tcp-operators] }}
---
kind: resource
version: v1
metadata: {{ name: tcp-echo, labels: {{ env: test }} }}
spec:
  tcp: {{ address: "{address}" }}
  worker_selector: {{ pool: dev }}
"#
    );
    vec![PolicySource {
        name: "outage-tcp.yaml".into(),
        content: yaml,
    }]
}

/// Send `payload` on `client` and expect it echoed back.
async fn echoes(client: &mut TcpStream, payload: &[u8]) -> bool {
    if client.write_all(payload).await.is_err() {
        return false;
    }
    let mut got = vec![0; payload.len()];
    matches!(
        tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut got)).await,
        Ok(Ok(_))
    ) && got == payload
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_worker_session_needs_a_fresh_enough_policy_and_open_ones_do_not() {
    let Some(mut deployment) = Deployment::start().await else {
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
            source: String::new(),
            require_tests: false,
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

    // Logging in needs the control plane, so get the certificate before the outage.
    let ca = std::fs::read_to_string(deployment.ca_file()).expect("CA");
    let developer = deployment
        .login(DEVELOPER, &["tcp-users"])
        .await
        .expect("developer login");
    let proxy = deployment.proxy_addr.to_string();
    let connect = |name: &'static str| {
        let (proxy, ca, developer) = (proxy.clone(), ca.clone(), developer.clone());
        async move {
            db_client::listen_on(
                &proxy,
                &ca,
                developer,
                limen_tunnel::alpn::TCP,
                name,
                "access",
                "",
            )
            .await
        }
    };

    let (listener, refused) = connect("tcp-echo").await;
    let mut open = TcpStream::connect(listener).await.expect("local listener");
    assert!(echoes(&mut open, b"before the outage").await);
    assert!(refused.lock().expect("refusal list").is_empty());

    deployment.stop_control_plane().await;

    // The open session keeps working.
    assert!(
        echoes(&mut open, b"during the outage").await,
        "an open session survives the outage"
    );

    // Inside the grace period (3s in tests) the proxy and the worker still decide from their
    // cached snapshot, so a new session is allowed with no control plane at all.
    let (listener, refused) = connect("tcp-echo").await;
    let mut within = TcpStream::connect(listener).await.expect("local listener");
    assert!(
        echoes(&mut within, b"new session in grace").await,
        "a new session inside the grace period is allowed: {:?}",
        refused.lock().expect("refusal list")
    );

    // Past it, nothing can be decided, so a new session is refused (fail closed).
    tokio::time::sleep(Duration::from_secs(5)).await;
    let (listener, refused) = connect("tcp-echo").await;
    let mut late = TcpStream::connect(listener).await.expect("local listener");
    let _ = late.write_all(b"never echoed").await;
    eventually(
        Duration::from_secs(10),
        "refusal past the grace",
        || async { !refused.lock().expect("refusal list").is_empty() },
    )
    .await;
    let mut nothing = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), late.read_to_end(&mut nothing)).await;
    assert!(nothing.is_empty(), "a refused session must carry no data");

    // Sessions that were open before the outage, and during the grace period, still work.
    assert!(
        echoes(&mut open, b"after the grace period").await,
        "an open session survives past the grace period"
    );
    assert!(echoes(&mut within, b"also after").await);
    worker.stop().await;
}

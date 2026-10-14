//! Phase 2 end to end: SSH through proxy and worker to a target that trusts
//! only the Limen SSH user CA, with recording, audit, denials, and the
//! control plane outage semantics of ADR-0011.

use std::collections::HashMap;
use std::time::Duration;

use limen_e2e::{Deployment, eventually, ssh_client};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, CreateJoinTokenRequest, PolicySource};
use limen_testkit::ssh_target::SshTarget;
use russh::ChannelMsg;

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

fn read_jsonl(d: &Deployment, file: &str) -> Vec<serde_json::Value> {
    std::fs::read_to_string(d.dir.path().join(file))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect()
}

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread")]
async fn ssh_end_to_end_with_recording_audit_and_outage() {
    let Some(mut d) = Deployment::start().await else {
        return;
    };
    let target = SshTarget::start(&d.public_ca("ssh-user-ca.pub")).await;
    let host_ca = d.public_ca("ssh-host-ca.pub");
    let ca_pem = std::fs::read_to_string(d.ca_file()).expect("ca");
    let proxy_addr = d.proxy_addr.to_string();

    // Policy, and a worker labelled pool=dev.
    let alice = d
        .login("alice@example.com", &["admins"])
        .await
        .expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(alice)));
    let applied = admin
        .apply_policy(ApplyPolicyRequest {
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

    // bob runs a command as ubuntu on web-1.
    let bob = || async { d.login("bob@example.com", &["ops"]).await.expect("bob") };
    let conn = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        bob().await,
        &host_ca,
        "web-1",
        "ubuntu",
    )
    .await
    .expect("ssh session");
    let (out, status) = ssh_client::exec(&conn, "whoami").await.expect("exec");
    assert_eq!(out, "target: login=ubuntu command=whoami\n");
    assert_eq!(status, Some(0));
    // The target saw a per-session certificate naming the session and user.
    let (login, key_id) = target
        .logins
        .lock()
        .expect("lock")
        .last()
        .cloned()
        .expect("target login");
    assert_eq!(login, "ubuntu");
    assert!(
        key_id.starts_with("limen:") && key_id.ends_with(":bob@example.com"),
        "key id {key_id}"
    );
    drop(conn);

    // Recording and audit trail.
    eventually(
        Duration::from_secs(10),
        "session.end in the proxy audit",
        || async {
            read_jsonl(&d, "proxy/audit/proxy.jsonl")
                .iter()
                .any(|e| e["kind"] == "session.end")
        },
    )
    .await;
    let proxy_events = read_jsonl(&d, "proxy/audit/proxy.jsonl");
    let end = proxy_events
        .iter()
        .find(|e| e["kind"] == "session.end")
        .expect("session.end");
    let uri = end["data"]["recording_uri"]
        .as_str()
        .expect("recording uri");
    let path = uri.strip_prefix("file://").expect("file uri");
    let cast = std::fs::read_to_string(path).expect("recording");
    let header: serde_json::Value =
        serde_json::from_str(cast.lines().next().expect("header")).expect("json");
    assert_eq!(header["version"], 3);
    assert!(
        cast.contains("login=ubuntu command=whoami"),
        "recording has the output"
    );
    assert_eq!(
        end["data"]["recording_sha256"].as_str().map(str::len),
        Some(64)
    );
    assert!(
        proxy_events
            .iter()
            .any(|e| e["kind"] == "session.start" && e["user"] == "bob@example.com")
    );
    let worker_events = read_jsonl(&d, "worker/audit/worker.jsonl");
    let exec = worker_events
        .iter()
        .find(|e| e["kind"] == "ssh.exec")
        .expect("ssh.exec");
    assert_eq!(exec["data"]["command"], "whoami");
    assert_eq!(
        exec["session_id"], end["session_id"],
        "events link by session id"
    );

    // Denials: wrong login, unknown resource, unpinned host key.
    let err = ssh_client::connect(&proxy_addr, &ca_pem, bob().await, &host_ca, "web-1", "root")
        .await
        .err()
        .expect("root denied");
    assert!(err.contains("access denied"), "{err}");
    let err = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        bob().await,
        &host_ca,
        "nope",
        "ubuntu",
    )
    .await
    .err()
    .expect("unknown resource");
    assert!(err.contains("access denied"), "{err}");
    let err = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        bob().await,
        &host_ca,
        "web-unpinned",
        "ubuntu",
    )
    .await
    .err()
    .expect("unpinned host");
    assert!(err.contains("host_key"), "{err}");
    assert!(
        read_jsonl(&d, "proxy/audit/proxy.jsonl")
            .iter()
            .any(|e| e["kind"] == "auth.denied" && e["data"]["login"] == "root")
    );

    // A client that doesn't trust the Limen host CA refuses the worker: no MITM.
    let rogue_ca =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("key");
    let rogue_ca = rogue_ca.public_key().to_openssh().expect("openssh");
    let err = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        bob().await,
        &rogue_ca,
        "web-1",
        "ubuntu",
    )
    .await
    .err()
    .expect("host CA mismatch");
    assert!(err.contains("ssh"), "{err}");

    // Control plane outage (ADR-0011). Get bob's certificate first: logging
    // in needs the control plane too.
    let bob_cert = bob().await;
    let conn = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        bob_cert.clone(),
        &host_ca,
        "web-1",
        "ubuntu",
    )
    .await
    .expect("session before outage");
    let mut shell = conn.channel_open_session().await.expect("channel");
    shell
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .expect("pty");
    shell.request_shell(true).await.expect("shell");
    assert!(read_until(&mut shell, "welcome ubuntu").await);

    d.stop_control_plane().await;

    // The open session keeps working.
    shell
        .data(&b"still here\n"[..])
        .await
        .expect("send during outage");
    assert!(
        read_until(&mut shell, "still here").await,
        "existing session survives the outage"
    );

    // Within the grace period the proxy still decides, but SSH fails closed:
    // only the control plane can issue the per-session certificates.
    let err = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        bob_cert.clone(),
        &host_ca,
        "web-1",
        "ubuntu",
    )
    .await
    .err()
    .expect("new session fails");
    assert!(err.contains("control plane"), "{err}");

    // Past the grace period (3s in tests), the proxy can't decide at all.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let err = ssh_client::connect(&proxy_addr, &ca_pem, bob_cert, &host_ca, "web-1", "ubuntu")
        .await
        .err()
        .expect("stale policy");
    assert!(err.contains("can't be decided"), "{err}");

    // And the open session still works after the grace period.
    shell
        .data(&b"after grace\n"[..])
        .await
        .expect("send after grace");
    assert!(
        read_until(&mut shell, "after grace").await,
        "existing session survives past the grace period"
    );
}

async fn read_until(channel: &mut russh::Channel<russh::client::Msg>, want: &str) -> bool {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(10), channel.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => {
                seen.extend_from_slice(&data);
                if String::from_utf8_lossy(&seen).contains(want) {
                    return true;
                }
            }
            Ok(Some(_)) => {}
            _ => return false,
        }
    }
    false
}

//! Phase 2 end to end: SSH through proxy and worker to a target that trusts
//! only the Limen SSH user CA, with recording, audit, denials, and the
//! control plane outage semantics of ADR-0011.

use std::collections::HashMap;
use std::time::Duration;

use limen_e2e::{Deployment, eventually, ssh_client};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, CreateJoinTokenRequest, PolicySource};
use limen_testkit::ssh_target::SshTarget;
use limen_testkit::users::{ADMIN, DEVELOPER};
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

/// The control plane's JSONL audit sink in the test deployment.
const AUDIT: &str = "audit/control-plane.jsonl";

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
    let admin_user = d.login(ADMIN, &["admins"]).await.expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(admin_user)));
    let applied = admin
        .apply_policy(ApplyPolicyRequest {
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

    // dev_user runs a command as ubuntu on web-1.
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
        key_id.starts_with("limen:") && key_id.ends_with(&format!(":{DEVELOPER}")),
        "key id {key_id}"
    );
    drop(conn);

    // Recording and audit trail. Every component's events reach the control
    // plane through the spools; the recording is uploaded by the worker.
    eventually(
        Duration::from_secs(20),
        "session.end and session.recording in the control plane's audit trail",
        || async {
            let events = read_jsonl(&d, AUDIT);
            events.iter().any(|e| e["kind"] == "session.end")
                && events.iter().any(|e| e["kind"] == "session.recording")
        },
    )
    .await;
    let proxy_events = read_jsonl(&d, AUDIT);
    let end = proxy_events
        .iter()
        .find(|e| e["kind"] == "session.end")
        .expect("session.end");
    assert_eq!(end["producer"]["component"], "proxy");
    let stored = proxy_events
        .iter()
        .find(|e| e["kind"] == "session.recording" && e["session_id"] == end["session_id"])
        .expect("session.recording for this session");
    assert_eq!(
        stored["data"]["sha256"], end["data"]["recording_sha256"],
        "the stored recording is the one the session produced"
    );
    let uri = stored["data"]["recording_uri"]
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
            .any(|e| e["kind"] == "session.start" && e["user"] == DEVELOPER)
    );
    let worker_events = read_jsonl(&d, AUDIT);
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
    let err = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        dev_user().await,
        &host_ca,
        "web-1",
        "root",
    )
    .await
    .err()
    .expect("root denied");
    assert!(err.contains("access denied"), "{err}");
    let err = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        dev_user().await,
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
        dev_user().await,
        &host_ca,
        "web-unpinned",
        "ubuntu",
    )
    .await
    .err()
    .expect("unpinned host");
    assert!(err.contains("host_key"), "{err}");
    eventually(Duration::from_secs(10), "auth.denied for root", || async {
        read_jsonl(&d, AUDIT)
            .iter()
            .any(|e| e["kind"] == "auth.denied" && e["data"]["login"] == "root")
    })
    .await;

    // A client that doesn't trust the Limen host CA refuses the worker: no MITM.
    let rogue_ca =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("key");
    let rogue_ca = rogue_ca.public_key().to_openssh().expect("openssh");
    let err = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        dev_user().await,
        &rogue_ca,
        "web-1",
        "ubuntu",
    )
    .await
    .err()
    .expect("host CA mismatch");
    assert!(err.contains("ssh"), "{err}");

    // Control plane outage (ADR-0011). Get dev_user's certificate first: logging
    // in needs the control plane too.
    let developer_cert = dev_user().await;
    let conn = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        developer_cert.clone(),
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
        developer_cert.clone(),
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
    let err = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        developer_cert,
        &host_ca,
        "web-1",
        "ubuntu",
    )
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

/// ADR-0004: the worker is tunnelled to proxy A only; the session lands on
/// proxy B, which reaches the worker through A.
#[tokio::test(flavor = "multi_thread")]
async fn ssh_through_a_peer_proxy() {
    let Some(d) = Deployment::start().await else {
        return;
    };
    let target = SshTarget::start(&d.public_ca("ssh-user-ca.pub")).await;
    let host_ca = d.public_ca("ssh-host-ca.pub");
    let ca_pem = std::fs::read_to_string(d.ca_file()).expect("ca");

    let admin_user = d.login(ADMIN, &["admins"]).await.expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(admin_user)));
    admin
        .apply_policy(ApplyPolicyRequest {
            require_tests: false,
            sources: policy(&target.addr.to_string(), &target.host_key),
            dry_run: false,
            source_ref: String::new(),
        })
        .await
        .expect("apply");
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
    eventually(
        Duration::from_secs(15),
        "worker tunnels on proxy A",
        || async { d.proxy().tunnels.summaries().len() == 2 },
    )
    .await;

    let (proxy_b, addr_b) = d.start_extra_proxy("proxy-b").await;
    assert!(
        proxy_b.proxy.tunnels.summaries().is_empty(),
        "proxy B holds no tunnels"
    );
    eventually(
        Duration::from_secs(15),
        "proxy B and the worker have the policy",
        || async {
            proxy_b.proxy.policy_version().is_some() && worker.worker.policy_version().is_some()
        },
    )
    .await;

    let dev_user = d.login(DEVELOPER, &["ops"]).await.expect("developer");
    let mut last_err = String::new();
    // Proxy A reports its tunnels within a moment; B caches the registry for 5s.
    for _ in 0..40 {
        match ssh_client::connect(
            &addr_b.to_string(),
            &ca_pem,
            dev_user.clone(),
            &host_ca,
            "web-1",
            "ubuntu",
        )
        .await
        {
            Ok(conn) => {
                let (out, status) = ssh_client::exec(&conn, "hostname").await.expect("exec");
                assert_eq!(out, "target: login=ubuntu command=hostname\n");
                assert_eq!(status, Some(0));
                let proxy_b_id = proxy_b.proxy.id();
                eventually(
                    Duration::from_secs(10),
                    "proxy B's session.start",
                    || async {
                        read_jsonl(&d, AUDIT).iter().any(|e| {
                            e["kind"] == "session.start"
                                && e["producer"]["instance_id"]
                                    .as_str()
                                    .is_some_and(|i| i.starts_with(&format!("{proxy_b_id}/")))
                        })
                    },
                )
                .await;
                let events = read_jsonl(&d, AUDIT);
                assert!(
                    events.iter().any(|e| e["kind"] == "session.start"),
                    "proxy B audits the session it authorized"
                );
                return;
            }
            Err(e) => last_err = e,
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("session through the peer never succeeded: {last_err}");
}

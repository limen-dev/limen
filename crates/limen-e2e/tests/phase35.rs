//! Phase 3.5: locking a user and killing a session (ADR-0017). Both reach
//! proxies and workers through the signed policy snapshot, so a live SSH
//! session ends within a refresh, and the control plane refuses new
//! certificates at once.

use std::collections::HashMap;
use std::time::Duration;

use limen_e2e::{Deployment, eventually, ssh_client};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{
    ApplyPolicyRequest, CreateJoinTokenRequest, KillSessionRequest, ListLocksRequest,
    LockUserRequest, PolicySource, UnlockUserRequest,
};
use limen_testkit::ssh_target::SshTarget;
use limen_testkit::users::{ADMIN, DEVELOPER, GUEST};
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
"#
    );
    vec![PolicySource {
        name: "policy.yaml".into(),
        content: yaml,
    }]
}

fn read_jsonl(d: &Deployment) -> Vec<serde_json::Value> {
    std::fs::read_to_string(d.dir.path().join("audit/control-plane.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect()
}

/// Read until the channel closes or `want` shows up. `Some(true)` if `want`
/// arrived, `Some(false)` if the channel ended, `None` on timeout.
async fn read_until_closed(
    channel: &mut russh::Channel<russh::client::Msg>,
    want: &str,
    within: Duration,
) -> Option<bool> {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let left = deadline.checked_duration_since(tokio::time::Instant::now())?;
        match tokio::time::timeout(left, channel.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => {
                seen.extend_from_slice(&data);
                if String::from_utf8_lossy(&seen).contains(want) {
                    return Some(true);
                }
            }
            Ok(Some(ChannelMsg::Close | ChannelMsg::Eof) | None) => return Some(false),
            Ok(Some(_)) => {}
            Err(_) => return None,
        }
    }
}

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread")]
async fn lock_ends_live_sessions_and_kill_ends_one() {
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
    eventually(Duration::from_secs(15), "worker tunnel", || async {
        d.proxy().tunnels.summaries().len() == 2
    })
    .await;
    eventually(Duration::from_secs(15), "policy everywhere", || async {
        d.proxy().policy_version() == Some(applied.version)
            && worker.worker.policy_version() == Some(applied.version)
    })
    .await;

    let dev_user = d.login(DEVELOPER, &["ops"]).await.expect("developer");
    let guest_user = d.login(GUEST, &["ops"]).await.expect("guest");
    let open_shell = |identity: limen_tunnel::tls::Identity| {
        let (proxy_addr, ca_pem, host_ca) = (proxy_addr.clone(), ca_pem.clone(), host_ca.clone());
        async move {
            let conn =
                ssh_client::connect(&proxy_addr, &ca_pem, identity, &host_ca, "web-1", "ubuntu")
                    .await
                    .expect("ssh session");
            let mut shell = conn.channel_open_session().await.expect("channel");
            shell
                .request_pty(true, "xterm", 80, 24, 0, 0, &[])
                .await
                .expect("pty");
            shell.request_shell(true).await.expect("shell");
            assert_eq!(
                read_until_closed(&mut shell, "welcome ubuntu", Duration::from_secs(10)).await,
                Some(true)
            );
            (conn, shell)
        }
    };

    // Two live sessions: dev_user's and guest_user's.
    let (_bob_conn, mut developer_shell) = open_shell(dev_user.clone()).await;
    let (_carol_conn, mut guest_shell) = open_shell(guest_user.clone()).await;
    let guest_session = read_jsonl(&d)
        .iter()
        .find(|e| e["kind"] == "session.start" && e["user"] == GUEST)
        .map(|e| e["session_id"].as_str().expect("id").to_owned());
    let guest_session = match guest_session {
        Some(s) => s,
        None => {
            eventually(Duration::from_secs(15), "guest's session.start", || async {
                read_jsonl(&d)
                    .iter()
                    .any(|e| e["kind"] == "session.start" && e["user"] == GUEST)
            })
            .await;
            read_jsonl(&d)
                .iter()
                .find(|e| e["kind"] == "session.start" && e["user"] == GUEST)
                .map(|e| e["session_id"].as_str().expect("id").to_owned())
                .expect("session id")
        }
    };

    // Killing guest_user's session ends it, not dev_user's.
    assert!(
        admin
            .kill_session(KillSessionRequest {
                session_id: guest_session.clone(),
                reason: "testing".into(),
            })
            .await
            .expect("kill")
            .into_inner()
            .killed
    );
    assert_eq!(
        read_until_closed(&mut guest_shell, "never appears", Duration::from_secs(20)).await,
        Some(false),
        "the killed session ends"
    );
    developer_shell
        .data(&b"still here\n"[..])
        .await
        .expect("send");
    assert_eq!(
        read_until_closed(&mut developer_shell, "still here", Duration::from_secs(10)).await,
        Some(true),
        "another user's session is untouched"
    );

    // Locking dev_user ends his session and refuses a new one, at once.
    assert!(
        admin
            .lock_user(LockUserRequest {
                username: DEVELOPER.into(),
                reason: "laptop stolen".into(),
            })
            .await
            .expect("lock")
            .into_inner()
            .locked
    );
    assert!(
        !admin
            .lock_user(LockUserRequest {
                username: DEVELOPER.into(),
                reason: "again".into(),
            })
            .await
            .expect("lock again")
            .into_inner()
            .locked,
        "a second lock changes nothing"
    );
    let locks = admin
        .list_locks(ListLocksRequest {})
        .await
        .expect("list")
        .into_inner()
        .locks;
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].reason, "laptop stolen");
    assert_eq!(locks[0].locked_by, ADMIN);
    assert_eq!(
        read_until_closed(
            &mut developer_shell,
            "never appears",
            Duration::from_secs(20)
        )
        .await,
        Some(false),
        "the locked user's session ends"
    );
    let err = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        dev_user.clone(),
        &host_ca,
        "web-1",
        "ubuntu",
    )
    .await
    .err()
    .expect("locked user refused");
    assert!(err.contains("user locked"), "{err}");
    // Login is refused too.
    let err = d
        .login(DEVELOPER, &["ops"])
        .await
        .expect_err("locked user can't log in");
    assert!(err.message().contains("user locked"), "{}", err.message());

    // Unlocking restores access.
    assert!(
        admin
            .unlock_user(UnlockUserRequest {
                username: DEVELOPER.into(),
            })
            .await
            .expect("unlock")
            .into_inner()
            .unlocked
    );
    eventually(
        Duration::from_secs(20),
        "developer can connect again",
        || async {
            ssh_client::connect(
                &proxy_addr,
                &ca_pem,
                dev_user.clone(),
                &host_ca,
                "web-1",
                "ubuntu",
            )
            .await
            .is_ok()
        },
    )
    .await;

    // Non-admins can't lock anyone.
    let mut as_bob = AdminClient::new(d.proxy_channel(Some(dev_user.clone())));
    let denied = as_bob
        .lock_user(LockUserRequest {
            username: GUEST.into(),
            reason: "no".into(),
        })
        .await
        .expect_err("non-admin");
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    // Everything is audited, and the sessions ended for the right reasons.
    eventually(Duration::from_secs(20), "audit events", || async {
        let events = read_jsonl(&d);
        let ended = |why: &str| {
            events
                .iter()
                .any(|e| e["kind"] == "session.end" && e["data"]["reason"] == why)
        };
        ["user.lock", "user.unlock", "session.kill"]
            .iter()
            .all(|k| events.iter().any(|e| e["kind"] == *k))
            && ended("session killed")
            && ended("user locked")
    })
    .await;
    let events = read_jsonl(&d);
    let lock = events
        .iter()
        .find(|e| e["kind"] == "user.lock")
        .expect("user.lock");
    assert_eq!(lock["user"], ADMIN);
    assert_eq!(lock["data"]["target_user"], DEVELOPER);
    assert_eq!(lock["data"]["reason"], "laptop stolen");
    let kill = events
        .iter()
        .find(|e| e["kind"] == "session.kill")
        .expect("session.kill");
    assert_eq!(kill["session_id"], guest_session);
    assert!(
        events
            .iter()
            .any(|e| e["kind"] == "auth.denied" && e["data"]["reason"] == "user locked")
    );
}

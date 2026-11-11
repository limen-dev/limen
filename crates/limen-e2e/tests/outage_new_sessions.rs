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

/// Apply the policy, enrol a worker and wait until both sides hold it. Returns the worker.
async fn tcp_deployment_ready(deployment: &Deployment) -> limen_e2e::RunningWorker {
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
            replay_days: 0,
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
    worker
}

/// Open a local listener whose connections become sessions to `tcp-echo`.
async fn listener_for(
    deployment: &Deployment,
    developer: &limen_tunnel::tls::Identity,
) -> (
    std::net::SocketAddr,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
    let ca = std::fs::read_to_string(deployment.ca_file()).expect("CA");
    db_client::listen_on(
        &deployment.proxy_addr.to_string(),
        &ca,
        developer.clone(),
        limen_tunnel::alpn::TCP,
        "tcp-echo",
        "access",
        "",
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_worker_session_needs_a_fresh_enough_policy_and_open_ones_do_not() {
    let Some(mut deployment) = Deployment::start().await else {
        return;
    };
    let worker = tcp_deployment_ready(&deployment).await;

    // Logging in needs the control plane, so get the certificate before the outage.
    let developer = deployment
        .login(DEVELOPER, &["tcp-users"])
        .await
        .expect("developer login");

    let (listener, refused) = listener_for(&deployment, &developer).await;
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
    let (listener, refused) = listener_for(&deployment, &developer).await;
    let mut within = TcpStream::connect(listener).await.expect("local listener");
    assert!(
        echoes(&mut within, b"new session in grace").await,
        "a new session inside the grace period is allowed: {:?}",
        refused.lock().expect("refusal list")
    );

    // Past it, nothing can be decided, so a new session is refused (fail closed).
    tokio::time::sleep(Duration::from_secs(5)).await;
    let (listener, refused) = listener_for(&deployment, &developer).await;
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

/// A login is a control plane job (it signs the certificate), so with the control plane down it
/// fails, inside the grace period as well as after it; nobody gets in who did not already hold a
/// certificate.
#[tokio::test(flavor = "multi_thread")]
async fn logging_in_fails_while_the_control_plane_is_down() {
    let Some(mut deployment) = Deployment::start().await else {
        return;
    };
    let worker = tcp_deployment_ready(&deployment).await;
    deployment
        .login(DEVELOPER, &["tcp-users"])
        .await
        .expect("login works while the control plane is up");

    deployment.stop_control_plane().await;

    // Inside the grace period.
    let err = deployment
        .login(DEVELOPER, &["tcp-users"])
        .await
        .expect_err("a login inside the grace period must fail");
    eprintln!("login in grace: {} {}", err.code(), err.message());

    // After it.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let err = deployment
        .login(DEVELOPER, &["tcp-users"])
        .await
        .expect_err("a login past the grace period must fail");
    eprintln!("login after grace: {} {}", err.code(), err.message());
    worker.stop().await;
}

/// With the control plane down, open new sessions for up to `window` and report how many were
/// allowed, when one was first closed without carrying data (if any), and the refusals the client
/// saw. `proxy_args` is the only thing that differs between the two spool tests.
async fn new_sessions_during_an_outage(
    proxy_args: &[&str],
    window: Duration,
) -> (usize, Option<Duration>, Vec<String>) {
    let mut deployment = Deployment::start_with_proxy_args(proxy_args)
        .await
        .expect("a deployment");
    let worker = tcp_deployment_ready(&deployment).await;
    let developer = deployment
        .login(DEVELOPER, &["tcp-users"])
        .await
        .expect("developer login");
    let (listener, refused) = listener_for(&deployment, &developer).await;

    // Works while events drain to the control plane.
    let mut first = TcpStream::connect(listener).await.expect("local listener");
    assert!(echoes(&mut first, b"recorded").await);
    drop(first);

    deployment.stop_control_plane().await;

    let started = tokio::time::Instant::now();
    let mut allowed = 0;
    let mut closed_at = None;
    while started.elapsed() < window && closed_at.is_none() {
        let mut c = TcpStream::connect(listener).await.expect("local listener");
        if echoes(&mut c, b"x").await {
            allowed += 1;
        } else {
            closed_at = Some(started.elapsed());
        }
        // Ten a second, well under the proxy's accept limit (50 a second per address, burst
        // 200). Unpaced, a fast machine runs out of burst and the proxy drops the connection,
        // which looks exactly like a refused session.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let reasons = refused.lock().expect("refusal list").clone();
    worker.stop().await;
    (allowed, closed_at, reasons)
}

/// When the control plane is down nothing drains the proxy's audit spool. Once it is full, audit
/// fails closed (ADR-0009, ADR-0011): a new session is refused rather than run unrecorded.
/// The control run, with the default spool size, shows that it is the spool and not something
/// else about the outage that stops the session.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_audit_spool_refuses_new_sessions_instead_of_running_unrecorded() {
    if limen_testkit::database_url().is_none() {
        return;
    }
    // Inside the 3s grace period, so a stale policy cannot be the reason.
    let window = Duration::from_millis(1500);

    let (allowed, closed_at, reasons) = Box::pin(new_sessions_during_an_outage(&[], window)).await;
    eprintln!("control: allowed {allowed}, closed at {closed_at:?}, refusals {reasons:?}");
    assert!(
        closed_at.is_none() && allowed > 0,
        "with room in the spool, new sessions run during the grace period"
    );

    let (allowed, closed_at, reasons) = Box::pin(new_sessions_during_an_outage(
        &["--audit-spool-max-bytes=1500"],
        window,
    ))
    .await;
    eprintln!("tiny spool: allowed {allowed}, closed at {closed_at:?}, refusals {reasons:?}");
    assert!(
        closed_at.is_some(),
        "a full spool must stop new sessions inside the grace period (allowed {allowed})"
    );
    assert!(
        reasons.iter().all(|r| !r.contains("can't be decided")),
        "the policy was still fresh, so this is not the grace period: {reasons:?}"
    );
}

/// The other audit failure mode (ADR-0009, design section 8): with `degrade` a full spool does not
/// stop the session. The same tiny spool and window as the `fail_closed` test, so the only
/// difference is the mode.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_audit_spool_in_degrade_mode_lets_new_sessions_run() {
    if limen_testkit::database_url().is_none() {
        return;
    }
    let window = Duration::from_millis(1500);
    let (allowed, closed_at, reasons) = Box::pin(new_sessions_during_an_outage(
        &[
            "--audit-spool-max-bytes=1500",
            "--audit-failure-mode=degrade",
        ],
        window,
    ))
    .await;
    eprintln!("degrade: allowed {allowed}, closed at {closed_at:?}, refusals {reasons:?}");
    assert!(
        closed_at.is_none() && allowed > 0,
        "degrade keeps sessions running with a full spool (allowed {allowed}, refusals {reasons:?})"
    );
}

/// When a control plane comes back, a session allowed during the outage has its audit events
/// delivered (the proxy spooled them, delivery is at-least-once), and new sessions that the
/// stale policy had refused work again, without restarting the proxy or the worker.
#[tokio::test(flavor = "multi_thread")]
async fn a_returning_control_plane_gets_the_outage_audit_and_new_sessions_work_again() {
    let Some(mut deployment) = Box::pin(Deployment::start_scaled(&[])).await else {
        return;
    };
    let worker = tcp_deployment_ready(&deployment).await;
    let developer = deployment
        .login(DEVELOPER, &["tcp-users"])
        .await
        .expect("developer login");
    let (listener, refused) = listener_for(&deployment, &developer).await;

    deployment.stop_control_plane().await;

    // Allowed inside the grace period, with the control plane down.
    let mut during = TcpStream::connect(listener).await.expect("local listener");
    assert!(echoes(&mut during, b"during the outage").await);
    drop(during);

    // Past the grace period the same request is refused.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut late = TcpStream::connect(listener).await.expect("local listener");
    let _ = late.write_all(b"never echoed").await;
    eventually(
        Duration::from_secs(10),
        "refusal past the grace",
        || async { !refused.lock().expect("refusal list").is_empty() },
    )
    .await;
    drop(late);

    // A replacement control plane on the same database; the name proxies dial now points to it.
    let second = deployment.start_extra_control_plane("cp-e2e-2").await;
    limen_tunnel::connect::set_test_resolution(&deployment.cp_dial, vec![second.addr]);

    // The outage's audit reaches the new control plane's trail.
    let trail = deployment.dir.path().join("audit/cp-e2e-2.jsonl");
    eventually(
        Duration::from_secs(40),
        "the outage session in the new control plane's audit",
        || async {
            std::fs::read_to_string(&trail)
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .any(|e| e["kind"] == "session.start" && e["data"]["kind"] == "tcp")
        },
    )
    .await;

    // Policy is fresh again, so a new session is allowed.
    let mut again = None;
    for _ in 0..40 {
        let mut c = TcpStream::connect(listener).await.expect("local listener");
        if echoes(&mut c, b"back").await {
            again = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        again.is_some(),
        "new sessions work once a control plane is back"
    );
    deployment
        .login(DEVELOPER, &["tcp-users"])
        .await
        .expect("logins work again");
    worker.stop().await;
    second.stop().await;
}

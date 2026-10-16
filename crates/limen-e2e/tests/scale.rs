//! Phase 5 scale-out: connections rebalance onto control plane replicas,
//! and sessions go to workers with room (per-worker session cap).
//!
//! Needs `LIMEN_TEST_DATABASE_URL`; prints SKIPPED without it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use limen_e2e::{Deployment, RunningWorker, eventually, ssh_client};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::worker_tunnel_client::WorkerTunnelClient;
use limen_proto::v1::{ApplyPolicyRequest, CreateJoinTokenRequest, PolicySource, TunnelFrame};
use limen_proxy::tunnels::Load;
use limen_testkit::ssh_target::SshTarget;
use limen_testkit::users::{ADMIN, DEVELOPER};
use tokio::net::TcpListener;

/// The maximum connection age these tests give the control planes.
const AGE_SECS: u64 = 2;
const GRACE_SECS: u64 = 1;

/// Accepts on its own port and pipes each connection to `target`, counting
/// them: the test's view of which replica a client reached.
async fn counting_forwarder(target: SocketAddr) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&count);
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if let Ok(mut outbound) = tokio::net::TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    (addr, count)
}

#[tokio::test(flavor = "multi_thread")]
async fn new_replica_receives_connections_within_one_age_period() {
    let age = format!("--max-connection-age-secs={AGE_SECS}");
    let grace = format!("--connection-age-grace-secs={GRACE_SECS}");
    let Some(d) = Deployment::start_scaled(&[&age, &grace]).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL to run end-to-end tests");
        return;
    };
    // The proxy is up on the first replica: it fetched a policy snapshot.
    eventually(Duration::from_secs(20), "proxy policy snapshot", || async {
        d.proxy().policy_version().is_some()
    })
    .await;

    // Scale out. For one age period the name resolves to the new replica
    // alone, so the proxy's next connection must land there: its existing
    // connection (it calls every second, for the policy refresh) has to end
    // at its age, and the redial has to resolve the name again. Without a
    // maximum age the proxy stays on the first replica forever.
    let second = d.start_extra_control_plane("cp-e2e-2").await;
    let (via, accepted) = counting_forwarder(second.addr).await;
    limen_tunnel::connect::set_test_resolution(&d.cp_dial, vec![via]);
    // At most the age (+10 % jitter) plus the grace for a busy connection,
    // and a little slack for the redial.
    let period = Duration::from_secs(AGE_SECS) * 11 / 10 + Duration::from_secs(GRACE_SECS);
    eventually(
        period + Duration::from_secs(3),
        "a proxy connection to the new replica within one age period",
        || async { accepted.load(Ordering::SeqCst) > 0 },
    )
    .await;
    // Then both, as DNS would once the new one is registered.
    limen_tunnel::connect::set_test_resolution(&d.cp_dial, vec![d.cp_addr, via]);

    // Relayed calls keep working while connections move.
    for _ in 0..3 {
        d.login("scale-user@example.com", &["admins"])
            .await
            .expect("login through the proxy");
        tokio::time::sleep(period / 2).await;
    }
    second.stop().await;
}

// ---- Per-worker session cap -------------------------------------------------

fn session_policy(target_addr: &str, host_key: &str) -> Vec<PolicySource> {
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

/// A deployment with an SSH target, the policy above, and one worker
/// (pool=dev) per entry of `caps`, started with `--max-sessions=<cap>`,
/// tunnelled and up to date.
struct Capped {
    d: Deployment,
    _target: SshTarget,
    workers: Vec<RunningWorker>,
    host_ca: String,
    ca_pem: String,
}

async fn capped_deployment(caps: &[u32]) -> Option<Capped> {
    let d = Deployment::start().await?;
    let target = SshTarget::start(&d.public_ca("ssh-user-ca.pub")).await;
    let admin_user = d.login(ADMIN, &["admins"]).await.expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(admin_user)));
    let applied = admin
        .apply_policy(ApplyPolicyRequest {
            sources: session_policy(&target.addr.to_string(), &target.host_key),
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
    let mut workers = Vec::new();
    for cap in caps {
        let name = format!("worker-{}", uuid::Uuid::now_v7().simple());
        let cap = format!("--max-sessions={cap}");
        workers.push(d.start_worker_with(&token, &name, &[&cap]).await);
    }
    eventually(Duration::from_secs(15), "worker tunnels", || async {
        d.proxy().tunnels.summaries().len() == 2 * caps.len()
    })
    .await;
    eventually(
        Duration::from_secs(15),
        "proxy and workers have the policy",
        || async {
            d.proxy().policy_version() == Some(applied.version)
                && workers
                    .iter()
                    .all(|w| w.worker.policy_version() == Some(applied.version))
        },
    )
    .await;
    Some(Capped {
        host_ca: d.public_ca("ssh-host-ca.pub"),
        ca_pem: std::fs::read_to_string(d.ca_file()).expect("ca"),
        d,
        _target: target,
        workers,
    })
}

impl Capped {
    async fn ssh(
        &self,
        proxy_addr: SocketAddr,
        resource: &str,
    ) -> Result<russh::client::Handle<ssh_client::HostCheck>, String> {
        let user = self.d.login(DEVELOPER, &["ops"]).await.expect("developer");
        // Refusals are immediate: a full pool must never hang.
        tokio::time::timeout(
            Duration::from_secs(20),
            ssh_client::connect(
                &proxy_addr.to_string(),
                &self.ca_pem,
                user,
                &self.host_ca,
                resource,
                "ubuntu",
            ),
        )
        .await
        .expect("the session is decided without hanging")
    }

    /// Take one of `worker`'s session slots behind the proxy's back, for as
    /// long as the returned task runs: the proxy's figure for it goes stale.
    /// (An open with no first frame holds a slot until the worker's 10 s
    /// wait for it ends; the task opens again at once.)
    async fn fill_behind_the_proxys_back(&self, worker: usize) -> tokio::task::JoinHandle<()> {
        let w = &self.workers[worker].worker;
        let before = w.active_sessions();
        let tunnel = self.d.proxy().tunnels.channel_for(&w.id()).expect("tunnel");
        let task = tokio::spawn(async move {
            loop {
                let _ = WorkerTunnelClient::new(tunnel.clone())
                    .open_session(tonic::codegen::tokio_stream::pending::<TunnelFrame>())
                    .await;
            }
        });
        eventually(
            Duration::from_secs(5),
            "a slot taken behind the proxy's back",
            || async { w.active_sessions() > before },
        )
        .await;
        task
    }

    fn refused(&self) -> u64 {
        self.workers
            .iter()
            .map(|w| w.worker.sessions_refused_at_cap())
            .sum()
    }

    fn audit(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.d.dir.path().join("audit/control-plane.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).expect("json"))
            .collect()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_refuses_over_cap() {
    let Some(c) = Box::pin(capped_deployment(&[1])).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL to run end-to-end tests");
        return;
    };
    let worker_id = c.workers[0].worker.id();
    // The worker reports its cap with every ping.
    assert_eq!(
        c.d.proxy().tunnels.load(&worker_id),
        Some(Load { active: 0, max: 1 })
    );

    // A session the worker refuses after taking its slot gives the slot back.
    let err = c
        .ssh(c.d.proxy_addr, "web-unpinned")
        .await
        .err()
        .expect("unpinned host refused");
    assert!(err.contains("host_key"), "{err}");
    assert_eq!(c.workers[0].worker.active_sessions(), 0);

    let first = c.ssh(c.d.proxy_addr, "web-1").await.expect("first session");
    assert_eq!(c.workers[0].worker.active_sessions(), 1);
    assert_eq!(
        c.d.proxy().tunnels.load(&worker_id),
        Some(Load { active: 1, max: 1 }),
        "the proxy counts the session it opened before the next ping"
    );

    // Past the proxy's own check (a proxy whose view is stale would do
    // this): the worker itself refuses, with resource_exhausted.
    let tunnel = c.d.proxy().tunnels.channel_for(&worker_id).expect("tunnel");
    let refused = WorkerTunnelClient::new(tunnel)
        .open_session(tonic::codegen::tokio_stream::iter(Vec::<TunnelFrame>::new()))
        .await
        .expect_err("the worker refuses a session over its cap");
    assert_eq!(
        refused.code(),
        tonic::Code::ResourceExhausted,
        "{refused:?}"
    );
    assert!(refused.message().contains("no capacity"), "{refused:?}");

    // The session ends: its slot comes back, on the worker and on the proxy,
    // without waiting for a ping.
    drop(first);
    eventually(Duration::from_secs(10), "the slot is released", || async {
        c.workers[0].worker.active_sessions() == 0
            && c.d.proxy().tunnels.load(&worker_id) == Some(Load { active: 0, max: 1 })
    })
    .await;
    let again = c.ssh(c.d.proxy_addr, "web-1").await.expect("room again");
    let (out, status) = ssh_client::exec(&again, "whoami").await.expect("exec");
    assert_eq!(out, "target: login=ubuntu command=whoami\n");
    assert_eq!(status, Some(0));
}

#[tokio::test(flavor = "multi_thread")]
async fn capacity_error_is_audited() {
    let Some(c) = Box::pin(capped_deployment(&[1])).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL to run end-to-end tests");
        return;
    };
    let _first = c.ssh(c.d.proxy_addr, "web-1").await.expect("first session");

    // The only eligible worker is full: a clear error, at once, and audited.
    let err = c
        .ssh(c.d.proxy_addr, "web-1")
        .await
        .err()
        .expect("no room for a second session");
    assert!(err.starts_with("no capacity"), "{err}");
    eventually(
        Duration::from_secs(20),
        "the capacity denial in the audit trail",
        || async {
            c.audit().iter().any(|e| {
                e["kind"] == "auth.denied"
                    && e["data"]["reason"] == "capacity"
                    && e["user"] == DEVELOPER
                    && e["data"]["resource"] == "web-1"
                    && e["producer"]["component"] == "proxy"
            })
        },
    )
    .await;

    // Through a peer proxy that holds no tunnel: the same answer, whether its
    // registry view is already full or the proxy holding the tunnel refuses.
    let (proxy_b, addr_b) = c.d.start_extra_proxy("proxy-b").await;
    eventually(
        Duration::from_secs(15),
        "proxy B has the policy",
        || async { proxy_b.proxy.policy_version().is_some() },
    )
    .await;
    let mut last = String::new();
    for _ in 0..40 {
        // Until proxy A's report reaches the registry, B finds no worker.
        match c.ssh(addr_b, "web-1").await {
            Ok(_) => panic!("a peered session past the cap"),
            Err(e) if e.starts_with("no capacity") => {
                last.clear();
                break;
            }
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(last.is_empty(), "peered session: {last}");
    let b = proxy_b.proxy.id();
    eventually(
        Duration::from_secs(20),
        "proxy B audits its capacity denial",
        || async {
            c.audit().iter().any(|e| {
                e["kind"] == "auth.denied"
                    && e["data"]["reason"] == "capacity"
                    && e["producer"]["instance_id"]
                        .as_str()
                        .is_some_and(|i| i.starts_with(&format!("{b}/")))
            })
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_full_worker_is_skipped_for_one_with_room() {
    let Some(c) = Box::pin(capped_deployment(&[1, 2])).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL to run end-to-end tests");
        return;
    };
    let (full, roomy) = (&c.workers[0].worker, &c.workers[1].worker);
    // The first worker is full, but the proxy's last figure says it's idle.
    let filler = c.fill_behind_the_proxys_back(0).await;
    assert_eq!(
        c.d.proxy().tunnels.load(&full.id()),
        Some(Load { active: 0, max: 1 })
    );

    // Both sessions land on the second worker. The second one, at least,
    // goes to the first worker first (it looks emptier: 0/1 against 1/2),
    // is refused there, and is retried with a new grant.
    let one = c.ssh(c.d.proxy_addr, "web-1").await.expect("first session");
    let two = c
        .ssh(c.d.proxy_addr, "web-1")
        .await
        .expect("second session");
    assert_eq!(roomy.active_sessions(), 2);
    assert!(c.refused() >= 1, "the full worker was tried and refused");
    let (out, status) = ssh_client::exec(&two, "whoami").await.expect("exec");
    assert_eq!(out, "target: login=ubuntu command=whoami\n");
    assert_eq!(status, Some(0));
    // No denial was audited for the refused attempts.
    assert!(
        !c.audit()
            .iter()
            .any(|e| e["kind"] == "auth.denied" && e["data"]["reason"] == "capacity"),
        "only final outcomes are audited"
    );
    drop((one, two));
    filler.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn every_worker_full_gives_up_after_three_attempts() {
    let Some(c) = Box::pin(capped_deployment(&[1, 1, 1, 1])).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL to run end-to-end tests");
        return;
    };
    let mut fillers = Vec::new();
    for i in 0..4 {
        fillers.push(c.fill_behind_the_proxys_back(i).await);
    }
    // Every figure the proxy has says "idle"; every worker is full.
    let err = c
        .ssh(c.d.proxy_addr, "web-1")
        .await
        .err()
        .expect("no worker has room");
    assert!(err.starts_with("no capacity"), "{err}");
    assert_eq!(c.refused(), 3, "three workers tried, then it gave up");
    eventually(
        Duration::from_secs(20),
        "one audited capacity denial",
        || async {
            c.audit()
                .iter()
                .filter(|e| e["kind"] == "auth.denied" && e["data"]["reason"] == "capacity")
                .count()
                == 1
        },
    )
    .await;
    for f in fillers {
        f.abort();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_through_a_peer_is_retried_and_the_holder_frees_the_slot() {
    let Some(c) = Box::pin(capped_deployment(&[1, 2])).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL to run end-to-end tests");
        return;
    };
    let (proxy_b, addr_b) = c.d.start_extra_proxy("proxy-b").await;
    eventually(
        Duration::from_secs(15),
        "proxy B has the policy",
        || async { proxy_b.proxy.policy_version().is_some() },
    )
    .await;
    // Proxy B holds no tunnel: sessions through it are peered to proxy A.
    // Until A's report reaches the registry, B finds no worker.
    let mut first = None;
    let mut last = String::new();
    for _ in 0..40 {
        match c.ssh(addr_b, "web-1").await {
            Ok(conn) => {
                first = Some(conn);
                break;
            }
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let first = first.unwrap_or_else(|| panic!("no peered session: {last}"));
    drop(first);
    let (full, roomy) = (&c.workers[0].worker, &c.workers[1].worker);
    // Once a peered session ends, the proxy holding the tunnel frees its slot.
    let a = c.d.proxy();
    eventually(
        Duration::from_secs(10),
        "proxy A frees the peered session's slot",
        || async {
            full.active_sessions() == 0
                && roomy.active_sessions() == 0
                && a.tunnels.load(&full.id()).is_some_and(|l| l.active == 0)
                && a.tunnels.load(&roomy.id()).is_some_and(|l| l.active == 0)
        },
    )
    .await;

    // Now the first worker is full behind everyone's back. B's figures (from
    // the registry) and A's say it's idle, so B picks it about half the
    // time; A forwards, the worker refuses, and B tries the other one.
    let filler = c.fill_behind_the_proxys_back(0).await;
    for i in 0..6 {
        let conn = c
            .ssh(addr_b, "web-1")
            .await
            .unwrap_or_else(|e| panic!("peered session {i}: {e}"));
        assert_eq!(
            roomy.active_sessions(),
            1,
            "session {i} is on the worker with room"
        );
        drop(conn);
        eventually(
            Duration::from_secs(10),
            "the slot comes back on A",
            || async {
                roomy.active_sessions() == 0
                    && a.tunnels.load(&roomy.id()).is_some_and(|l| l.active == 0)
            },
        )
        .await;
    }
    eprintln!(
        "refusals by the full worker: {}",
        full.sessions_refused_at_cap()
    );
    filler.abort();
}

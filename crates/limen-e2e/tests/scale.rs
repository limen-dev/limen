//! Phase 5 scale-out: connections rebalance onto control plane replicas.
//!
//! Needs `LIMEN_TEST_DATABASE_URL`; prints SKIPPED without it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use limen_e2e::{Deployment, eventually};
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

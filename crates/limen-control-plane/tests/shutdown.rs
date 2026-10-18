//! Shutdown: not ready first, `Ingest` refused, in-flight work bounded, the
//! spool drained or abandoned within the budget, then the registry row gone.

mod common;

use std::time::{Duration, Instant};

use common::Harness;
use limen_proto::v1::IngestRequest;
use limen_proto::v1::audit_ingest_server::AuditIngest;
use tonic::{Code, Request};

const DRAIN_TIMEOUT_SECS: u64 = 5;

async fn get(url: &str) -> Option<(u16, String)> {
    let r = reqwest::Client::new()
        .get(url)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .ok()?;
    let status = r.status().as_u16();
    Some((status, r.text().await.unwrap_or_default()))
}

/// A server that accepts connections and never answers, like a sink that
/// has hung.
async fn black_hole() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    addr
}

#[tokio::test]
async fn shutdown_is_ordered_and_stays_within_the_budget() {
    let hole = black_hole().await;
    let admin = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr")
    };
    let Some(h) = Harness::start_with(&[
        format!("--datadog-logs-url=http://{hole}/logs"),
        "--datadog-api-key=k".into(),
        format!("--drain-timeout={DRAIN_TIMEOUT_SECS}s"),
        format!("--admin-listen={admin}"),
    ])
    .await
    else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let ready = format!("http://{admin}/readyz");
    for _ in 0..100 {
        if get(&ready).await.is_some_and(|(s, _)| s == 200) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(get(&ready).await.map(|r| r.0), Some(200));

    // A dead sink with records waiting, and a connection that never
    // finishes its handshake.
    for i in 0..5u64 {
        let event = limen_audit::Event::new(
            limen_audit::EventKind::SessionRecording,
            limen_audit::Producer {
                component: "control-plane".into(),
                instance_id: "cp-test".into(),
                seq: i,
            },
            serde_json::json!({ "n": i }),
        );
        h.state
            .pipeline
            .spool
            .append(&serde_json::to_vec(&event).expect("json"))
            .await
            .expect("append");
    }
    let _hung = tokio::net::TcpStream::connect(h.addr).await.expect("hung");

    let started = Instant::now();
    h.begin_shutdown();

    // Not ready first, while the process is still alive and scrapable.
    let mut not_ready = None;
    for _ in 0..100 {
        if let Some(r) = get(&ready).await
            && r.0 == 503
        {
            not_ready = Some(r);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (_, body) = not_ready.expect("/readyz goes 503 during the drain");
    assert_eq!(body, "shutting down");
    // The API port closes as soon as the accept loop stops, so a client
    // dialing the shared name gets "refused" and moves on to another
    // replica, instead of landing in the backlog of a listener nobody
    // accepts from. (readyz flips first, from another task: allow a moment.)
    let mut refused = false;
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(h.addr).await.is_err() {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(refused, "new connections are refused during the drain");
    assert_eq!(
        get(&format!("http://{admin}/healthz")).await.map(|r| r.0),
        Some(200)
    );
    assert_eq!(
        get(&format!("http://{admin}/metrics")).await.map(|r| r.0),
        Some(200)
    );
    let rows = |db: sqlx::PgPool| async move {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM control_plane_replicas")
            .fetch_one(&db)
            .await
            .expect("count")
    };
    assert_eq!(rows(h.state.db.clone()).await, 1, "still registered");

    let err = limen_control_plane::services::ingest::IngestService(h.state.clone())
        .ingest(Request::new(IngestRequest { events: vec![] }))
        .await
        .expect_err("ingest is refused while draining");
    assert_eq!(err.code(), Code::Unavailable);

    h.finish().await.expect("run");
    let total = started.elapsed();
    // 80 % of the drain timeout is the budget; a hung connection and a dead
    // sink must not push past it (the old code needed ~1.8x).
    assert!(
        total < Duration::from_millis(DRAIN_TIMEOUT_SECS * 800 + 700),
        "shutdown took {total:?}"
    );
    assert_eq!(rows(h.state.db.clone()).await, 0, "deregistered at the end");
    assert!(
        h.state
            .pipeline
            .spool
            .pending(limen_control_plane::pipeline::DATADOG)
            > 0,
        "the dead sink's records stay spooled"
    );
}

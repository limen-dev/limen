//! Handoff: an ephemeral replica that is shutting down gives the audit
//! records its sinks have not shipped to a live peer (design §A).

mod common;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::Harness;
use limen_audit::spool::{Spool, SpoolConfig};
use limen_audit::{Event, EventKind, Producer};
use limen_control_plane::handoff_client::{self, HandoffTls};
use limen_control_plane::pipeline::DATADOG;
use limen_control_plane::replicas::{self, Replica, SpoolMode};
use limen_core::identity::ComponentKind;
use limen_proto::v1::audit_handoff_client::AuditHandoffClient;
use limen_proto::v1::audit_handoff_server::{AuditHandoff, AuditHandoffServer};
use limen_proto::v1::{HandoffAck, HandoffBatch};
use limen_tunnel::tls::Identity;
use tokio_stream::StreamExt as _;
use tonic::{Code, Request, Response, Status, Streaming};
use uuid::Uuid;

/// Nothing listens here, so the Datadog sink can never ship.
const DEAD_SINK: &str = "--datadog-logs-url=http://127.0.0.1:1/logs";

fn event(n: u64) -> Event {
    Event::new(
        EventKind::SessionRecording,
        Producer {
            component: "proxy".into(),
            instance_id: "proxy-elsewhere".into(),
            seq: n,
        },
        serde_json::json!({ "n": n }),
    )
}

/// Spool `n` events (appended together, so they share fsyncs). Returns their ids.
async fn spool_events(spool: &Spool, n: u64) -> BTreeSet<Uuid> {
    let events: Vec<Event> = (0..n).map(event).collect();
    let raws: Vec<Vec<u8>> = events
        .iter()
        .map(|e| serde_json::to_vec(e).expect("json"))
        .collect();
    for r in futures::future::join_all(raws.iter().map(|r| spool.append(r))).await {
        r.expect("append");
    }
    events.iter().map(|e| e.event_id).collect()
}

fn ids_of(events: &[Event]) -> BTreeSet<Uuid> {
    events.iter().map(|e| e.event_id).collect()
}

/// Replica A (sinks: console, JSONL, and a dead Datadog) with a live peer B
/// on the same database.
async fn pair(mode: &str) -> Option<(Harness, Harness)> {
    let a = Harness::start_with(&[
        "--id=cp-a".into(),
        format!("--spool-mode={mode}"),
        DEAD_SINK.into(),
        "--datadog-api-key=k".into(),
        "--drain-timeout=5s".into(),
    ])
    .await?;
    let b = a.start_peer(&["--id=cp-b".into()]).await;
    Some((a, b))
}

/// A control plane client certificate for `id`, from `h`'s internal CA.
async fn control_plane_identity(h: &Harness, id: &str) -> Identity {
    let key = common::new_key();
    let issued = h
        .state
        .cas
        .internal
        .issue_component(limen_ca::ComponentCertRequest {
            csr_der: common::csr(&key),
            kind: ComponentKind::ControlPlane,
            id: id.into(),
            dns_names: vec!["localhost".into()],
            labels: std::collections::BTreeMap::new(),
            ttl: Duration::from_mins(10),
        })
        .await
        .expect("issue");
    let chain = format!("{}{}", issued.pem, h.state.cas.internal.cert_pem());
    Identity::from_pem(&chain, &key.serialize_pem()).expect("identity")
}

/// One batch, sent on a fresh stream; returns the acks or the refusal.
async fn handoff_once(
    h: &Harness,
    identity: Identity,
    events: Vec<Vec<u8>>,
) -> Result<Vec<HandoffAck>, Status> {
    let mut client = AuditHandoffClient::new(h.channel(Some(identity)));
    let batch = HandoffBatch {
        events,
        last_index: 41,
    };
    let mut acks = client
        .handoff(tokio_stream::iter(vec![batch]))
        .await?
        .into_inner();
    let mut out = Vec::new();
    while let Some(ack) = acks.next().await {
        out.push(ack?);
    }
    Ok(out)
}

#[tokio::test]
async fn ephemeral_replica_hands_unshipped_events_to_peer() {
    let Some((a, b)) = Box::pin(pair("ephemeral")).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let ids = spool_events(&a.state.pipeline.spool, 50).await;
    a.begin_shutdown();
    a.finish().await.expect("run");

    assert_eq!(
        a.state.pipeline.spool.pending(DATADOG),
        0,
        "everything the dead sink missed was handed off and committed"
    );
    let at_b = ids_of(&b.audit_events().await);
    assert!(
        ids.is_subset(&at_b),
        "{} of {} events reached the peer",
        ids.intersection(&at_b).count(),
        ids.len()
    );
    b.begin_shutdown();
    b.finish().await.expect("run b");
}

#[tokio::test]
async fn durable_mode_does_not_hand_off() {
    let Some((a, b)) = Box::pin(pair("durable")).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let ids = spool_events(&a.state.pipeline.spool, 20).await;
    a.begin_shutdown();
    a.finish().await.expect("run");

    assert!(
        a.state.pipeline.spool.pending(DATADOG) >= 20,
        "the spool keeps them for the next start on the same volume"
    );
    let at_b = ids_of(&b.audit_events().await);
    assert!(ids.is_disjoint(&at_b), "nothing was handed to the peer");
    b.begin_shutdown();
    b.finish().await.expect("run b");
}

#[tokio::test]
async fn unregistered_control_plane_cert_is_refused() {
    let Some(h) = Harness::start().await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let ghost = control_plane_identity(&h, "cp-ghost").await;
    let raw = serde_json::to_vec(&event(1)).expect("json");
    let err = handoff_once(&h, ghost, vec![raw.clone()])
        .await
        .expect_err("no registry row");
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");

    // A row that went stale is no better than none.
    let stale = replicas::register(
        &h.state.db,
        "cp-stale",
        "https://localhost:1",
        SpoolMode::Ephemeral,
    )
    .await
    .expect("register");
    sqlx::query(
        "UPDATE control_plane_replicas SET heartbeat_at = now() - interval '1 minute' WHERE id = $1",
    )
    .bind(&stale.id)
    .execute(&h.state.db)
    .await
    .expect("age");
    let err = handoff_once(&h, control_plane_identity(&h, "cp-stale").await, vec![raw])
        .await
        .expect_err("stale row");
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
}

#[tokio::test]
async fn proxy_cert_is_refused() {
    let Some(h) = Harness::start().await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let (proxy_id, proxy) = h.enroll_proxy().await;
    // Even with a registry row in its name.
    replicas::register(
        &h.state.db,
        &proxy_id,
        "https://localhost:1",
        SpoolMode::Ephemeral,
    )
    .await
    .expect("register");
    let raw = serde_json::to_vec(&event(1)).expect("json");
    let err = handoff_once(&h, proxy, vec![raw]).await.expect_err("proxy");
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
}

#[tokio::test]
async fn registered_peer_is_acked_and_draining_receiver_refuses() {
    let Some(h) = Harness::start().await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    replicas::register(
        &h.state.db,
        "cp-peer",
        "https://localhost:1",
        SpoolMode::Ephemeral,
    )
    .await
    .expect("register");
    let e = event(7);
    let raw = serde_json::to_vec(&e).expect("json");

    // Events must parse; nothing of a bad batch is kept.
    let err = handoff_once(
        &h,
        control_plane_identity(&h, "cp-peer").await,
        vec![raw.clone(), b"not an event".to_vec()],
    )
    .await
    .expect_err("malformed");
    assert_eq!(err.code(), Code::InvalidArgument, "{err:?}");

    let acks = handoff_once(
        &h,
        control_plane_identity(&h, "cp-peer").await,
        vec![raw.clone()],
    )
    .await
    .expect("handoff");
    assert_eq!(
        acks.iter().map(|a| a.durable_upto).collect::<Vec<_>>(),
        [41]
    );
    let events = h.audit_events().await;
    assert_eq!(
        events.iter().filter(|x| x.event_id == e.event_id).count(),
        1
    );

    h.state
        .draining
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let err = handoff_once(&h, control_plane_identity(&h, "cp-peer").await, vec![raw])
        .await
        .expect_err("draining");
    assert_eq!(err.code(), Code::Unavailable, "{err:?}");
}

/// A receiver that acks the first batch, takes the second, and dies before
/// acking it.
#[derive(Clone, Default)]
struct DiesMidStream {
    acked: Arc<Mutex<Vec<Event>>>,
}

#[tonic::async_trait]
impl AuditHandoff for DiesMidStream {
    type HandoffStream =
        std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<HandoffAck, Status>> + Send>>;

    async fn handoff(
        &self,
        request: Request<Streaming<HandoffBatch>>,
    ) -> Result<Response<Self::HandoffStream>, Status> {
        let mut batches = request.into_inner();
        let acked = Arc::clone(&self.acked);
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            if let Some(Ok(first)) = batches.next().await {
                acked.lock().expect("lock").extend(
                    first
                        .events
                        .iter()
                        .map(|r| serde_json::from_slice::<Event>(r).expect("event")),
                );
                let _ = tx
                    .send(Ok(HandoffAck {
                        durable_upto: first.last_index,
                    }))
                    .await;
            }
            let _ = batches.next().await;
            let _ = tx.send(Err(Status::unavailable("receiver died"))).await;
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

/// Serve `service` with a control plane certificate, as a peer would.
async fn serve_stub(h: &Harness, service: DiesMidStream) -> Replica {
    let identity = control_plane_identity(h, "cp-dying").await;
    let tls = limen_tunnel::tls::server_config(
        identity,
        &[h.internal_ca()],
        limen_tunnel::tls::ClientAuth::Required,
        &[limen_tunnel::alpn::H2],
    )
    .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let routes = tonic::service::Routes::new(AuditHandoffServer::new(service))
        .prepare()
        .into_axum_router();
    tokio::spawn(async move {
        while let Ok((tcp, remote)) = listener.accept().await {
            let (acceptor, routes) = (acceptor.clone(), routes.clone());
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    let peer = limen_tunnel::PeerInfo::from_tls(&tls, Some(remote));
                    let _ = limen_tunnel::serve::serve_h2(
                        tls,
                        peer,
                        routes,
                        limen_tunnel::serve::H2Settings::default(),
                    )
                    .await;
                }
            });
        }
    });
    Replica {
        id: "cp-dying".into(),
        ingest_url: format!("https://localhost:{port}"),
    }
}

#[tokio::test]
async fn handoff_retry_after_receiver_restart_loses_nothing() {
    let Some(b) = Harness::start_with(&["--id=cp-b".into()]).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    // The sender: its own spool, with two consumers at different offsets.
    let dir = tempfile::tempdir().expect("dir");
    let spool = Spool::open(SpoolConfig::new(dir.path(), &["console", "s3"])).expect("spool");
    spool.start();
    let ids = spool_events(&spool, 2500).await;
    spool.commit("console", 2500).expect("console shipped all");
    spool.commit("s3", 0).expect("s3 shipped none");

    replicas::register(
        &b.state.db,
        "cp-sender",
        "https://localhost:1",
        SpoolMode::Ephemeral,
    )
    .await
    .expect("register sender");
    let tls = HandoffTls::issue(&b.state.cas, "cp-sender", &["localhost".to_owned()])
        .await
        .expect("client tls");
    let dying = DiesMidStream::default();
    let first = serve_stub(&b, dying.clone()).await;
    let peer_b = Replica {
        id: "cp-b".into(),
        ingest_url: format!("https://localhost:{}", b.addr.port()),
    };

    let sent = handoff_client::send_spool(&spool, &[first, peer_b], &tls, Duration::from_secs(20))
        .await
        .expect("handoff");
    assert_eq!(sent, 2500, "acked records, counted once");
    assert_eq!(spool.pending("s3"), 0, "every consumer committed");
    assert_eq!(spool.pending("console"), 0);

    let at_dying = ids_of(&dying.acked.lock().expect("lock"));
    assert_eq!(at_dying.len(), 1000, "the first batch was acked there");
    let at_b = ids_of(&b.audit_events().await);
    let union: BTreeSet<Uuid> = at_dying.union(&at_b).copied().collect();
    assert!(ids.is_subset(&union), "nothing lost");
    // The batch the dying receiver took but never acked went to B as well.
    let second: Vec<Uuid> = ids.difference(&at_dying).copied().collect();
    assert!(second.iter().all(|id| at_b.contains(id)));
}

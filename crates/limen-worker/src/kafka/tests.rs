//! Whole-session tests: a Kafka client, the worker's session code, and a fake
//! cluster of brokers on loopback sockets, so the worker's real dial path and
//! its broker-slot logic are used. The real brokers are exercised by
//! `deploy/compose/test-phase11-scenarios.sh`.

use std::sync::{Arc, Mutex};

use limen_audit::{Emitter, EventKind, FailureMode, MemorySink};
use limen_core::broker::KafkaSlot;
use limen_policy::{KafkaClass, KafkaGrant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use super::proto::{Broker, MetadataPartition, MetadataResponse, MetadataTopic};
use super::wire::{Reader, Writer};
use super::*;

/// One request a fake broker received.
#[derive(Debug, Clone)]
struct Seen {
    api: i16,
    body: Vec<u8>,
}

#[derive(Clone)]
struct FakeBroker {
    addr: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    /// `(user, password)` of each SASL/PLAIN login.
    logins: Arc<Mutex<Vec<(String, String)>>>,
}

impl FakeBroker {
    fn seen(&self, api: i16) -> Vec<Seen> {
        self.seen
            .lock()
            .expect("lock")
            .iter()
            .filter(|s| s.api == api)
            .cloned()
            .collect()
    }

    fn requests_after_login(&self) -> usize {
        self.seen
            .lock()
            .expect("lock")
            .iter()
            .filter(|s| !matches!(s.api, 18 | 17 | 36))
            .count()
    }
}

type Cluster = Arc<Mutex<Vec<(i32, String)>>>;

/// Start `n` fake brokers (node IDs 1..=n) that know each other's addresses.
async fn fake_cluster(n: usize) -> Vec<FakeBroker> {
    let cluster: Cluster = Arc::default();
    let mut brokers = Vec::new();
    let mut listeners = Vec::new();
    for i in 0..n {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = l.local_addr().expect("addr").to_string();
        cluster
            .lock()
            .expect("lock")
            .push((i32::try_from(i).expect("small") + 1, addr.clone()));
        brokers.push(FakeBroker {
            addr,
            seen: Arc::default(),
            logins: Arc::default(),
        });
        listeners.push(l);
    }
    for (broker, listener) in brokers.iter().cloned().zip(listeners) {
        let cluster = Arc::clone(&cluster);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (broker, cluster) = (broker.clone(), Arc::clone(&cluster));
                tokio::spawn(serve_fake(stream, broker, cluster));
            }
        });
    }
    brokers
}

async fn read_message(stream: &mut TcpStream) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt as _;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.ok()?;
    let mut msg = vec![0u8; usize::try_from(i32::from_be_bytes(len)).ok()?];
    stream.read_exact(&mut msg).await.ok()?;
    Some(msg)
}

fn metadata_for(version: i16, cluster: &Cluster, requested: Option<&[String]>) -> Vec<u8> {
    let brokers: Vec<Broker> = cluster
        .lock()
        .expect("lock")
        .iter()
        .map(|(id, addr)| {
            let (host, port) = addr.rsplit_once(':').expect("host:port");
            Broker {
                node_id: *id,
                host: host.to_owned(),
                port: port.parse().expect("port"),
                rack: None,
            }
        })
        .collect();
    let topic = |name: &str, internal: bool| MetadataTopic {
        error: 0,
        name: name.to_owned(),
        internal,
        partitions: vec![MetadataPartition {
            error: 0,
            index: 0,
            leader: 2,
            leader_epoch: 0,
            replicas: vec![2, 1],
            isr: vec![2, 1],
            offline: Vec::new(),
        }],
        authorized_operations: i32::MIN,
    };
    let all = [
        topic("orders.new", false),
        topic("payments", false),
        topic("__consumer_offsets", true),
    ];
    let topics = match requested {
        None => all.to_vec(),
        Some(names) => all
            .iter()
            .filter(|t| names.contains(&t.name))
            .cloned()
            .collect(),
    };
    MetadataResponse {
        throttle_ms: 0,
        brokers,
        cluster_id: Some("fake".into()),
        controller_id: 1,
        topics,
        cluster_authorized_operations: i32::MIN,
    }
    .encode(version)
}

async fn serve_fake(mut stream: TcpStream, broker: FakeBroker, cluster: Cluster) {
    while let Some(msg) = read_message(&mut stream).await {
        let h = wire::parse_request_header(&msg).expect("header");
        let body = msg[h.body_at..].to_vec();
        broker.seen.lock().expect("lock").push(Seen {
            api: h.api_key,
            body: body.clone(),
        });
        let reply: Option<Vec<u8>> = match h.api_key {
            wire::api::API_VERSIONS => {
                let mut w = Writer::new()
                    .i16(0)
                    .i32(i32::try_from(wire::api::SUPPORTED.len()).expect("n"));
                for (k, lo, hi) in wire::api::SUPPORTED {
                    w = w.i16(k).i16(lo).i16(hi + 3);
                }
                Some(w.finish())
            }
            wire::api::SASL_HANDSHAKE => Some(Writer::new().i16(0).i32(1).string("PLAIN").finish()),
            wire::api::SASL_AUTHENTICATE => {
                let mut r = Reader::new(&body);
                let token = r
                    .nullable_bytes()
                    .expect("bytes")
                    .unwrap_or_default()
                    .to_vec();
                let mut parts = token.split(|b| *b == 0);
                parts.next();
                let user = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
                let pass = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
                broker.logins.lock().expect("lock").push((user, pass));
                Some(
                    Writer::new()
                        .i16(0)
                        .nullable_string(None)
                        .bytes(&[])
                        .i64(0)
                        .finish(),
                )
            }
            wire::api::METADATA => {
                let names = Reader::new(&body).array(Reader::string).expect("names");
                Some(metadata_for(h.api_version, &cluster, names.as_deref()))
            }
            wire::api::PRODUCE => {
                let Ok(proto::Parsed::Produce { topics, .. }) =
                    proto::parse_request(h.api_key, h.api_version, &body)
                else {
                    return;
                };
                let mut w = Writer::new().i32(i32::try_from(topics.spans.len()).expect("n"));
                for t in &topics.spans {
                    w = w
                        .string(&t.name)
                        .i32(i32::try_from(t.partitions.len()).expect("n"));
                    for p in &t.partitions {
                        w = w
                            .i32(*p)
                            .i16(0)
                            .i64(7)
                            .i64(-1)
                            .i64(0)
                            .i32(0)
                            .nullable_string(None);
                    }
                }
                Some(w.i32(0).finish())
            }
            wire::api::FETCH => {
                let Ok(proto::Parsed::Fetch { topics }) =
                    proto::parse_request(h.api_key, h.api_version, &body)
                else {
                    return;
                };
                let mut w = Writer::new()
                    .i32(0)
                    .i16(0)
                    .i32(0)
                    .i32(i32::try_from(topics.spans.len()).expect("n"));
                for t in &topics.spans {
                    w = w
                        .string(&t.name)
                        .i32(i32::try_from(t.partitions.len()).expect("n"));
                    for p in &t.partitions {
                        w = w
                            .i32(*p)
                            .i16(0)
                            .i64(5)
                            .i64(5)
                            .i64(0)
                            .i32(-1)
                            .i32(-1)
                            .bytes(b"");
                    }
                }
                Some(w.finish())
            }
            wire::api::FIND_COORDINATOR => Some(
                Writer::new()
                    .i32(0)
                    .i16(0)
                    .nullable_string(None)
                    .i32(2)
                    .string("kafka-2.internal")
                    .i32(9092)
                    .finish(),
            ),
            wire::api::HEARTBEAT => Some(Writer::new().i16(0).finish()),
            wire::api::CREATE_TOPICS => {
                let Ok(proto::Parsed::CreateTopics { topics }) =
                    proto::parse_request(h.api_key, h.api_version, &body)
                else {
                    return;
                };
                // v2 and later start with the throttle time.
                let w = if h.api_version >= 2 {
                    Writer::new().i32(0)
                } else {
                    Writer::new()
                };
                let mut w = w.i32(i32::try_from(topics.spans.len()).expect("n"));
                for t in &topics.spans {
                    w = w.string(&t.name).i16(0).nullable_string(None);
                }
                Some(w.finish())
            }
            _ => None,
        };
        if let Some(body) = reply {
            let out = response_message(h.correlation_id, &body);
            if stream.write_all(&out).await.is_err() {
                return;
            }
        }
    }
}

fn grant(classes: &[KafkaClass], topics: &[&str], groups: &[&str]) -> KafkaGrant {
    KafkaGrant {
        users: vec!["limen-consumer".into()],
        classes: classes.to_vec(),
        topics: topics.iter().map(|s| (*s).to_owned()).collect(),
        groups: groups.iter().map(|s| (*s).to_owned()).collect(),
    }
}

struct Client {
    reader: MessageReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    next: i32,
}

impl Client {
    /// Send a request and return its correlation id.
    async fn send(&mut self, api: i16, version: i16, body: &[u8]) -> i32 {
        self.next += 1;
        let head = Writer::new()
            .i16(api)
            .i16(version)
            .i32(self.next)
            .string("test-client")
            .finish();
        let mut msg = head;
        msg.extend_from_slice(body);
        self.writer.write_all(&framed(&msg)).await.expect("send");
        self.writer.flush().await.expect("flush");
        self.next
    }

    async fn recv(&mut self) -> (i32, Vec<u8>) {
        let msg = tokio::time::timeout(Duration::from_secs(5), self.reader.next())
            .await
            .expect("a response in time")
            .expect("readable")
            .expect("not closed");
        (
            i32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]),
            msg[4..].to_vec(),
        )
    }

    async fn call(&mut self, api: i16, version: i16, body: &[u8]) -> Vec<u8> {
        let id = self.send(api, version, body).await;
        let (got, body) = self.recv().await;
        assert_eq!(got, id);
        body
    }

    async fn closed(&mut self) -> bool {
        matches!(
            tokio::time::timeout(Duration::from_secs(5), self.reader.next()).await,
            Ok(Ok(None) | Err(_))
        )
    }
}

struct Rig {
    client: Client,
    brokers: Vec<FakeBroker>,
    sink: Arc<MemorySink>,
    done: tokio::task::JoinHandle<anyhow::Result<SessionOutcome>>,
    _dir: tempfile::TempDir,
}

/// `ports` are the CLI's listeners (bootstrap first); `slot` the one connected.
async fn start(
    grants: Vec<KafkaGrant>,
    slot: usize,
    ports: &[u16],
    configure: impl FnOnce(&mut SessionConfig),
) -> Rig {
    let brokers = fake_cluster(2).await;
    let dir = tempfile::tempdir().expect("dir");
    let creds = dir.path().join("creds.json");
    std::fs::write(
        &creds,
        r#"{"events-kafka": {"limen-consumer": "broker-secret"}}"#,
    )
    .expect("creds");
    let settings = Arc::new(Settings::load(None, Some(&creds)).expect("settings"));
    let target: BrokerTarget = serde_json::from_value(serde_json::json!({
        "endpoint": brokers[0].addr, "tls": false, "sasl": "plain",
    }))
    .expect("target");
    let mut config = SessionConfig::new(
        Uuid::now_v7().to_string(),
        "dev@example.com".into(),
        "limen-consumer".into(),
        "events-kafka".into(),
        target,
        KafkaSlot::new(slot, ports.to_vec()),
    );
    configure(&mut config);
    let prepared = prepare(&settings, grants, config).expect("prepared");
    let (client, server) = tokio::io::duplex(1 << 22);
    let sink = Arc::new(MemorySink::default());
    let audit = Emitter::new("worker", "w1", sink.clone(), FailureMode::FailClosed);
    let done = tokio::spawn(serve(server, prepared, audit));
    let (r, w) = tokio::io::split(client);
    Rig {
        client: Client {
            reader: MessageReader::new(r, 1 << 26),
            writer: w,
            next: 0,
        },
        brokers,
        sink,
        done,
        _dir: dir,
    }
}

async fn rig(grants: Vec<KafkaGrant>) -> Rig {
    start(grants, 0, &[41000, 41001, 41002], |_| {}).await
}

fn events(sink: &MemorySink, kind: EventKind) -> Vec<Value> {
    sink.events()
        .into_iter()
        .filter(|e| e.kind == kind)
        .map(|e| e.data)
        .collect()
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(200)).await;
}

fn produce_body(acks: i16, topics: &[(&str, &[i32])]) -> Vec<u8> {
    let mut w = Writer::new()
        .nullable_string(None)
        .i16(acks)
        .i32(5000)
        .i32(i32::try_from(topics.len()).expect("n"));
    for (name, parts) in topics {
        w = w.string(name).i32(i32::try_from(parts.len()).expect("n"));
        for p in *parts {
            w = w.i32(*p).bytes(b"super-secret-record");
        }
    }
    w.finish()
}

fn fetch_body(topic: &str) -> Vec<u8> {
    Writer::new()
        .i32(-1)
        .i32(100)
        .i32(1)
        .i32(1 << 20)
        .i8(0)
        .i32(0)
        .i32(-1) // session
        .i32(1)
        .string(topic)
        .i32(1)
        .i32(0)
        .i32(-1)
        .i64(0)
        .i64(0)
        .i32(1 << 20)
        .i32(0) // forgotten
        .string("")
        .finish()
}

/// Topic names and per-partition errors in a Produce v8 response.
fn produce_result(body: &[u8]) -> Vec<(String, Vec<(i32, i16)>)> {
    let mut r = Reader::new(body);
    r.array(|r| {
        let name = r.string()?;
        let parts = r
            .array(|r| {
                let index = r.i32()?;
                let err = r.i16()?;
                r.skip(8 + 8 + 8)?;
                r.skip_array(|r| r.skip(0))?;
                r.nullable_string()?;
                Ok((index, err))
            })?
            .unwrap_or_default();
        Ok((name, parts))
    })
    .expect("parses")
    .unwrap_or_default()
}

#[tokio::test]
async fn the_worker_logs_in_with_its_own_credential_and_answers_api_versions_itself() {
    let mut rig = rig(vec![grant(&[KafkaClass::Read], &[], &[])]).await;
    let body = rig.client.call(wire::api::API_VERSIONS, 2, &[]).await;
    let mut r = Reader::new(&body);
    assert_eq!(r.i16(), Ok(0));
    let offered = r
        .array(|r| Ok((r.i16()?, r.i16()?, r.i16()?)))
        .expect("array")
        .expect("not null");
    // The broker said it can do three versions more than the worker reads; the worker doesn't offer them.
    assert!(offered.contains(&(wire::api::FETCH, 4, 11)), "{offered:?}");
    assert!(offered.iter().all(|(_, _, hi)| *hi <= 11));
    assert!(
        rig.brokers[0]
            .logins
            .lock()
            .expect("lock")
            .iter()
            .any(|l| l == &("limen-consumer".to_owned(), "broker-secret".to_owned())),
        "the broker saw the worker's login"
    );
    // The client's ApiVersions never reached the broker (only the worker's own did).
    assert_eq!(rig.brokers[0].seen(wire::api::API_VERSIONS).len(), 1);
}

#[tokio::test]
async fn a_newer_api_versions_request_is_told_to_use_an_older_one_in_the_shape_clients_know() {
    let mut rig = rig(vec![grant(&[KafkaClass::Read], &[], &[])]).await;
    let body = rig.client.call(wire::api::API_VERSIONS, 3, &[]).await;
    let mut r = Reader::new(&body);
    assert_eq!(r.i16(), Ok(35), "UNSUPPORTED_VERSION");
    let n = r.array_len().expect("array").expect("not null");
    assert!(n > 5);
    // ... and the connection is still good for a version we read.
    let ok = rig.client.call(wire::api::API_VERSIONS, 1, &[]).await;
    assert_eq!(Reader::new(&ok).i16(), Ok(0));
}

#[tokio::test]
async fn produce_to_a_refused_topic_is_cut_out_and_answered_by_the_worker() {
    let mut rig = rig(vec![grant(&[KafkaClass::Write], &["orders.*"], &[])]).await;
    let body = produce_body(1, &[("orders.new", &[0]), ("payments", &[0, 1])]);
    let resp = rig.client.call(wire::api::PRODUCE, 8, &body).await;
    let result = produce_result(&resp);
    let by_name: std::collections::BTreeMap<_, _> = result.into_iter().collect();
    assert_eq!(
        by_name["orders.new"],
        [(0, 0)],
        "the allowed topic got the broker's answer"
    );
    assert_eq!(
        by_name["payments"],
        [(0, 29), (1, 29)],
        "the other got TOPIC_AUTHORIZATION_FAILED"
    );
    // The broker never heard of "payments".
    let seen = rig.brokers[0].seen(wire::api::PRODUCE);
    assert_eq!(seen.len(), 1);
    assert!(!seen[0].body.windows(8).any(|w| w == b"payments"));
    assert!(seen[0].body.windows(10).any(|w| w == b"orders.new"));
    settle().await;
    let denied = events(&rig.sink, EventKind::AuthDenied);
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["action"], "kafka");
    assert_eq!(denied[0]["operation"], "Produce");
    assert_eq!(denied[0]["topics"][0], "payments");
}

#[tokio::test]
async fn produce_with_nothing_allowed_never_reaches_the_broker() {
    let mut rig = rig(vec![grant(&[KafkaClass::Write], &["orders.*"], &[])]).await;
    let resp = rig
        .client
        .call(
            wire::api::PRODUCE,
            8,
            &produce_body(1, &[("payments", &[0])]),
        )
        .await;
    assert_eq!(
        produce_result(&resp),
        [("payments".to_owned(), vec![(0, 29)])]
    );
    // acks=0: the broker would not answer, so neither does the worker.
    rig.client
        .send(
            wire::api::PRODUCE,
            8,
            &produce_body(0, &[("payments", &[0])]),
        )
        .await;
    // A request after it still gets its own answer, in order.
    let body = rig
        .client
        .call(
            wire::api::PRODUCE,
            8,
            &produce_body(1, &[("orders.new", &[0])]),
        )
        .await;
    assert_eq!(produce_result(&body)[0].1, [(0, 0)]);
    assert_eq!(rig.brokers[0].seen(wire::api::PRODUCE).len(), 1);
}

#[tokio::test]
async fn a_role_with_only_read_cannot_produce_anything() {
    let mut rig = rig(vec![grant(&[KafkaClass::Read], &[], &[])]).await;
    let resp = rig
        .client
        .call(
            wire::api::PRODUCE,
            8,
            &produce_body(1, &[("orders.new", &[0])]),
        )
        .await;
    assert_eq!(produce_result(&resp)[0].1, [(0, 29)]);
    settle().await;
    let denied = events(&rig.sink, EventKind::AuthDenied);
    assert!(
        denied[0]["reason"]
            .as_str()
            .expect("reason")
            .contains("write"),
        "{denied:?}"
    );
}

#[tokio::test]
async fn record_contents_never_reach_the_audit_trail() {
    let mut rig = rig(vec![grant(&[KafkaClass::Write], &[], &[])]).await;
    rig.client
        .call(
            wire::api::PRODUCE,
            8,
            &produce_body(1, &[("orders.new", &[0])]),
        )
        .await;
    settle().await;
    let all = format!("{:?}", rig.sink.events());
    assert!(!all.contains("super-secret-record"), "{all}");
    assert!(!all.contains("broker-secret"));
    let produced: Vec<_> = events(&rig.sink, EventKind::KafkaRequest)
        .into_iter()
        .filter(|d| d["api"] == "Produce")
        .collect();
    assert_eq!(produced.len(), 1);
    assert_eq!(produced[0]["topics"][0]["name"], "orders.new");
    assert_eq!(produced[0]["kafka_user"], "limen-consumer");
    assert!(produced[0]["topics"][0]["bytes"].as_u64().expect("bytes") > 0);
}

#[tokio::test]
async fn metadata_lists_only_reachable_topics_with_brokers_at_the_local_ports() {
    let mut rig = rig(vec![grant(&[KafkaClass::Read], &["orders.*"], &[])]).await;
    // v1, all topics (null array).
    let body = rig
        .client
        .call(wire::api::METADATA, 1, &Writer::new().i32(-1).finish())
        .await;
    let m = MetadataResponse::decode(1, &body).expect("decodes");
    // Brokers 1 and 2 are on listeners 1 and 2 (rank 0 and 1), not at their real addresses.
    let addrs: Vec<_> = m
        .brokers
        .iter()
        .map(|b| (b.node_id, b.host.as_str(), b.port))
        .collect();
    assert_eq!(addrs, [(1, "127.0.0.1", 41001), (2, "127.0.0.1", 41002)]);
    let topics: Vec<_> = m.topics.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        topics,
        ["orders.new"],
        "payments and the internal topic are not shown"
    );
    // A topic asked for by name and refused is an error entry, not silence.
    let named = Writer::new()
        .i32(2)
        .string("orders.new")
        .string("payments")
        .finish();
    let body = rig.client.call(wire::api::METADATA, 1, &named).await;
    let m = MetadataResponse::decode(1, &body).expect("decodes");
    let by_name: std::collections::BTreeMap<_, _> =
        m.topics.iter().map(|t| (t.name.clone(), t.error)).collect();
    assert_eq!(by_name["orders.new"], 0);
    assert_eq!(by_name["payments"], 29);
    // The broker was asked for orders.new only.
    let asked = rig.brokers[0].seen(wire::api::METADATA);
    let last = asked.last().expect("asked");
    assert!(!last.body.windows(8).any(|w| w == b"payments"));
}

#[tokio::test]
async fn automatic_topic_creation_is_switched_off_unless_the_role_can_create_topics() {
    let mut rig = rig(vec![grant(&[KafkaClass::Read], &[], &[])]).await;
    // v4: topics, allow_auto_topic_creation = true.
    let body = Writer::new().i32(1).string("orders.new").i8(1).finish();
    rig.client.call(wire::api::METADATA, 4, &body).await;
    let seen = rig.brokers[0].seen(wire::api::METADATA);
    assert_eq!(*seen.last().expect("seen").body.last().expect("flag"), 0);
    let mut rig = rig_admin().await;
    rig.client.call(wire::api::METADATA, 4, &body).await;
    let seen = rig.brokers[0].seen(wire::api::METADATA);
    assert_eq!(
        *seen.last().expect("seen").body.last().expect("flag"),
        1,
        "an admin may auto-create"
    );
}

async fn rig_admin() -> Rig {
    rig(vec![grant(
        &[KafkaClass::Read, KafkaClass::Admin],
        &[],
        &[],
    )])
    .await
}

#[tokio::test]
async fn find_coordinator_is_rewritten_and_a_refused_group_never_reaches_the_broker() {
    let mut rig = rig(vec![grant(&[KafkaClass::Read], &[], &["reports-*"])]).await;
    // The client asks for metadata first, as clients do.
    rig.client
        .call(wire::api::METADATA, 1, &Writer::new().i32(0).finish())
        .await;
    let ask = |g: &str| Writer::new().string(g).i8(0).finish();
    let body = rig
        .client
        .call(wire::api::FIND_COORDINATOR, 1, &ask("reports-daily"))
        .await;
    let c = CoordinatorResponse::decode(1, &body).expect("decodes");
    assert_eq!(
        (c.node_id, c.host.as_str(), c.port),
        (2, "127.0.0.1", 41002)
    );
    let body = rig
        .client
        .call(wire::api::FIND_COORDINATOR, 1, &ask("other-group"))
        .await;
    let c = CoordinatorResponse::decode(1, &body).expect("decodes");
    assert_eq!(c.error, 30, "GROUP_AUTHORIZATION_FAILED");
    assert_eq!(rig.brokers[0].seen(wire::api::FIND_COORDINATOR).len(), 1);
    // A transaction coordinator is refused outright.
    let txn = Writer::new().string("tx").i8(1).finish();
    let body = rig.client.call(wire::api::FIND_COORDINATOR, 1, &txn).await;
    assert_eq!(
        CoordinatorResponse::decode(1, &body)
            .expect("decodes")
            .error,
        53
    );
}

#[tokio::test]
async fn a_cluster_bigger_than_the_cli_opened_listeners_is_a_clear_refusal() {
    // Bootstrap plus ONE broker listener, for a two-broker cluster.
    let mut rig = start(
        vec![grant(&[KafkaClass::Read], &[], &[])],
        0,
        &[41000, 41001],
        |_| {},
    )
    .await;
    rig.client
        .send(wire::api::METADATA, 1, &Writer::new().i32(-1).finish())
        .await;
    assert!(
        rig.client.closed().await,
        "the session ends instead of handing out a dead address"
    );
    settle().await;
    let denied = events(&rig.sink, EventKind::AuthDenied);
    let reason = denied.last().expect("denied")["reason"]
        .as_str()
        .expect("reason")
        .to_owned();
    assert!(reason.contains("--brokers 2"), "{reason}");
}

#[tokio::test]
async fn a_session_on_a_broker_slot_goes_to_the_broker_of_that_rank() {
    // Slot 2 is the broker of rank 1: node 2, the second fake broker.
    let mut rig = start(
        vec![grant(&[KafkaClass::Read], &[], &[])],
        2,
        &[41000, 41001, 41002],
        |_| {},
    )
    .await;
    rig.client
        .call(wire::api::METADATA, 1, &Writer::new().i32(0).finish())
        .await;
    assert_eq!(
        rig.brokers[1].seen(wire::api::METADATA).len(),
        1,
        "node 2 was asked"
    );
    assert!(
        rig.brokers[1].logins.lock().expect("lock").len() == 1,
        "the worker logged in to node 2"
    );
    // Node 1 only answered the lookup of the broker list.
    assert_eq!(rig.brokers[0].seen(wire::api::METADATA).len(), 1);
    assert_eq!(rig.brokers[0].requests_after_login(), 1);
    drop(rig.done);
    // And slot 1 is rank 0.
    let mut rig = start(
        vec![grant(&[KafkaClass::Read], &[], &[])],
        1,
        &[41000, 41001, 41002],
        |_| {},
    )
    .await;
    rig.client
        .call(wire::api::METADATA, 1, &Writer::new().i32(0).finish())
        .await;
    assert_eq!(
        rig.brokers[0].seen(wire::api::METADATA).len(),
        2,
        "node 1: the lookup and the client's own"
    );
}

#[tokio::test]
async fn responses_keep_their_order_when_the_worker_answers_one_itself() {
    let mut rig = rig(vec![grant(&[KafkaClass::Write], &["orders.*"], &[])]).await;
    let a = rig
        .client
        .send(wire::api::METADATA, 1, &Writer::new().i32(0).finish())
        .await;
    let b = rig
        .client
        .send(
            wire::api::PRODUCE,
            8,
            &produce_body(1, &[("payments", &[0])]),
        )
        .await;
    let c = rig
        .client
        .send(
            wire::api::PRODUCE,
            8,
            &produce_body(1, &[("orders.new", &[0])]),
        )
        .await;
    let d = rig
        .client
        .send(
            wire::api::PRODUCE,
            8,
            &produce_body(1, &[("payments", &[0])]),
        )
        .await;
    let mut got = Vec::new();
    for _ in 0..4 {
        got.push(rig.client.recv().await.0);
    }
    assert_eq!(got, [a, b, c, d]);
}

#[tokio::test]
async fn fetches_are_logged_at_first_contact_and_then_once_per_window_with_counts() {
    let mut rig = start(
        vec![grant(&[KafkaClass::Read], &[], &[])],
        0,
        &[41000, 41001, 41002],
        |c| {
            c.dedupe_window = Duration::from_millis(400);
        },
    )
    .await;
    for _ in 0..5 {
        rig.client
            .call(wire::api::FETCH, 11, &fetch_body("orders.new"))
            .await;
    }
    settle().await;
    let fetches = |sink: &MemorySink| -> Vec<Value> {
        events(sink, EventKind::KafkaRequest)
            .into_iter()
            .filter(|d| d["api"] == "Fetch")
            .collect()
    };
    assert_eq!(fetches(&rig.sink).len(), 1, "five polls, one event");
    tokio::time::sleep(Duration::from_millis(450)).await;
    rig.client
        .call(wire::api::FETCH, 11, &fetch_body("orders.new"))
        .await;
    settle().await;
    let all = fetches(&rig.sink);
    assert_eq!(all.len(), 2);
    assert_eq!(
        all[1]["topics"][0]["requests"], 5,
        "the 4 skipped polls and this one"
    );
    // The end of the session says what was never logged on its own.
    rig.client
        .call(wire::api::FETCH, 11, &fetch_body("orders.new"))
        .await;
    drop(rig.client);
    let _ = tokio::time::timeout(Duration::from_secs(5), rig.done).await;
    let summary = &events(&rig.sink, EventKind::KafkaSummary)[0];
    assert!(summary["requests"].as_u64().expect("n") >= 7);
    assert_eq!(summary["unlogged"][0]["name"], "orders.new");
}

#[tokio::test]
async fn heartbeats_are_counted_not_logged_and_group_requests_are_logged() {
    let mut rig = rig(vec![grant(&[KafkaClass::Read], &[], &[])]).await;
    for _ in 0..3 {
        rig.client
            .call(
                wire::api::HEARTBEAT,
                0,
                &Writer::new().string("g").i32(1).string("m").finish(),
            )
            .await;
    }
    settle().await;
    assert!(
        events(&rig.sink, EventKind::KafkaRequest)
            .iter()
            .all(|d| d["api"] != "Heartbeat")
    );
    // A refused group's heartbeat is answered by the worker.
    let mut denied = rig_with_groups(&["only-this"]).await;
    let body = denied
        .client
        .call(
            wire::api::HEARTBEAT,
            0,
            &Writer::new().string("g").i32(1).string("m").finish(),
        )
        .await;
    assert_eq!(Reader::new(&body).i16(), Ok(30));
    assert_eq!(denied.brokers[0].seen(wire::api::HEARTBEAT).len(), 0);
}

async fn rig_with_groups(groups: &[&str]) -> Rig {
    rig(vec![grant(&[KafkaClass::Read], &[], groups)]).await
}

#[tokio::test]
async fn creating_topics_needs_admin() {
    let mut rig = rig(vec![grant(
        &[KafkaClass::Read, KafkaClass::Write],
        &[],
        &[],
    )])
    .await;
    let create = Writer::new()
        .i32(1)
        .string("brand-new")
        .i32(3)
        .i16(1)
        .i32(0)
        .i32(0)
        .i32(30_000)
        .i8(0)
        .finish();
    let body = rig.client.call(wire::api::CREATE_TOPICS, 1, &create).await;
    let mut r = Reader::new(&body);
    assert_eq!(r.array_len(), Ok(Some(1)));
    assert_eq!(r.string().as_deref(), Ok("brand-new"));
    assert_eq!(r.i16(), Ok(29));
    assert_eq!(rig.brokers[0].seen(wire::api::CREATE_TOPICS).len(), 0);
    let mut rig = rig_admin().await;
    let body = rig.client.call(wire::api::CREATE_TOPICS, 1, &create).await;
    let mut r = Reader::new(&body);
    r.array_len().expect("n");
    assert_eq!(r.string().as_deref(), Ok("brand-new"));
    assert_eq!(r.i16(), Ok(0));
    settle().await;
    let made: Vec<_> = events(&rig.sink, EventKind::KafkaRequest)
        .into_iter()
        .filter(|d| d["api"] == "CreateTopics")
        .collect();
    assert_eq!(made.len(), 1);
}

#[tokio::test]
async fn an_api_or_version_outside_the_table_ends_the_session_and_is_audited() {
    let mut rig = rig(vec![grant(
        &[KafkaClass::Read, KafkaClass::Write],
        &[],
        &[],
    )])
    .await;
    // Produce v9 is the first flexible version: not read, not offered.
    rig.client.send(wire::api::PRODUCE, 9, &[0; 16]).await;
    assert!(rig.client.closed().await);
    settle().await;
    let denied = events(&rig.sink, EventKind::AuthDenied);
    assert!(
        denied[0]["reason"]
            .as_str()
            .expect("reason")
            .contains("version 9"),
        "{denied:?}"
    );
    // An API nobody relays, such as DescribeAcls (29).
    let mut rig = rig_admin().await;
    rig.client.send(29, 0, &[0; 8]).await;
    assert!(rig.client.closed().await);
    assert_eq!(rig.brokers[0].requests_after_login(), 0);
}

#[tokio::test]
async fn transactions_are_not_supported() {
    let mut rig = rig(vec![grant(&[KafkaClass::Write], &[], &[])]).await;
    let body = Writer::new()
        .nullable_string(Some("tx-1"))
        .i32(60_000)
        .finish();
    let resp = rig.client.call(wire::api::INIT_PRODUCER_ID, 1, &body).await;
    let mut r = Reader::new(&resp);
    r.i32().expect("throttle");
    assert_eq!(r.i16(), Ok(53));
    // A plain idempotent producer's InitProducerId is fine.
    let body = Writer::new().nullable_string(None).i32(60_000).finish();
    rig.client.send(wire::api::INIT_PRODUCER_ID, 1, &body).await;
    settle().await;
    assert_eq!(rig.brokers[0].seen(wire::api::INIT_PRODUCER_ID).len(), 1);
}

#[tokio::test]
async fn sasl_from_the_client_is_accepted_and_discarded() {
    let mut rig = rig(vec![grant(&[KafkaClass::Read], &[], &[])]).await;
    let hs = rig
        .client
        .call(
            wire::api::SASL_HANDSHAKE,
            1,
            &Writer::new().string("PLAIN").finish(),
        )
        .await;
    assert_eq!(Reader::new(&hs).i16(), Ok(0));
    let hs = rig
        .client
        .call(
            wire::api::SASL_HANDSHAKE,
            1,
            &Writer::new().string("GSSAPI").finish(),
        )
        .await;
    assert_eq!(Reader::new(&hs).i16(), Ok(33));
    let auth = rig
        .client
        .call(
            wire::api::SASL_AUTHENTICATE,
            1,
            &Writer::new().bytes(b"\0mallory\0hunter2").finish(),
        )
        .await;
    assert_eq!(Reader::new(&auth).i16(), Ok(0));
    // The broker never saw the client's credentials.
    let logins = rig.brokers[0].logins.lock().expect("lock").clone();
    assert!(
        logins
            .iter()
            .all(|(u, p)| u == "limen-consumer" && p == "broker-secret"),
        "{logins:?}"
    );
    let all = format!("{:?}", rig.sink.events());
    assert!(!all.contains("hunter2"));
}

#[tokio::test]
async fn audit_failing_closed_stops_requests_and_answers_with_a_retriable_error() {
    let mut rig = rig(vec![grant(&[KafkaClass::Write], &[], &[])]).await;
    rig.sink.set_failing(true);
    let resp = rig
        .client
        .call(
            wire::api::PRODUCE,
            8,
            &produce_body(1, &[("orders.new", &[0])]),
        )
        .await;
    assert_eq!(
        produce_result(&resp)[0].1,
        [(0, 7)],
        "REQUEST_TIMED_OUT, which producers retry"
    );
    settle().await;
    assert_eq!(
        rig.brokers[0].seen(wire::api::PRODUCE).len(),
        0,
        "an unaudited request doesn't run"
    );
    rig.sink.set_failing(false);
    let resp = rig
        .client
        .call(
            wire::api::PRODUCE,
            8,
            &produce_body(1, &[("orders.new", &[0])]),
        )
        .await;
    assert_eq!(produce_result(&resp)[0].1, [(0, 0)]);
}

#[tokio::test]
async fn a_broker_that_goes_away_ends_the_session() {
    let mut rig = rig(vec![grant(&[KafkaClass::Read], &[], &[])]).await;
    rig.client
        .call(wire::api::METADATA, 1, &Writer::new().i32(0).finish())
        .await;
    drop(rig.brokers);
    // The accept loops hold the listeners; the connection itself stays up.
    drop(rig.client);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), rig.done)
            .await
            .is_ok()
    );
}

#[test]
fn a_missing_password_is_caught_when_the_session_is_prepared() {
    let settings = Arc::new(Settings::default());
    let target: BrokerTarget = serde_json::from_value(
        serde_json::json!({ "endpoint": "k:9092", "sasl": "scram-sha-512" }),
    )
    .expect("target");
    let config = SessionConfig::new(
        "s".into(),
        "u".into(),
        "limen-consumer".into(),
        "events-kafka".into(),
        target.clone(),
        KafkaSlot::new(0, vec![1, 2]),
    );
    let err = prepare(&settings, vec![], config).expect_err("no password");
    assert!(err.to_string().contains("no password"), "{err}");
    // An open listener needs no credential.
    let open: BrokerTarget =
        serde_json::from_value(serde_json::json!({ "endpoint": "k:9092", "sasl": "none" }))
            .expect("target");
    let config = SessionConfig::new(
        "s".into(),
        "u".into(),
        "limen-consumer".into(),
        "events-kafka".into(),
        open,
        KafkaSlot::new(0, vec![1, 2]),
    );
    assert!(prepare(&settings, vec![], config).is_ok());
}

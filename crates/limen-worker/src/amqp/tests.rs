//! Whole-session tests: an AMQP client, the worker's session code, and a fake
//! broker on a loopback socket, so the worker's real dial path is used. The
//! real broker is exercised by `demos/demo-phase11.sh`.

use std::sync::{Arc, Mutex};

use limen_audit::{Emitter, EventKind, FailureMode, MemorySink};
use limen_policy::{MqClass, MqGrant};
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;

use super::codec::{Field, Out};
use super::*;

/// What the fake broker saw: its login, and every frame after the handshake.
#[derive(Default)]
struct BrokerLog {
    login: Option<(String, String, String, String)>,
    frames: Vec<Frame>,
    connections: usize,
}

struct FakeBroker {
    addr: String,
    log: Arc<Mutex<BrokerLog>>,
    push: mpsc::UnboundedSender<Frame>,
}

impl FakeBroker {
    fn frames(&self) -> Vec<Frame> {
        self.log.lock().expect("lock").frames.clone()
    }

    fn methods(&self) -> Vec<(u16, u16, u16)> {
        self.frames()
            .iter()
            .filter_map(|f| f.as_method().map(|(c, m, _)| (f.channel, c, m)))
            .collect()
    }
}

async fn fake_broker() -> FakeBroker {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let log: Arc<Mutex<BrokerLog>> = Arc::default();
    let (push, mut pushed) = mpsc::unbounded_channel::<Frame>();
    let seen = Arc::clone(&log);
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        seen.lock().expect("lock").connections += 1;
        let (r, mut w) = tokio::io::split(stream);
        let mut reader = FrameReader::new(r, 1 << 20);
        let mut header = [0u8; 8];
        // The protocol header is not a frame.
        reader.reader.read_exact(&mut header).await.expect("header");
        assert_eq!(header, PROTOCOL_HEADER);
        write_frame(&mut w, &connection_start())
            .await
            .expect("start");
        let ok = reader.next().await.expect("start-ok").expect("frame");
        let (_, _, args) = ok.as_method().expect("method");
        let mut a = Args::new(args);
        a.skip_long().expect("props");
        assert_eq!(a.shortstr().as_deref(), Ok("PLAIN"));
        let response = a.longstr().expect("response").to_vec();
        let mut parts = response.split(|b| *b == 0);
        parts.next();
        let user = String::from_utf8_lossy(parts.next().expect("user")).into_owned();
        let password = String::from_utf8_lossy(parts.next().expect("password")).into_owned();
        write_frame(&mut w, &connection_tune(2047, 131_072, 0))
            .await
            .expect("tune");
        reader.next().await.expect("tune-ok").expect("frame");
        let open = reader.next().await.expect("open").expect("frame");
        let (_, _, args) = open.as_method().expect("method");
        let vhost = Args::new(args).shortstr().expect("vhost");
        // The connection name is in the properties table; its text is enough.
        let name = String::from_utf8_lossy(&ok.payload)
            .split("limen:")
            .nth(1)
            .map(|rest| format!("limen:{}", rest.chars().take(36).collect::<String>()))
            .unwrap_or_default();
        seen.lock().expect("lock").login = Some((user, password, vhost, name));
        write_frame(&mut w, &connection_open_ok())
            .await
            .expect("open-ok");
        loop {
            tokio::select! {
                frame = reader.next() => {
                    let Ok(Some(frame)) = frame else { return };
                    seen.lock().expect("lock").frames.push(frame.clone());
                    let reply = match frame.as_method() {
                        Some((20, 10, _)) => Some(Frame::method(frame.channel, 20, 11, &Out::new().longstr(b"").finish())),
                        Some((20, 40, _)) => Some(channel_close_ok(frame.channel)),
                        Some((50, 10, args)) => {
                            let mut a = Args::new(args);
                            a.u16().expect("reserved");
                            let name = a.shortstr().expect("queue");
                            let name = if name.is_empty() { "amq.gen-fake".to_owned() } else { name };
                            Some(Frame::method(frame.channel, 50, 11, &Out::new().shortstr(&name).u32(0).u32(0).finish()))
                        }
                        Some((60, 20, _)) => Some(Frame::method(frame.channel, 60, 21, &Out::new().shortstr("ctag").finish())),
                        Some((10, 50, _)) => {
                            let _ = write_frame(&mut w, &Frame::method(0, 10, 51, &[])).await;
                            return;
                        }
                        _ => None,
                    };
                    if let Some(reply) = reply
                        && write_frame(&mut w, &reply).await.is_err()
                    {
                        return;
                    }
                }
                Some(frame) = pushed.recv() => {
                    if write_frame(&mut w, &frame).await.is_err() { return; }
                }
            }
        }
    });
    FakeBroker { addr, log, push }
}

fn grant(vhosts: &[&str], classes: &[MqClass], names: &[&str]) -> MqGrant {
    MqGrant {
        users: vec!["limen-app".into()],
        vhosts: vhosts.iter().map(|s| (*s).to_owned()).collect(),
        classes: classes.to_vec(),
        names: names.iter().map(|s| (*s).to_owned()).collect(),
    }
}

struct Rig {
    client: Peer,
    broker: FakeBroker,
    sink: Arc<MemorySink>,
    done: tokio::task::JoinHandle<anyhow::Result<SessionOutcome>>,
    _dir: tempfile::TempDir,
}

/// The test's AMQP client.
struct Peer {
    reader: FrameReader<tokio::io::ReadHalf<DuplexStream>>,
    writer: tokio::io::WriteHalf<DuplexStream>,
}

impl Peer {
    async fn send(&mut self, frame: &Frame) {
        write_frame(&mut self.writer, frame).await.expect("send");
    }

    async fn send_bytes(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).await.expect("send");
        self.writer.flush().await.expect("flush");
    }

    async fn recv(&mut self) -> Frame {
        tokio::time::timeout(Duration::from_secs(5), self.reader.next())
            .await
            .expect("a frame in time")
            .expect("readable")
            .expect("not closed")
    }

    async fn recv_method(&mut self) -> (u16, u16, u16, Vec<u8>) {
        loop {
            let f = self.recv().await;
            if let Some((c, m, a)) = f.as_method() {
                return (f.channel, c, m, a.to_vec());
            }
        }
    }

    /// Open a channel and wait for `OpenOk`.
    async fn open_channel(&mut self, channel: u16) {
        self.send(&Frame::method(
            channel,
            20,
            10,
            &Out::new().shortstr("").finish(),
        ))
        .await;
        let (ch, c, m, _) = self.recv_method().await;
        assert_eq!((ch, c, m), (channel, 20, 11));
    }

    async fn publish(&mut self, channel: u16, exchange: &str, key: &str, body: &[u8]) {
        let args = Out::new()
            .u16(0)
            .shortstr(exchange)
            .shortstr(key)
            .u8(0)
            .finish();
        for frame in publish_frames(channel, &args, body) {
            self.send(&frame).await;
        }
    }
}

fn publish_frames(channel: u16, publish_args: &[u8], body: &[u8]) -> Vec<Frame> {
    let mut header = vec![0, 60, 0, 0];
    header.extend_from_slice(&(body.len() as u64).to_be_bytes());
    header.extend_from_slice(&[0, 0]);
    vec![
        Frame::method(channel, 60, 40, publish_args),
        Frame {
            kind: HEADER,
            channel,
            payload: header,
        },
        Frame {
            kind: BODY,
            channel,
            payload: body.to_vec(),
        },
    ]
}

/// Run the handshake as a client with its own (ignored) login and open `vhost`.
/// `Err` is the client of a session that was refused at `Connection.Open`.
async fn start(
    grants: Vec<MqGrant>,
    vhost: &str,
    sink: Option<Arc<MemorySink>>,
) -> Result<Rig, (Peer, (u16, u16, Vec<u8>))> {
    let broker = fake_broker().await;
    let dir = tempfile::tempdir().expect("dir");
    let creds = dir.path().join("creds.json");
    std::fs::write(&creds, r#"{"orders-mq": {"limen-app": "broker-secret"}}"#).expect("creds");
    let settings = Arc::new(Settings::load(None, Some(&creds)).expect("settings"));
    let target =
        serde_json::from_value(serde_json::json!({ "endpoint": broker.addr, "tls": false }))
            .expect("target");
    let session_id = Uuid::now_v7().to_string();
    let config = SessionConfig {
        session_id,
        username: "dev@example.com".into(),
        mq_user: "limen-app".into(),
        resource: "orders-mq".into(),
        target,
    };
    let prepared = prepare(&settings, grants, config).expect("prepared");
    let (client, server) = tokio::io::duplex(1 << 20);
    let sink = sink.unwrap_or_default();
    let audit = Emitter::new("worker", "w1", sink.clone(), FailureMode::FailClosed);
    let done = tokio::spawn(serve(server, prepared, audit));
    let (r, w) = tokio::io::split(client);
    let mut peer = Peer {
        reader: FrameReader::new(r, 1 << 20),
        writer: w,
    };
    peer.send_bytes(&PROTOCOL_HEADER).await;
    peer.recv_method().await; // Start
    // The client's own login is whatever it likes.
    peer.send(&Frame::method(
        0,
        10,
        11,
        &Out::new()
            .table(&[("product", Field::Str("test"))])
            .shortstr("PLAIN")
            .longstr(b"\0mallory\0hunter2")
            .shortstr("en_US")
            .finish(),
    ))
    .await;
    peer.recv_method().await; // Tune
    peer.send(&Frame::method(
        0,
        10,
        31,
        &Out::new().u16(2047).u32(131_072).u16(0).finish(),
    ))
    .await;
    peer.send(&connection_open(vhost)).await;
    let (_, c, m, args) = peer.recv_method().await;
    if (c, m) != (10, 41) {
        return Err((peer, (c, m, args)));
    }
    Ok(Rig {
        client: peer,
        broker,
        sink,
        done,
        _dir: dir,
    })
}

async fn rig(grants: Vec<MqGrant>) -> Rig {
    start(grants, "/", None)
        .await
        .map_err(|(_, refusal)| refusal)
        .expect("the session was refused")
}

fn events(sink: &MemorySink, kind: EventKind) -> Vec<serde_json::Value> {
    sink.events()
        .into_iter()
        .filter(|e| e.kind == kind)
        .map(|e| e.data)
        .collect()
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn the_worker_logs_in_with_its_own_credential_never_the_clients() {
    let mut rig = rig(vec![grant(&[], &[], &[])]).await;
    rig.client.open_channel(1).await;
    let (user, password, vhost, name) = rig
        .broker
        .log
        .lock()
        .expect("lock")
        .login
        .clone()
        .expect("logged in");
    assert_eq!(
        (user.as_str(), password.as_str(), vhost.as_str()),
        ("limen-app", "broker-secret", "/")
    );
    assert!(name.starts_with("limen:"), "{name}");
    // The client's credentials appear nowhere in the audit trail either.
    let all = format!("{:?}", rig.sink.events());
    assert!(
        !all.contains("hunter2") && !all.contains("broker-secret"),
        "{all}"
    );
}

#[tokio::test]
async fn a_publish_is_audited_with_its_size_and_never_its_body() {
    let mut rig = rig(vec![grant(&[], &[], &["orders", "events"])]).await;
    rig.client.open_channel(1).await;
    rig.client
        .publish(1, "orders", "order.new", b"top-secret-card-number")
        .await;
    settle().await;
    let seen = rig.broker.frames();
    // Channel.Open, then the publish method, header, and body, in order.
    let kinds_seen: Vec<u8> = seen.iter().map(|f| f.kind).collect();
    assert_eq!(kinds_seen, [METHOD, METHOD, HEADER, BODY]);
    assert_eq!(seen[3].payload, b"top-secret-card-number");
    let ops = events(&rig.sink, EventKind::MqOperation);
    let publish = ops
        .iter()
        .find(|d| d["action"] == "publish")
        .expect("publish event");
    assert_eq!(publish["exchange"], "orders");
    assert_eq!(publish["routing_key"], "order.new");
    assert_eq!(publish["size"], 22);
    assert_eq!(publish["mq_user"], "limen-app");
    assert_eq!(publish["vhost"], "/");
    let all = format!("{:?}", rig.sink.events());
    assert!(
        !all.contains("top-secret-card-number"),
        "bodies never reach the trail"
    );
}

#[tokio::test]
async fn a_refused_publish_closes_its_channel_and_never_reaches_the_broker() {
    let mut rig = rig(vec![grant(&[], &[], &["orders"])]).await;
    rig.client.open_channel(1).await;
    rig.client.open_channel(2).await;
    rig.client.publish(1, "payments", "x", b"nope").await;
    let (ch, c, m, args) = rig.client.recv_method().await;
    assert_eq!((ch, c, m), (1, 20, 40), "Channel.Close");
    assert_eq!(Args::new(&args).u16(), Ok(403));
    // The client answers; the worker closed the broker's side by itself.
    rig.client.send(&channel_close_ok(1)).await;
    settle().await;
    let methods = rig.broker.methods();
    assert!(
        methods.contains(&(1, 20, 40)),
        "the worker closed channel 1 at the broker: {methods:?}"
    );
    assert!(!methods.contains(&(1, 60, 40)), "the publish never arrived");
    assert!(
        rig.broker.frames().iter().all(|f| f.kind != BODY),
        "neither did its body"
    );
    // The other channel is unaffected.
    rig.client.publish(2, "orders", "k", b"fine").await;
    settle().await;
    assert!(rig.broker.methods().contains(&(2, 60, 40)));
    // And the refused one can be opened again once it is closed on both sides.
    rig.client.open_channel(1).await;
    let denied = events(&rig.sink, EventKind::AuthDenied);
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["action"], "mq");
    assert_eq!(denied[0]["operation"], "publish");
    assert_eq!(denied[0]["exchange"], "payments");
}

#[tokio::test]
async fn configuring_needs_the_configure_permission() {
    let mut rig = rig(vec![grant(&[], &[], &[])]).await;
    rig.client.open_channel(1).await;
    let args = Out::new()
        .u16(0)
        .shortstr("new-queue")
        .u8(0)
        .u32(0)
        .finish();
    rig.client.send(&Frame::method(1, 50, 10, &args)).await;
    let (ch, c, m, _) = rig.client.recv_method().await;
    assert_eq!((ch, c, m), (1, 20, 40));
    settle().await;
    assert!(!rig.broker.methods().contains(&(1, 50, 10)));
    let denied = events(&rig.sink, EventKind::AuthDenied);
    assert!(
        denied[0]["reason"]
            .as_str()
            .expect("reason")
            .contains("configure"),
        "{denied:?}"
    );
}

#[tokio::test]
async fn a_refused_vhost_is_audited_and_the_broker_never_sees_a_connection() {
    let sink = Arc::new(MemorySink::default());
    let Err((_peer, (class, method, args))) = start(
        vec![grant(&["orders-*"], &[], &[])],
        "secret",
        Some(sink.clone()),
    )
    .await
    else {
        panic!("should be refused");
    };
    assert_eq!((class, method), (10, 50), "Connection.Close");
    assert_eq!(Args::new(&args).u16(), Ok(403));
    settle().await;
    let denied = events(&sink, EventKind::AuthDenied);
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0]["operation"], "connect");
    assert_eq!(denied[0]["vhost"], "secret");
    assert_eq!(events(&sink, EventKind::MqOperation).len(), 0);
}

#[tokio::test]
async fn consuming_is_audited_and_deliveries_are_counted_not_logged() {
    let mut rig = rig(vec![grant(&[], &[MqClass::Read], &["jobs"])]).await;
    rig.client.open_channel(1).await;
    let args = Out::new()
        .u16(0)
        .shortstr("jobs")
        .shortstr("")
        .u8(0)
        .u32(0)
        .finish();
    rig.client.send(&Frame::method(1, 60, 20, &args)).await;
    let (_, c, m, _) = rig.client.recv_method().await;
    assert_eq!((c, m), (60, 21), "ConsumeOk comes from the broker");
    // The broker delivers three messages.
    for i in 0..3u8 {
        let deliver = Out::new()
            .shortstr("ctag")
            .u32(u32::from(i) + 1)
            .u8(0)
            .shortstr("")
            .shortstr("jobs")
            .finish();
        rig.broker
            .push
            .send(Frame::method(1, 60, 60, &deliver))
            .expect("push");
        let mut header = vec![0, 60, 0, 0];
        header.extend_from_slice(&5u64.to_be_bytes());
        header.extend_from_slice(&[0, 0]);
        rig.broker
            .push
            .send(Frame {
                kind: HEADER,
                channel: 1,
                payload: header,
            })
            .expect("push");
        rig.broker
            .push
            .send(Frame {
                kind: BODY,
                channel: 1,
                payload: b"hello".to_vec(),
            })
            .expect("push");
    }
    for _ in 0..3 {
        let (_, c, m, _) = rig.client.recv_method().await;
        assert_eq!((c, m), (60, 60));
        rig.client.recv().await;
        assert_eq!(rig.client.recv().await.payload, b"hello");
    }
    // Close the connection politely; the summary follows.
    rig.client.send(&connection_close(200, "bye", 0, 0)).await;
    rig.client.recv_method().await;
    drop(rig.client);
    let _ = tokio::time::timeout(Duration::from_secs(5), rig.done).await;
    let ops = events(&rig.sink, EventKind::MqOperation);
    assert!(
        ops.iter()
            .any(|d| d["action"] == "consume" && d["queue"] == "jobs")
    );
    let summary = &events(&rig.sink, EventKind::MqSummary)[0];
    assert_eq!(summary["delivered"], 3);
    assert_eq!(summary["delivered_bytes"], 15);
    assert_eq!(summary["published"], 0);
    let all = format!("{:?}", rig.sink.events());
    assert!(!all.contains("hello"));
}

#[tokio::test]
async fn a_server_named_queue_belongs_to_the_session_that_declared_it() {
    let mut rig = rig(vec![grant(
        &[],
        &[MqClass::Read, MqClass::Configure],
        &["orders.*"],
    )])
    .await;
    rig.client.open_channel(1).await;
    let declare = Out::new().u16(0).shortstr("").u8(0).u32(0).finish();
    rig.client.send(&Frame::method(1, 50, 10, &declare)).await;
    let (_, c, m, args) = rig.client.recv_method().await;
    assert_eq!((c, m), (50, 11));
    let name = Args::new(&args).shortstr().expect("name");
    assert_eq!(name, "amq.gen-fake");
    let consume = Out::new()
        .u16(0)
        .shortstr(&name)
        .shortstr("")
        .u8(0)
        .u32(0)
        .finish();
    rig.client.send(&Frame::method(1, 60, 20, &consume)).await;
    let (_, c, m, _) = rig.client.recv_method().await;
    assert_eq!(
        (c, m),
        (60, 21),
        "its own queue is usable whatever the patterns"
    );
    // Somebody else's amq.gen queue is not.
    rig.client.open_channel(2).await;
    let other = Out::new()
        .u16(0)
        .shortstr("amq.gen-someone-else")
        .shortstr("")
        .u8(0)
        .u32(0)
        .finish();
    rig.client.send(&Frame::method(2, 60, 20, &other)).await;
    let (ch, c, m, _) = rig.client.recv_method().await;
    assert_eq!((ch, c, m), (2, 20, 40));
}

#[tokio::test]
async fn a_method_the_worker_does_not_know_is_refused_not_relayed() {
    let mut rig = rig(vec![grant(&[], &[], &[])]).await;
    rig.client.open_channel(1).await;
    rig.client.send(&Frame::method(1, 60, 99, &[])).await;
    let (ch, c, m, args) = rig.client.recv_method().await;
    assert_eq!((ch, c, m), (1, 20, 40));
    assert_eq!(Args::new(&args).u16(), Ok(540));
    settle().await;
    assert!(!rig.broker.methods().contains(&(1, 60, 99)));
}

#[tokio::test]
async fn audit_failing_closed_stops_operations_but_not_the_connection() {
    let mut rig = rig(vec![grant(&[], &[], &[])]).await;
    rig.client.open_channel(1).await;
    rig.sink.set_failing(true);
    rig.client.publish(1, "x", "k", b"body").await;
    let (ch, c, m, args) = rig.client.recv_method().await;
    assert_eq!((ch, c, m), (1, 20, 40), "the channel is closed");
    assert_eq!(Args::new(&args).u16(), Ok(541));
    settle().await;
    assert!(
        !rig.broker.methods().contains(&(1, 60, 40)),
        "an operation that can't be audited doesn't run"
    );
    rig.sink.set_failing(false);
    rig.client.send(&channel_close_ok(1)).await;
    rig.client.open_channel(1).await;
    rig.client.publish(1, "x", "k", b"body").await;
    settle().await;
    assert!(rig.broker.methods().contains(&(1, 60, 40)));
}

#[tokio::test]
async fn a_burst_of_publishes_arrives_in_order_and_each_is_audited() {
    let mut rig = rig(vec![grant(&[], &[], &[])]).await;
    rig.client.open_channel(1).await;
    let mut burst = Vec::new();
    for i in 0..300u32 {
        let args = Out::new()
            .u16(0)
            .shortstr("x")
            .shortstr(&format!("k{i}"))
            .u8(0)
            .finish();
        for f in publish_frames(1, &args, format!("body-{i}").as_bytes()) {
            burst.extend_from_slice(&f.encode());
        }
    }
    rig.client.send_bytes(&burst).await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    let keys: Vec<String> = rig
        .broker
        .frames()
        .iter()
        .filter_map(Frame::as_method)
        .filter(|(c, m, _)| (*c, *m) == (60, 40))
        .map(|(_, _, a)| {
            let mut a = Args::new(a);
            a.u16().expect("reserved");
            a.shortstr().expect("exchange");
            a.shortstr().expect("key")
        })
        .collect();
    let expected: Vec<String> = (0..300).map(|i| format!("k{i}")).collect();
    assert_eq!(keys, expected);
    let published = events(&rig.sink, EventKind::MqOperation)
        .into_iter()
        .filter(|d| d["action"] == "publish")
        .count();
    assert_eq!(published, 300);
}

#[tokio::test]
async fn a_client_that_speaks_another_protocol_is_told_what_this_is() {
    let broker = fake_broker().await;
    let dir = tempfile::tempdir().expect("dir");
    let creds = dir.path().join("c.json");
    std::fs::write(&creds, r#"{"orders-mq": {"limen-app": "x"}}"#).expect("creds");
    let settings = Arc::new(Settings::load(None, Some(&creds)).expect("settings"));
    let target =
        serde_json::from_value(serde_json::json!({ "endpoint": broker.addr, "tls": false }))
            .expect("target");
    let prepared = prepare(
        &settings,
        vec![grant(&[], &[], &[])],
        SessionConfig {
            session_id: Uuid::now_v7().to_string(),
            username: "u".into(),
            mq_user: "limen-app".into(),
            resource: "orders-mq".into(),
            target,
        },
    )
    .expect("prepared");
    let (mut client, server) = tokio::io::duplex(4096);
    let audit = Emitter::new(
        "worker",
        "w1",
        Arc::new(MemorySink::default()),
        FailureMode::FailClosed,
    );
    let done = tokio::spawn(serve(server, prepared, audit));
    client
        .write_all(b"AMQP\x01\x01\x00\x0a")
        .await
        .expect("write");
    let mut reply = [0u8; 8];
    tokio::io::AsyncReadExt::read_exact(&mut client, &mut reply)
        .await
        .expect("reply");
    assert_eq!(reply, PROTOCOL_HEADER);
    let _ = done.await;
    assert_eq!(broker.log.lock().expect("lock").connections, 0);
}

#[tokio::test]
async fn an_oversize_frame_ends_the_connection_with_a_frame_error() {
    let mut rig = rig(vec![grant(&[], &[], &[])]).await;
    rig.client.open_channel(1).await;
    // A body frame announcing more than the agreed frame size.
    rig.client
        .send_bytes(&[BODY, 0, 1, 0x00, 0x20, 0x00, 0x00])
        .await;
    let (_, c, m, args) = rig.client.recv_method().await;
    assert_eq!((c, m), (10, 50), "Connection.Close");
    assert_eq!(Args::new(&args).u16(), Ok(501));
}

#[test]
fn a_missing_broker_credential_is_caught_when_the_session_is_prepared() {
    let settings = Arc::new(Settings::default());
    let target =
        serde_json::from_value(serde_json::json!({ "endpoint": "mq:5672" })).expect("target");
    let err = prepare(
        &settings,
        vec![],
        SessionConfig {
            session_id: "s".into(),
            username: "u".into(),
            mq_user: "limen-app".into(),
            resource: "orders-mq".into(),
            target,
        },
    )
    .expect_err("no credential");
    assert!(err.to_string().contains("no credential"), "{err}");
}

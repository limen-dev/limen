//! Phase 11 end to end: an AMQP client reaches a broker through the proxy and
//! the worker with no credential, policy is enforced per operation, every
//! operation is audited without its body, and a lock ends the session
//! (ADR-0037).
//!
//! Needs `LIMEN_TEST_DATABASE_URL` (control plane state). The broker is a small
//! in-process stand-in (real `RabbitMQ` and Kafka are exercised by
//! `demos/demo-phase11.sh`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use limen_e2e::{Deployment, db_client, eventually};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, CreateJoinTokenRequest, LockUserRequest, PolicySource};
use limen_testkit::users::{ADMIN, DEVELOPER};
use limen_worker::amqp::codec::{
    Args, BODY, Frame, HEADER, Out, connection_close_ok, connection_open_ok, connection_start,
    connection_tune, ids, parse_frame,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SECRET_BODY: &str = "card-4111111111111111";
const PROTOCOL_HEADER: [u8; 8] = *b"AMQP\x00\x00\x09\x01";

/// What the stand-in broker saw: the login, and the methods after it.
#[derive(Default)]
struct Seen {
    login: Option<(String, String)>,
    methods: Vec<(u16, u16, u16)>,
}

async fn read_frame(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Frame> {
    loop {
        if let Some((frame, used)) = parse_frame(buf, 1 << 20).expect("frame") {
            buf.drain(..used);
            return Some(frame);
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// A broker that accepts any login, opens any vhost, and answers channel opens
/// and closes; it records everything.
async fn fake_broker() -> (String, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let seen: Arc<Mutex<Seen>> = Arc::default();
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut header = [0u8; 8];
                if s.read_exact(&mut header).await.is_err() || header != PROTOCOL_HEADER {
                    return;
                }
                let mut buf = Vec::new();
                s.write_all(&connection_start().encode())
                    .await
                    .expect("start");
                let ok = read_frame(&mut s, &mut buf).await.expect("start-ok");
                let (_, _, args) = ok.as_method().expect("method");
                let mut a = Args::new(args);
                a.skip_long().expect("properties");
                a.shortstr().expect("mechanism");
                let response = a.longstr().expect("response").to_vec();
                let mut parts = response.split(|b| *b == 0).skip(1);
                let user = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
                let password =
                    String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
                log.lock().expect("lock").login = Some((user, password));
                s.write_all(&connection_tune(2047, 131_072, 0).encode())
                    .await
                    .expect("tune");
                read_frame(&mut s, &mut buf).await.expect("tune-ok");
                read_frame(&mut s, &mut buf).await.expect("open");
                s.write_all(&connection_open_ok().encode())
                    .await
                    .expect("open-ok");
                while let Some(frame) = read_frame(&mut s, &mut buf).await {
                    let Some((class, method, _)) = frame.as_method() else {
                        continue;
                    };
                    log.lock()
                        .expect("lock")
                        .methods
                        .push((frame.channel, class, method));
                    let reply = match (class, method) {
                        (20, 10) => Some(Frame::method(
                            frame.channel,
                            20,
                            11,
                            &Out::new().longstr(b"").finish(),
                        )),
                        (20, 40) => Some(Frame::method(frame.channel, 20, 41, &[])),
                        (10, 50) => {
                            let _ = s.write_all(&connection_close_ok().encode()).await;
                            return;
                        }
                        _ => None,
                    };
                    if let Some(reply) = reply {
                        let _ = s.write_all(&reply.encode()).await;
                    }
                }
            });
        }
    });
    (addr, seen)
}

fn policy(target: &str) -> Vec<PolicySource> {
    let yaml = format!(
        r#"
kind: role
version: v1
metadata: {{ name: brokers }}
spec:
  allow:
    - resources: {{ kind: [rabbitmq], labels: {{ env: [test] }} }}
      mq: {{ users: [limen-app], classes: [read, write], names: ["orders.*"] }}
    - resources: {{ kind: [kafka], labels: {{ env: [test] }} }}
      kafka: {{ users: [limen-app] }}
---
kind: role_mapping
version: v1
metadata: {{ name: idp }}
spec:
  - {{ idp_group: brokers, roles: [brokers] }}
---
kind: resource
version: v1
metadata: {{ name: orders-mq, labels: {{ env: test }} }}
spec:
  rabbitmq:
    endpoint: "{target}"
    tls: false
  worker_selector: {{ pool: dev }}
---
kind: resource
version: v1
metadata: {{ name: events-kafka, labels: {{ env: test }} }}
spec:
  kafka:
    endpoint: "127.0.0.1:1"
    tls: false
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

/// The client side of the handshake, ending with `Connection.Open` accepted.
async fn amqp_connect(addr: std::net::SocketAddr, vhost: &str) -> (TcpStream, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.write_all(&PROTOCOL_HEADER).await.expect("header");
    let mut buf = Vec::new();
    read_frame(&mut s, &mut buf).await.expect("start");
    let start_ok = Frame::method(
        0,
        10,
        11,
        &Out::new()
            .u32(0)
            .shortstr("PLAIN")
            .longstr(b"\0anyone\0anything")
            .shortstr("en_US")
            .finish(),
    );
    s.write_all(&start_ok.encode()).await.expect("start-ok");
    read_frame(&mut s, &mut buf).await.expect("tune");
    let tune_ok = Frame::method(
        0,
        10,
        31,
        &Out::new().u16(2047).u32(131_072).u16(0).finish(),
    );
    s.write_all(&tune_ok.encode()).await.expect("tune-ok");
    let open = Frame::method(
        0,
        10,
        40,
        &Out::new().shortstr(vhost).shortstr("").u8(0).finish(),
    );
    s.write_all(&open.encode()).await.expect("open");
    (s, buf)
}

async fn method(s: &mut TcpStream, buf: &mut Vec<u8>) -> (u16, u16, u16, Vec<u8>) {
    loop {
        let f = tokio::time::timeout(Duration::from_secs(5), read_frame(s, buf))
            .await
            .expect("a frame in time")
            .expect("not closed");
        if let Some((c, m, a)) = f.as_method() {
            return (f.channel, c, m, a.to_vec());
        }
    }
}

async fn publish(s: &mut TcpStream, channel: u16, exchange: &str, key: &str, body: &[u8]) {
    let args = Out::new()
        .u16(0)
        .shortstr(exchange)
        .shortstr(key)
        .u8(0)
        .finish();
    let mut header = vec![0, 60, 0, 0];
    header.extend_from_slice(&(body.len() as u64).to_be_bytes());
    header.extend_from_slice(&[0, 0]);
    for frame in [
        Frame::method(channel, 60, 40, &args),
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
    ] {
        s.write_all(&frame.encode()).await.expect("send");
    }
}

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread")]
async fn amqp_through_limen() {
    let Some(d) = Deployment::start().await else {
        return;
    };
    let (target, seen) = fake_broker().await;
    let creds = d.dir.path().join("broker-credentials.json");
    std::fs::write(
        &creds,
        r#"{"orders-mq": {"limen-app": "worker-held-pw"}, "events-kafka": {"limen-app": "worker-held-pw"}}"#,
    )
    .expect("credentials");

    let ca_pem = std::fs::read_to_string(d.ca_file()).expect("ca");
    let proxy_addr = d.proxy_addr.to_string();
    let admin_user = d.login(ADMIN, &["admins"]).await.expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(admin_user)));
    let applied = admin
        .apply_policy(ApplyPolicyRequest {
            sources: policy(&target),
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
    let worker = d
        .start_worker_with(
            &token,
            "worker",
            &[&format!("--broker-credentials-file={}", creds.display())],
        )
        .await;
    eventually(Duration::from_secs(15), "worker tunnels", || async {
        d.proxy().tunnels.summaries().len() == 2
    })
    .await;
    eventually(Duration::from_secs(15), "policy everywhere", || async {
        d.proxy().policy_version() == Some(applied.version)
            && worker.worker.policy_version() == Some(applied.version)
    })
    .await;

    // A developer connects with no credential and publishes.
    let dev = d.login(DEVELOPER, &["brokers"]).await.expect("developer");
    let (addr, refused) = db_client::listen_on(
        &proxy_addr,
        &ca_pem,
        dev.clone(),
        limen_tunnel::alpn::MQ,
        "orders-mq",
        "limen-app",
        "",
    )
    .await;
    let (mut client, mut buf) = amqp_connect(addr, "/").await;
    let (_, c, m, _) = method(&mut client, &mut buf).await;
    assert_eq!((c, m), (ids::CONNECTION, ids::OPEN_OK));
    client
        .write_all(&Frame::method(1, 20, 10, &Out::new().shortstr("").finish()).encode())
        .await
        .expect("open channel");
    let (ch, c, m, _) = method(&mut client, &mut buf).await;
    assert_eq!((ch, c, m), (1, 20, 11));
    publish(&mut client, 1, "orders.x", "new", SECRET_BODY.as_bytes()).await;
    eventually(
        Duration::from_secs(5),
        "the broker saw the publish",
        || async {
            seen.lock()
                .expect("lock")
                .methods
                .contains(&(1, ids::BASIC, 40))
        },
    )
    .await;
    {
        let seen = seen.lock().expect("lock");
        assert_eq!(
            seen.login.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
            Some(("limen-app", "worker-held-pw")),
            "the worker logs in as the broker user; the client's login is dropped"
        );
    }
    // A publish to a name the role doesn't cover closes that channel with 403,
    // and never reaches the broker.
    publish(&mut client, 1, "payments", "x", b"nope").await;
    let (ch, c, m, args) = method(&mut client, &mut buf).await;
    assert_eq!((ch, c, m), (1, ids::CHANNEL, ids::CHANNEL_CLOSE));
    assert_eq!(Args::new(&args).u16().expect("code"), 403);
    assert_eq!(
        seen.lock()
            .expect("lock")
            .methods
            .iter()
            .filter(|(_, c, m)| (*c, *m) == (ids::BASIC, 40))
            .count(),
        1,
        "only the allowed publish was forwarded"
    );
    assert!(refused.lock().expect("lock").is_empty());

    // A broker user policy doesn't grant is refused by the proxy.
    let (bad, bad_refused) = db_client::listen_on(
        &proxy_addr,
        &ca_pem,
        dev.clone(),
        limen_tunnel::alpn::MQ,
        "orders-mq",
        "admin",
        "",
    )
    .await;
    let _ = TcpStream::connect(bad).await;
    eventually(Duration::from_secs(5), "refusal recorded", || async {
        !bad_refused.lock().expect("lock").is_empty()
    })
    .await;
    assert!(bad_refused.lock().expect("lock")[0].contains("access denied"));

    // The anchor a `limen mq|kafka connect` run holds: authorized, and then
    // open and idle (so the console shows the run active) until the CLI stops.
    for (alpn, resource) in [
        (limen_tunnel::alpn::MQ, "orders-mq"),
        (limen_tunnel::alpn::KAFKA, "events-kafka"),
    ] {
        let (anchor, anchor_refused) = db_client::listen_on(
            &proxy_addr,
            &ca_pem,
            dev.clone(),
            alpn,
            resource,
            "limen-app",
            limen_core::broker::ANCHOR,
        )
        .await;
        let mut held = TcpStream::connect(anchor).await.expect("anchor");
        let mut byte = [0u8; 1];
        let idle = tokio::time::timeout(Duration::from_secs(2), held.read(&mut byte)).await;
        assert!(idle.is_err(), "{resource}: the anchor should stay open");
        assert!(anchor_refused.lock().expect("lock").is_empty());
    }

    // A Kafka session needs the CLI's listener table, and a malformed one is refused.
    let (kbad, kbad_refused) = db_client::listen_on(
        &proxy_addr,
        &ca_pem,
        dev.clone(),
        limen_tunnel::alpn::KAFKA,
        "events-kafka",
        "limen-app",
        "not a slot table",
    )
    .await;
    let _ = TcpStream::connect(kbad).await;
    eventually(Duration::from_secs(5), "table refusal", || async {
        !kbad_refused.lock().expect("lock").is_empty()
    })
    .await;

    // The trail: names and sizes, never the body.
    eventually(
        Duration::from_secs(20),
        "mq events in the trail",
        || async {
            let events = read_jsonl(&d);
            events
                .iter()
                .any(|e| e["kind"] == "mq.operation" && e["data"]["action"] == "publish")
                && events
                    .iter()
                    .any(|e| e["kind"] == "auth.denied" && e["data"]["action"] == "mq")
        },
    )
    .await;
    let events = read_jsonl(&d);
    let start = events
        .iter()
        .find(|e| e["kind"] == "session.start" && e["data"]["kind"] == "rabbitmq")
        .expect("session.start");
    assert_eq!(start["user"], DEVELOPER);
    assert_eq!(start["data"]["mq_user"], "limen-app");
    let publish_event = events
        .iter()
        .find(|e| e["kind"] == "mq.operation" && e["data"]["action"] == "publish")
        .expect("mq.operation");
    assert_eq!(publish_event["producer"]["component"], "worker");
    assert_eq!(publish_event["data"]["exchange"], "orders.x");
    assert_eq!(publish_event["data"]["routing_key"], "new");
    assert_eq!(publish_event["data"]["size"], SECRET_BODY.len());
    assert_eq!(publish_event["session_id"], start["session_id"]);
    let text = serde_json::to_string(&events).expect("json");
    for secret in [SECRET_BODY, "worker-held-pw", "anything"] {
        assert!(!text.contains(secret), "{secret} reached the audit trail");
    }

    // Locking the developer ends the open session.
    assert!(
        admin
            .lock_user(LockUserRequest {
                username: DEVELOPER.into(),
                reason: "test".into(),
            })
            .await
            .expect("lock")
            .into_inner()
            .locked
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let mut chunk = [0u8; 1024];
        if let Ok(Ok(0) | Err(_)) =
            tokio::time::timeout(Duration::from_millis(500), client.read(&mut chunk)).await
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the open session should end when the user is locked"
        );
    }
    worker.stop().await;
}

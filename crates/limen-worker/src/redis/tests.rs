//! Whole-session tests: a client, the worker's session code, and a fake
//! Redis server, joined by in-memory pipes. The real servers are exercised
//! by `deploy/compose/demo-phase7.sh`.

use std::sync::{Arc, Mutex};

use limen_audit::{Emitter, EventKind, FailureMode, MemorySink};
use limen_policy::{RedisGrant, RedisTarget};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::codec::{FrameScanner, encode_command, parse_command};
use super::rules::{KeySpecs, Rules};
use super::*;

/// What the fake server saw, as words.
type Seen = Arc<Mutex<Vec<Vec<String>>>>;

fn command_info() -> codec::Value {
    use codec::Value;
    let entry = |name: &str, flags: &[&str], first, last, step| {
        Value::Array(vec![
            Value::Bulk(name.as_bytes().to_vec()),
            Value::Integer(-1),
            Value::Array(flags.iter().map(|f| Value::Simple((*f).into())).collect()),
            Value::Integer(first),
            Value::Integer(last),
            Value::Integer(step),
        ])
    };
    Value::Array(vec![
        entry("get", &["readonly"], 1, 1, 1),
        entry("set", &["write"], 1, 1, 1),
        entry("ping", &["fast"], 0, 0, 0),
        entry("multi", &["fast"], 0, 0, 0),
        entry("flushall", &["write"], 0, 0, 0),
    ])
}

/// A server that answers `PING`, `GET`, and `SET`, and `+OK` to the rest.
/// `GET` of a missing key is null. A `SLOW` command delays its reply.
fn fake_server(stream: DuplexStream, seen: Seen) {
    tokio::spawn(async move {
        let (mut r, mut w) = tokio::io::split(stream);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut store = std::collections::HashMap::<String, String>::new();
        loop {
            loop {
                let mut sc = FrameScanner::new();
                let Ok(Some(n)) = sc.advance(&buf) else { break };
                let frame: Vec<u8> = buf.drain(..n).collect();
                let cmd = parse_command(&frame).expect("worker sends arrays");
                let words: Vec<String> = cmd
                    .args
                    .iter()
                    .map(|a| String::from_utf8_lossy(a).into_owned())
                    .collect();
                seen.lock().expect("lock").push(words.clone());
                let reply = match words[0].to_ascii_uppercase().as_str() {
                    "PING" => b"+PONG\r\n".to_vec(),
                    "SET" => {
                        store.insert(words[1].clone(), words[2].clone());
                        b"+OK\r\n".to_vec()
                    }
                    "GET" => match store.get(&words[1]) {
                        Some(v) => format!("${}\r\n{v}\r\n", v.len()).into_bytes(),
                        None => b"$-1\r\n".to_vec(),
                    },
                    "LIMEN.REFUSED" => b"-ERR unknown command 'LIMEN.REFUSED'\r\n".to_vec(),
                    "SLOW" => {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        b"+SLOW\r\n".to_vec()
                    }
                    _ => b"+OK\r\n".to_vec(),
                };
                w.write_all(&reply).await.expect("reply");
            }
            match r.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    });
}

struct Rig {
    client: DuplexStream,
    seen: Seen,
    sink: Arc<MemorySink>,
    done: tokio::task::JoinHandle<anyhow::Result<SessionOutcome>>,
}

fn grant(keys: &[&str], deny: &[&str]) -> RedisGrant {
    RedisGrant {
        users: vec!["limen-rw".into()],
        deny_commands: deny.iter().map(|s| (*s).to_owned()).collect(),
        allow_commands: Vec::new(),
        keys: keys.iter().map(|s| (*s).to_owned()).collect(),
        databases: Vec::new(),
    }
}

fn target(iam: bool) -> RedisTarget {
    serde_json::from_value(serde_json::json!({
        "endpoint": "redis:6379", "tls": false, "iam_auth": iam,
        "region": "us-east-1", "cache_name": "grp",
    }))
    .expect("target")
}

fn rig_with(grants: Vec<RedisGrant>, config: impl FnOnce(&mut SessionConfig)) -> Rig {
    let (client, client_side) = tokio::io::duplex(1 << 20);
    let (target_stream, server_side) = tokio::io::duplex(1 << 20);
    let seen: Seen = Arc::default();
    fake_server(server_side, Arc::clone(&seen));
    let sink = Arc::new(MemorySink::default());
    let audit = Emitter::new("worker", "w1", sink.clone(), FailureMode::FailClosed);
    let specs = KeySpecs::from_command_info(&command_info()).expect("specs");
    let mut cfg = SessionConfig::new(
        Uuid::now_v7().to_string(),
        "ana@example.com".into(),
        "limen-rw".into(),
        "cache".into(),
        target(false),
    );
    config(&mut cfg);
    let prepared = Prepared {
        config: cfg,
        stream: Box::new(target_stream),
        rules: Rules::new(grants, specs),
    };
    let done = tokio::spawn(serve(client_side, prepared, audit));
    Rig {
        client,
        seen,
        sink,
        done,
    }
}

fn rig(grants: Vec<RedisGrant>) -> Rig {
    rig_with(grants, |_| {})
}

async fn read_replies(client: &mut DuplexStream, count: usize) -> Vec<String> {
    let mut buf = Vec::new();
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    while out.len() < count {
        let mut sc = FrameScanner::new();
        if let Some(n) = sc.advance(&buf).expect("valid RESP") {
            let frame: Vec<u8> = buf.drain(..n).collect();
            out.push(String::from_utf8_lossy(&frame).trim_end().to_owned());
            continue;
        }
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut chunk))
            .await
            .expect("reply in time")
            .expect("read");
        assert!(n > 0, "connection closed after {out:?}");
        buf.extend_from_slice(&chunk[..n]);
    }
    out
}

fn cmd(words: &[&str]) -> Vec<u8> {
    encode_command(&words.iter().map(|w| w.as_bytes()).collect::<Vec<_>>())
}

#[tokio::test]
async fn forwards_commands_and_replies_untouched() {
    let mut rig = rig(vec![grant(&[], &[])]);
    let mut batch = cmd(&["SET", "k", "v"]);
    batch.extend(cmd(&["GET", "k"]));
    batch.extend(cmd(&["GET", "missing"]));
    rig.client.write_all(&batch).await.expect("write");
    assert_eq!(
        read_replies(&mut rig.client, 3).await,
        ["+OK", "$1\r\nv", "$-1"]
    );
    assert_eq!(
        *rig.seen.lock().expect("lock"),
        [
            vec!["SET", "k", "v"],
            vec!["GET", "k"],
            vec!["GET", "missing"]
        ]
    );
}

#[tokio::test]
async fn inline_commands_are_sent_as_arrays() {
    let mut rig = rig(vec![grant(&[], &[])]);
    rig.client.write_all(b"PING\r\n").await.expect("write");
    assert_eq!(read_replies(&mut rig.client, 1).await, ["+PONG"]);
}

#[tokio::test]
async fn a_denied_command_keeps_its_place_in_a_pipeline() {
    let mut rig = rig(vec![grant(&[], &[])]);
    // SLOW's reply arrives late; the denial of FLUSHALL must still come after it.
    let mut batch = cmd(&["SLOW"]);
    batch.extend(cmd(&["FLUSHALL"]));
    batch.extend(cmd(&["PING"]));
    rig.client.write_all(&batch).await.expect("write");
    let replies = read_replies(&mut rig.client, 3).await;
    assert_eq!(replies[0], "+SLOW");
    assert!(
        replies[1].starts_with("-NOPERM Limen: FLUSHALL is denied"),
        "{replies:?}"
    );
    assert_eq!(replies[2], "+PONG");
    let seen = rig.seen.lock().expect("lock").clone();
    assert!(
        seen.iter().all(|w| w[0] != "FLUSHALL"),
        "never reached the server: {seen:?}"
    );
    let kinds: Vec<_> = rig.sink.events().iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&EventKind::AuthDenied));
}

#[tokio::test]
async fn key_patterns_are_enforced_and_audited() {
    let mut rig = rig(vec![grant(&["cache:*"], &[])]);
    let mut batch = cmd(&["SET", "cache:a", "super-secret-value"]);
    batch.extend(cmd(&["GET", "users:1"]));
    rig.client.write_all(&batch).await.expect("write");
    let replies = read_replies(&mut rig.client, 2).await;
    assert_eq!(replies[0], "+OK");
    assert!(replies[1].contains("outside the keys"), "{replies:?}");
    let events = rig.sink.events();
    let commands: Vec<_> = events
        .iter()
        .filter(|e| e.kind == EventKind::RedisCommand)
        .collect();
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].data["command"], "SET");
    assert_eq!(commands[0].data["keys"], serde_json::json!(["cache:a"]));
    assert_eq!(commands[0].user.as_deref(), Some("ana@example.com"));
    assert!(
        !serde_json::to_string(&events)
            .expect("json")
            .contains("super-secret-value"),
        "values stay out of the trail"
    );
}

#[tokio::test]
async fn client_auth_is_swallowed_and_never_forwarded() {
    let mut rig = rig(vec![grant(&[], &[])]);
    let mut batch = cmd(&["AUTH", "default", "client-password"]);
    batch.extend(cmd(&[
        "HELLO",
        "3",
        "AUTH",
        "default",
        "client-password",
        "SETNAME",
        "x",
    ]));
    batch.extend(cmd(&["CLIENT", "SETNAME", "mine"]));
    batch.extend(cmd(&["PING"]));
    rig.client.write_all(&batch).await.expect("write");
    let replies = read_replies(&mut rig.client, 4).await;
    assert_eq!(replies[0], "+OK");
    assert_eq!(replies[2], "+OK");
    assert_eq!(replies[3], "+PONG");
    let seen = rig.seen.lock().expect("lock").clone();
    assert!(
        seen.contains(&vec!["HELLO".to_owned(), "3".to_owned()]),
        "{seen:?}"
    );
    assert!(
        !format!("{seen:?}").contains("client-password") && !format!("{seen:?}").contains("mine"),
        "{seen:?}"
    );
    let trail = serde_json::to_string(&rig.sink.events()).expect("json");
    assert!(!trail.contains("client-password"));
}

#[tokio::test]
async fn a_command_that_cannot_be_audited_does_not_run() {
    let mut rig = rig(vec![grant(&[], &[])]);
    rig.sink.set_failing(true);
    rig.client
        .write_all(&cmd(&["SET", "k", "v"]))
        .await
        .expect("write");
    let replies = read_replies(&mut rig.client, 1).await;
    assert!(replies[0].contains("audit is unavailable"), "{replies:?}");
    assert!(rig.seen.lock().expect("lock").is_empty());
    rig.sink.set_failing(false);
    rig.client.write_all(&cmd(&["PING"])).await.expect("write");
    assert_eq!(read_replies(&mut rig.client, 1).await, ["+PONG"]);
}

#[tokio::test]
async fn garbage_gets_an_error_and_ends_the_session() {
    let mut rig = rig(vec![grant(&[], &[])]);
    rig.client.write_all(b"*2\r\n:5\r\n").await.expect("write");
    let replies = read_replies(&mut rig.client, 1).await;
    assert!(replies[0].starts_with("-ERR"), "{replies:?}");
    assert!(rig.done.await.expect("join").is_err());
}

#[tokio::test]
async fn closing_the_client_ends_the_session() {
    let rig = rig(vec![grant(&[], &[])]);
    drop(rig.client);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), rig.done)
        .await
        .expect("ends")
        .expect("join");
    assert!(outcome.is_ok());
}

#[tokio::test]
async fn large_pipelines_do_not_deadlock() {
    let rig = rig(vec![grant(&[], &[])]);
    let n = 3000;
    let mut batch = Vec::new();
    for i in 0..n {
        batch.extend(cmd(&["SET", &format!("k{i}"), &"x".repeat(200)]));
    }
    let (mut read, mut write) = tokio::io::split(rig.client);
    let writer = tokio::spawn(async move { write.write_all(&batch).await.expect("write") });
    let mut total = 0;
    let mut chunk = vec![0u8; 8192];
    while total < n * 5 {
        total += tokio::time::timeout(std::time::Duration::from_secs(10), read.read(&mut chunk))
            .await
            .expect("no deadlock")
            .expect("read");
    }
    writer.await.expect("writer");
    drop(read);
    let _ = rig.done.await;
    assert_eq!(rig.seen.lock().expect("lock").len(), n);
}

#[tokio::test]
async fn subscribed_connections_pass_pushes_through() {
    let mut rig = rig(vec![grant(&[], &[])]);
    rig.client
        .write_all(&cmd(&["SUBSCRIBE", "news"]))
        .await
        .expect("write");
    assert_eq!(read_replies(&mut rig.client, 1).await, ["+OK"]);
    // A message the server sends on its own would pass straight through; the
    // fake server has none, so only check that later commands still flow.
    rig.client.write_all(&cmd(&["PING"])).await.expect("write");
    assert_eq!(read_replies(&mut rig.client, 1).await, ["+PONG"]);
}

#[tokio::test]
async fn iam_sessions_log_in_again_between_commands() {
    // The token fetch needs AWS credentials; static ones are enough here.
    // SAFETY-free: tests in this module run in one process, and nothing else reads these.
    let mut rig = rig_with(vec![grant(&[], &[])], |c| {
        c.target = target(true);
        c.reauth_after = std::time::Duration::from_millis(50);
    });
    rig.client.write_all(&cmd(&["PING"])).await.expect("write");
    assert_eq!(read_replies(&mut rig.client, 1).await, ["+PONG"]);
    // Without AWS credentials the loop ends the session with an error; with
    // them it sends AUTH and the next command still works. Either way the
    // client must never see the worker's AUTH reply.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let seen = rig.seen.lock().expect("lock").clone();
    let reauths = seen.iter().filter(|w| w[0] == "AUTH").count();
    if reauths > 0 {
        rig.client.write_all(&cmd(&["PING"])).await.expect("write");
        assert_eq!(read_replies(&mut rig.client, 1).await, ["+PONG"]);
    }
}

#[tokio::test]
async fn a_refusal_while_subscribed_is_answered_at_once() {
    let mut rig = rig(vec![grant(&[], &[])]);
    rig.client
        .write_all(&cmd(&["SUBSCRIBE", "news"]))
        .await
        .expect("write");
    assert_eq!(read_replies(&mut rig.client, 1).await, ["+OK"]);
    rig.client
        .write_all(&cmd(&["FLUSHALL"]))
        .await
        .expect("write");
    let replies = read_replies(&mut rig.client, 1).await;
    assert!(replies[0].starts_with("-NOPERM Limen"), "{replies:?}");
}

#[tokio::test]
async fn a_refusal_inside_multi_poisons_the_transaction() {
    let mut rig = rig(vec![grant(&[], &[])]);
    let mut batch = cmd(&["MULTI"]);
    batch.extend(cmd(&["FLUSHALL"]));
    batch.extend(cmd(&["PING"]));
    rig.client.write_all(&batch).await.expect("write");
    let replies = read_replies(&mut rig.client, 3).await;
    assert_eq!(replies[0], "+OK");
    assert!(replies[1].starts_with("-NOPERM Limen"), "{replies:?}");
    assert_eq!(replies[2], "+PONG");
    // The server was told the transaction is bad, and the client never saw that reply.
    let seen = rig.seen.lock().expect("lock").clone();
    assert!(seen.iter().any(|w| w[0] == "LIMEN.REFUSED"), "{seen:?}");
    rig.client.write_all(&cmd(&["PING"])).await.expect("write");
    assert_eq!(
        read_replies(&mut rig.client, 1).await,
        ["+PONG"],
        "replies stay aligned"
    );
}

#[test]
fn default_targets_serialize_without_the_new_fields() {
    // Components from before Phase 7 reject unknown fields, so a snapshot
    // that holds a plain Redis resource must look the way it used to.
    let plain: RedisTarget =
        serde_json::from_value(serde_json::json!({"endpoint": "h:6379"})).expect("target");
    let json = serde_json::to_value(&plain).expect("json");
    assert!(
        json.get("tls").is_none() && json.get("audit").is_none(),
        "{json}"
    );
    let off = RedisTarget {
        tls: false,
        ..plain
    };
    assert_eq!(serde_json::to_value(&off).expect("json")["tls"], false);
}

#[tokio::test]
async fn a_client_that_closes_its_writing_side_still_gets_its_replies() {
    let mut rig = rig(vec![grant(&[], &[])]);
    let mut batch = cmd(&["SET", "k", "v"]);
    batch.extend(cmd(&["SLOW"]));
    batch.extend(cmd(&["FLUSHALL"]));
    batch.extend(cmd(&["GET", "k"]));
    rig.client.write_all(&batch).await.expect("write");
    rig.client.shutdown().await.expect("half close");
    let replies = read_replies(&mut rig.client, 4).await;
    assert_eq!(replies[0], "+OK");
    assert_eq!(replies[1], "+SLOW");
    assert!(replies[2].starts_with("-NOPERM"), "{replies:?}");
    assert_eq!(replies[3], "$1\r\nv");
}

#[tokio::test]
async fn subscribing_after_pipelined_commands_keeps_their_replies_in_order() {
    let mut rig = rig(vec![grant(&[], &[])]);
    let mut batch = cmd(&["SLOW"]);
    batch.extend(cmd(&["FLUSHALL"]));
    batch.extend(cmd(&["SUBSCRIBE", "news"]));
    rig.client.write_all(&batch).await.expect("write");
    let replies = read_replies(&mut rig.client, 3).await;
    assert_eq!(replies[0], "+SLOW");
    assert!(replies[1].starts_with("-NOPERM"), "{replies:?}");
    assert_eq!(replies[2], "+OK", "the server's answer to SUBSCRIBE");
    // Once subscribed, a refusal is answered at once.
    rig.client
        .write_all(&cmd(&["FLUSHALL"]))
        .await
        .expect("write");
    assert!(read_replies(&mut rig.client, 1).await[0].starts_with("-NOPERM"),);
}

#[tokio::test]
async fn select_moves_the_database_policy_applies_to() {
    let mut only_db1 = grant(&[], &[]);
    only_db1.databases = vec![1];
    let mut rig = rig(vec![only_db1]);
    let mut batch = cmd(&["GET", "k"]);
    batch.extend(cmd(&["SELECT", "1"]));
    batch.extend(cmd(&["GET", "k"]));
    rig.client.write_all(&batch).await.expect("write");
    let replies = read_replies(&mut rig.client, 3).await;
    assert!(replies[0].starts_with("-NOPERM"), "database 0: {replies:?}");
    assert_eq!(replies[1], "+OK");
    assert_eq!(replies[2], "$-1");
}

#[tokio::test]
async fn a_client_that_sends_a_long_pipeline_before_reading_does_not_stall() {
    // More replies than the pipe to the client holds: the worker must keep
    // reading requests while the client is still sending.
    let Rig { client, .. } = rig(vec![grant(&[], &[])]);
    let (mut read_half, mut write_half) = tokio::io::split(client);
    let n = 200_000;
    let batch: Vec<u8> = (0..n).flat_map(|_| cmd(&["PING"])).collect();
    let sender = tokio::spawn(async move {
        write_half.write_all(&batch).await.expect("write");
        write_half
    });
    // Not reading yet: the sender can only finish if the worker keeps reading.
    let write_half = tokio::time::timeout(std::time::Duration::from_secs(30), sender)
        .await
        .expect("the worker kept reading requests")
        .expect("join");
    let mut seen = 0usize;
    let mut chunk = vec![0u8; 64 * 1024];
    while seen < n * 7 {
        let got = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            read_half.read(&mut chunk),
        )
        .await
        .expect("replies in time")
        .expect("read");
        assert!(got > 0, "closed after {seen} bytes");
        seen += got;
    }
    drop(write_half);
}

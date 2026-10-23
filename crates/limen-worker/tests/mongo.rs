//! MongoDB sessions through the worker's relay (ADR-0035), against a real
//! MongoDB. Set `LIMEN_TEST_MONGO_TARGET=host:port` to a server started as
//! `scripts/ci-db-targets.sh` does (TLS, SCRAM, X.509; users and data
//! from `deploy/compose/config/targets/mongo/init.js`), with
//! `LIMEN_TEST_MONGO_CA_FILE` and `LIMEN_TEST_MONGO_CLIENT_PEM`. Without them
//! the tests print SKIPPED.
//!
//! The client here speaks the wire protocol with the worker's own codec, so
//! these tests check the relay; `mongosh` through the full stack is
//! `demos/demo-phase9.sh`.

use std::sync::Arc;
use std::time::Duration;

use limen_audit::{Emitter, FailureMode, MemorySink};
use limen_core::secret::Secret;
use limen_policy::Policy;
use limen_policy::model::MongoTarget;
use limen_worker::db::Target;
use limen_worker::mongo::bson::{Builder, Doc, Value};
use limen_worker::mongo::wire::{self, Header, MORE_TO_COME, OP_MSG};
use limen_worker::mongo::{
    Access, Login, Prepared, SessionConfig, Sha, UpstreamError, credentials, prepare, serve,
};
use tokio::io::DuplexStream;

struct Env {
    target: String,
    ca: String,
    client_pem: String,
}

fn env() -> Option<Env> {
    let target = std::env::var("LIMEN_TEST_MONGO_TARGET").ok();
    let ca = std::env::var("LIMEN_TEST_MONGO_CA_FILE").ok();
    let client_pem = std::env::var("LIMEN_TEST_MONGO_CLIENT_PEM").ok();
    match (target, ca, client_pem) {
        (Some(target), Some(ca), Some(client_pem)) => Some(Env {
            target,
            ca,
            client_pem,
        }),
        _ => {
            eprintln!(
                "SKIPPED: set LIMEN_TEST_MONGO_TARGET, LIMEN_TEST_MONGO_CA_FILE, and LIMEN_TEST_MONGO_CLIENT_PEM (see scripts/ci-db-targets.sh)"
            );
            None
        }
    }
}

const POLICY: &str = r#"
kind: role
version: v1
metadata: { name: dev }
spec:
  allow:
    - resources: { kind: [mongodb], labels: { "*": ["*"] } }
      mongo: { roles: [read, limen-x509], databases: [orders] }
    - resources: { kind: [mongodb], labels: { "*": ["*"] } }
      mongo: { roles: [write], databases: [orders], deny_commands: [dropDatabase] }
"#;

fn spec_json(env: &Env, creds: &std::path::Path, auth: &str) -> serde_json::Value {
    serde_json::json!({
        "endpoint": env.target,
        "auth": auth,
        "default_database": "orders",
        "credentials_dir": creds.to_str().expect("utf8"),
        "tls_ca_file": env.ca,
    })
}

fn policy_for(spec: &serde_json::Value) -> Arc<Policy> {
    // A resource document built from the same spec the worker is given.
    let resource =
        format!("kind: resource\nversion: v1\nmetadata: {{ name: m }}\nspec:\n  mongodb: {spec}\n");
    Arc::new(
        Policy::parse_yaml([("r.yaml", POLICY), ("m.yaml", resource.as_str())]).expect("policy"),
    )
}

struct Harness {
    sink: Arc<MemorySink>,
    client: Client,
    /// The relay's task, so a test can cancel the session from outside.
    relay: tokio::task::JoinHandle<()>,
    _creds: tempfile::TempDir,
}

struct Client {
    io: DuplexStream,
    next: i32,
}

impl Client {
    async fn send(&mut self, body: Vec<u8>) -> i32 {
        self.next += 1;
        let header = Header {
            request_id: self.next,
            response_to: 0,
            opcode: OP_MSG,
        };
        wire::write_message(&mut self.io, header, &body)
            .await
            .expect("send");
        self.next
    }

    async fn reply_to(&mut self, id: i32) -> Vec<u8> {
        let msg = tokio::time::timeout(Duration::from_secs(120), wire::read_message(&mut self.io))
            .await
            .expect("reply in time")
            .expect("read")
            .expect("a reply");
        assert_eq!(msg.header.response_to, id, "the reply answers this request");
        wire::parse_op_msg(&msg.body)
            .expect("op_msg")
            .command
            .as_bytes()
            .to_vec()
    }

    /// Send a command and return the reply document.
    async fn run(&mut self, doc: Vec<u8>) -> Vec<u8> {
        let id = self.send(wire::op_msg_body(&doc)).await;
        self.reply_to(id).await
    }

    /// Whether the worker has closed the session.
    async fn closed(&mut self) -> bool {
        matches!(
            tokio::time::timeout(Duration::from_secs(5), wire::read_message(&mut self.io)).await,
            Ok(Ok(None) | Err(_))
        )
    }
}

fn cmd(name: &str, value: &str, db: &str) -> Builder {
    Builder::new().str(name, value).str("$db", db)
}

fn ok(reply: &[u8]) -> bool {
    Doc::new(reply)
        .expect("doc")
        .get("ok")
        .expect("ok")
        .is_some_and(|v| v.is_truthy())
}

fn code(reply: &[u8]) -> Option<i64> {
    Doc::new(reply)
        .expect("doc")
        .get("code")
        .expect("code")
        .and_then(|v| v.as_i64())
}

async fn open(env: &Env, role: &str, auth: &str) -> Result<Harness, UpstreamError> {
    open_with(env, role, auth, serde_json::json!({})).await
}

async fn open_with(
    env: &Env,
    role: &str,
    auth: &str,
    extra: serde_json::Value,
) -> Result<Harness, UpstreamError> {
    let creds = tempfile::tempdir().expect("dir");
    std::fs::write(creds.path().join("read"), "limen-read-dev-only\n").expect("secret");
    std::fs::write(creds.path().join("write"), "limen-rw-dev-only\n").expect("secret");
    std::fs::copy(&env.client_pem, creds.path().join("limen-x509.pem")).expect("pem");
    let mut spec_value = spec_json(env, creds.path(), auth);
    if let (Some(m), Some(e)) = (spec_value.as_object_mut(), extra.as_object()) {
        m.extend(e.clone());
    }
    let spec: MongoTarget = serde_json::from_value(spec_value.clone()).expect("spec");
    let policy = policy_for(&spec_value);
    let aws = None;
    let (login, identity) = credentials(&spec, role, aws).await.expect("credentials");
    let target = Target::from_mongo(&spec, false, identity)
        .await
        .expect("target");
    let source = if auth == "x509" { "$external" } else { "admin" };
    let access = Access::new(policy, vec!["dev".into()], "m", role);
    let sink = Arc::new(MemorySink::default());
    let config = SessionConfig::new(
        uuid::Uuid::now_v7(),
        "dev@example.com".into(),
        "m".into(),
        role.into(),
        &spec,
    );
    let prepared: Prepared = prepare(config, &target, &login, source, access).await?;
    let (ours, theirs) = tokio::io::duplex(1024 * 1024);
    let emitter = Emitter::new("worker", "w1", sink.clone(), FailureMode::FailClosed);
    let relay = tokio::spawn(async move {
        let _ = serve(theirs, prepared, emitter).await;
    });
    Ok(Harness {
        sink,
        relay,
        client: Client { io: ours, next: 0 },
        _creds: creds,
    })
}

async fn session(env: &Env, role: &str) -> Harness {
    open(env, role, "scram").await.expect("open")
}

fn events(h: &Harness, kind: &str) -> Vec<serde_json::Value> {
    h.sink
        .events()
        .into_iter()
        .filter_map(|e| {
            let v = serde_json::to_value(&e).expect("json");
            (v["kind"] == kind).then_some(v)
        })
        .collect()
}

/// A root login for setup and checks outside the relay.
async fn admin(env: &Env) -> limen_worker::mongo::Upstream {
    let creds = tempfile::tempdir().expect("dir");
    let spec: MongoTarget =
        serde_json::from_value(spec_json(env, creds.path(), "scram")).expect("spec");
    let target = Target::from_mongo(&spec, false, None)
        .await
        .expect("target");
    limen_worker::mongo::upstream::connect(
        &target,
        &Login::Scram {
            sha: Sha::Sha256,
            user: "limen_admin".into(),
            password: Secret::new("limen-admin-dev-only".into()),
        },
        "admin",
        "limen-test-admin",
    )
    .await
    .expect("admin login")
}

#[tokio::test(flavor = "multi_thread")]
async fn commands_flow_and_every_command_is_audited() {
    let Some(env) = env() else { return };
    let mut h = session(&env, "read").await;

    // The handshake is answered by the worker.
    let hello = h
        .client
        .run(
            Builder::new()
                .i32("hello", 1)
                .bool("helloOk", true)
                .str("$db", "admin")
                .finish(),
        )
        .await;
    let d = Doc::new(&hello).expect("doc");
    assert!(ok(&hello));
    assert_eq!(
        d.get("isWritablePrimary").expect("ok"),
        Some(Value::Bool(true))
    );
    assert!(
        d.get("setName").expect("ok").is_none(),
        "presented as standalone"
    );
    assert!(
        d.get("compression").expect("ok").is_none(),
        "no compression is offered"
    );

    // The session is logged in as the role, by the worker.
    let status = h
        .client
        .run(
            Builder::new()
                .i32("connectionStatus", 1)
                .str("$db", "admin")
                .finish(),
        )
        .await;
    let d = Doc::new(&status).expect("doc");
    let Some(Value::Doc(info)) = d.get("authInfo").expect("ok") else {
        panic!("no authInfo");
    };
    let Some(Value::Array(users)) = info.get("authenticatedUsers").expect("ok") else {
        panic!("no users");
    };
    let Some(Ok((_, Value::Doc(user)))) = users.iter().next() else {
        panic!("no user");
    };
    assert_eq!(user.get("user").expect("ok"), Some(Value::Str("read")));

    // A real query comes back whole.
    let found = h
        .client
        .run(
            cmd("find", "customers", "orders")
                .doc("filter", &Builder::new().str("tier", "silver"))
                .finish(),
        )
        .await;
    assert!(ok(&found));
    let d = Doc::new(&found).expect("doc");
    let Some(Value::Doc(cursor)) = d.get("cursor").expect("ok") else {
        panic!("no cursor");
    };
    let Some(Value::Array(batch)) = cursor.get("firstBatch").expect("ok") else {
        panic!("no batch");
    };
    assert_eq!(batch.iter().count(), 2);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let commands = events(&h, "mongo.command");
    let names: Vec<_> = commands
        .iter()
        .filter_map(|e| e["data"]["command"].as_str())
        .collect();
    assert_eq!(
        names,
        ["connectionStatus", "find"],
        "the handshake is not audited"
    );
    let find = &commands[1];
    assert_eq!(find["user"], "dev@example.com");
    assert_eq!(find["data"]["mongo_role"], "read");
    assert_eq!(find["data"]["database"], "orders");
    assert_eq!(find["data"]["collection"], "customers");
    assert_eq!(find["data"]["summary"], r#"{"filter":{"tier":"?"}}"#);
    assert_eq!(find["data"]["redacted"], true);

    let ends = events(&h, "mongo.command.end");
    let end = ends
        .iter()
        .find(|e| e["data"]["command_id"] == find["event_id"])
        .expect("end");
    assert_eq!(end["data"]["status"], "ok");
    assert_eq!(end["data"]["docs"], 2);
    assert_every_command_has_one_end(&h).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn values_never_reach_the_audit_trail_by_default() {
    let Some(env) = env() else { return };
    let mut h = session(&env, "write").await;
    let marker = "4111-1111-1111-1111";
    let mut admin = admin(&env).await;
    // A run that died before its cleanup must not poison this one.
    let _ = admin
        .run(cmd("drop", "audit_test", "orders").finish())
        .await;

    // An insert: the document travels in a document sequence and is only counted.
    let insert = |doc: &[u8]| {
        let command = cmd("insert", "audit_test", "orders").finish();
        let mut body = 0u32.to_le_bytes().to_vec();
        body.push(0);
        body.extend_from_slice(&command);
        body.push(1);
        let mut section = b"documents\0".to_vec();
        section.extend_from_slice(doc);
        body.extend_from_slice(&(i32::try_from(section.len() + 4).expect("len")).to_le_bytes());
        body.extend_from_slice(&section);
        body
    };
    let doc = Builder::new()
        .str("_id", marker)
        .str("customer", "Zed")
        .finish();
    let id = h.client.send(insert(&doc)).await;
    let reply = h.client.reply_to(id).await;
    assert!(ok(&reply));
    assert_eq!(
        Doc::new(&reply)
            .expect("doc")
            .get("n")
            .expect("ok")
            .and_then(|v| v.as_i64()),
        Some(1)
    );

    // A filter that names the same value.
    let found = h
        .client
        .run(
            cmd("find", "audit_test", "orders")
                .doc("filter", &Builder::new().str("_id", marker))
                .finish(),
        )
        .await;
    assert!(ok(&found));

    // The same _id again: the server's error quotes the value ("dup key: ...").
    // The client gets it; the audit trail keeps only the code.
    let id = h.client.send(insert(&doc)).await;
    let reply = h.client.reply_to(id).await;
    assert!(ok(&reply), "a write error is reported in writeErrors");
    assert!(
        String::from_utf8_lossy(&reply).contains(marker),
        "the client does see the server's message"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    let everything = h
        .sink
        .events()
        .into_iter()
        .map(|e| serde_json::to_string(&e).expect("json"))
        .collect::<String>();
    assert!(
        !everything.contains(marker),
        "a value reached the audit trail"
    );
    assert!(!everything.contains("Zed"));
    let inserts = events(&h, "mongo.command");
    let insert = inserts
        .iter()
        .find(|e| e["data"]["command"] == "insert")
        .expect("insert");
    assert_eq!(insert["data"]["summary"], r#"{"documents":{"count":1}}"#);
    let failed: Vec<_> = events(&h, "mongo.command.end")
        .into_iter()
        .filter(|e| e["data"]["status"] == "error")
        .collect();
    assert_eq!(failed.len(), 1, "the duplicate key");
    assert_eq!(failed[0]["data"]["error_code"], 11000);
    assert_eq!(failed[0]["data"]["write_errors"], 1);

    let _ = admin
        .run(cmd("drop", "audit_test", "orders").finish())
        .await;
    assert_every_command_has_one_end(&h).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_database_policy_does_not_grant_is_refused_and_audited() {
    let Some(env) = env() else { return };
    let mut h = session(&env, "read").await;

    let denied = h
        .client
        .run(cmd("find", "ledger", "billing").finish())
        .await;
    assert!(!ok(&denied));
    assert_eq!(code(&denied), Some(13));
    // The session goes on: a refused command is an error reply, not a disconnect.
    let fine = h
        .client
        .run(cmd("find", "customers", "orders").finish())
        .await;
    assert!(ok(&fine));

    // `admin` metadata passes; admin changes don't.
    let ping = h
        .client
        .run(Builder::new().i32("ping", 1).str("$db", "admin").finish())
        .await;
    assert!(ok(&ping));
    let create = h
        .client
        .run(
            Builder::new()
                .str("createUser", "mallory")
                .str("pwd", "x")
                .str("$db", "admin")
                .finish(),
        )
        .await;
    assert_eq!(code(&create), Some(13));

    tokio::time::sleep(Duration::from_millis(200)).await;
    let refused: Vec<_> = events(&h, "mongo.command")
        .into_iter()
        .filter(|e| e["data"]["phase"] == "refused")
        .collect();
    assert_eq!(refused.len(), 2);
    assert_eq!(refused[0]["data"]["command"], "find");
    assert_eq!(refused[0]["data"]["database"], "billing");
    assert_eq!(refused[0]["data"]["reason"], "database_not_granted");
    assert_eq!(refused[1]["data"]["command"], "createUser");
    assert_every_command_has_one_end(&h).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_servers_own_grants_still_apply_inside_a_database() {
    let Some(env) = env() else { return };
    let mut h = session(&env, "read").await;
    // `read` has the read role on orders: the server refuses the write,
    // and the audit trail says so.
    let doc = Builder::new().str("x", "y").finish();
    let command = cmd("insert", "customers", "orders").finish();
    let mut body = 0u32.to_le_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(&command);
    body.push(1);
    let mut section = b"documents\0".to_vec();
    section.extend_from_slice(&doc);
    body.extend_from_slice(&(i32::try_from(section.len() + 4).expect("len")).to_le_bytes());
    body.extend_from_slice(&section);
    let id = h.client.send(body).await;
    let reply = h.client.reply_to(id).await;
    assert!(!ok(&reply));
    assert_eq!(code(&reply), Some(13), "the server's Unauthorized");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let ends = events(&h, "mongo.command.end");
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0]["data"]["status"], "error");
    assert_eq!(ends[0]["data"]["error_code"], 13);
    assert_eq!(ends[0]["data"]["error_code_name"], "Unauthorized");
    assert!(
        ends[0]["data"].get("error").is_none(),
        "error text is kept only when the resource keeps values"
    );
    assert_every_command_has_one_end(&h).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn deny_commands_in_a_grant_are_enforced() {
    let Some(env) = env() else { return };
    let mut h = session(&env, "write").await;
    let r = h
        .client
        .run(cmd("dropDatabase", "1", "orders").finish())
        .await;
    assert_eq!(code(&r), Some(13));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let refused = events(&h, "mongo.command");
    assert_eq!(refused[0]["data"]["reason"], "command_denied");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_cannot_log_in_as_someone_else() {
    let Some(env) = env() else { return };
    let mut h = session(&env, "read").await;
    for name in ["authenticate", "saslStart", "logout"] {
        let r = h
            .client
            .run(Builder::new().i32(name, 1).str("$db", "admin").finish())
            .await;
        assert_eq!(code(&r), Some(18), "{name}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cursors_stay_with_the_session_that_opened_them() {
    let Some(env) = env() else { return };
    let mut a = session(&env, "read").await;
    let mut b = session(&env, "read").await;

    let first = a
        .client
        .run(
            cmd("find", "customers", "orders")
                .i32("batchSize", 1)
                .finish(),
        )
        .await;
    let d = Doc::new(&first).expect("doc");
    let Some(Value::Doc(cursor)) = d.get("cursor").expect("ok") else {
        panic!("no cursor");
    };
    let id = cursor
        .get("id")
        .expect("ok")
        .and_then(|v| v.as_i64())
        .expect("id");
    assert_ne!(id, 0);

    let get_more = |id: i64| {
        Builder::new()
            .i64("getMore", id)
            .str("collection", "customers")
            .i32("batchSize", 5)
            .str("$db", "orders")
            .finish()
    };
    // Another session using the same server login can't read it.
    let stolen = b.client.run(get_more(id)).await;
    assert_eq!(code(&stolen), Some(43));
    // The owner can, and finishes it.
    let rest = a.client.run(get_more(id)).await;
    assert!(ok(&rest));
    let again = a.client.run(get_more(id)).await;
    assert_eq!(code(&again), Some(43), "a finished cursor is forgotten");
}

#[tokio::test(flavor = "multi_thread")]
async fn x509_login_uses_the_certificate() {
    let Some(env) = env() else { return };
    let mut h = open(&env, "limen-x509", "x509").await.expect("x509 login");
    let status = h
        .client
        .run(
            Builder::new()
                .i32("connectionStatus", 1)
                .str("$db", "admin")
                .finish(),
        )
        .await;
    let d = Doc::new(&status).expect("doc");
    let Some(Value::Doc(info)) = d.get("authInfo").expect("ok") else {
        panic!("no authInfo");
    };
    let Some(Value::Array(users)) = info.get("authenticatedUsers").expect("ok") else {
        panic!("no users");
    };
    let Some(Ok((_, Value::Doc(user)))) = users.iter().next() else {
        panic!("no user");
    };
    assert_eq!(
        user.get("user").expect("ok"),
        Some(Value::Str("CN=limen-x509,O=Limen"))
    );
    assert_eq!(user.get("db").expect("ok"), Some(Value::Str("$external")));
    let found = h
        .client
        .run(cmd("find", "customers", "orders").finish())
        .await;
    assert!(ok(&found));
}

#[tokio::test(flavor = "multi_thread")]
async fn scram_sha1_login_works_for_servers_without_sha256() {
    let Some(env) = env() else { return };
    let mut h = open(&env, "read", "scram_sha1").await.expect("sha1 login");
    let found = h
        .client
        .run(cmd("find", "customers", "orders").finish())
        .await;
    assert!(ok(&found));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_password_fails_before_the_session_opens() {
    let Some(env) = env() else { return };
    let creds = tempfile::tempdir().expect("dir");
    std::fs::write(creds.path().join("read"), "not-the-password\n").expect("secret");
    let spec: MongoTarget =
        serde_json::from_value(spec_json(&env, creds.path(), "scram")).expect("spec");
    let (login, _) = credentials(&spec, "read", None).await.expect("credentials");
    let target = Target::from_mongo(&spec, false, None)
        .await
        .expect("target");
    let err = limen_worker::mongo::upstream::connect(&target, &login, "admin", "t")
        .await
        .expect_err("login must fail");
    assert!(
        err.to_string().contains("Authentication failed")
            || err.to_string().contains("AuthenticationFailed"),
        "{err}"
    );
    assert!(!err.to_string().contains("not-the-password"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unacknowledged_write_gets_no_reply_and_the_session_goes_on() {
    let Some(env) = env() else { return };
    let mut h = session(&env, "write").await;
    let mut admin = admin(&env).await;
    let _ = admin
        .run(cmd("drop", "unack_test", "orders").finish())
        .await;

    let doc = Builder::new().str("n", "fire-and-forget").finish();
    let command = cmd("insert", "unack_test", "orders")
        .doc("writeConcern", &Builder::new().i32("w", 0))
        .finish();
    let mut body = MORE_TO_COME.to_le_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(&command);
    body.push(1);
    let mut section = b"documents\0".to_vec();
    section.extend_from_slice(&doc);
    body.extend_from_slice(&(i32::try_from(section.len() + 4).expect("len")).to_le_bytes());
    body.extend_from_slice(&section);
    h.client.send(body).await;

    // The next command is answered normally: nothing is out of step.
    let ping = h
        .client
        .run(Builder::new().i32("ping", 1).str("$db", "admin").finish())
        .await;
    assert!(ok(&ping));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let ends = events(&h, "mongo.command.end");
    assert!(
        ends.iter().any(|e| e["data"]["status"] == "unacknowledged"),
        "{ends:?}"
    );
    let _ = admin
        .run(cmd("drop", "unack_test", "orders").finish())
        .await;
    assert_every_command_has_one_end(&h).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_command_that_cannot_be_audited_does_not_run() {
    let Some(env) = env() else { return };
    let mut h = session(&env, "read").await;
    let ok_first = h
        .client
        .run(cmd("find", "customers", "orders").finish())
        .await;
    assert!(ok(&ok_first));

    // The outcome of the first command is written just after its reply; wait
    // for it so the failure below is about the second command.
    for _ in 0..100 {
        if !events(&h, "mongo.command.end").is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    h.sink.set_failing(true);
    let refused = h
        .client
        .run(cmd("find", "customers", "orders").finish())
        .await;
    assert!(!ok(&refused));
    assert_eq!(code(&refused), Some(8000));
    assert!(
        h.client.closed().await,
        "the session ends when the trail is down"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_legacy_handshake_still_works() {
    let Some(env) = env() else { return };
    let mut h = session(&env, "read").await;
    let query = Builder::new()
        .i32("isMaster", 1)
        .bool("helloOk", true)
        .finish();
    let mut body = 0i32.to_le_bytes().to_vec();
    body.extend_from_slice(b"admin.$cmd\0");
    body.extend_from_slice(&0i32.to_le_bytes());
    body.extend_from_slice(&(-1i32).to_le_bytes());
    body.extend_from_slice(&query);
    let header = Header {
        request_id: 5,
        response_to: 0,
        opcode: wire::OP_QUERY,
    };
    wire::write_message(&mut h.client.io, header, &body)
        .await
        .expect("send");
    let reply = wire::read_message(&mut h.client.io)
        .await
        .expect("read")
        .expect("reply");
    assert_eq!(reply.header.opcode, wire::OP_REPLY);
    assert_eq!(reply.header.response_to, 5);
    let doc = Doc::new(&reply.body[20..]).expect("doc");
    assert_eq!(doc.get("ismaster").expect("ok"), Some(Value::Bool(true)));
    assert_eq!(doc.get("helloOk").expect("ok"), Some(Value::Bool(true)));
    // And it is only for the handshake.
    let bad = Builder::new().str("find", "customers").finish();
    let mut body = 0i32.to_le_bytes().to_vec();
    body.extend_from_slice(b"orders.customers\0");
    body.extend_from_slice(&0i32.to_le_bytes());
    body.extend_from_slice(&(-1i32).to_le_bytes());
    body.extend_from_slice(&bad);
    wire::write_message(&mut h.client.io, header, &body)
        .await
        .expect("send");
    assert!(h.client.closed().await);
}

#[tokio::test(flavor = "multi_thread")]
async fn pipelines_stay_in_the_granted_databases() {
    let Some(env) = env() else { return };
    let mut h = session(&env, "read").await;
    let aggregate = |stages: &[Vec<u8>]| {
        cmd("aggregate", "customers", "orders")
            .docs_array("pipeline", stages)
            .doc("cursor", &Builder::new())
            .finish()
    };
    let target = |db: &str, coll: &str| Builder::new().str("db", db).str("coll", coll);

    // A join inside the granted database runs.
    let join = Builder::new()
        .doc(
            "$lookup",
            &Builder::new()
                .str("from", "invoices")
                .str("localField", "name")
                .str("foreignField", "customer")
                .str("as", "invoices"),
        )
        .finish();
    let ok_reply = h.client.run(aggregate(&[join])).await;
    assert!(
        ok(&ok_reply),
        "a same-database $lookup is the server's call"
    );

    // The same join, or a write, aimed at another database never leaves the worker.
    let across = Builder::new()
        .doc(
            "$lookup",
            &Builder::new()
                .doc("from", &target("billing", "ledger"))
                .str("localField", "name")
                .str("foreignField", "entry")
                .str("as", "ledger"),
        )
        .finish();
    let denied = h.client.run(aggregate(&[across])).await;
    assert_eq!(code(&denied), Some(13));
    let out = Builder::new()
        .doc("$out", &target("billing", "stolen"))
        .finish();
    let denied = h.client.run(aggregate(&[out])).await;
    assert_eq!(code(&denied), Some(13));

    tokio::time::sleep(Duration::from_millis(200)).await;
    let refused: Vec<_> = events(&h, "mongo.command")
        .into_iter()
        .filter(|e| e["data"]["phase"] == "refused")
        .collect();
    assert_eq!(refused.len(), 2);
    assert_eq!(refused[0]["data"]["reason"], "database_not_granted");
    assert_eq!(refused[0]["data"]["command"], "aggregate");
}

/// The invariant the audit trail promises: every command that was forwarded
/// has exactly one end event, and every end event names a forwarded command.
async fn assert_every_command_has_one_end(h: &Harness) {
    // Ends are written just after the reply, and a cancelled command's from a task.
    for _ in 0..100 {
        let forwarded = events(h, "mongo.command")
            .iter()
            .filter(|e| e["data"]["phase"] == "forward")
            .count();
        if events(h, "mongo.command.end").len() >= forwarded {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut forwarded: Vec<_> = events(h, "mongo.command")
        .iter()
        .filter(|e| e["data"]["phase"] == "forward")
        .map(|e| e["event_id"].to_string())
        .collect();
    let mut ended: Vec<_> = events(h, "mongo.command.end")
        .iter()
        .map(|e| e["data"]["command_id"].to_string())
        .collect();
    forwarded.sort();
    ended.sort();
    assert_eq!(forwarded, ended, "one end event per forwarded command");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_cancelled_mid_command_records_that_it_did_not_complete() {
    let Some(env) = env() else { return };
    let mut h = session(&env, "read").await;
    let ok_reply = h
        .client
        .run(cmd("find", "customers", "orders").finish())
        .await;
    assert!(ok(&ok_reply));

    // A command the server holds for a few seconds, then the session is cut:
    // what a lock, a kill, a drain, or the TTL does.
    let slow = cmd("find", "customers", "orders")
        .doc(
            "filter",
            &Builder::new().str("$where", "sleep(4000) || true"),
        )
        .finish();
    h.client.send(wire::op_msg_body(&slow)).await;
    for _ in 0..100 {
        if events(&h, "mongo.command").len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    h.relay.abort();
    let _ = (&mut h.relay).await;

    assert_every_command_has_one_end(&h).await;
    let ends = events(&h, "mongo.command.end");
    assert_eq!(ends.len(), 2);
    let statuses: Vec<_> = ends
        .iter()
        .map(|e| e["data"]["status"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(
        statuses.contains(&"ok".to_owned()) && statuses.contains(&"not_completed".to_owned()),
        "{statuses:?}"
    );
    // The shape of the cancelled command is in the trail, without its code.
    let started = events(&h, "mongo.command");
    assert!(
        started
            .iter()
            .any(|e| e["data"]["summary"] == r#"{"filter":{"$where":"?"}}"#)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mixed_session_leaves_one_end_per_command() {
    let Some(env) = env() else { return };
    let mut h = session(&env, "read").await;
    let admin_ping = Builder::new().i32("ping", 1).str("$db", "admin").finish();
    // ok, server error, refused (no end event), a cursor, and a bad command.
    for command in [
        cmd("find", "customers", "orders").finish(),
        cmd("find", "ledger", "billing").finish(),
        cmd("insert", "customers", "orders").finish(),
        admin_ping,
        cmd("find", "customers", "orders")
            .i32("batchSize", 1)
            .finish(),
        Builder::new()
            .str("nonsense", "x")
            .str("$db", "orders")
            .finish(),
    ] {
        let _ = h.client.run(command).await;
    }
    assert_every_command_has_one_end(&h).await;
    let refused = events(&h, "mongo.command")
        .iter()
        .filter(|e| e["data"]["phase"] == "refused")
        .count();
    assert_eq!(refused, 1, "refusals have no end event");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_in_a_loop_is_paced_instead_of_flooding_the_trail() {
    let Some(env) = env() else { return };
    // 20 commands a second after a burst of 100.
    let mut h = open_with(
        &env,
        "read",
        "scram",
        serde_json::json!({ "max_commands_per_second": 20 }),
    )
    .await
    .expect("open");
    let ping = || Builder::new().i32("ping", 1).str("$db", "admin").finish();
    let started = std::time::Instant::now();
    for _ in 0..100 {
        assert!(ok(&h.client.run(ping()).await));
    }
    let burst = started.elapsed();
    let after = std::time::Instant::now();
    for _ in 0..40 {
        assert!(ok(&h.client.run(ping()).await));
    }
    // 40 more at 20 a second take about two seconds; none is refused or lost.
    assert!(
        after.elapsed() >= Duration::from_millis(1_800),
        "{:?}",
        after.elapsed()
    );
    assert!(
        burst < after.elapsed() * 3,
        "the burst was not paced: {burst:?}"
    );
    assert_every_command_has_one_end(&h).await;
    assert_eq!(events(&h, "mongo.command").len(), 140);
}

//! Phase 9 end to end: a MongoDB client reaches a MongoDB target through the
//! proxy and the worker, with no credentials, a redacted audit record for
//! every command, and the denials and locks of the earlier phases (ADR-0035).
//!
//! Needs `LIMEN_TEST_DATABASE_URL` (control plane state) and the MongoDB
//! target of `scripts/ci-db-targets.sh`: `LIMEN_TEST_MONGO_TARGET`,
//! `LIMEN_TEST_MONGO_CA_FILE`.

use std::collections::HashMap;
use std::time::Duration;

use limen_e2e::{Deployment, db_client, eventually};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, CreateJoinTokenRequest, LockUserRequest, PolicySource};
use limen_testkit::users::{ADMIN, DEVELOPER};
use limen_worker::mongo::bson::{Builder, Doc, Value};
use limen_worker::mongo::wire::{self, Header, OP_MSG};
use tokio::net::TcpStream;

fn policy(target: &str, ca: &str, creds: &str) -> Vec<PolicySource> {
    let yaml = format!(
        r#"
kind: role
version: v1
metadata: {{ name: analysts }}
spec:
  allow:
    - resources: {{ kind: [mongodb], labels: {{ env: [test] }} }}
      mongo: {{ roles: [read], databases: [orders] }}
---
kind: role_mapping
version: v1
metadata: {{ name: idp }}
spec:
  - {{ idp_group: analysts, roles: [analysts] }}
---
kind: resource
version: v1
metadata: {{ name: catalog-test, labels: {{ env: test }} }}
spec:
  mongodb:
    endpoint: "{target}"
    default_database: orders
    credentials_dir: "{creds}"
    tls_ca_file: "{ca}"
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

struct Client {
    io: TcpStream,
    next: i32,
}

impl Client {
    async fn run(&mut self, doc: Vec<u8>) -> Vec<u8> {
        self.next += 1;
        let header = Header {
            request_id: self.next,
            response_to: 0,
            opcode: OP_MSG,
        };
        wire::write_message(&mut self.io, header, &wire::op_msg_body(&doc))
            .await
            .expect("send");
        let msg = wire::read_message(&mut self.io)
            .await
            .expect("read")
            .expect("a reply");
        wire::parse_op_msg(&msg.body)
            .expect("op_msg")
            .command
            .as_bytes()
            .to_vec()
    }
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

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread")]
async fn mongodb_through_limen() {
    let (Ok(target), Ok(ca)) = (
        std::env::var("LIMEN_TEST_MONGO_TARGET"),
        std::env::var("LIMEN_TEST_MONGO_CA_FILE"),
    ) else {
        eprintln!("SKIPPED: set LIMEN_TEST_MONGO_TARGET and LIMEN_TEST_MONGO_CA_FILE");
        return;
    };
    let Some(d) = Deployment::start().await else {
        return;
    };
    let creds = d.dir.path().join("mongo-creds");
    std::fs::create_dir_all(&creds).expect("dir");
    std::fs::write(creds.join("read"), "limen-read-dev-only\n").expect("secret");

    let ca_pem = std::fs::read_to_string(d.ca_file()).expect("ca");
    let proxy_addr = d.proxy_addr.to_string();
    let admin_user = d.login(ADMIN, &["admins"]).await.expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(admin_user)));
    let applied = admin
        .apply_policy(ApplyPolicyRequest {
            sources: policy(&target, &ca, creds.to_str().expect("utf8")),
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
    let worker = d.start_worker(&token, "worker").await;
    eventually(Duration::from_secs(15), "worker and policy", || async {
        d.proxy().tunnels.summaries().len() == 2
            && d.proxy().policy_version() == Some(applied.version)
            && worker.worker.policy_version() == Some(applied.version)
    })
    .await;

    // An analyst connects with no credentials and queries.
    let analyst = d.login(DEVELOPER, &["analysts"]).await.expect("analyst");
    let (addr, refused) = db_client::listen_on(
        &proxy_addr,
        &ca_pem,
        analyst.clone(),
        limen_tunnel::alpn::MONGO,
        "catalog-test",
        "read",
        "orders",
    )
    .await;
    let mut c = Client {
        io: TcpStream::connect(addr)
            .await
            .expect("connect through Limen"),
        next: 0,
    };
    let hello = c
        .run(Builder::new().i32("hello", 1).str("$db", "admin").finish())
        .await;
    assert!(ok(&hello));
    let found = c
        .run(
            Builder::new()
                .str("find", "customers")
                .doc("filter", &Builder::new().str("email", "ada@example.com"))
                .str("$db", "orders")
                .finish(),
        )
        .await;
    assert!(ok(&found));
    let d1 = Doc::new(&found).expect("doc");
    let Some(Value::Doc(cursor)) = d1.get("cursor").expect("ok") else {
        panic!("no cursor");
    };
    let Some(Value::Array(batch)) = cursor.get("firstBatch").expect("ok") else {
        panic!("no batch");
    };
    assert_eq!(batch.iter().count(), 1);
    // The worker refuses another database; the role's server grants refuse a write.
    let other = c
        .run(
            Builder::new()
                .str("find", "ledger")
                .str("$db", "billing")
                .finish(),
        )
        .await;
    assert_eq!(code(&other), Some(13));
    assert!(refused.lock().expect("lock").is_empty());

    // A role policy doesn't grant is refused at the proxy and audited, with
    // nothing sent to the server. So is a database it doesn't grant.
    let (bad_addr, bad_refused) = db_client::listen_on(
        &proxy_addr,
        &ca_pem,
        analyst.clone(),
        limen_tunnel::alpn::MONGO,
        "catalog-test",
        "limen_admin",
        "orders",
    )
    .await;
    let _ = TcpStream::connect(bad_addr).await;
    let (other_addr, other_refused) = db_client::listen_on(
        &proxy_addr,
        &ca_pem,
        analyst.clone(),
        limen_tunnel::alpn::MONGO,
        "catalog-test",
        "read",
        "billing",
    )
    .await;
    let _ = TcpStream::connect(other_addr).await;
    // A MongoDB resource is not reachable over the SQL protocol's ALPN.
    let (wrong_addr, wrong_refused) = db_client::listen(
        &proxy_addr,
        &ca_pem,
        analyst.clone(),
        "catalog-test",
        "read",
        "orders",
    )
    .await;
    let _ = TcpStream::connect(wrong_addr).await;
    eventually(Duration::from_secs(5), "refusals recorded", || async {
        !bad_refused.lock().expect("lock").is_empty()
            && !other_refused.lock().expect("lock").is_empty()
            && !wrong_refused.lock().expect("lock").is_empty()
    })
    .await;
    assert!(bad_refused.lock().expect("lock")[0].contains("access denied"));

    // The trail: session.start, commands, ends, and denials.
    eventually(
        Duration::from_secs(20),
        "mongo events in the trail",
        || async {
            let events = read_jsonl(&d);
            events
                .iter()
                .filter(|e| e["kind"] == "mongo.command.end")
                .count()
                >= 1
                && events
                    .iter()
                    .filter(|e| e["kind"] == "mongo.command" && e["data"]["phase"] == "refused")
                    .count()
                    >= 1
                && events.iter().filter(|e| e["kind"] == "auth.denied").count() >= 2
        },
    )
    .await;
    let events = read_jsonl(&d);
    let start = events
        .iter()
        .find(|e| e["kind"] == "session.start" && e["data"]["kind"] == "mongodb")
        .expect("session.start");
    assert_eq!(start["user"], DEVELOPER);
    assert_eq!(start["data"]["database"], "orders");
    assert_eq!(start["data"]["mongo_role"], "read");
    let find = events
        .iter()
        .find(|e| {
            e["kind"] == "mongo.command"
                && e["data"]["command"] == "find"
                && e["data"]["phase"] == "forward"
        })
        .expect("mongo.command find");
    assert_eq!(find["producer"]["component"], "worker");
    assert_eq!(find["data"]["summary"], r#"{"filter":{"email":"?"}}"#);
    assert_eq!(
        find["session_id"], start["session_id"],
        "linked to the proxy session by id"
    );
    assert!(events.iter().any(|e| e["kind"] == "mongo.command.end"
        && e["data"]["command_id"] == find["event_id"]
        && e["data"]["status"] == "ok"
        && e["data"]["docs"] == 1));
    assert!(events.iter().any(|e| e["kind"] == "mongo.command"
        && e["data"]["phase"] == "refused"
        && e["data"]["database"] == "billing"));
    let denials: Vec<_> = events
        .iter()
        .filter(|e| e["kind"] == "auth.denied")
        .collect();
    let action = |name: &str| {
        denials
            .iter()
            .filter(|e| e["data"]["action"] == name)
            .count()
    };
    assert_eq!(
        action("mongo"),
        2,
        "the unlisted role and the ungranted database"
    );
    assert_eq!(
        action("db"),
        1,
        "the MongoDB resource over the SQL protocol"
    );
    assert_eq!(denials.len(), 3);
    let everything = serde_json::to_string(&events).expect("json");
    assert!(!everything.contains("limen-read-dev-only"));
    assert!(
        !everything.contains("ada@example.com"),
        "values stay out of the trail"
    );

    // Locking the analyst ends the open session at once.
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
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let ping = Builder::new().i32("ping", 1).str("$db", "admin").finish();
        c.next += 1;
        let header = Header {
            request_id: c.next,
            response_to: 0,
            opcode: OP_MSG,
        };
        let sent = wire::write_message(&mut c.io, header, &wire::op_msg_body(&ping)).await;
        let answered = matches!(wire::read_message(&mut c.io).await, Ok(Some(_)));
        if sent.is_err() || !answered {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the open session should end when the user is locked"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    worker.stop().await;
}

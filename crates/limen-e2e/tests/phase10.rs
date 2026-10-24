//! Phase 10 end to end: an HTTP client reaches a search server through the
//! proxy and the worker with no credential, policy is enforced by method
//! class and index pattern, every request is audited, and a lock ends the
//! session (ADR-0036).
//!
//! Needs `LIMEN_TEST_DATABASE_URL` (control plane state). The search server
//! is a small in-process stand-in (the real engines are exercised by
//! `demos/demo-phase10.sh`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use limen_e2e::{Deployment, db_client, eventually};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, CreateJoinTokenRequest, LockUserRequest, PolicySource};
use limen_testkit::users::{ADMIN, DEVELOPER};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SECRET_DOC: &str = "classified-salary-data";

/// What the stand-in server saw: request line and `Authorization` header.
type Seen = Arc<Mutex<Vec<(String, String)>>>;

/// A minimal HTTP/1.1 server: reads each request with its body and answers
/// with a fixed JSON body, keeping the connection open.
async fn fake_engine() -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let seen: Seen = Arc::default();
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let head_end = loop {
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                    let length: usize = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    while buf.len() < head_end + length {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    buf.drain(..head_end + length);
                    let line = head.lines().next().unwrap_or_default().to_owned();
                    let auth = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .starts_with("authorization:")
                                .then(|| l.to_owned())
                        })
                        .unwrap_or_default();
                    log.lock().expect("lock").push((line, auth));
                    let body = r#"{"took":1,"hits":{"total":{"value":1},"hits":[{"_id":"1"}]}}"#;
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nx-elastic-product: Elasticsearch\r\ncontent-length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if stream.write_all(reply.as_bytes()).await.is_err() {
                        return;
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
metadata: {{ name: searchers }}
spec:
  allow:
    - resources: {{ kind: [elasticsearch], labels: {{ env: [test] }} }}
      search: {{ roles: [read], indices: ["app-*"] }}
---
kind: role_mapping
version: v1
metadata: {{ name: idp }}
spec:
  - {{ idp_group: searchers, roles: [searchers] }}
---
kind: resource
version: v1
metadata: {{ name: logs-test, labels: {{ env: test }} }}
spec:
  elasticsearch:
    endpoint: "{target}"
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

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread")]
async fn search_through_limen() {
    let Some(d) = Deployment::start().await else {
        return;
    };
    let (target, seen) = fake_engine().await;
    let creds = d.dir.path().join("search-credentials.json");
    std::fs::write(
        &creds,
        r#"{"logs-test": {"read": {"basic": {"username": "limen", "password": "worker-held-pw"}}}}"#,
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
            &[&format!("--search-credentials-file={}", creds.display())],
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

    // A developer connects with no credential and searches.
    let dev = d.login(DEVELOPER, &["searchers"]).await.expect("developer");
    let (addr, refused) = db_client::listen_on(
        &proxy_addr,
        &ca_pem,
        dev.clone(),
        limen_tunnel::alpn::SEARCH,
        "logs-test",
        "read",
        "",
    )
    .await;
    let http = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client");
    let base = format!("http://{addr}");
    let r = http
        .post(format!("{base}/app-1/_search?size=1"))
        .header("authorization", "Bearer the-clients-own-token")
        .json(&serde_json::json!({"query": {"match_all": {}}, "note": SECRET_DOC}))
        .send()
        .await
        .expect("search");
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.headers()["x-elastic-product"],
        "Elasticsearch",
        "the engine's headers reach the client"
    );
    assert_eq!(
        r.json::<serde_json::Value>().await.expect("json")["took"],
        1
    );
    {
        let seen = seen.lock().expect("lock");
        let (line, auth) = seen.last().expect("the engine saw the request");
        assert_eq!(line, "POST /app-1/_search?size=1 HTTP/1.1");
        assert!(
            auth.contains("Basic bGltZW46d29ya2VyLWhlbGQtcHc="),
            "{auth}"
        );
        assert!(!auth.contains("the-clients-own-token"));
    }
    // Refused by policy: never sent to the engine.
    let before = seen.lock().expect("lock").len();
    for (method, path) in [
        ("POST", "/secret-1/_search"),
        ("POST", "/_search"),
        ("PUT", "/app-1/_doc/1"),
        ("DELETE", "/app-1"),
        ("GET", "/.security/_search"),
    ] {
        let r = http
            .request(method.parse().expect("method"), format!("{base}{path}"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("refusal");
        assert!(
            r.status() == 403 || r.status() == 400,
            "{method} {path}: {}",
            r.status()
        );
        let text = r.text().await.expect("text");
        assert!(text.contains("Limen:"), "{text}");
    }
    assert_eq!(
        seen.lock().expect("lock").len(),
        before,
        "nothing reached the engine"
    );
    assert!(refused.lock().expect("lock").is_empty());

    // A role policy doesn't grant is refused by the proxy.
    let (bad, bad_refused) = db_client::listen_on(
        &proxy_addr,
        &ca_pem,
        dev.clone(),
        limen_tunnel::alpn::SEARCH,
        "logs-test",
        "limen-admin",
        "",
    )
    .await;
    let _ = http.get(format!("http://{bad}/")).send().await;
    eventually(Duration::from_secs(5), "refusal recorded", || async {
        !bad_refused.lock().expect("lock").is_empty()
    })
    .await;
    assert!(bad_refused.lock().expect("lock")[0].contains("access denied"));

    // The trail.
    eventually(
        Duration::from_secs(20),
        "search events in the trail",
        || async {
            let events = read_jsonl(&d);
            events
                .iter()
                .filter(|e| e["kind"] == "search.response")
                .count()
                >= 1
                && events
                    .iter()
                    .filter(|e| e["kind"] == "auth.denied" && e["data"]["action"] == "search")
                    .count()
                    >= 5
        },
    )
    .await;
    let events = read_jsonl(&d);
    let start = events
        .iter()
        .find(|e| e["kind"] == "session.start" && e["data"]["kind"] == "elasticsearch")
        .expect("session.start");
    assert_eq!(start["user"], DEVELOPER);
    let request = events
        .iter()
        .find(|e| e["kind"] == "search.request")
        .expect("search.request");
    assert_eq!(request["producer"]["component"], "worker");
    assert_eq!(request["data"]["path"], "/app-1/_search");
    assert_eq!(request["data"]["class"], "read");
    assert_eq!(request["data"]["indices"], serde_json::json!(["app-1"]));
    assert_eq!(request["data"]["engine_role"], "read");
    assert!(
        events.iter().any(|e| e["kind"] == "search.response"
            && e["data"]["request_id"] == request["event_id"]
            && e["data"]["status"] == 200),
        "the response is linked to its request"
    );
    assert_eq!(request["session_id"], start["session_id"]);
    let text = serde_json::to_string(&events).expect("json");
    for secret in [SECRET_DOC, "worker-held-pw", "the-clients-own-token"] {
        assert!(!text.contains(secret), "{secret} reached the audit trail");
    }
    // A second connection is a second session.
    let second = http
        .get(format!("{base}/app-2/_doc/1"))
        .send()
        .await
        .expect("get");
    assert_eq!(second.status(), 200);

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
        let r = http
            .post(format!("{base}/app-1/_search"))
            .json(&serde_json::json!({}))
            .send()
            .await;
        if r.map_or(true, |r| r.status() != 200) {
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

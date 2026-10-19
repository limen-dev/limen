//! Search sessions against an in-process fake engine.

use std::io::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt as _, Full, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use limen_audit::{Emitter, EventKind, FailureMode, MemorySink};
use limen_policy::{SearchAudit, SearchClass, SearchGrant, SearchTarget};
use tokio::net::TcpListener;
use uuid::Uuid;

use super::target::{AwsSource, Settings};
use super::{SessionConfig, prepare, serve};
use crate::db::sigv4::{self, Credentials};

// ---- a fake engine -------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    headers: HeaderMap,
    body: Vec<u8>,
    connection: usize,
}

#[derive(Debug, Default)]
struct Fake {
    seen: Mutex<Vec<Seen>>,
    connections: AtomicUsize,
    /// Requires this `Authorization` header or answers 401.
    require: Mutex<Option<String>>,
    /// Closes the connection after this many requests on it.
    close_after: AtomicUsize,
    /// Answers `GET /` with 403, like a role that may not read the root.
    root_forbidden: std::sync::atomic::AtomicBool,
}

impl Fake {
    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().expect("lock").clone()
    }
    /// Requests other than the worker's own probe of `/`.
    fn user_requests(&self) -> Vec<Seen> {
        self.requests()
            .into_iter()
            .filter(|s| !(s.method == "GET" && s.target == "/"))
            .collect()
    }
}

type FakeBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

fn text(status: u16, body: &str) -> Response<FakeBody> {
    let mut r = Response::new(Full::new(Bytes::from(body.to_owned())).boxed());
    *r.status_mut() = StatusCode::from_u16(status).expect("status");
    r.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/json; charset=UTF-8"),
    );
    r
}

async fn fake_handle(fake: Arc<Fake>, conn: usize, req: Request<Incoming>) -> Response<FakeBody> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|c| c.to_bytes().to_vec())
        .unwrap_or_default();
    let target = parts
        .uri
        .path_and_query()
        .map(ToString::to_string)
        .unwrap_or_default();
    fake.seen.lock().expect("lock").push(Seen {
        method: parts.method.to_string(),
        target: target.clone(),
        headers: parts.headers.clone(),
        body,
        connection: conn,
    });
    if let Some(want) = fake.require.lock().expect("lock").clone() {
        let got = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok());
        if got != Some(want.as_str()) {
            let mut r = text(
                401,
                r#"{"error":{"type":"security_exception","reason":"missing authentication credentials for REST request"},"status":401}"#,
            );
            r.headers_mut().insert(
                "www-authenticate",
                HeaderValue::from_static("Basic realm=\"security\""),
            );
            return r;
        }
    }
    let path = parts.uri.path();
    let mut response = match path {
        "/" if fake.root_forbidden.load(Ordering::SeqCst) => text(
            403,
            r#"{"error":{"type":"security_exception","reason":"no permissions for [cluster:monitor/main]"},"status":403}"#,
        ),
        "/" => text(200, r#"{"name":"fake","version":{"number":"8.15.0"}}"#),
        p if p.starts_with("/missing/") => text(
            404,
            r#"{"error":{"root_cause":[],"type":"index_not_found_exception","reason":"no such index [missing]"},"status":404}"#,
        ),
        p if p.starts_with("/engine-denied/") => text(
            403,
            r#"{"error":{"type":"security_exception","reason":"action [indices:data/read/search] is unauthorized for user [limen]"},"status":403}"#,
        ),
        p if p.starts_with("/big/") => {
            let chunk = Bytes::from(vec![b'x'; 64 * 1024]);
            let frames: Vec<Result<Frame<Bytes>, std::convert::Infallible>> =
                (0..16).map(|_| Ok(Frame::data(chunk.clone()))).collect();
            let mut r = Response::new(StreamBody::new(futures::stream::iter(frames)).boxed());
            r.headers_mut().insert(
                "content-type",
                HeaderValue::from_static("application/octet-stream"),
            );
            r
        }
        p if p.ends_with("/_bulk") || p == "/_bulk" => {
            text(200, r#"{"took":1,"errors":false,"items":[]}"#)
        }
        p if p.ends_with("/_search") || p == "/_search" => {
            let mut r = text(
                200,
                r#"{"took":1,"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}}"#,
            );
            r.headers_mut()
                .insert("set-cookie", HeaderValue::from_static("session=abc"));
            r
        }
        _ => text(200, r#"{"acknowledged":true}"#),
    };
    let limit = fake.close_after.load(Ordering::SeqCst);
    if limit > 0
        && fake
            .seen
            .lock()
            .expect("lock")
            .iter()
            .filter(|s| s.connection == conn)
            .count()
            >= limit
    {
        response
            .headers_mut()
            .insert("connection", HeaderValue::from_static("close"));
    }
    response
}

async fn start_fake() -> (Arc<Fake>, String) {
    let fake = Arc::new(Fake::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let f = Arc::clone(&fake);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let conn = f.connections.fetch_add(1, Ordering::SeqCst) + 1;
            let f = Arc::clone(&f);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| {
                    let f = Arc::clone(&f);
                    async move { Ok::<_, std::convert::Infallible>(fake_handle(f, conn, req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (fake, addr)
}

// ---- the client side -----------------------------------------------------------------

struct Client {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("json body")
    }
}

impl Client {
    async fn send(
        &mut self,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Reply {
        let mut req = Request::builder()
            .method(method)
            .uri(target)
            .header("host", "localhost");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let req = req
            .body(Full::new(Bytes::copy_from_slice(body)))
            .expect("request");
        self.sender.ready().await.expect("connection open");
        let resp = self.sender.send_request(req).await.expect("response");
        let (parts, body) = resp.into_parts();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: body.collect().await.expect("body").to_bytes(),
        }
    }

    async fn get(&mut self, target: &str) -> Reply {
        self.send("GET", target, &[], b"").await
    }

    async fn post(&mut self, target: &str, body: &str) -> Reply {
        self.send(
            "POST",
            target,
            &[("content-type", "application/json")],
            body.as_bytes(),
        )
        .await
    }
}

// ---- the harness ---------------------------------------------------------------------

struct Options {
    grants: Vec<SearchGrant>,
    audit: SearchAudit,
    /// `(user, password)` the worker has for the role.
    login: Option<(&'static str, &'static str)>,
    aws: Option<AwsSource>,
    max_body: Option<usize>,
    idle: Option<std::time::Duration>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            grants: vec![grant(&[SearchClass::Read], &["logs-*"])],
            audit: SearchAudit::default(),
            login: Some(("limen", "pw")),
            aws: None,
            max_body: None,
            idle: None,
        }
    }
}

fn grant(classes: &[SearchClass], indices: &[&str]) -> SearchGrant {
    SearchGrant {
        roles: vec!["limen-read".into()],
        classes: classes.to_vec(),
        indices: indices.iter().map(|s| (*s).to_owned()).collect(),
    }
}

struct Harness {
    client: Client,
    fake: Arc<Fake>,
    sink: Arc<MemorySink>,
    session: Uuid,
    served: tokio::task::JoinHandle<()>,
}

fn settings(login: Option<(&str, &str)>) -> Settings {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("creds.json");
    let json = match login {
        Some((u, p)) => format!(
            r#"{{"logs": {{"limen-read": {{"basic": {{"username": "{u}", "password": "{p}"}}}}}}}}"#
        ),
        None => "{}".to_owned(),
    };
    std::fs::write(&path, json).expect("write");
    Settings::load(None, Some(&path)).expect("settings")
}

async fn try_start(o: Options, fake: Arc<Fake>, addr: String) -> anyhow::Result<Harness> {
    let sink = Arc::new(MemorySink::default());
    let emitter = Emitter::new("worker", "w1", sink.clone(), FailureMode::FailClosed);
    let session = Uuid::now_v7();
    let config = SessionConfig {
        session_id: session,
        username: "alice@example.com".into(),
        resource: "logs".into(),
        engine_role: "limen-read".into(),
        engine: "elasticsearch",
        target: SearchTarget {
            endpoint: addr,
            region: o.aws.as_ref().map(|_| "eu-west-1".to_owned()),
            aws: o.aws.is_some(),
            serverless: false,
            tls: false,
            audit: o.audit,
        },
    };
    let mut settings = settings(o.login);
    if let Some(n) = o.max_body {
        settings = settings.with_max_body(n);
    }
    if let Some(idle) = o.idle {
        settings = settings.with_idle(idle);
    }
    let prepared = prepare(&settings, o.grants, config, o.aws).await?;
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    let served = tokio::spawn(async move {
        let _ = serve(ours, prepared, emitter).await;
    });
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(theirs))
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(Harness {
        client: Client { sender },
        fake,
        sink,
        session,
        served,
    })
}

async fn start(o: Options) -> Harness {
    let (fake, addr) = start_fake().await;
    *fake.require.lock().expect("lock") = o.login.map(|(u, p)| {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
        )
    });
    try_start(o, fake, addr).await.expect("start")
}

impl Harness {
    fn events(&self, kind: EventKind) -> Vec<limen_audit::Event> {
        self.sink
            .events()
            .into_iter()
            .filter(|e| e.kind == kind)
            .collect()
    }
}

// ---- tests ---------------------------------------------------------------------------

#[tokio::test]
async fn a_read_is_forwarded_with_the_workers_credential_and_audited() {
    let mut h = start(Options::default()).await;
    let r = h
        .client
        .send(
            "POST",
            "/logs-1/_search?size=2&pretty",
            &[
                ("content-type", "application/json"),
                ("authorization", "Bearer the-users-own-token"),
                ("x-api-key", "client-key"),
                ("es-security-runas-user", "elastic"),
                ("opensearch_security_impersonate_as", "admin"),
                ("x-forwarded-for", "1.2.3.4"),
                ("x-proxy-user", "root"),
                ("x-opaque-id", "spoofed"),
                ("x-elastic-client-meta", "es=8.0"),
            ],
            br#"{"query":{"match_all":{}}}"#,
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["took"], 1);
    // The engine saw the worker's login, the Limen session, and none of the client's.
    let seen = h.fake.user_requests();
    assert_eq!(seen.len(), 1);
    let s = &seen[0];
    assert_eq!(
        (s.method.as_str(), s.target.as_str()),
        ("POST", "/logs-1/_search?size=2&pretty")
    );
    assert_eq!(s.body, br#"{"query":{"match_all":{}}}"#);
    let h_ = &s.headers;
    assert_eq!(h_["authorization"], "Basic bGltZW46cHc=");
    assert_eq!(
        h_["x-opaque-id"].to_str().expect("str"),
        format!("limen:{}", h.session)
    );
    assert_eq!(h_["x-elastic-client-meta"], "es=8.0");
    assert_eq!(h_["content-type"], "application/json");
    for gone in [
        "x-api-key",
        "es-security-runas-user",
        "opensearch_security_impersonate_as",
        "x-forwarded-for",
        "x-proxy-user",
    ] {
        assert!(!h_.contains_key(gone), "{gone} reached the engine");
    }
    // The response lost what belongs to the worker's login.
    assert!(!r.headers.contains_key("set-cookie"));
    // Audited, request first.
    let req = h.events(EventKind::SearchRequest);
    let resp = h.events(EventKind::SearchResponse);
    assert_eq!((req.len(), resp.len()), (1, 1));
    let d = &req[0].data;
    assert_eq!(d["method"], "POST");
    assert_eq!(d["path"], "/logs-1/_search");
    assert_eq!(d["api"], "search");
    assert_eq!(d["class"], "read");
    assert_eq!(d["indices"], serde_json::json!(["logs-1"]));
    assert_eq!(d["engine_role"], "limen-read");
    assert_eq!(d["query_params"], serde_json::json!(["size", "pretty"]));
    assert!(d.get("query").is_none() && d.get("body").is_none(), "{d}");
    assert_eq!(req[0].user.as_deref(), Some("alice@example.com"));
    assert_eq!(req[0].session_id, Some(h.session));
    assert_eq!(
        resp[0].data["request_id"],
        serde_json::json!(req[0].event_id)
    );
    assert_eq!(resp[0].data["status"], 200);
    let order: Vec<_> = h.sink.events().iter().map(|e| e.kind).collect();
    assert_eq!(order, [EventKind::SearchRequest, EventKind::SearchResponse]);
}

#[tokio::test]
async fn refusals_never_reach_the_engine_and_keep_the_connection() {
    let mut h = start(Options::default()).await;
    // A write when only read is granted, an index outside the pattern, every
    // index, a hidden index, and an unknown API.
    for (method, target) in [
        ("PUT", "/logs-1/_doc/1"),
        ("POST", "/orders/_search"),
        ("POST", "/_search"),
        ("POST", "/.security/_search"),
        ("GET", "/_cluster/settings"),
        ("DELETE", "/logs-1"),
    ] {
        let r = h
            .client
            .send(
                method,
                target,
                &[("content-type", "application/json")],
                b"{}",
            )
            .await;
        assert_eq!(r.status, 403, "{method} {target}");
        let j = r.json();
        assert_eq!(j["error"]["type"], "limen_security_exception");
        assert!(
            j["error"]["reason"]
                .as_str()
                .expect("reason")
                .starts_with("Limen: ")
        );
        assert_eq!(r.headers["x-limen-refused"], "true");
    }
    assert!(
        h.fake.user_requests().is_empty(),
        "{:?}",
        h.fake.user_requests()
    );
    let denied = h.events(EventKind::AuthDenied);
    assert_eq!(denied.len(), 6);
    assert_eq!(denied[0].data["action"], "search");
    assert_eq!(denied[0].data["class"], "write");
    assert_eq!(denied[1].data["indices"], serde_json::json!(["orders"]));
    assert_eq!(denied[2].data["indices_all"], true);
    // The connection survives a refusal, so a client pool doesn't redial.
    let ok = h.client.post("/logs-2/_search", "{}").await;
    assert_eq!(ok.status, 200);
    assert_eq!(h.fake.connections.load(Ordering::SeqCst), 1);
    assert_eq!(h.events(EventKind::SearchRequest).len(), 1);
}

#[tokio::test]
async fn paths_that_can_be_read_two_ways_are_refused() {
    let mut h = start(Options::default()).await;
    for target in [
        "/logs-1/../.security/_search",
        "/logs-1%2F..%2F.security/_search",
        "//logs-1/_search",
        "/%3Clogs-%7Bnow%2Fd%7D%3E/_search",
        "/remote:logs-1/_search",
    ] {
        let r = h.client.post(target, "{}").await;
        assert_eq!(r.status, 400, "{target}");
    }
    assert!(h.fake.user_requests().is_empty());
    assert_eq!(h.events(EventKind::AuthDenied).len(), 5);
}

#[tokio::test]
async fn bulk_is_checked_per_action_and_counted_in_the_trail() {
    let mut h = start(Options {
        grants: vec![grant(&[SearchClass::Write], &["logs-*"])],
        ..Options::default()
    })
    .await;
    let bad = "{\"index\":{\"_index\":\"logs-1\"}}\n{\"a\":1}\n{\"index\":{\"_index\":\"orders\"}}\n{\"a\":2}\n";
    let r = h
        .client
        .send(
            "POST",
            "/_bulk",
            &[("content-type", "application/x-ndjson")],
            bad.as_bytes(),
        )
        .await;
    assert_eq!(r.status, 403);
    assert!(h.fake.user_requests().is_empty());
    let good = "{\"index\":{\"_index\":\"logs-1\"}}\n{\"a\":1}\n{\"delete\":{\"_index\":\"logs-2\",\"_id\":\"7\"}}\n{\"create\":{\"_index\":\"logs-1\"}}\n{\"a\":3}\n";
    let r = h
        .client
        .send(
            "POST",
            "/_bulk",
            &[("content-type", "application/x-ndjson")],
            good.as_bytes(),
        )
        .await;
    assert_eq!(r.status, 200);
    // The engine got the body byte for byte.
    assert_eq!(h.fake.user_requests()[0].body, good.as_bytes());
    let d = &h.events(EventKind::SearchRequest)[0].data;
    assert_eq!(d["api"], "bulk");
    assert_eq!(d["class"], "write");
    assert_eq!(d["items"], 3);
    assert_eq!(
        d["bulk"]["logs-1"],
        serde_json::json!({"index": 1, "create": 1})
    );
    assert_eq!(d["bulk"]["logs-2"], serde_json::json!({"delete": 1}));
    assert!(
        d.get("body").is_none(),
        "bodies are not logged by default: {d}"
    );
}

#[tokio::test]
async fn gzip_bulk_bodies_are_inspected_and_forwarded_as_sent() {
    use std::io::Write as _;
    let mut h = start(Options {
        grants: vec![grant(&[SearchClass::Write], &["logs-*"])],
        ..Options::default()
    })
    .await;
    let gz = |text: &str| {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(text.as_bytes()).expect("write");
        e.finish().expect("finish")
    };
    let headers = [
        ("content-type", "application/x-ndjson"),
        ("content-encoding", "gzip"),
    ];
    let bad = gz("{\"index\":{\"_index\":\"orders\"}}\n{}\n");
    let r = h.client.send("POST", "/_bulk", &headers, &bad).await;
    assert_eq!(r.status, 403, "a compressed body is read, not trusted");
    let good = gz("{\"index\":{\"_index\":\"logs-1\"}}\n{}\n");
    let r = h.client.send("POST", "/_bulk", &headers, &good).await;
    assert_eq!(r.status, 200);
    let seen = h.fake.user_requests();
    assert_eq!(seen[0].body, good);
    assert_eq!(seen[0].headers["content-encoding"], "gzip");
    // A body the worker has to read but can't (brotli) is refused.
    let r = h
        .client
        .send("POST", "/_bulk", &[("content-encoding", "br")], b"whatever")
        .await;
    assert_eq!(r.status, 400);
}

#[tokio::test]
async fn a_body_the_worker_must_read_is_capped() {
    let mut h = start(Options {
        grants: vec![grant(&[SearchClass::Write], &["logs-*"])],
        max_body: Some(4096),
        ..Options::default()
    })
    .await;
    let big = format!(
        "{{\"index\":{{\"_index\":\"logs-1\"}}}}\n{{\"a\":\"{}\"}}\n",
        "x".repeat(10_000)
    );
    let r = h
        .client
        .send(
            "POST",
            "/_bulk",
            &[("content-type", "application/x-ndjson")],
            big.as_bytes(),
        )
        .await;
    assert_eq!(r.status, 413);
    assert_eq!(
        r.headers["connection"], "close",
        "the rest of the body was not read"
    );
    assert!(h.fake.user_requests().is_empty());
    // A body that is only streamed has no cap here (the engine has its own).
    let mut h = start(Options {
        grants: vec![grant(&[SearchClass::Write], &["logs-*"])],
        max_body: Some(4096),
        ..Options::default()
    })
    .await;
    let doc = format!(r#"{{"a":"{}"}}"#, "x".repeat(10_000));
    // (write only: the document API streams)
    let r = h
        .client
        .send(
            "PUT",
            "/logs-1/_doc/1",
            &[("content-type", "application/json")],
            doc.as_bytes(),
        )
        .await;
    assert_eq!(r.status, 200);
    // A gzip bomb is bounded after decoding too.
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(&vec![b' '; 1 << 20]).expect("write");
    let bomb = e.finish().expect("finish");
    assert!(bomb.len() < 4096);
    let r = h
        .client
        .send(
            "POST",
            "/_bulk",
            &[
                ("content-type", "application/x-ndjson"),
                ("content-encoding", "gzip"),
            ],
            &bomb,
        )
        .await;
    assert_eq!(r.status, 400);
    assert!(
        h.fake.user_requests().len() == 1,
        "only the streamed document reached the engine"
    );
}

#[tokio::test]
async fn documents_stream_to_the_engine_without_being_read() {
    let mut h = start(Options {
        grants: vec![grant(&[SearchClass::Read, SearchClass::Write], &["logs-*"])],
        ..Options::default()
    })
    .await;
    let doc = format!(r#"{{"message":"{}"}}"#, "x".repeat(300_000));
    let r = h
        .client
        .send(
            "PUT",
            "/logs-1/_doc/9",
            &[("content-type", "application/json")],
            doc.as_bytes(),
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(h.fake.user_requests()[0].body, doc.as_bytes());
    let d = &h.events(EventKind::SearchRequest)[0].data;
    assert_eq!(d["api"], "doc.write");
    assert_eq!(d["body_bytes"], doc.len());
}

#[tokio::test]
async fn audit_failing_means_the_request_is_not_sent() {
    let mut h = start(Options::default()).await;
    h.sink.set_failing(true);
    let r = h.client.post("/logs-1/_search", "{}").await;
    assert_eq!(r.status, 503);
    assert_eq!(r.json()["error"]["type"], "limen_audit_exception");
    assert!(
        h.fake.user_requests().is_empty(),
        "the engine saw a request that wasn't audited"
    );
    assert_eq!(r.headers["connection"], "close");
    h.sink.set_failing(false);
}

#[tokio::test]
async fn engine_errors_pass_through_and_their_type_is_recorded_without_the_reason() {
    let mut h = start(Options::default()).await;
    let r = h.client.post("/logs-1/_search", "{}").await;
    assert_eq!(r.status, 200);
    let r = h.get("/missing/_search").await;
    // `missing` is outside logs-*: the worker refuses before the engine does.
    assert_eq!(r.status, 403);
    // Inside the grant, the engine's own error reaches the client unchanged.
    let mut h2 = start(Options {
        grants: vec![grant(&[SearchClass::Read], &["*"])],
        ..Options::default()
    })
    .await;
    let r = h2.client.post("/missing/_search", "{}").await;
    assert_eq!(r.status, 404);
    assert_eq!(r.json()["error"]["type"], "index_not_found_exception");
    let r = h2.client.post("/engine-denied/_search", "{}").await;
    assert_eq!(
        r.status, 403,
        "the engine's authorization failures are shown as they are"
    );
    assert_eq!(r.json()["error"]["type"], "security_exception");
    let resp = h2.events(EventKind::SearchResponse);
    assert_eq!(resp[0].data["status"], 404);
    assert_eq!(resp[0].data["outcome"], "error");
    assert_eq!(resp[0].data["error_type"], "index_not_found_exception");
    assert_eq!(resp[1].data["error_type"], "security_exception");
    assert!(
        !resp[0].data.to_string().contains("no such index"),
        "the reason can echo data"
    );
}

impl Harness {
    async fn get(&mut self, target: &str) -> Reply {
        self.client.get(target).await
    }
}

#[tokio::test]
async fn a_rejected_worker_credential_is_not_shown_to_the_user() {
    let (fake, addr) = start_fake().await;
    *fake.require.lock().expect("lock") = Some("Basic something-else".into());
    // Preparing already notices.
    let err = try_start(Options::default(), Arc::clone(&fake), addr.clone())
        .await
        .err()
        .expect("401 at start");
    assert!(err.to_string().contains("401"), "{err}");
    // A credential that stops working later is a 502 with no realm.
    let (fake, addr) = start_fake().await;
    let mut h = try_start(Options::default(), Arc::clone(&fake), addr)
        .await
        .expect("start");
    *fake.require.lock().expect("lock") = Some("Basic changed".into());
    let r = h.client.post("/logs-1/_search", "{}").await;
    assert_eq!(r.status, 502);
    assert!(!r.headers.contains_key("www-authenticate"));
    assert_eq!(r.json()["error"]["type"], "limen_upstream_exception");
    assert_eq!(h.events(EventKind::SearchResponse)[0].data["status"], 401);
}

#[tokio::test]
async fn a_role_that_may_not_read_the_root_still_starts() {
    // Fine-grained access control can refuse `GET /`; that isn't a bad credential.
    let (fake, addr) = start_fake().await;
    fake.root_forbidden.store(true, Ordering::SeqCst);
    let mut h = try_start(Options::default(), Arc::clone(&fake), addr)
        .await
        .expect("starts");
    assert_eq!(h.client.post("/logs-1/_search", "{}").await.status, 200);
}

#[tokio::test]
async fn many_requests_share_one_connection_to_the_engine() {
    let mut h = start(Options::default()).await;
    for _ in 0..20 {
        assert_eq!(h.client.post("/logs-1/_search", "{}").await.status, 200);
    }
    assert_eq!(h.fake.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_connection_the_engine_closed_is_replaced() {
    let mut h = start(Options::default()).await;
    h.fake.close_after.store(1, Ordering::SeqCst);
    // Every response closes its connection; each request needs a new one.
    for _ in 0..3 {
        assert_eq!(h.client.post("/logs-1/_search", "{}").await.status, 200);
    }
    assert!(h.fake.connections.load(Ordering::SeqCst) >= 3);
    assert_eq!(h.events(EventKind::SearchResponse).len(), 3);
}

#[tokio::test]
async fn large_responses_stream_through() {
    let mut h = start(Options {
        grants: vec![grant(&[SearchClass::Read], &[])],
        ..Options::default()
    })
    .await;
    let r = h.client.post("/big/_search", "{}").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body.len(), 16 * 64 * 1024);
    // HEAD has a head and no body.
    let r = h.client.send("HEAD", "/logs-1/_doc/1", &[], b"").await;
    assert_eq!(r.status, 200);
    assert!(r.body.is_empty());
}

#[tokio::test]
async fn audit_options_are_per_resource() {
    let mut h = start(Options {
        grants: vec![grant(&[SearchClass::Read, SearchClass::Write], &[])],
        audit: SearchAudit {
            log_bodies: true,
            log_query: true,
            redact_ids: true,
        },
        ..Options::default()
    })
    .await;
    let r = h
        .client
        .post(
            "/users/_search?q=email:bob@example.com",
            r#"{"query":{"match":{"name":"bob"}}}"#,
        )
        .await;
    assert_eq!(r.status, 200);
    let r = h.get("/users/_doc/bob%40example.com").await;
    assert_eq!(r.status, 200);
    let events = h.events(EventKind::SearchRequest);
    let search = &events[0].data;
    assert_eq!(search["query"], "q=email:bob@example.com");
    assert_eq!(search["body"], r#"{"query":{"match":{"name":"bob"}}}"#);
    assert!(search.get("query_params").is_none());
    let doc = events[1].data["path"].as_str().expect("path");
    assert!(
        doc.starts_with("/users/_doc/h:") && !doc.contains("bob"),
        "{doc}"
    );
    // Same id, same hash, so the trail can still follow it.
    let again = h.get("/users/_doc/bob%40example.com").await;
    assert_eq!(again.status, 200);
    assert_eq!(
        h.events(EventKind::SearchRequest)[2].data["path"],
        events[1].data["path"]
    );
    // The engine still got the real path.
    assert_eq!(
        h.fake.user_requests()[1].target,
        "/users/_doc/bob%40example.com"
    );
}

#[tokio::test]
async fn credential_apis_are_never_logged_even_when_bodies_are() {
    let mut h = start(Options {
        grants: vec![grant(
            &[SearchClass::Read, SearchClass::Write, SearchClass::Admin],
            &[],
        )],
        audit: SearchAudit {
            log_bodies: true,
            ..SearchAudit::default()
        },
        ..Options::default()
    })
    .await;
    let r = h
        .client
        .send(
            "PUT",
            "/_security/user/bob",
            &[("content-type", "application/json")],
            br#"{"password":"hunter2hunter2"}"#,
        )
        .await;
    assert_eq!(r.status, 200);
    let events = h.sink.events();
    assert!(
        !serde_json::to_string(&events)
            .expect("json")
            .contains("hunter2")
    );
    assert!(
        h.events(EventKind::SearchRequest)[0]
            .data
            .get("body")
            .is_none()
    );
}

#[tokio::test]
async fn the_source_parameter_is_refused_under_an_index_restriction() {
    let mut h = start(Options::default()).await;
    let r = h.get("/logs-1/_search?source=%7B%22query%22%3A%7B%7D%7D&source_content_type=application/json").await;
    assert_eq!(r.status, 403);
    assert!(h.fake.user_requests().is_empty());
}

#[tokio::test]
async fn search_bodies_cannot_reach_around_the_index_pattern() {
    let mut h = start(Options::default()).await;
    let r = h
        .client
        .post(
            "/logs-1/_search",
            r#"{"query":{"terms":{"user":{"index":"orders","id":"1","path":"u"}}}}"#,
        )
        .await;
    assert_eq!(r.status, 403);
    let r = h
        .client
        .post(
            "/_msearch",
            "{\"index\":\"logs-1\"}\n{}\n{\"index\":\"orders\"}\n{}\n",
        )
        .await;
    assert_eq!(r.status, 403);
    assert!(h.fake.user_requests().is_empty());
}

#[tokio::test]
async fn remote_reindex_is_refused() {
    let mut h = start(Options {
        grants: vec![grant(&[SearchClass::Read, SearchClass::Write], &["logs-*"])],
        ..Options::default()
    })
    .await;
    let r = h
        .client
        .post("/_reindex", r#"{"source":{"index":"logs-1","remote":{"host":"http://elsewhere:9200"}},"dest":{"index":"logs-2"}}"#)
        .await;
    assert_eq!(r.status, 403);
    assert!(h.fake.user_requests().is_empty());
}

#[tokio::test]
async fn an_idle_connection_ends_and_frees_its_slot() {
    let mut h = start(Options {
        idle: Some(std::time::Duration::from_millis(300)),
        ..Options::default()
    })
    .await;
    assert_eq!(h.client.post("/logs-1/_search", "{}").await.status, 200);
    // Busy connections are not idle: a request every 100 ms keeps it going.
    for _ in 0..6 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(h.client.post("/logs-1/_search", "{}").await.status, 200);
    }
    let Harness { client, served, .. } = h;
    let started = std::time::Instant::now();
    // Keep the client end open and send nothing.
    let _keep = client;
    tokio::time::timeout(std::time::Duration::from_secs(5), served)
        .await
        .expect("an idle connection ends by itself")
        .expect("task");
    assert!(started.elapsed() < std::time::Duration::from_secs(4));
}

#[tokio::test]
async fn a_connection_that_has_sent_nothing_stays_open() {
    // The CLI keeps one open to show its run as active.
    let h = start(Options {
        idle: Some(std::time::Duration::from_millis(200)),
        ..Options::default()
    })
    .await;
    let Harness { client, served, .. } = h;
    let _keep = client;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(900), served)
            .await
            .is_err(),
        "a connection with no request yet must not be ended as idle"
    );
}

#[tokio::test]
async fn closing_the_client_ends_the_session() {
    let h = start(Options::default()).await;
    let Harness { client, served, .. } = h;
    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(5), served)
        .await
        .expect("the session ends when the client goes")
        .expect("task");
}

// ---- SigV4 ---------------------------------------------------------------------------

fn creds() -> Credentials {
    Credentials {
        access_key: "AKIDEXAMPLE".into(),
        secret_key: limen_core::secret::Secret::new(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        ),
        session_token: None,
    }
}

fn at(s: &str) -> time::OffsetDateTime {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).expect("time")
}

// The expected values come from an independent implementation of the
// specification (hand-written Python, `hmac` and `hashlib` only), not from
// this code, and for the path "/logs-1/_doc/a%40b" they include the double
// encoding every service but S3 requires. Not a call to a real service.
#[test]
fn sigv4_for_opensearch_service_matches_an_independent_implementation() {
    let body = br#"{"query":{"match_all":{}}}"#;
    let payload = sigv4::sha256_hex(body);
    assert_eq!(
        payload,
        "baa6846b65b050d71831bb2e4cd6e6f1593902f6d82b16a6c1f9979d14cfcd12"
    );
    let query = sigv4::canonical_query(&[
        ("size".into(), "2".into()),
        ("pretty".into(), String::new()),
    ]);
    let signed = sigv4::sign_headers(
        &sigv4::Target {
            method: "POST",
            host: "search-logs-abc.eu-west-1.es.amazonaws.com",
            path: "/logs-1/_search",
            region: "eu-west-1",
            service: "es",
        },
        &query,
        &[
            ("content-type", "application/json"),
            ("x-amz-content-sha256", &payload),
        ],
        body,
        &creds(),
        at("2026-10-18T12:00:00Z"),
    );
    assert_eq!(
        signed.authorization,
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261018/eu-west-1/es/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=7a3ccd98e274f359f77f0a64dc7093c0f3ece3ab20a3cde1086d6ccfff396481"
    );
    let empty = sigv4::sha256_hex(b"");
    let signed = sigv4::sign_headers(
        &sigv4::Target {
            method: "GET",
            host: "search-logs-abc.eu-west-1.es.amazonaws.com",
            path: "/logs-1/_doc/a%40b",
            region: "eu-west-1",
            service: "es",
        },
        "",
        &[("x-amz-content-sha256", &empty)],
        b"",
        &creds(),
        at("2026-10-18T12:00:00Z"),
    );
    assert!(
        signed.authorization.ends_with(
            "Signature=e99de48146e69d45bbab3e2ddc5f22e700320f31bef64b9de5912cf4b9323832"
        ),
        "{}",
        signed.authorization
    );
    let serverless = sigv4::sign_headers(
        &sigv4::Target {
            method: "GET",
            host: "abc.eu-west-1.aoss.amazonaws.com",
            path: "/_cat/indices",
            region: "eu-west-1",
            service: "aoss",
        },
        &sigv4::canonical_query(&[("v".into(), String::new())]),
        &[("x-amz-content-sha256", &empty)],
        b"",
        &creds(),
        at("2026-10-18T12:00:00Z"),
    );
    assert!(
        serverless.authorization.ends_with(
            "Signature=7f087ca0481eb26afe1535e742772105b7d8abb7364ffe5c066d44cd2d028739"
        ),
        "{}",
        serverless.authorization
    );
}

#[tokio::test]
async fn aws_targets_are_signed_per_request_and_carry_no_other_credential() {
    let source: AwsSource = Arc::new(|| Box::pin(async { Ok(creds()) }));
    let mut h = start(Options {
        grants: vec![grant(&[SearchClass::Read], &[])],
        login: None,
        aws: Some(source),
        ..Options::default()
    })
    .await;
    let body = r#"{"query":{"match_all":{}}}"#;
    let r = h.client.post("/logs-1/_search?size=1", body).await;
    assert_eq!(r.status, 200);
    let s = &h.fake.user_requests()[0];
    let auth = s.headers["authorization"].to_str().expect("str");
    assert!(
        auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"),
        "{auth}"
    );
    assert!(auth.contains("/eu-west-1/es/aws4_request"), "{auth}");
    assert!(
        auth.contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date"),
        "{auth}"
    );
    assert_eq!(
        s.headers["x-amz-content-sha256"].to_str().expect("str"),
        sigv4::sha256_hex(body.as_bytes())
    );
    assert!(s.headers.contains_key("x-amz-date"));
    // Signed with the host it was sent to.
    assert_eq!(s.headers["host"].to_str().expect("str"), h.fake_host());
}

impl Harness {
    fn fake_host(&self) -> String {
        self.fake.requests()[0].headers["host"]
            .to_str()
            .expect("str")
            .to_owned()
    }
}

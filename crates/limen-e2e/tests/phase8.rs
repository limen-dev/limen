//! Phase 8 end to end: `kubectl`'s requests through proxy and worker to a
//! stand-in API server, by impersonation, with exec recorded and audited.
//!
//! The API server is a test double (`limen_testkit::kube_api`). Real clusters
//! are covered by `demos/demo-phase8.sh` on kind.

use std::time::Duration;

use http::{Request, StatusCode};
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use limen_e2e::eventually;
use limen_kube::ws::{self, Sender};
use limen_testkit::users::DEVELOPER;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

mod common;

use common::{Env, connect, read_jsonl, text};

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread")]
async fn kubectl_by_impersonation_with_recorded_exec() {
    let Some(Env { d, api, worker, .. }) = Env::start().await else {
        return;
    };

    let dev = d.login(DEVELOPER, &["ops"]).await.expect("developer");

    // 1. A plain request: the worker's credential and the user's impersonation,
    //    whatever the client tried to send.
    let mut conn = connect(&d, d.proxy_addr, Some(dev.clone())).await;
    let request = Request::get("/k8s/eks-dev/api/v1/namespaces/dev/pods?limit=5")
        .header("host", "localhost")
        .header("authorization", "Bearer stolen")
        .header("impersonate-user", "system:admin")
        .header("impersonate-group", "system:masters")
        .header("x-limen-client-cert", "AAAA")
        .body(Empty::<Bytes>::new())
        .expect("request");
    let (status, body) = text(conn.send_request(request).await.expect("response")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("PodList"));
    let seen = api.seen();
    let list = seen.last().expect("the API server saw the request");
    assert_eq!(list.uri, "/api/v1/namespaces/dev/pods?limit=5");
    assert_eq!(list.header("authorization"), Some("Bearer sa-token-123"));
    assert_eq!(list.headers_named("impersonate-user"), [DEVELOPER]);
    assert_eq!(
        list.headers_named("impersonate-group"),
        ["limen:edit", "limen:view"]
    );
    assert_eq!(list.headers_named("authorization").len(), 1);
    assert!(list.header("impersonate-extra-limen-session").is_some());
    assert!(list.header("x-limen-client-cert").is_none());

    // 2. Refusals never reach the cluster.
    let before = api.seen().len();
    let mut conn = connect(&d, d.proxy_addr, Some(dev.clone())).await;
    let (status, body) = text(
        conn.send_request(
            Request::get("/k8s/eks-prod/api/v1/pods")
                .header("host", "localhost")
                .body(Empty::<Bytes>::new())
                .expect("request"),
        )
        .await
        .expect("response"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body.contains("\"kind\":\"Status\""),
        "kubectl-readable: {body}"
    );
    let outsider = d
        .login("outsider@example.com", &["guests"])
        .await
        .expect("login");
    let mut conn = connect(&d, d.proxy_addr, Some(outsider)).await;
    let (status, _) = text(
        conn.send_request(
            Request::get("/k8s/eks-dev/api/v1/pods")
                .header("host", "localhost")
                .body(Empty::<Bytes>::new())
                .expect("request"),
        )
        .await
        .expect("response"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let mut conn = connect(&d, d.proxy_addr, None).await;
    let (status, _) = text(
        conn.send_request(
            Request::get("/k8s/eks-dev/api/v1/pods")
                .header("host", "localhost")
                .body(Empty::<Bytes>::new())
                .expect("request"),
        )
        .await
        .expect("response"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(api.seen().len(), before, "the cluster saw none of them");

    // 3. Only exec, attach, and port-forward may upgrade.
    let mut conn = connect(&d, d.proxy_addr, Some(dev.clone())).await;
    let (status, _) = text(
        conn.send_request(
            Request::get("/k8s/eks-dev/api/v1/namespaces/dev/pods?watch=true")
                .header("host", "localhost")
                .header("connection", "Upgrade")
                .header("upgrade", "websocket")
                .body(Empty::<Bytes>::new())
                .expect("request"),
        )
        .await
        .expect("response"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 4. exec over WebSocket: relayed untouched, recorded, audited.
    let mut conn = connect(&d, d.proxy_addr, Some(dev.clone())).await;
    let mut response = conn
        .send_request(
            Request::get("/k8s/eks-dev/api/v1/namespaces/dev/pods/web/exec?command=ls&command=-l&stdout=true&tty=true")
                .header("host", "localhost")
                .header("connection", "Upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header("sec-websocket-protocol", "v4.channel.k8s.io, base64.channel.k8s.io")
                .header("sec-websocket-extensions", "permessage-deflate")
                .body(Empty::<Bytes>::new())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    let mut io = TokioIo::new(hyper::upgrade::on(&mut response).await.expect("upgrade"));
    let mut resize = vec![4u8];
    resize.extend(br#"{"Width":100,"Height":30}"#);
    io.write_all(&ws::encode(Sender::Client, 0x2, &resize))
        .await
        .expect("send resize");
    let mut decoder = ws::Decoder::new(Sender::Server);
    let mut channels = Vec::new();
    let mut buf = [0u8; 4096];
    while channels.len() < 3 {
        let n = tokio::time::timeout(Duration::from_secs(10), io.read(&mut buf))
            .await
            .expect("exec output in time")
            .expect("read");
        assert!(n > 0, "stream ended early");
        for message in decoder.push(&buf[..n]).expect("frames") {
            if let ws::Message::Binary(m) = message {
                channels.push(m);
            }
        }
    }
    assert_eq!(channels[0], b"\x01hello from pod\r\n");
    assert_eq!(channels[1], b"\x02warning\r\n");
    drop(io);

    let exec = api
        .seen()
        .into_iter()
        .find(|s| s.uri.contains("/exec"))
        .expect("the API server saw the exec");
    assert_eq!(
        exec.header("sec-websocket-protocol"),
        Some("v4.channel.k8s.io")
    );
    assert!(exec.header("sec-websocket-extensions").is_none());
    assert_eq!(exec.headers_named("impersonate-user"), [DEVELOPER]);
    eventually(
        Duration::from_secs(10),
        "the resize reached the cluster",
        || async { !api.client_bytes.lock().expect("lock").is_empty() },
    )
    .await;

    // The audit trail: the request, then the session, linked by session_id.
    eventually(Duration::from_secs(20), "kube audit events", || async {
        let events = read_jsonl(&d);
        events
            .iter()
            .any(|e| e["kind"] == "session.end" && e["data"]["kind"] == "kube")
    })
    .await;
    let events = read_jsonl(&d);
    let req = events
        .iter()
        .find(|e| {
            e["kind"] == "kube.request"
                && e["data"]["k8s_resource"] == "pods"
                && e["data"]["verb"] == "list"
        })
        .expect("kube.request for the list");
    assert_eq!(req["user"], DEVELOPER);
    assert_eq!(req["data"]["status"], 200);
    assert_eq!(req["data"]["namespace"], "dev");
    assert_eq!(req["data"]["resource"], "eks-dev");
    let start = events
        .iter()
        .find(|e| e["kind"] == "session.start" && e["data"]["kind"] == "kube")
        .expect("session.start");
    assert_eq!(start["data"]["login"], "exec");
    assert_eq!(start["data"]["command"], "ls -l");
    assert_eq!(start["data"]["pod"], "web");
    let end = events
        .iter()
        .find(|e| e["kind"] == "session.end" && e["session_id"] == start["session_id"])
        .expect("session.end");
    assert_eq!(end["data"]["exit_code"], 3);
    assert!(
        end["data"]["recording_sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64)
    );
    assert!(
        events.iter().any(|e| e["kind"] == "auth.denied"
            && e["data"]["action"] == "kube"
            && e["data"]["resource"] == "eks-prod"),
        "the denial is audited"
    );

    // The recording reaches the control plane and plays like any other.
    let recordings = d.dir.path().join("recordings");
    eventually(Duration::from_secs(30), "the recording upload", || async {
        // Stored as recordings/dt=<day>/<session>.cast.
        std::fs::read_dir(&recordings)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .flat_map(|day| std::fs::read_dir(day.path()).into_iter().flatten())
            .filter_map(Result::ok)
            .any(|e| {
                std::fs::read_to_string(e.path()).is_ok_and(|t| {
                    t.contains("hello from pod") && t.contains("100x30") && t.contains("\"x\"")
                })
            })
    })
    .await;
    worker.stop().await;
}

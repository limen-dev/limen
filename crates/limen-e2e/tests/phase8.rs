//! Phase 8 end to end: `kubectl`'s requests through proxy and worker to a
//! stand-in API server, by impersonation, with exec recorded and audited.
//!
//! The API server is a test double (`limen_testkit::kube_api`). Real clusters
//! are covered by `deploy/compose/demo-phase8.sh` on kind.

use std::collections::HashMap;
use std::time::Duration;

use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use limen_e2e::{Deployment, eventually};
use limen_kube::ws::{self, Sender};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, CreateJoinTokenRequest, PolicySource};
use limen_testkit::kube_api::KubeApi;
use limen_testkit::users::{ADMIN, DEVELOPER};
use limen_tunnel::tls::{Identity, client_config};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const POLICY: &str = r#"
kind: role
version: v1
metadata: { name: ops }
spec:
  allow:
    - resources: { kind: [kubernetes], labels: { env: [test] } }
      kube: { groups: ["limen:view", "limen:edit"] }
---
kind: role
version: v1
metadata: { name: prod-only }
spec:
  allow:
    - resources: { kind: [kubernetes], labels: { env: [prod] } }
      kube: { groups: ["limen:view"] }
---
kind: role_mapping
version: v1
metadata: { name: idp }
spec:
  - { idp_group: ops, roles: [ops] }
  - { idp_group: guests, roles: [prod-only] }
---
kind: resource
version: v1
metadata: { name: eks-dev, labels: { env: test } }
spec:
  kubernetes: { cluster_name: dev }
  worker_selector: { pool: dev }
---
kind: resource
version: v1
metadata: { name: eks-prod, labels: { env: prod } }
spec:
  kubernetes: { cluster_name: prod }
  worker_selector: { pool: dev }
"#;

type Sender1 = hyper::client::conn::http1::SendRequest<Empty<Bytes>>;

/// An HTTP/1.1 connection to the proxy, presenting `identity` if given.
async fn connect(d: &Deployment, identity: Option<Identity>) -> Sender1 {
    let roots =
        limen_tunnel::tls::certs_from_pem(&std::fs::read_to_string(d.ca_file()).expect("ca"))
            .expect("roots");
    let tls = client_config(&roots, identity, &[limen_tunnel::alpn::HTTP1]).expect("tls");
    let tcp = tokio::net::TcpStream::connect(d.proxy_addr)
        .await
        .expect("tcp");
    let tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls))
        .connect("localhost".try_into().expect("name"), tcp)
        .await
        .expect("tls handshake");
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .expect("http");
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    sender
}

async fn text(response: http::Response<hyper::body::Incoming>) -> (StatusCode, String) {
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
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
async fn kubectl_by_impersonation_with_recorded_exec() {
    let Some(d) = Deployment::start().await else {
        return;
    };
    let api = KubeApi::start("sa-token-123").await;
    let ca_file = d.dir.path().join("kube-ca.pem");
    let token_file = d.dir.path().join("kube-token");
    std::fs::write(&ca_file, &api.ca_pem).expect("ca");
    std::fs::write(&token_file, "sa-token-123\n").expect("token");

    let admin_user = d.login(ADMIN, &["admins"]).await.expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(admin_user)));
    let applied = admin
        .apply_policy(ApplyPolicyRequest {
            sources: vec![PolicySource {
                name: "policy.yaml".into(),
                content: POLICY.into(),
            }],
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
        })
        .await
        .expect("token")
        .into_inner()
        .token;
    let worker = d
        .start_worker_with(
            &token,
            "worker",
            &[
                "--kube-cluster=dev".into(),
                format!("--kube-api-server={}", api.url()),
                format!("--kube-ca-file={}", ca_file.display()),
                format!("--kube-token-file={}", token_file.display()),
            ],
        )
        .await;
    eventually(
        Duration::from_secs(15),
        "worker tunnels and policy",
        || async {
            d.proxy().tunnels.summaries().len() == 2
                && d.proxy().policy_version() == Some(applied.version)
                && worker.worker.policy_version() == Some(applied.version)
        },
    )
    .await;

    let dev = d.login(DEVELOPER, &["ops"]).await.expect("developer");

    // 1. A plain request: the worker's credential and the user's impersonation,
    //    whatever the client tried to send.
    let mut conn = connect(&d, Some(dev.clone())).await;
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
    let mut conn = connect(&d, Some(dev.clone())).await;
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
    let mut conn = connect(&d, Some(outsider)).await;
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
    let mut conn = connect(&d, None).await;
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
    let mut conn = connect(&d, Some(dev.clone())).await;
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
    let mut conn = connect(&d, Some(dev.clone())).await;
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

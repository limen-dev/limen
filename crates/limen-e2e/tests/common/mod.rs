//! Shared setup for the Kubernetes end-to-end tests: a deployment with one
//! kube worker in front of a stand-in API server (`limen_testkit::kube_api`).

#![allow(dead_code)] // each test file uses a different part

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use limen_e2e::{Deployment, RunningWorker, eventually};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, CreateJoinTokenRequest, PolicySource};
use limen_testkit::kube_api::KubeApi;
use limen_testkit::users::ADMIN;
use limen_tunnel::connect::TracedChannel as Channel;
use limen_tunnel::tls::{Identity, client_config};

pub const TOKEN: &str = "sa-token-123";

/// `eks-dev` is the cluster the worker serves. `eks-other` is a cluster the
/// same worker may be asked for but is not configured for. `eks-nokube` wants
/// a worker with the label `pool=plain`.
pub const POLICY: &str = r#"
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
kind: role
version: v1
metadata: { name: short }
spec:
  max_session_ttl: 4s
  allow:
    - resources: { kind: [kubernetes], labels: { env: [test] } }
      kube: { groups: ["limen:view"] }
---
kind: role_mapping
version: v1
metadata: { name: idp }
spec:
  - { idp_group: ops, roles: [ops] }
  - { idp_group: short, roles: [short] }
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
metadata: { name: eks-other, labels: { env: test } }
spec:
  kubernetes: { cluster_name: other }
  worker_selector: { pool: dev }
---
kind: resource
version: v1
metadata: { name: eks-nokube, labels: { env: test } }
spec:
  kubernetes: { cluster_name: nokube }
  worker_selector: { pool: plain }
---
kind: resource
version: v1
metadata: { name: eks-prod, labels: { env: prod } }
spec:
  kubernetes: { cluster_name: prod }
  worker_selector: { pool: dev }
"#;

pub struct Env {
    pub d: Deployment,
    pub api: KubeApi,
    pub worker: RunningWorker,
    pub admin: AdminClient<Channel>,
    pub token_file: PathBuf,
    pub policy_version: i64,
}

impl Env {
    /// `None` without a test database.
    pub async fn start() -> Option<Self> {
        // Boxed: the whole deployment's setup is a large future.
        Box::pin(Self::boot()).await
    }

    async fn boot() -> Option<Self> {
        let d = Box::pin(Deployment::start()).await?;
        let api = KubeApi::start(TOKEN).await;
        let ca_file = d.dir.path().join("kube-ca.pem");
        let token_file = d.dir.path().join("kube-token");
        std::fs::write(&ca_file, &api.ca_pem).expect("ca");
        std::fs::write(&token_file, format!("{TOKEN}\n")).expect("token");

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
        let worker = d
            .start_worker_with(
                &join_token(&mut admin, "dev").await,
                "worker",
                &[
                    "--kube-cluster=dev",
                    &format!("--kube-api-server={}", api.url()),
                    &format!("--kube-ca-file={}", ca_file.display()),
                    &format!("--kube-token-file={}", token_file.display()),
                ],
            )
            .await;
        let env = Self {
            d,
            api,
            worker,
            admin,
            token_file,
            policy_version: applied.version,
        };
        env.wait_for_policy(&env.worker).await;
        Some(env)
    }

    pub async fn wait_for_policy(&self, worker: &RunningWorker) {
        eventually(Duration::from_secs(20), "tunnels and policy", || async {
            self.d.proxy().policy_version() == Some(self.policy_version)
                && worker.worker.policy_version() == Some(self.policy_version)
                && !self.d.proxy().tunnels.summaries().is_empty()
        })
        .await;
    }

    /// A second worker with a label and no cluster, for "this worker does not
    /// serve Kubernetes".
    pub async fn start_plain_worker(&mut self) -> RunningWorker {
        let token = join_token(&mut self.admin, "plain").await;
        let worker = self.d.start_worker(&token, "plain-worker").await;
        self.wait_for_policy(&worker).await;
        worker
    }
}

pub async fn join_token(admin: &mut AdminClient<Channel>, pool: &str) -> String {
    admin
        .create_join_token(CreateJoinTokenRequest {
            kind: "worker".into(),
            ttl_seconds: 600,
            labels: HashMap::from([("pool".to_owned(), pool.to_owned())]),
            dns_names: vec![],
            name: String::new(),
        })
        .await
        .expect("token")
        .into_inner()
        .token
}

pub type Client = hyper::client::conn::http1::SendRequest<Empty<Bytes>>;

/// An HTTP/1.1 connection to the proxy at `addr`, presenting `identity` if given.
pub async fn connect(d: &Deployment, addr: SocketAddr, identity: Option<Identity>) -> Client {
    let roots =
        limen_tunnel::tls::certs_from_pem(&std::fs::read_to_string(d.ca_file()).expect("ca"))
            .expect("roots");
    let tls = client_config(&roots, identity, &[limen_tunnel::alpn::HTTP1]).expect("tls");
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp");
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

pub fn get(path: &str) -> Request<Empty<Bytes>> {
    Request::get(path)
        .header("host", "localhost")
        .body(Empty::<Bytes>::new())
        .expect("request")
}

pub async fn text(response: http::Response<hyper::body::Incoming>) -> (StatusCode, String) {
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

pub fn read_jsonl(d: &Deployment) -> Vec<serde_json::Value> {
    std::fs::read_to_string(d.dir.path().join("audit/control-plane.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect()
}

/// The upgrade request `kubectl exec` makes over WebSocket.
pub fn exec_upgrade(path: &str) -> Request<Empty<Bytes>> {
    Request::get(path)
        .header("host", "localhost")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-protocol", "v4.channel.k8s.io")
        .body(Empty::<Bytes>::new())
        .expect("request")
}

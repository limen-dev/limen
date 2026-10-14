//! A whole Limen deployment in one process, for end-to-end tests.

#![allow(clippy::missing_panics_doc, clippy::must_use_candidate, clippy::similar_names)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use limen_proto::v1::LoginFlow;
use limen_testkit::idp::{Claims, MockIdp};
use limen_tunnel::connect::{SharedClientConfig, channel};
use limen_tunnel::tls::{Identity, client_config};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData};
use sqlx::Connection;
use tokio::sync::watch;
use tonic::transport::Channel;

pub const CLIENT_ID: &str = "limen-cli";
pub const PROXY_TOKEN: &str = "e2e-static-proxy-token-0123456789abcdef";

#[derive(Parser)]
struct Args<C: clap::Args> {
    #[command(flatten)]
    config: C,
}

fn parse<C: clap::Args>(args: &[String]) -> C {
    let mut argv = vec!["test".to_owned()];
    argv.extend_from_slice(args);
    Args::<C>::try_parse_from(argv)
        .expect("valid test config")
        .config
}

#[derive(Debug)]
pub struct Deployment {
    pub dir: tempfile::TempDir,
    pub idp: MockIdp,
    pub cp_addr: SocketAddr,
    pub proxy_addr: SocketAddr,
    pub proxy: Option<RunningProxy>,
    _cp_shutdown: watch::Sender<bool>,
}

#[derive(Debug)]
pub struct RunningProxy {
    pub proxy: limen_proxy::Proxy,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

#[derive(Debug)]
pub struct RunningWorker {
    pub worker: limen_worker::Worker,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl RunningWorker {
    pub async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = self.task.await;
    }
}

impl Deployment {
    /// Start a control plane and one proxy. `None` without a test database.
    pub async fn start() -> Option<Self> {
        let base = limen_testkit::database_url()?;
        let mut conn = sqlx::PgConnection::connect(&base).await.expect("connect");
        let name = format!("limen_e2e_{}", uuid::Uuid::now_v7().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut conn)
            .await
            .expect("create db");
        let db_url = format!("{}/{name}", base.rsplit_once('/').expect("url").0);

        let dir = limen_testkit::temp_dir().expect("tempdir");
        let idp = MockIdp::start(CLIENT_ID).await;
        let cp_config: limen_control_plane::Config = parse(&[
            "--id=cp-e2e".into(),
            format!("--database-url={db_url}"),
            format!("--ca-dir={}", dir.path().join("ca").display()),
            format!("--ca-export-dir={}", dir.path().join("ca-public").display()),
            format!("--oidc-issuer={}", idp.issuer),
            format!("--oidc-client-id={CLIENT_ID}"),
            "--bootstrap-admin-group=admins".into(),
            format!("--static-join-token=proxy:{PROXY_TOKEN}"),
            "--proxy-dns-name=localhost".into(),
            format!(
                "--audit-file={}",
                dir.path().join("audit/control-plane.jsonl").display()
            ),
            "--admin-listen=127.0.0.1:0".into(),
        ]);
        let state = limen_control_plane::build_state(cp_config)
            .await
            .expect("control plane state");
        let cp_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let cp_addr = cp_listener.local_addr().expect("addr");
        let (cp_tx, cp_rx) = watch::channel(false);
        tokio::spawn(limen_control_plane::run(state, cp_listener, cp_rx));

        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let proxy_addr = proxy_listener.local_addr().expect("addr");
        let mut deployment = Self {
            dir,
            idp,
            cp_addr,
            proxy_addr,
            proxy: None,
            _cp_shutdown: cp_tx,
        };
        deployment.proxy = Some(deployment.start_proxy(proxy_listener).await);
        Some(deployment)
    }

    pub fn ca_file(&self) -> PathBuf {
        self.dir.path().join("ca-public/internal-ca.pem")
    }

    async fn start_proxy(&self, listener: tokio::net::TcpListener) -> RunningProxy {
        let config: limen_proxy::Config = parse(&[
            format!("--control-plane-addr={}", self.cp_addr),
            format!("--ca-file={}", self.ca_file().display()),
            format!("--join-token={PROXY_TOKEN}"),
            format!("--data-dir={}", self.dir.path().join("proxy").display()),
            "--admin-listen=127.0.0.1:0".into(),
            "--drain-timeout-secs=1".into(),
        ]);
        let (proxy, creds_tx) = limen_proxy::Proxy::start(config)
            .await
            .expect("proxy start");
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(limen_proxy::run(proxy.clone(), creds_tx, listener, rx));
        RunningProxy {
            proxy,
            shutdown: tx,
            task,
        }
    }

    /// Stop the proxy (as SIGTERM would) and start a new one on the same port.
    pub async fn restart_proxy(&mut self) {
        if let Some(running) = self.proxy.take() {
            let _ = running.shutdown.send(true);
            running.task.await.expect("proxy task").expect("proxy run");
        }
        let listener = tokio::net::TcpListener::bind(self.proxy_addr)
            .await
            .expect("rebind proxy port");
        self.proxy = Some(self.start_proxy(listener).await);
    }

    pub fn proxy(&self) -> &limen_proxy::Proxy {
        &self.proxy.as_ref().expect("proxy running").proxy
    }

    pub async fn start_worker(&self, join_token: &str, name: &str) -> RunningWorker {
        let config: limen_worker::Config = parse(&[
            format!("--proxy-addr={}", self.proxy_addr),
            format!("--ca-file={}", self.ca_file().display()),
            format!("--join-token={join_token}"),
            format!("--data-dir={}", self.dir.path().join(name).display()),
            "--admin-listen=127.0.0.1:0".into(),
            "--drain-timeout=1s".into(),
        ]);
        let (worker, creds_tx) = limen_worker::Worker::start(config)
            .await
            .expect("worker start");
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(limen_worker::run(worker.clone(), creds_tx, rx));
        RunningWorker {
            worker,
            shutdown: tx,
            task,
        }
    }

    /// A channel to the proxy's API, as the CLI would open it.
    pub fn proxy_channel(&self, identity: Option<Identity>) -> Channel {
        let roots = limen_tunnel::tls::certs_from_pem(
            &std::fs::read_to_string(self.ca_file()).expect("ca"),
        )
        .expect("roots");
        let tls = client_config(&roots, identity, &[limen_tunnel::alpn::H2]).expect("tls");
        channel(
            &self.proxy_addr.to_string(),
            "localhost",
            SharedClientConfig::new(tls),
        )
    }

    /// Log in through the proxy, as the CLI does. Returns a TLS identity.
    pub async fn login(&self, email: &str, groups: &[&str]) -> Result<Identity, tonic::Status> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let csr = CertificateParams::default()
            .serialize_request(&key)
            .expect("csr")
            .der()
            .to_vec();
        let salt = vec![5u8; 32];
        let nonce = limen_control_plane::services::auth::expected_nonce(
            &key.subject_public_key_info(),
            &salt,
        );
        let token = self
            .idp
            .id_token(&Claims::user(email, groups).with_nonce(&nonce));
        let resp = limen_proto::v1::auth_client::AuthClient::new(self.proxy_channel(None))
            .login(limen_proto::v1::LoginRequest {
                id_token: token,
                csr_der: csr,
                nonce_salt: salt,
                flow: LoginFlow::Pkce.into(),
            })
            .await?
            .into_inner();
        Ok(Identity::from_pem(&resp.cert_pem, &key.serialize_pem()).expect("identity"))
    }
}

/// Poll `check` until it returns true or `timeout` passes.
pub async fn eventually<F, Fut>(timeout: Duration, what: &str, check: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out after {timeout:?} waiting for {what}");
}

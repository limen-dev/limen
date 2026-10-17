//! A whole Limen deployment in one process, for end-to-end tests.

#![allow(
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::similar_names
)]

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
pub const CONSOLE_CLIENT_ID: &str = "limen-console";
pub const CONSOLE_SECRET: &str = "e2e-console-client-secret";
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
    cp_shutdown: watch::Sender<bool>,
    cp_task: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
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
        Self::start_inner(false).await
    }

    /// Like [`start`](Self::start), with the web console enabled. Its public
    /// URL is `https://localhost:<proxy port>`, and the mock IdP knows the
    /// console's OIDC client ([`CONSOLE_CLIENT_ID`], [`CONSOLE_SECRET`]).
    pub async fn start_with_console() -> Option<Self> {
        Self::start_inner(true).await
    }

    async fn start_inner(console: bool) -> Option<Self> {
        if std::env::var_os("LIMEN_TEST_LOG").is_some() {
            limen_core::telemetry::init(limen_core::telemetry::LogFormat::Text);
        }
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
        // The console's public URL needs the proxy's port, so bind it first.
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let proxy_addr = proxy_listener.local_addr().expect("addr");
        let mut console_args = Vec::new();
        if console {
            idp.set_browser_client(CONSOLE_CLIENT_ID, CONSOLE_SECRET);
            console_args.push(format!(
                "--console-public-url=https://localhost:{}",
                proxy_addr.port()
            ));
            console_args.push(format!("--console-oidc-client-secret={CONSOLE_SECRET}"));
        }
        let mut cp_args = vec!["--id=cp-e2e".to_owned(), format!("--database-url={db_url}")];
        cp_args.extend(console_args);
        cp_args.extend([
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
            format!(
                "--audit-spool-dir={}",
                dir.path().join("cp-spool").display()
            ),
            format!(
                "--recordings-dir={}",
                dir.path().join("recordings").display()
            ),
            "--admin-listen=127.0.0.1:0".into(),
            "--drain-timeout=0s".into(),
            // The mock issuer is plain http.
            "--bot-allow-insecure-issuers".into(),
        ]);
        let cp_config: limen_control_plane::Config = parse(&cp_args);
        let state = limen_control_plane::build_state(cp_config)
            .await
            .expect("control plane state");
        let cp_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let cp_addr = cp_listener.local_addr().expect("addr");
        let (cp_tx, cp_rx) = watch::channel(false);
        let cp_task = tokio::spawn(limen_control_plane::run(state, cp_listener, cp_rx));

        let mut deployment = Self {
            dir,
            idp,
            cp_addr,
            proxy_addr,
            proxy: None,
            cp_shutdown: cp_tx,
            cp_task: Some(cp_task),
        };
        deployment.proxy = Some(deployment.start_proxy(proxy_listener).await);
        Some(deployment)
    }

    pub fn ca_file(&self) -> PathBuf {
        self.dir.path().join("ca-public/internal-ca.pem")
    }

    /// An exported public CA file, such as `ssh-user-ca.pub` or `ssh-host-ca.pub`.
    pub fn public_ca(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.path().join("ca-public").join(name)).expect("exported CA")
    }

    /// Stop the control plane abruptly: no drain, open connections are cut.
    pub async fn stop_control_plane(&mut self) {
        let _ = self.cp_shutdown.send(true);
        if let Some(task) = self.cp_task.take() {
            let _ = task.await;
        }
    }

    async fn start_proxy(&self, listener: tokio::net::TcpListener) -> RunningProxy {
        self.start_named_proxy(listener, "proxy").await
    }

    /// Another proxy, with its own identity and data directory. Returns it
    /// and the address it listens on.
    pub async fn start_extra_proxy(&self, name: &str) -> (RunningProxy, SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        (self.start_named_proxy(listener, name).await, addr)
    }

    async fn start_named_proxy(
        &self,
        listener: tokio::net::TcpListener,
        name: &str,
    ) -> RunningProxy {
        let addr = listener.local_addr().expect("addr");
        let config: limen_proxy::Config = parse(&[
            format!("--control-plane-addr={}", self.cp_addr),
            format!("--ca-file={}", self.ca_file().display()),
            format!("--join-token={PROXY_TOKEN}"),
            format!("--data-dir={}", self.dir.path().join(name).display()),
            format!("--peer-address={addr}"),
            "--admin-listen=127.0.0.1:0".into(),
            "--drain-timeout-secs=1".into(),
            "--policy-refresh-secs=1".into(),
            "--policy-grace-secs=3".into(),
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
        self.start_worker_with(join_token, name, &[]).await
    }

    /// A worker with extra command-line flags, for example a Kubernetes cluster.
    pub async fn start_worker_with(
        &self,
        join_token: &str,
        name: &str,
        extra: &[String],
    ) -> RunningWorker {
        let mut args = vec![
            format!("--proxy-addr={}", self.proxy_addr),
            format!("--ca-file={}", self.ca_file().display()),
            format!("--join-token={join_token}"),
            format!("--data-dir={}", self.dir.path().join(name).display()),
            "--admin-listen=127.0.0.1:0".into(),
            "--drain-timeout=1s".into(),
            "--policy-refresh=1s".into(),
            "--policy-grace=3s".into(),
        ];
        args.extend_from_slice(extra);
        let config: limen_worker::Config = parse(&args);
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

    /// Log a bot in through the proxy with a workload identity token, as
    /// `limen login --bot` does. Returns a TLS identity.
    pub async fn bot_login(&self, method: &str, token: String) -> Result<Identity, tonic::Status> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let csr = CertificateParams::default()
            .serialize_request(&key)
            .expect("csr")
            .der()
            .to_vec();
        let resp = limen_proto::v1::auth_client::AuthClient::new(self.proxy_channel(None))
            .bot_login(limen_proto::v1::BotLoginRequest {
                method: method.into(),
                token,
                csr_der: csr,
                bot: String::new(),
            })
            .await?
            .into_inner();
        Ok(Identity::from_pem(&resp.cert_pem, &key.serialize_pem()).expect("identity"))
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

/// An SSH client doing what `limen ssh` makes OpenSSH do: mTLS to the proxy,
/// the session handshake, then SSH to the worker, checking its host
/// certificate against the Limen SSH host CA and authenticating with `none`.
pub mod ssh_client {
    use std::sync::Arc;

    use limen_proto::v1::{SessionRequest, SessionResponse};
    use limen_tunnel::connect::dial;
    use limen_tunnel::framing::{read_message, write_message};
    use limen_tunnel::tls::{Identity, client_config};
    use russh::keys::{HashAlg, PublicKey, PublicKeyOrCertificate};
    use russh::{ChannelMsg, client};

    #[derive(Debug)]
    pub struct HostCheck {
        pub host_ca: PublicKey,
        pub host_name: String,
    }

    impl client::Handler for HostCheck {
        type Error = russh::Error;

        #[allow(clippy::unused_async_trait_impl)] // the trait method is async
        async fn check_server_key(
            &mut self,
            server: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(match server {
                PublicKeyOrCertificate::Certificate(cert) => {
                    cert.cert_type().is_host()
                        && cert
                            .validate([&self.host_ca.fingerprint(HashAlg::Sha256)])
                            .is_ok()
                        && cert.valid_principals().contains(&self.host_name)
                }
                PublicKeyOrCertificate::PublicKey { .. } => false,
            })
        }
    }

    /// Open an SSH connection to `resource` as `login` through the proxy.
    /// `Err` carries the proxy's refusal message, or the SSH failure.
    pub async fn connect(
        proxy_addr: &str,
        ca_pem: &str,
        identity: Identity,
        host_ca_openssh: &str,
        resource: &str,
        login: &str,
    ) -> Result<client::Handle<HostCheck>, String> {
        let roots = limen_tunnel::tls::certs_from_pem(ca_pem).map_err(|e| e.to_string())?;
        let tls_config = client_config(&roots, Some(identity), &[limen_tunnel::alpn::SSH])
            .map_err(|e| e.to_string())?;
        let mut tls = dial(proxy_addr, "localhost", Arc::new(tls_config))
            .await
            .map_err(|e| e.to_string())?;
        write_message(
            &mut tls,
            &SessionRequest {
                resource: resource.into(),
                principal: login.into(),
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        let response: SessionResponse = read_message(&mut tls).await.map_err(|e| e.to_string())?;
        if !response.ok {
            return Err(response.error);
        }
        let handler = HostCheck {
            host_ca: PublicKey::from_openssh(host_ca_openssh.trim()).map_err(|e| e.to_string())?,
            host_name: resource.into(),
        };
        // Ask for the host certificate, as OpenSSH does for hosts with an
        // @cert-authority entry in known_hosts.
        let config = client::Config {
            preferred: russh::Preferred {
                host_key_certificates: std::borrow::Cow::Borrowed(&[
                    russh::keys::Algorithm::Ed25519,
                ]),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut handle = client::connect_stream(Arc::new(config), tls, handler)
            .await
            .map_err(|e| format!("ssh: {e}"))?;
        let auth = handle
            .authenticate_none(login)
            .await
            .map_err(|e| format!("ssh auth: {e}"))?;
        if !auth.success() {
            return Err("ssh: authentication rejected".into());
        }
        Ok(handle)
    }

    /// Run a command and collect (stdout, exit status).
    pub async fn exec(
        handle: &client::Handle<HostCheck>,
        command: &str,
    ) -> Result<(String, Option<u32>), String> {
        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| e.to_string())?;
        channel
            .exec(true, command)
            .await
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        let mut status = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => out.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok((String::from_utf8_lossy(&out).into_owned(), status))
    }
}

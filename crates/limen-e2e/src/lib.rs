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
use limen_tunnel::connect::TracedChannel as Channel;
use limen_tunnel::connect::{SharedClientConfig, channel};
use limen_tunnel::tls::{Identity, client_config};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData};
use sqlx::Connection;
use tokio::sync::watch;

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
    /// What proxies dial to reach the control plane: `cp_addr`, or a name
    /// resolved by [`limen_tunnel::connect::set_test_resolution`] (see
    /// [`Deployment::start_scaled`]).
    pub cp_dial: String,
    /// Control plane flags shared by every replica (not `--id` or paths).
    cp_args: Vec<String>,
    /// Extra flags for every proxy this deployment starts.
    proxy_args: Vec<String>,
    /// When the deployment started, if its proxies report to the registry
    /// less often than release builds allow (see [`Self::check_registry_lease`]).
    rare_reports_since: Option<std::time::Instant>,
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

impl RunningProxy {
    /// Tell the proxy to stop, as SIGTERM does, without waiting: it drains.
    pub fn begin_stop(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Whether the proxy's `run` has returned.
    pub fn has_stopped(&self) -> bool {
        self.task.is_finished()
    }
}

#[derive(Debug)]
pub struct RunningWorker {
    pub worker: limen_worker::Worker,
    /// Its `--data-dir`.
    pub data_dir: PathBuf,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

/// A control plane replica started next to the deployment's own.
#[derive(Debug)]
pub struct RunningControlPlane {
    pub addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl RunningControlPlane {
    pub async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = self.task.await;
    }
}

impl RunningWorker {
    pub async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = self.task.await;
    }

    /// Tell the worker to stop, as SIGTERM does, without waiting: it drains.
    pub fn begin_stop(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Whether the worker's `run` has returned.
    pub fn has_stopped(&self) -> bool {
        self.task.is_finished()
    }
}

impl Deployment {
    /// Start a control plane and one proxy. `None` without a test database.
    pub async fn start() -> Option<Self> {
        Self::start_inner(false, &[], false, &[]).await
    }

    /// Like [`start`](Self::start), with extra flags for every proxy, such
    /// as `--ping-interval-secs=3600`.
    pub async fn start_with_proxy_args(proxy_args: &[&str]) -> Option<Self> {
        let extra: Vec<String> = proxy_args.iter().map(|&a| a.to_owned()).collect();
        Self::start_inner(false, &[], false, &extra).await
    }

    /// Like [`start`](Self::start), with extra flags for every control plane
    /// (`cp_args`) and every proxy (`proxy_args`).
    pub async fn start_with_args(cp_args: &[&str], proxy_args: &[&str]) -> Option<Self> {
        let cp: Vec<String> = cp_args.iter().map(|&a| a.to_owned()).collect();
        let proxy: Vec<String> = proxy_args.iter().map(|&a| a.to_owned()).collect();
        Self::start_inner(false, &cp, false, &proxy).await
    }

    /// For tests with several control plane replicas: proxies dial a name
    /// that resolves (through the test hook) to the first replica until the
    /// test says otherwise. `cp_args` go to every replica.
    pub async fn start_scaled(cp_args: &[&str]) -> Option<Self> {
        let extra: Vec<String> = cp_args.iter().map(|&a| a.to_owned()).collect();
        Self::start_inner(false, &extra, true, &[]).await
    }

    /// Like [`start`](Self::start), with the web console enabled. Its public
    /// URL is `https://localhost:<proxy port>`, and the mock IdP knows the
    /// console's OIDC client ([`CONSOLE_CLIENT_ID`], [`CONSOLE_SECRET`]).
    pub async fn start_with_console() -> Option<Self> {
        Self::start_inner(true, &[], false, &[]).await
    }

    async fn start_inner(
        console: bool,
        extra_cp_args: &[String],
        named: bool,
        proxy_args: &[String],
    ) -> Option<Self> {
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
        let mut cp_args = vec![format!("--database-url={db_url}")];
        cp_args.extend(console_args);
        cp_args.extend([
            format!("--ca-dir={}", dir.path().join("ca").display()),
            format!("--ca-export-dir={}", dir.path().join("ca-public").display()),
            format!("--oidc-issuer={}", idp.issuer),
            format!("--oidc-client-id={CLIENT_ID}"),
            "--bootstrap-admin-group=admins".into(),
            // Proxies may pick any name with --name (none by default).
            format!("--static-join-token=proxy:{PROXY_TOKEN}:limen.io/name=*"),
            "--proxy-dns-name=localhost".into(),
            format!(
                "--recordings-dir={}",
                dir.path().join("recordings").display()
            ),
            "--admin-listen=127.0.0.1:0".into(),
            "--drain-timeout=0s".into(),
            // The mock issuer is plain http.
            "--bot-allow-insecure-issuers".into(),
        ]);
        cp_args.extend_from_slice(extra_cp_args);
        let (cp_addr, cp_tx, cp_task) =
            spawn_control_plane(&cp_args, dir.path(), "cp-e2e", "control-plane", "cp-spool").await;
        let cp_dial = if named {
            let name = format!("cp-{}.limen.test:3080", uuid::Uuid::now_v7().simple());
            limen_tunnel::connect::set_test_resolution(&name, vec![cp_addr]);
            name
        } else {
            cp_addr.to_string()
        };

        let mut deployment = Self {
            dir,
            idp,
            cp_addr,
            cp_dial,
            cp_args,
            proxy_args: proxy_args.to_vec(),
            rare_reports_since: rare_reports(proxy_args).then(std::time::Instant::now),
            proxy_addr,
            proxy: None,
            cp_shutdown: cp_tx,
            cp_task: Some(cp_task),
        };
        deployment.proxy = Some(deployment.start_proxy(proxy_listener).await);
        Some(deployment)
    }

    /// With a report interval past the release cap, proxies renew their
    /// registry leases only when a tunnel changes, so a test must finish
    /// well within the lease or peers lose the tunnels. Fails fast, with a
    /// clear message, once such a deployment is 30 s old.
    pub fn check_registry_lease(&self) {
        if let Some(since) = self.rare_reports_since {
            let age = since.elapsed();
            assert!(
                age < RARE_REPORTS_MAX_AGE,
                "this test runs its proxies with a long --report-interval-secs and is {age:?} old: \
                 past {RARE_REPORTS_MAX_AGE:?}, the {}s registry leases may expire mid-test; \
                 make the test shorter",
                limen_core::registry::TUNNEL_LEASE_SECS
            );
        }
    }

    pub fn ca_file(&self) -> PathBuf {
        self.dir.path().join("ca-public/internal-ca.pem")
    }

    /// An exported public CA file, such as `ssh-user-ca.pub` or `ssh-host-ca.pub`.
    pub fn public_ca(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.path().join("ca-public").join(name)).expect("exported CA")
    }

    /// Start another control plane replica on the same database and CA.
    /// Proxies reach it only once the test adds its address to
    /// [`cp_dial`](Self::cp_dial)'s resolution.
    pub async fn start_extra_control_plane(&self, id: &str) -> RunningControlPlane {
        let (addr, shutdown, task) = spawn_control_plane(
            &self.cp_args,
            self.dir.path(),
            id,
            id,
            &format!("{id}-spool"),
        )
        .await;
        RunningControlPlane {
            addr,
            shutdown,
            task,
        }
    }

    /// Stop the control plane abruptly: no drain, open connections are cut.
    pub async fn stop_control_plane(&mut self) {
        let _ = self.cp_shutdown.send(true);
        if let Some(task) = self.cp_task.take() {
            let _ = task.await;
        }
    }

    async fn start_proxy(&self, listener: tokio::net::TcpListener) -> RunningProxy {
        self.start_named_proxy(listener, "proxy", &[]).await
    }

    /// Another proxy, with its own identity and data directory. Returns it
    /// and the address it listens on.
    pub async fn start_extra_proxy(&self, name: &str) -> (RunningProxy, SocketAddr) {
        self.start_extra_proxy_with(name, &[]).await
    }

    /// [`start_extra_proxy`](Self::start_extra_proxy) with extra flags for
    /// this proxy only, such as `--name=proxy-b`. They replace the
    /// deployment's proxy flags they repeat.
    pub async fn start_extra_proxy_with(
        &self,
        name: &str,
        extra: &[&str],
    ) -> (RunningProxy, SocketAddr) {
        self.check_registry_lease();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        (self.start_named_proxy(listener, name, extra).await, addr)
    }

    async fn start_named_proxy(
        &self,
        listener: tokio::net::TcpListener,
        name: &str,
        extra: &[&str],
    ) -> RunningProxy {
        let addr = listener.local_addr().expect("addr");
        let mut args = vec![
            format!("--control-plane-addr={}", self.cp_dial),
            format!("--ca-file={}", self.ca_file().display()),
            format!("--join-token={PROXY_TOKEN}"),
            format!("--data-dir={}", self.dir.path().join(name).display()),
            format!("--peer-address={addr}"),
            "--admin-listen=127.0.0.1:0".into(),
            "--drain-timeout-secs=1".into(),
            "--policy-refresh-secs=1".into(),
            "--policy-grace-secs=3".into(),
        ];
        // This proxy's own flags replace the deployment's that they repeat.
        let flag = |a: &str| a.split('=').next().unwrap_or_default().to_owned();
        let own: Vec<String> = extra.iter().map(|a| flag(a)).collect();
        args.extend(
            self.proxy_args
                .iter()
                .filter(|a| !own.contains(&flag(a)))
                .cloned(),
        );
        args.extend(extra.iter().map(|&a| a.to_owned()));
        let config: limen_proxy::Config = parse(&args);
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

    /// [`start_worker`](Self::start_worker) with extra flags, such as
    /// `--max-sessions=1` or `--drain-timeout-secs=20` (default here: 1).
    pub async fn start_worker_with(
        &self,
        join_token: &str,
        name: &str,
        extra: &[&str],
    ) -> RunningWorker {
        let data_dir = self.dir.path().join(name);
        let mut args = vec![
            format!("--proxy-addr={}", self.proxy_addr),
            format!("--ca-file={}", self.ca_file().display()),
            format!("--join-token={join_token}"),
            format!("--data-dir={}", data_dir.display()),
            "--admin-listen=127.0.0.1:0".into(),
            "--policy-refresh=1s".into(),
            "--policy-grace=3s".into(),
        ];
        if !extra.iter().any(|a| a.starts_with("--drain-timeout-secs")) {
            args.push("--drain-timeout-secs=1".into());
        }
        args.extend(extra.iter().map(|&a| a.to_owned()));
        let config: limen_worker::Config = parse(&args);
        let (worker, creds_tx) = limen_worker::Worker::start(config)
            .await
            .expect("worker start");
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(limen_worker::run(worker.clone(), creds_tx, rx));
        RunningWorker {
            worker,
            data_dir,
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
        let (cert_pem, key_pem) = self.login_pem(email, groups).await?;
        Ok(Identity::from_pem(&cert_pem, &key_pem).expect("identity"))
    }

    /// Like [`login`](Self::login), returning the certificate and private key
    /// as PEM, which is what the CLI stores in a profile.
    pub async fn login_pem(
        &self,
        email: &str,
        groups: &[&str],
    ) -> Result<(String, String), tonic::Status> {
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
        Ok((resp.cert_pem, key.serialize_pem()))
    }
}

/// How long a deployment whose proxies report rarely may run (see
/// [`Deployment::check_registry_lease`]): well within the registry lease.
const RARE_REPORTS_MAX_AGE: Duration = Duration::from_secs(30);

/// Whether `proxy_args` set a report interval past the release cap.
fn rare_reports(proxy_args: &[String]) -> bool {
    proxy_args.iter().any(|a| {
        a.strip_prefix("--report-interval-secs=")
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|v| v > limen_core::registry::MAX_REPORT_INTERVAL_SECS)
    })
}

/// Start a control plane replica with `args` plus its own id, audit file,
/// and spool under `dir`.
async fn spawn_control_plane(
    args: &[String],
    dir: &std::path::Path,
    id: &str,
    audit_name: &str,
    spool: &str,
) -> (
    SocketAddr,
    watch::Sender<bool>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let mut args = args.to_vec();
    args.extend([
        format!("--id={id}"),
        format!(
            "--audit-file={}",
            dir.join(format!("audit/{audit_name}.jsonl")).display()
        ),
        format!("--audit-spool-dir={}", dir.join(spool).display()),
    ]);
    let config: limen_control_plane::Config = parse(&args);
    let state = limen_control_plane::build_state(config)
        .await
        .expect("control plane state");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(limen_control_plane::run(state, listener, rx));
    (addr, tx, task)
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
                database: String::new(),
                group: String::new(),
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

#[cfg(test)]
mod tests {
    #[test]
    fn only_report_intervals_past_the_release_cap_count_as_rare() {
        let args = |a: &[&str]| a.iter().map(|&s| s.to_owned()).collect::<Vec<_>>();
        assert!(super::rare_reports(&args(&["--report-interval-secs=3600"])));
        assert!(super::rare_reports(&args(&[
            "--x",
            "--report-interval-secs=16"
        ])));
        assert!(!super::rare_reports(&args(&["--report-interval-secs=15"])));
        assert!(!super::rare_reports(&args(&["--ping-interval-secs=3600"])));
        assert!(!super::rare_reports(&[]));
    }
}

/// What a database client of `limen db connect` does, for tests: a loopback
/// listener whose every connection becomes one session through the proxy.
pub mod db_client {
    use std::sync::Arc;

    use limen_proto::v1::{SessionRequest, SessionResponse};
    use limen_tunnel::framing::{read_message, write_message};
    use limen_tunnel::tls::{Identity, certs_from_pem, client_config};

    /// Listen on a free loopback port. Connections the proxy refuses are
    /// closed after the refusal is stored in `errors`.
    pub async fn listen(
        proxy_addr: &str,
        ca_pem: &str,
        identity: Identity,
        resource: &str,
        role: &str,
        database: &str,
    ) -> (std::net::SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
        listen_on(
            proxy_addr,
            ca_pem,
            identity,
            limen_tunnel::alpn::DB,
            resource,
            role,
            database,
        )
        .await
    }

    /// The same for another protocol's ALPN (`limen-mongo/1`).
    pub async fn listen_on(
        proxy_addr: &str,
        ca_pem: &str,
        identity: Identity,
        alpn: &[u8],
        resource: &str,
        role: &str,
        database: &str,
    ) -> (std::net::SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
        let tls = Arc::new(
            client_config(
                &certs_from_pem(ca_pem).expect("ca"),
                Some(identity),
                &[alpn],
            )
            .expect("tls"),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let errors = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (proxy_addr, resource, role, database) = (
            proxy_addr.to_owned(),
            resource.to_owned(),
            role.to_owned(),
            database.to_owned(),
        );
        let seen = Arc::clone(&errors);
        tokio::spawn(async move {
            loop {
                let Ok((mut local, _)) = listener.accept().await else {
                    return;
                };
                let (tls, proxy_addr, seen) =
                    (Arc::clone(&tls), proxy_addr.clone(), Arc::clone(&seen));
                let request = SessionRequest {
                    resource: resource.clone(),
                    principal: role.clone(),
                    database: database.clone(),
                    group: String::new(),
                };
                tokio::spawn(async move {
                    let mut remote = limen_tunnel::connect::dial(&proxy_addr, "localhost", tls)
                        .await
                        .expect("dial the proxy");
                    write_message(&mut remote, &request).await.expect("request");
                    let response: SessionResponse =
                        read_message(&mut remote).await.expect("answer");
                    if !response.ok {
                        seen.lock().expect("lock").push(response.error);
                        return;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
                });
            }
        });
        (addr, errors)
    }
}

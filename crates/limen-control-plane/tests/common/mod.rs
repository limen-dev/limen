//! Harness: a control plane on a fresh database with a mock IdP, plus
//! helpers that act as the CLI, a proxy, and a worker.

#![allow(dead_code, clippy::missing_panics_doc)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use clap::Parser;
use limen_control_plane::state::AppState;
use limen_control_plane::{Config, build_state, run};
use limen_proto::relay;
use limen_testkit::idp::MockIdp;
use limen_tunnel::connect::{SharedClientConfig, channel};
use limen_tunnel::tls::{Identity, client_config};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData};
use rustls_pki_types::CertificateDer;
use sqlx::Connection;
use tokio::sync::watch;
use tonic::transport::Channel;

pub const CLIENT_ID: &str = "limen-cli";
pub const STATIC_PROXY_TOKEN: &str = "static-proxy-token-0123456789abcdef0123456789";

pub struct Harness {
    pub state: AppState,
    pub addr: SocketAddr,
    pub idp: MockIdp,
    pub audit_file: PathBuf,
    /// Shared with peers started by [`Harness::start_peer`].
    pub db_url: String,
    pub ca_dir: PathBuf,
    _dir: tempfile::TempDir,
    shutdown: watch::Sender<bool>,
    run_task: std::sync::Mutex<Option<tokio::task::JoinHandle<anyhow::Result<()>>>>,
}

#[derive(clap::Parser)]
struct Wrapper {
    #[command(flatten)]
    config: Config,
}

/// Create an empty database next to the one in `LIMEN_TEST_DATABASE_URL`.
async fn fresh_database(base: &str) -> String {
    let mut conn = sqlx::PgConnection::connect(base)
        .await
        .expect("connect to test database");
    let name = format!("limen_test_{}", uuid::Uuid::now_v7().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&mut conn)
        .await
        .expect("create database");
    let (prefix, _) = base.rsplit_once('/').expect("database URL has a path");
    format!("{prefix}/{name}")
}

impl Harness {
    /// Returns `None` (and the test should return) if no test database is configured.
    pub async fn start() -> Option<Self> {
        Self::start_with(&[]).await
    }

    /// Start with extra control plane flags.
    pub async fn start_with(extra: &[String]) -> Option<Self> {
        let base = limen_testkit::database_url()?;
        let db_url = fresh_database(&base).await;
        Some(Self::start_on(db_url, None, extra).await)
    }

    /// Another replica on this one's database and CA keys. Give it its own `--id`.
    pub async fn start_peer(&self, extra: &[String]) -> Self {
        Self::start_on(self.db_url.clone(), Some(self.ca_dir.clone()), extra).await
    }

    async fn start_on(db_url: String, ca_dir: Option<PathBuf>, extra: &[String]) -> Self {
        if std::env::var_os("LIMEN_TEST_LOG").is_some() {
            limen_core::telemetry::init(limen_core::telemetry::LogFormat::Text);
        }
        let idp = MockIdp::start(CLIENT_ID).await;
        let dir = limen_testkit::temp_dir().expect("tempdir");
        let audit_file = dir.path().join("audit.jsonl");
        let ca_dir = ca_dir.unwrap_or_else(|| dir.path().join("ca"));
        // Bound first, so the replica registers the address it really serves.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let args = [
            "test".to_owned(),
            "--id=cp-test".into(),
            format!("--database-url={db_url}"),
            format!("--ca-dir={}", ca_dir.display()),
            format!("--oidc-issuer={}", idp.issuer),
            format!("--oidc-client-id={CLIENT_ID}"),
            "--bootstrap-admin-group=admins".into(),
            format!("--static-join-token=proxy:{STATIC_PROXY_TOKEN}"),
            "--proxy-dns-name=localhost".into(),
            format!("--audit-file={}", audit_file.display()),
            format!("--audit-spool-dir={}", dir.path().join("spool").display()),
            format!(
                "--recordings-dir={}",
                dir.path().join("recordings").display()
            ),
            "--admin-listen=127.0.0.1:0".into(),
            "--dns-name=localhost".into(),
            format!("--advertise-url=https://localhost:{}", addr.port()),
        ];
        // Extra flags replace the defaults they repeat.
        let flag = |a: &str| a.split('=').next().unwrap_or_default().to_owned();
        let overridden: Vec<String> = extra.iter().map(|a| flag(a)).collect();
        let args: Vec<String> = args
            .into_iter()
            .filter(|a| !overridden.contains(&flag(a)))
            .chain(extra.iter().cloned())
            .collect();
        let config = Wrapper::try_parse_from(args).expect("config").config;
        let state = build_state(config).await.expect("build state");
        let (tx, rx) = watch::channel(false);
        let run_task = tokio::spawn(run(state.clone(), listener, rx));
        Self {
            state,
            addr,
            idp,
            audit_file,
            db_url,
            ca_dir,
            _dir: dir,
            shutdown: tx,
            run_task: std::sync::Mutex::new(Some(run_task)),
        }
    }

    /// Start shutting the control plane down.
    pub fn begin_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Wait for `run` to return (after `begin_shutdown`).
    pub async fn finish(&self) -> anyhow::Result<()> {
        let task = self.run_task.lock().expect("lock").take();
        task.expect("run task").await.expect("join")
    }

    pub fn internal_ca(&self) -> CertificateDer<'static> {
        self.state.cas.internal.cert_der().clone()
    }

    /// A channel to the control plane, optionally presenting a client identity.
    pub fn channel(&self, identity: Option<Identity>) -> Channel {
        let config = client_config(&[self.internal_ca()], identity, &[limen_tunnel::alpn::H2])
            .expect("client config");
        channel(
            &self.addr.to_string(),
            "localhost",
            SharedClientConfig::new(config),
        )
    }

    /// Audit events written so far.
    /// Audit events written so far, once the JSONL sink has caught up.
    pub async fn audit_events(&self) -> Vec<limen_audit::Event> {
        for _ in 0..200 {
            if self
                .state
                .pipeline
                .spool
                .pending(limen_control_plane::pipeline::JSONL)
                == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        std::fs::read_to_string(&self.audit_file)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).expect("audit line is valid JSON"))
            .collect()
    }

    pub async fn audit_kinds(&self) -> Vec<limen_audit::EventKind> {
        self.audit_events()
            .await
            .into_iter()
            .map(|e| e.kind)
            .collect()
    }

    /// Enroll a proxy with the static token. Returns its identity.
    pub async fn enroll_proxy(&self) -> (String, Identity) {
        let key = new_key();
        let mut client =
            limen_proto::v1::enrollment_client::EnrollmentClient::new(self.channel(None));
        let resp = client
            .enroll(limen_proto::v1::EnrollRequest {
                join_token: STATIC_PROXY_TOKEN.into(),
                csr_der: csr(&key),
                kind: "proxy".into(),
                dns_names: vec!["localhost".into()],
                name: String::new(),
            })
            .await
            .expect("enroll proxy")
            .into_inner();
        (
            resp.component_id,
            Identity::from_pem(&resp.cert_pem, &key.serialize_pem()).expect("identity"),
        )
    }

    /// Log in through the mock IdP with the PKCE nonce binding. Returns the
    /// response and the user's certificate DER.
    pub async fn login(
        &self,
        email: &str,
        groups: &[&str],
    ) -> Result<(limen_proto::v1::LoginResponse, CertificateDer<'static>), tonic::Status> {
        let key = new_key();
        let salt = [7u8; 32];
        let nonce = limen_control_plane::services::auth::expected_nonce(
            &key.subject_public_key_info(),
            &salt,
        );
        let token = self
            .idp
            .id_token(&limen_testkit::idp::Claims::user(email, groups).with_nonce(&nonce));
        let resp = self
            .login_raw(
                token,
                csr(&key),
                salt.to_vec(),
                limen_proto::v1::LoginFlow::Pkce,
            )
            .await?;
        let der = limen_tunnel::tls::certs_from_pem(&resp.cert_pem)
            .expect("cert")
            .remove(0);
        Ok((resp, der))
    }

    /// Log a bot in with a workload identity token. Returns the response and
    /// the certificate DER.
    pub async fn bot_login(
        &self,
        method: &str,
        token: String,
        bot: &str,
    ) -> Result<(limen_proto::v1::LoginResponse, CertificateDer<'static>), tonic::Status> {
        let key = new_key();
        let mut client = limen_proto::v1::auth_client::AuthClient::new(self.channel(None));
        let resp = client
            .bot_login(limen_proto::v1::BotLoginRequest {
                method: method.into(),
                token,
                csr_der: csr(&key),
                bot: bot.into(),
            })
            .await?
            .into_inner();
        let der = limen_tunnel::tls::certs_from_pem(&resp.cert_pem)
            .expect("cert")
            .remove(0);
        Ok((resp, der))
    }

    /// Like [`bot_login`](Self::bot_login), with a CSR of the caller's choosing.
    pub async fn bot_login_with_csr(
        &self,
        method: &str,
        token: String,
        bot: &str,
        csr_der: Vec<u8>,
    ) -> Result<limen_proto::v1::LoginResponse, tonic::Status> {
        let mut client = limen_proto::v1::auth_client::AuthClient::new(self.channel(None));
        client
            .bot_login(limen_proto::v1::BotLoginRequest {
                method: method.into(),
                token,
                csr_der,
                bot: bot.into(),
            })
            .await
            .map(tonic::Response::into_inner)
    }

    /// Replace the active policy, as if an admin had applied it.
    pub fn set_policy(&self, yaml: &[(&str, &str)]) {
        let policy = limen_policy::Policy::parse_yaml(yaml.iter().copied()).expect("policy");
        self.state
            .policy
            .set(limen_control_plane::state::LoadedPolicy {
                version: 1,
                policy: std::sync::Arc::new(policy),
                author: "test".into(),
                created_at: None,
            });
    }

    pub async fn login_raw(
        &self,
        id_token: String,
        csr_der: Vec<u8>,
        nonce_salt: Vec<u8>,
        flow: limen_proto::v1::LoginFlow,
    ) -> Result<limen_proto::v1::LoginResponse, tonic::Status> {
        let mut client = limen_proto::v1::auth_client::AuthClient::new(self.channel(None));
        client
            .login(limen_proto::v1::LoginRequest {
                id_token,
                csr_der,
                nonce_salt,
                flow: flow.into(),
            })
            .await
            .map(tonic::Response::into_inner)
    }
}

pub fn new_key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key")
}

pub fn csr(key: &KeyPair) -> Vec<u8> {
    CertificateParams::default()
        .serialize_request(key)
        .expect("csr")
        .der()
        .to_vec()
}

/// Wrap a message as the proxy relays it: forwarded marker plus the client's cert.
pub fn forwarded<T>(message: T, client_cert: Option<&CertificateDer<'_>>) -> tonic::Request<T> {
    let mut req = tonic::Request::new(message);
    req.metadata_mut()
        .insert(relay::FORWARDED, "1".parse().expect("ascii"));
    req.metadata_mut().insert(
        relay::CLIENT_ADDR,
        "203.0.113.7:51000".parse().expect("ascii"),
    );
    if let Some(cert) = client_cert {
        let b64 = base64::engine::general_purpose::STANDARD.encode(cert.as_ref());
        req.metadata_mut()
            .insert(relay::CLIENT_CERT, b64.parse().expect("ascii"));
    }
    req
}

pub async fn wait_for<F: Fn() -> bool>(what: &str, f: F) {
    for _ in 0..100 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

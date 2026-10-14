//! Limen worker: runs inside target networks, dials proxies outbound, and
//! serves sessions over reverse tunnels (ADR-0003). Protocol handlers
//! (SSH, PostgreSQL, MySQL, Redis, Kubernetes) arrive in Phases 2 to 6.

pub mod recording;
mod recordings;
mod session;
pub mod ssh;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use axum::http::StatusCode;
use axum::routing::get;
use clap::Args;
use futures::Stream;
use limen_component::ComponentCredentials;
use limen_core::backoff::Backoff;
use limen_core::secret::Secret;
use limen_proto::v1::worker_tunnel_server::{WorkerTunnel, WorkerTunnelServer};
use limen_proto::v1::{PingRequest, PingResponse, TunnelFrame};
use limen_tunnel::connect::{SharedClientConfig, channel, dial};
use limen_tunnel::serve::{H2Settings, serve_h2};
use limen_tunnel::tls::client_config;
use limen_tunnel::{PeerInfo, alpn};
use tokio::sync::watch;
use tonic::{Request, Response, Status, Streaming};

#[derive(Debug, Clone, Args)]
pub struct Config {
    /// Proxy address, `host:port`. The worker only ever connects out.
    #[arg(long, env = "LIMEN_PROXY_ADDR")]
    pub proxy_addr: String,

    /// Name in the proxy's certificate.
    #[arg(long, env = "LIMEN_PROXY_NAME", default_value = "localhost")]
    pub proxy_name: String,

    /// CA certificate to trust for the proxy before enrollment.
    #[arg(long, env = "LIMEN_CA_FILE")]
    pub ca_file: Option<PathBuf>,

    /// Join token for first enrollment. Ignored once enrolled.
    #[arg(long, env = "LIMEN_JOIN_TOKEN", value_parser = parse_secret)]
    pub join_token: Option<Secret<String>>,

    /// Number of tunnels to keep open (ADR-0003).
    #[arg(long, env = "LIMEN_TUNNELS", default_value_t = 2)]
    pub tunnels: usize,

    /// How long to wait for in-flight sessions on shutdown.
    #[arg(long, env = "LIMEN_DRAIN_TIMEOUT", value_parser = parse_duration, default_value = "10m")]
    pub drain_timeout: Duration,

    #[arg(long, env = "LIMEN_ADMIN_LISTEN", default_value = "0.0.0.0:3090")]
    pub admin_listen: SocketAddr,

    #[arg(long, env = "LIMEN_DATA_DIR", default_value = "/var/lib/limen/worker")]
    pub data_dir: PathBuf,

    /// How old the policy snapshot may get while the control plane is
    /// unreachable before new sessions fail closed (ADR-0011).
    #[arg(long, env = "LIMEN_POLICY_GRACE", value_parser = parse_duration, default_value = "5m")]
    pub policy_grace: Duration,

    /// How often to fetch a fresh policy snapshot.
    #[arg(long, env = "LIMEN_POLICY_REFRESH", value_parser = parse_duration, default_value = "10s")]
    pub policy_refresh: Duration,

    /// Refuse new audit events (and, by default, the actions they audit)
    /// once the local spool holds this many bytes, e.g. during a long
    /// control plane outage.
    #[arg(long, env = "LIMEN_AUDIT_SPOOL_MAX_BYTES", default_value_t = 512 * 1024 * 1024)]
    pub audit_spool_max_bytes: u64,

    #[arg(long, env = "LIMEN_AUDIT_FAILURE_MODE", default_value = "fail_closed")]
    pub audit_failure_mode: limen_audit::FailureMode,
}

#[allow(clippy::unnecessary_wraps)] // clap value parsers must return Result
fn parse_secret(s: &str) -> Result<Secret<String>, String> {
    Ok(Secret::new(s.to_owned()))
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let (n, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit())
            .ok_or("missing unit")?,
    );
    let n: u64 = n.parse().map_err(|_| "invalid number")?;
    match unit {
        "s" => Ok(Duration::from_secs(n)),
        "m" => Ok(Duration::from_mins(n)),
        "h" => Ok(Duration::from_hours(n)),
        _ => Err("use s, m, or h".into()),
    }
}

/// Shared worker state.
#[derive(Debug, Clone)]
pub struct Worker {
    config: Arc<Config>,
    creds: watch::Receiver<Arc<ComponentCredentials>>,
    draining: Arc<AtomicBool>,
    tunnels_up: Arc<AtomicUsize>,
    sessions: Arc<AtomicUsize>,
    pub(crate) policy: limen_session::snapshot::PolicyCache,
    pub(crate) nonces: Arc<limen_session::grant::NonceCache>,
    pub(crate) audit: limen_audit::Emitter,
    audit_spool: limen_audit::spool::Spool,
}

impl Worker {
    pub async fn start(
        config: Config,
    ) -> anyhow::Result<(Self, watch::Sender<Arc<ComponentCredentials>>)> {
        let bootstrap_ca = match &config.ca_file {
            Some(path) => Some(
                tokio::fs::read_to_string(path)
                    .await
                    .with_context(|| format!("reading {}", path.display()))?,
            ),
            None => None,
        };
        let (addr, name) = (config.proxy_addr.clone(), config.proxy_name.clone());
        // Enrollment goes through the proxy, which relays it to the control plane.
        let creds = limen_component::load_or_enroll(
            &config.data_dir,
            "worker",
            config.join_token.as_ref(),
            &[],
            || {
                let ca = bootstrap_ca
                    .as_deref()
                    .context("--ca-file is required to enroll")?;
                let tls =
                    client_config(&limen_tunnel::tls::certs_from_pem(ca)?, None, &[alpn::H2])?;
                Ok(channel(&addr, &name, SharedClientConfig::new(tls)))
            },
        )
        .await?;
        let policy = limen_session::snapshot::PolicyCache::new(
            config.policy_grace,
            Some(config.data_dir.join("policy.snapshot")),
        );
        policy.load(&creds.internal_ca()?);
        let (audit, audit_spool) = limen_component::audit::open(
            &config.data_dir.join("spool"),
            config.audit_spool_max_bytes,
            "worker",
            &creds.id,
            config.audit_failure_mode,
        )?;
        let (tx, rx) = watch::channel(Arc::new(creds));
        Ok((
            Self {
                config: Arc::new(config),
                creds: rx,
                draining: Arc::new(AtomicBool::new(false)),
                tunnels_up: Arc::new(AtomicUsize::new(0)),
                sessions: Arc::new(AtomicUsize::new(0)),
                policy,
                nonces: Arc::default(),
                audit,
                audit_spool,
            },
            tx,
        ))
    }

    pub(crate) fn credentials(&self) -> Arc<ComponentCredentials> {
        Arc::clone(&self.creds.borrow())
    }

    /// A channel to the control plane through the proxy, presenting this
    /// worker's certificate (which the proxy forwards).
    pub(crate) fn control_plane(&self) -> anyhow::Result<tonic::transport::Channel> {
        let creds = self.credentials();
        let tls = client_config(
            &[creds.internal_ca()?],
            Some(creds.tls_identity()?),
            &[alpn::H2],
        )?;
        Ok(channel(
            &self.config.proxy_addr,
            &self.config.proxy_name,
            SharedClientConfig::new(tls),
        ))
    }

    pub(crate) fn recordings_dir(&self) -> PathBuf {
        self.config.data_dir.join("recordings")
    }

    pub(crate) fn session_started(&self) -> SessionGuard {
        self.sessions.fetch_add(1, Ordering::SeqCst);
        SessionGuard(Arc::clone(&self.sessions))
    }

    #[must_use]
    pub fn active_sessions(&self) -> usize {
        self.sessions.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn policy_version(&self) -> Option<i64> {
        self.policy.latest().map(|s| s.version)
    }

    #[must_use]
    pub fn id(&self) -> String {
        self.creds.borrow().id.clone()
    }

    #[must_use]
    pub fn tunnels_up(&self) -> usize {
        self.tunnels_up.load(Ordering::SeqCst)
    }
}

/// Decrements the session count when dropped.
pub(crate) struct SessionGuard(Arc<AtomicUsize>);

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Fetch a fresh policy snapshot every 10 seconds (ADR-0011).
async fn policy_refresh(worker: Worker, mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(worker.config.policy_refresh.max(Duration::from_secs(1)));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        let result = async {
            let mut client =
                limen_proto::v1::policy_sync_client::PolicySyncClient::new(worker.control_plane()?);
            let signed = client
                .get_policy_snapshot(limen_proto::v1::GetPolicySnapshotRequest {})
                .await?
                .into_inner();
            let snapshot = worker
                .policy
                .update(&signed, &worker.credentials().internal_ca()?)?;
            anyhow::Ok(snapshot.version)
        }
        .await;
        if let Err(e) = result {
            let age = worker
                .policy
                .latest()
                .map(|s| (time::OffsetDateTime::now_utc() - s.issued_at).whole_seconds());
            tracing::warn!(error = %e, snapshot_age_secs = ?age, "policy refresh failed; using the cached snapshot within the grace period");
        }
    }
}

/// The gRPC service the proxy calls over a tunnel.
#[derive(Debug, Clone)]
struct TunnelService(Worker);

#[tonic::async_trait]
impl WorkerTunnel for TunnelService {
    type OpenSessionStream = Pin<Box<dyn Stream<Item = Result<TunnelFrame, Status>> + Send>>;

    async fn open_session(
        &self,
        request: Request<Streaming<TunnelFrame>>,
    ) -> Result<Response<Self::OpenSessionStream>, Status> {
        if self.0.draining.load(Ordering::SeqCst) {
            return Err(Status::unavailable("worker is draining"));
        }
        session::open(self.0.clone(), request.into_inner()).await
    }

    async fn ping(&self, _request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        Ok(Response::new(PingResponse {
            worker_id: self.0.id(),
            draining: self.0.draining.load(Ordering::SeqCst),
        }))
    }
}

/// Keep one tunnel open forever: dial, serve until it drops, back off, repeat.
async fn tunnel_loop(worker: Worker, index: usize, mut shutdown: watch::Receiver<bool>) {
    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_mins(1));
    let routes =
        tonic::service::Routes::new(WorkerTunnelServer::new(TunnelService(worker.clone())))
            .prepare();
    loop {
        if *shutdown.borrow() {
            return;
        }
        let creds = Arc::clone(&worker.creds.borrow());
        let config = match (creds.internal_ca(), creds.tls_identity()) {
            (Ok(ca), Ok(identity)) => client_config(&[ca], Some(identity), &[alpn::TUNNEL]),
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "invalid credentials");
                return;
            }
        };
        let started = Instant::now();
        let result = match config {
            Ok(config) => match dial(
                &worker.config.proxy_addr,
                &worker.config.proxy_name,
                Arc::new(config),
            )
            .await
            {
                Ok(tls) => {
                    worker.tunnels_up.fetch_add(1, Ordering::SeqCst);
                    tracing::info!(tunnel = index, proxy = %worker.config.proxy_addr, "tunnel connected");
                    let peer = PeerInfo {
                        remote_addr: None,
                        client_certs: Vec::new(),
                    };
                    let served = tokio::select! {
                        r = serve_h2(tls, peer, routes.clone(), H2Settings::default()) => r.map_err(anyhow::Error::from),
                        _ = shutdown.changed() => Ok(()),
                    };
                    worker.tunnels_up.fetch_sub(1, Ordering::SeqCst);
                    served
                }
                Err(e) => Err(e.into()),
            },
            Err(e) => Err(e.into()),
        };
        if *shutdown.borrow() {
            return;
        }
        // A tunnel that stayed up a while was healthy: start backoff over.
        if started.elapsed() > Duration::from_secs(30) {
            backoff.reset();
        }
        let delay = backoff.next_delay(rand::random());
        match result {
            Ok(()) => {
                tracing::warn!(tunnel = index, retry_in = ?delay, "tunnel closed by proxy; reconnecting");
            }
            Err(e) => {
                tracing::warn!(tunnel = index, error = %e, retry_in = ?delay, "tunnel failed; reconnecting");
            }
        }
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            _ = shutdown.changed() => return,
        }
    }
}

/// Run until `shutdown` flips, then drain.
pub async fn run(
    worker: Worker,
    creds_tx: watch::Sender<Arc<ComponentCredentials>>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let (addr, name) = (
        worker.config.proxy_addr.clone(),
        worker.config.proxy_name.clone(),
    );
    tokio::spawn(limen_component::renewal_loop(
        worker.config.data_dir.clone(),
        creds_tx,
        move |creds| {
            // Renewal also goes through the proxy, presenting the current cert.
            let tls = client_config(
                &[creds.internal_ca()?],
                Some(creds.tls_identity()?),
                &[alpn::H2],
            )?;
            Ok(channel(&addr, &name, SharedClientConfig::new(tls)))
        },
    ));

    // Tunnels stop only after draining, so they get their own shutdown signal.
    let (stop_tunnels, tunnels_rx) = watch::channel(false);
    for index in 0..worker.config.tunnels.max(1) {
        tokio::spawn(tunnel_loop(worker.clone(), index, tunnels_rx.clone()));
    }
    tokio::spawn(policy_refresh(worker.clone(), tunnels_rx.clone()));
    let shipper = worker.clone();
    tokio::spawn(limen_component::audit::ship(
        worker.audit_spool.clone(),
        move || shipper.control_plane(),
        tunnels_rx.clone(),
    ));
    tokio::spawn(recordings::upload_loop(worker.clone(), tunnels_rx.clone()));
    let admin = tokio::spawn(serve_admin(worker.clone()));
    tracing::info!(id = %worker.id(), tunnels = worker.config.tunnels, "worker running");

    let _ = shutdown.changed().await;
    worker.draining.store(true, Ordering::SeqCst);
    let deadline = Instant::now() + worker.config.drain_timeout;
    tracing::info!(
        sessions = worker.sessions.load(Ordering::SeqCst),
        "draining"
    );
    while worker.sessions.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let _ = stop_tunnels.send(true);
    admin.abort();
    Ok(())
}

async fn serve_admin(worker: Worker) -> anyhow::Result<()> {
    let ready = worker.clone();
    let app = axum::Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get(move || {
                let up = ready.tunnels_up();
                async move {
                    if up > 0 {
                        (StatusCode::OK, format!("ready: {up} tunnel(s) up"))
                    } else {
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            "no tunnel to any proxy".to_owned(),
                        )
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind(worker.config.admin_listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

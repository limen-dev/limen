//! Limen worker: runs inside target networks, dials proxies outbound, and
//! serves sessions over reverse tunnels (ADR-0003). Protocol handlers
//! (SSH, PostgreSQL, MySQL, Redis, Kubernetes) arrive in Phases 2 to 6.

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
        let (tx, rx) = watch::channel(Arc::new(creds));
        Ok((
            Self {
                config: Arc::new(config),
                creds: rx,
                draining: Arc::new(AtomicBool::new(false)),
                tunnels_up: Arc::new(AtomicUsize::new(0)),
                sessions: Arc::new(AtomicUsize::new(0)),
            },
            tx,
        ))
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

/// The gRPC service the proxy calls over a tunnel.
#[derive(Debug, Clone)]
struct TunnelService(Worker);

#[tonic::async_trait]
impl WorkerTunnel for TunnelService {
    type OpenSessionStream = Pin<Box<dyn Stream<Item = Result<TunnelFrame, Status>> + Send>>;

    async fn open_session(
        &self,
        _request: Request<Streaming<TunnelFrame>>,
    ) -> Result<Response<Self::OpenSessionStream>, Status> {
        if self.0.draining.load(Ordering::SeqCst) {
            return Err(Status::unavailable("worker is draining"));
        }
        Err(Status::unimplemented(
            "no protocol handlers yet: sessions arrive in Phase 2",
        ))
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

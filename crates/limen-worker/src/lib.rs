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
use limen_tunnel::connect::{SharedClientConfig, channel, dial, retry_if_went_away};
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

    /// Most sessions this worker serves at once. Over it, new sessions are
    /// refused (`resource_exhausted`), and proxies stop choosing this worker
    /// until it has room. 0: no cap.
    #[arg(long, env = "LIMEN_MAX_SESSIONS", default_value_t = 200)]
    pub max_sessions: u32,
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
    sessions: SessionSlots,
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
        let sessions = SessionSlots::new(config.max_sessions);
        Ok((
            Self {
                config: Arc::new(config),
                creds: rx,
                draining: Arc::new(AtomicBool::new(false)),
                tunnels_up: Arc::new(AtomicUsize::new(0)),
                sessions,
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

    #[must_use]
    pub fn active_sessions(&self) -> usize {
        self.sessions.active()
    }

    /// Sessions refused because this worker was at its cap, since it started.
    #[must_use]
    pub fn sessions_refused_at_cap(&self) -> u64 {
        self.sessions.refused.load(Ordering::SeqCst)
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

/// Sessions held, against the `--max-sessions` cap. A session takes its
/// slot before anything else (so the sessions being admitted count too) and
/// gives it back when its [`SessionGuard`] drops, on every path: the
/// session ending, an error, a panic, or the task being cancelled.
#[derive(Debug, Clone)]
pub(crate) struct SessionSlots {
    count: Arc<AtomicUsize>,
    /// Sessions refused at the cap, since start.
    refused: Arc<std::sync::atomic::AtomicU64>,
    /// 0: no cap.
    max: usize,
}

impl SessionSlots {
    pub(crate) fn new(max: u32) -> Self {
        Self {
            count: Arc::default(),
            refused: Arc::default(),
            max: usize::try_from(max).unwrap_or(usize::MAX),
        }
    }

    /// A slot, or `None` at the cap. Check and increment are one atomic step,
    /// so concurrent sessions can't overshoot.
    pub(crate) fn try_acquire(&self) -> Option<SessionGuard> {
        let max = self.max;
        let slot = self
            .count
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (max == 0 || n < max).then_some(n + 1)
            })
            .ok()
            .map(|_| SessionGuard(Arc::clone(&self.count)));
        if slot.is_none() {
            self.refused.fetch_add(1, Ordering::SeqCst);
            metrics::counter!("limen_worker_sessions_refused_total", "reason" => "capacity")
                .increment(1);
        }
        slot
    }

    pub(crate) fn active(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    fn max(&self) -> usize {
        self.max
    }
}

/// Gives a session slot back when dropped.
#[derive(Debug)]
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
            let channel = worker.control_plane()?;
            let signed = retry_if_went_away("policy snapshot", || {
                let mut client =
                    limen_proto::v1::policy_sync_client::PolicySyncClient::new(channel.clone());
                async move {
                    client
                        .get_policy_snapshot(limen_proto::v1::GetPolicySnapshotRequest {})
                        .await
                }
            })
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
        if let Some(snapshot) = worker.policy.latest() {
            #[allow(clippy::cast_precision_loss)]
            metrics::gauge!("limen_policy_snapshot_age_seconds")
                .set((time::OffsetDateTime::now_utc() - snapshot.issued_at).whole_seconds() as f64);
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
        let Some(slot) = self.0.sessions.try_acquire() else {
            tracing::info!(
                max_sessions = self.0.sessions.max(),
                "session refused: at the session cap"
            );
            return Err(Status::resource_exhausted(format!(
                "no capacity: this worker is at its limit of {} sessions",
                self.0.sessions.max()
            )));
        };
        session::open(self.0.clone(), slot, request.into_inner()).await
    }

    async fn ping(&self, _request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        let sessions = &self.0.sessions;
        Ok(Response::new(PingResponse {
            worker_id: self.0.id(),
            draining: self.0.draining.load(Ordering::SeqCst),
            active_sessions: u32::try_from(sessions.active()).unwrap_or(u32::MAX),
            max_sessions: u32::try_from(sessions.max()).unwrap_or(u32::MAX),
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
                    metrics::gauge!("limen_worker_tunnels_up").increment(1.0);
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
                    metrics::gauge!("limen_worker_tunnels_up").decrement(1.0);
                    served
                }
                Err(e) => Err(e.into()),
            },
            Err(e) => Err(e.into()),
        };
        if *shutdown.borrow() {
            return;
        }
        let delay = after_tunnel(result.is_ok(), started.elapsed(), &mut backoff);
        match result {
            Ok(()) if delay.is_zero() => {
                tracing::info!(tunnel = index, "tunnel closed by the proxy; reconnecting");
            }
            Ok(()) => {
                tracing::warn!(tunnel = index, retry_in = ?delay, "tunnel closed by the proxy soon after it opened; reconnecting");
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

/// A tunnel that stayed up this long was healthy.
const HEALTHY_TUNNEL: Duration = Duration::from_secs(30);
/// A clean close sooner than this after connecting is treated as a failure,
/// so a proxy that keeps closing at once does not make us spin.
const MIN_TUNNEL_UPTIME: Duration = Duration::from_secs(1);
/// The shortest wait before redialing after a short-lived tunnel closed cleanly.
const MIN_REDIAL: Duration = Duration::from_secs(2);

/// How long to wait before redialing after a tunnel ended. A clean close of
/// a tunnel that was up for a while (the proxy ended the connection on
/// purpose: shutdown, rebalancing) is a normal reconnect: at once, and the
/// name is resolved again. Failures back off. So does a clean close of a
/// short-lived tunnel, with a floor: a proxy that keeps accepting and then
/// closing must not get a redial every second.
fn after_tunnel(clean: bool, uptime: Duration, backoff: &mut Backoff) -> Duration {
    if uptime > HEALTHY_TUNNEL {
        backoff.reset();
        if clean {
            return Duration::ZERO;
        }
    }
    let delay = backoff.next_delay(rand::random());
    if clean && uptime >= MIN_TUNNEL_UPTIME {
        delay.max(MIN_REDIAL)
    } else {
        delay
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
    tracing::info!(sessions = worker.sessions.active(), "draining");
    while worker.sessions.active() > 0 && Instant::now() < deadline {
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
        .route("/metrics", get(|| async { limen_core::metrics::render() }))
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

#[cfg(test)]
mod reconnect_tests {
    use super::*;

    fn backoff() -> Backoff {
        Backoff::new(Duration::from_secs(1), Duration::from_mins(1))
    }

    #[test]
    fn a_clean_close_after_a_healthy_uptime_reconnects_at_once_and_forgets_earlier_failures() {
        let mut b = backoff();
        for _ in 0..5 {
            b.next_delay(0.5);
        }
        // A GOAWAY after a long uptime (rebalancing, a proxy restart).
        assert_eq!(
            after_tunnel(true, Duration::from_mins(5), &mut b),
            Duration::ZERO
        );
        assert_eq!(b.current_ceiling(), Duration::from_secs(1), "backoff reset");
    }

    #[test]
    fn clean_closes_of_short_lived_tunnels_back_off() {
        // A proxy that accepts, then cleanly closes after a few seconds,
        // again and again, must not get a redial every few seconds forever:
        // the delays grow, and the backoff is not reset by such a tunnel.
        let mut b = backoff();
        let mut total = Duration::ZERO;
        for _ in 0..8 {
            let delay = after_tunnel(true, Duration::from_secs(5), &mut b);
            assert!(
                !delay.is_zero(),
                "no immediate redial for a short-lived tunnel"
            );
            total += delay;
        }
        assert_eq!(
            b.current_ceiling(),
            Duration::from_mins(1),
            "grew to the cap"
        );
        assert!(
            total >= MIN_REDIAL * 8,
            "never faster than one redial per {MIN_REDIAL:?}: {total:?}"
        );
    }

    #[test]
    fn failures_and_instant_closes_back_off() {
        let mut b = backoff();
        after_tunnel(false, Duration::from_secs(5), &mut b);
        after_tunnel(true, Duration::from_millis(10), &mut b);
        assert_eq!(
            b.current_ceiling(),
            Duration::from_secs(4),
            "two attempts counted"
        );
        // A long-lived tunnel that then failed starts the backoff over.
        after_tunnel(false, Duration::from_mins(5), &mut b);
        assert_eq!(b.current_ceiling(), Duration::from_secs(2));
    }
}

#[cfg(test)]
mod cap_tests {
    use super::*;

    #[test]
    fn slots_stop_at_the_cap_and_come_back_when_released() {
        let slots = SessionSlots::new(2);
        let a = slots.try_acquire().expect("first");
        let b = slots.try_acquire().expect("second");
        assert!(slots.try_acquire().is_none(), "over the cap");
        assert_eq!(slots.refused.load(Ordering::SeqCst), 1);
        assert_eq!(slots.active(), 2);
        drop(a);
        assert_eq!(slots.active(), 1);
        let _c = slots.try_acquire().expect("a slot was released");
        drop(b);
        assert_eq!(slots.active(), 1);
    }

    #[test]
    fn zero_means_unlimited() {
        let slots = SessionSlots::new(0);
        let held: Vec<_> = (0..1000)
            .map(|_| slots.try_acquire().expect("no cap"))
            .collect();
        assert_eq!(slots.active(), 1000);
        drop(held);
        assert_eq!(slots.active(), 0);
    }

    #[test]
    fn a_panicking_session_releases_its_slot() {
        let slots = SessionSlots::new(1);
        let inner = slots.clone();
        let result = std::panic::catch_unwind(move || {
            let _slot = inner.try_acquire().expect("slot");
            panic!("session handler panicked");
        });
        assert!(result.is_err());
        assert_eq!(slots.active(), 0);
        assert!(slots.try_acquire().is_some());
    }

    #[tokio::test]
    async fn a_cancelled_session_releases_its_slot() {
        let slots = SessionSlots::new(1);
        let inner = slots.clone();
        let task = tokio::spawn(async move {
            let _slot = inner.try_acquire().expect("slot");
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        while slots.active() == 0 {
            tokio::task::yield_now().await;
        }
        task.abort();
        let _ = task.await;
        assert_eq!(slots.active(), 0);
    }

    #[test]
    fn concurrent_acquires_never_exceed_the_cap() {
        let slots = SessionSlots::new(5);
        let peak = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|s| {
            for _ in 0..16 {
                s.spawn(|| {
                    for _ in 0..2000 {
                        if let Some(slot) = slots.try_acquire() {
                            peak.fetch_max(slots.active(), Ordering::SeqCst);
                            drop(slot);
                        }
                    }
                });
            }
        });
        assert!(peak.load(Ordering::SeqCst) <= 5);
        assert_eq!(slots.active(), 0);
    }
}

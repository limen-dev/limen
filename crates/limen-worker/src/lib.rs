//! Limen worker: runs inside target networks, dials proxies outbound, and
//! serves sessions over reverse tunnels (ADR-0003). Protocol handlers
//! (SSH in Phase 2, Redis in Phase 7; databases and Kubernetes later).

pub mod amqp;
pub mod broker;
pub mod db;
pub mod kafka;
mod kube;
pub mod mongo;
pub mod recording;
mod recordings;
pub mod redis;
pub mod search;
mod session;
pub mod ssh;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
use limen_tunnel::serve::{H2Settings, serve_h2_until};
use limen_tunnel::tls::client_config;
use limen_tunnel::{PeerInfo, alpn};
use tokio::sync::{Notify, watch};
use tonic::{Request, Response, Status, Streaming};

#[derive(Debug, Clone, Args)]
#[allow(clippy::struct_excessive_bools)] // Independent opt-in flags for worker features.
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

    /// Display name, such as `prod-a-worker-1`: 1 to 63 characters of a-z,
    /// 0-9 and -. Sent only at first enrollment, and must be approved by the
    /// join token; fixed after that (a different value is ignored with a
    /// warning). Shown next to the ID in the console, audit data, and logs.
    #[arg(long, env = "LIMEN_NAME")]
    pub name: Option<String>,

    /// Number of tunnels to keep open (ADR-0003).
    #[arg(long, env = "LIMEN_TUNNELS", default_value_t = 2)]
    pub tunnels: usize,

    /// On SIGTERM, how long open sessions may go on (the worker takes no new
    /// ones meanwhile). Default 600 (10 minutes). The worker exits as soon as
    /// none is left; at the timeout it ends the rest, each with a
    /// `session.end` whose reason is `worker_drain`. Ending them and the last
    /// recording and audit uploads take up to 18 s more, so the
    /// orchestrator's grace period must be longer than this plus 18 s
    /// (Kubernetes `terminationGracePeriodSeconds`, ECS `stopTimeout`, an
    /// Auto Scaling lifecycle hook's timeout, Compose `stop_grace_period`).
    /// If you can't wait that long, lower it, and accept that sessions still
    /// open at the timeout are ended. Replaces `--drain-timeout` /
    /// `LIMEN_DRAIN_TIMEOUT` (a duration such as `10m`), still read, with a
    /// warning, when this is not set.
    #[arg(long, env = "LIMEN_DRAIN_TIMEOUT_SECS")]
    pub drain_timeout_secs: Option<u64>,

    /// Deprecated: use `--drain-timeout-secs`.
    #[arg(
        long = "drain-timeout",
        env = "LIMEN_DRAIN_TIMEOUT",
        value_parser = parse_duration,
        hide = true
    )]
    pub legacy_drain_timeout: Option<Duration>,

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

    /// CA bundle for TLS to Redis targets (for `ElastiCache`, the AWS bundle).
    #[arg(long, env = "LIMEN_REDIS_CA_FILE")]
    pub redis_ca_file: Option<PathBuf>,

    /// JSON file of Redis ACL passwords: `{"<resource>": {"<user>": "<password>"}}`.
    /// Used for targets that don't use IAM. The file is read at start-up.
    #[arg(long, env = "LIMEN_REDIS_CREDENTIALS_FILE")]
    pub redis_credentials_file: Option<PathBuf>,

    /// CA bundle for TLS to `OpenSearch` and Elasticsearch targets (for Amazon
    /// `OpenSearch` Service, the Amazon bundle; for Elastic Cloud, the system bundle).
    #[arg(long, env = "LIMEN_SEARCH_CA_FILE")]
    pub search_ca_file: Option<PathBuf>,

    /// JSON file of credentials for search targets that don't use `SigV4`:
    /// `{"<resource>": {"<engine role>": {"basic": {"username": "...", "password": "..."}}}}`
    /// (or `api_key`, `bearer`, `client_cert_file` and `client_key_file`).
    /// Read at start-up.
    #[arg(long, env = "LIMEN_SEARCH_CREDENTIALS_FILE")]
    pub search_credentials_file: Option<PathBuf>,

    /// The most a search request body may take in memory when the worker has
    /// to read it (`_bulk`, searches, and everything on a `SigV4` target).
    /// Larger ones are answered 413. Memory per session is up to this, twice
    /// for a gzip body.
    #[arg(long, env = "LIMEN_SEARCH_MAX_BODY_BYTES", default_value_t = search::target::DEFAULT_MAX_BODY)]
    pub search_max_body_bytes: usize,

    /// A search connection with no request for this long ends (and frees its
    /// session slot and its connection to the engine). Clients that pool
    /// connections open a new one when they need it.
    #[arg(long, env = "LIMEN_SEARCH_IDLE_TIMEOUT", value_parser = parse_duration, default_value = "1h")]
    pub search_idle_timeout: Duration,

    /// CA bundle for TLS to `RabbitMQ`, Amazon MQ, Kafka, and MSK targets (for
    /// the AWS services, the AWS bundle).
    #[arg(long, env = "LIMEN_BROKER_CA_FILE")]
    pub broker_ca_file: Option<PathBuf>,

    /// JSON file of broker logins: `{"<resource>": {"<broker user>": "<password>"}}`,
    /// where a user may instead be `{"password": …, "client_cert_file": …, "client_key_file": …}`.
    /// Read at start-up.
    #[arg(long, env = "LIMEN_BROKER_CREDENTIALS_FILE")]
    pub broker_credentials_file: Option<PathBuf>,

    /// Most sessions this worker serves at once. Over it, new sessions are
    /// refused (`resource_exhausted`), and proxies stop choosing this worker
    /// until it has room. 0: no cap.
    #[arg(long, env = "LIMEN_MAX_SESSIONS", default_value_t = 200)]
    pub max_sessions: u32,

    /// Reconcile the database roles declared in policy once, then exit
    /// (ADR-0033). Run it as a separate task with its own admin credentials.
    #[arg(long, env = "LIMEN_DB_BOOTSTRAP_ONCE")]
    pub db_bootstrap_once: bool,

    /// With `--db-bootstrap-once`: report differences without changing anything.
    #[arg(long, env = "LIMEN_DB_BOOTSTRAP_CHECK", requires = "db_bootstrap_once")]
    pub db_bootstrap_check: bool,

    /// Also reconcile database roles inside the running worker, this often.
    /// Off by default, so the admin credential stays out of the data path.
    #[arg(long, env = "LIMEN_DB_BOOTSTRAP_INTERVAL", value_parser = parse_duration)]
    pub db_bootstrap_interval: Option<Duration>,

    /// Let resources set `insecure_dev` and reach their database without TLS.
    /// For the local compose profile only (ADR-0033).
    #[arg(long, env = "LIMEN_ALLOW_INSECURE_DB_TARGETS")]
    pub allow_insecure_db_targets: bool,

    /// Let resources set `web.insecure_dev` and use plain HTTP upstreams.
    /// For local compose only (ADR-0022).
    #[arg(long, env = "LIMEN_ALLOW_INSECURE_WEB_TARGETS")]
    pub allow_insecure_web_targets: bool,

    #[command(flatten)]
    pub kube: kube::KubeConfig,
}

/// `--drain-timeout-secs` when unset (and so is the legacy setting).
const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_mins(10);

impl Config {
    /// The drain timeout, and a warning to log if the deprecated
    /// `--drain-timeout` / `LIMEN_DRAIN_TIMEOUT` is set.
    #[must_use]
    pub fn drain_timeout(&self) -> (Duration, Option<String>) {
        match (self.drain_timeout_secs, self.legacy_drain_timeout) {
            (Some(secs), None) => (Duration::from_secs(secs), None),
            (Some(secs), Some(_)) => (
                Duration::from_secs(secs),
                Some(format!(
                    "--drain-timeout / LIMEN_DRAIN_TIMEOUT is deprecated and ignored: \
                     --drain-timeout-secs / LIMEN_DRAIN_TIMEOUT_SECS ({secs}) is set; remove the old setting"
                )),
            ),
            (None, Some(legacy)) => (
                legacy,
                Some(format!(
                    "--drain-timeout / LIMEN_DRAIN_TIMEOUT is deprecated; using it ({}s) because \
                     --drain-timeout-secs / LIMEN_DRAIN_TIMEOUT_SECS is not set; switch to that",
                    legacy.as_secs()
                )),
            ),
            (None, None) => (DEFAULT_DRAIN_TIMEOUT, None),
        }
    }
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
    /// Sessions refused because the worker was draining, since start.
    refused_draining: Arc<AtomicU64>,
    /// Flipped when the drain timeout is up: open sessions end.
    end_sessions: Arc<watch::Sender<bool>>,
    tunnels_up: Arc<AtomicUsize>,
    sessions: SessionSlots,
    pub(crate) policy: limen_session::snapshot::PolicyCache,
    pub(crate) nonces: Arc<limen_session::grant::NonceCache>,
    pub(crate) audit: limen_audit::Emitter,
    pub(crate) redis: Arc<redis::target::Settings>,
    pub(crate) search: Arc<search::target::Settings>,
    pub(crate) broker: Arc<broker::Settings>,
    pub(crate) db_registry: Arc<db::Registry>,
    aws: Arc<tokio::sync::OnceCell<Result<db::iam::CredentialSource, String>>>,
    /// The cluster this worker serves, if it is a kube worker (ADR-0038).
    pub(crate) kube: Option<Arc<kube::Upstream>>,
    audit_spool: limen_audit::spool::Spool,
}

impl Worker {
    pub async fn start(
        config: Config,
    ) -> anyhow::Result<(Self, watch::Sender<Arc<ComponentCredentials>>)> {
        if let (_, Some(warning)) = config.drain_timeout() {
            tracing::warn!("{warning}");
        }
        let bootstrap_ca = match &config.ca_file {
            Some(path) => Some(
                tokio::fs::read_to_string(path)
                    .await
                    .with_context(|| format!("reading {}", path.display()))?,
            ),
            None => None,
        };
        let (addr, name) = (config.proxy_addr.clone(), config.proxy_name.clone());
        let own_name = limen_component::parse_name(config.name.as_deref())?;
        // Enrollment goes through the proxy, which relays it to the control plane.
        let creds = limen_component::load_or_enroll(
            &config.data_dir,
            "worker",
            config.join_token.as_ref(),
            &[],
            own_name.as_deref(),
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
        let redis = redis::target::Settings::load(
            config.redis_ca_file.as_deref(),
            config.redis_credentials_file.as_deref(),
        )?;
        let kube = config.kube.resolve()?.map(Arc::new);
        let search = search::target::Settings::load(
            config.search_ca_file.as_deref(),
            config.search_credentials_file.as_deref(),
        )?
        .with_max_body(config.search_max_body_bytes)
        .with_idle(config.search_idle_timeout);

        let broker = broker::Settings::load(
            config.broker_ca_file.as_deref(),
            config.broker_credentials_file.as_deref(),
        )?;
        let (tx, rx) = watch::channel(Arc::new(creds));
        let sessions = SessionSlots::new(config.max_sessions);
        Ok((
            Self {
                config: Arc::new(config),
                creds: rx,
                draining: Arc::new(AtomicBool::new(false)),
                refused_draining: Arc::default(),
                end_sessions: Arc::new(watch::channel(false).0),
                tunnels_up: Arc::new(AtomicUsize::new(0)),
                sessions,
                policy,
                nonces: Arc::default(),
                audit,
                redis: Arc::new(redis),
                search: Arc::new(search),
                broker: Arc::new(broker),
                db_registry: Arc::default(),
                aws: Arc::default(),
                kube,
                audit_spool,
            },
            tx,
        ))
    }

    /// Reconcile every database resource this worker serves. Returns the
    /// number of differences found (check) or changes made (apply), and the
    /// number that failed.
    pub async fn bootstrap_databases(&self, apply: bool) -> (usize, usize) {
        let Ok(snapshot) = self.policy.fresh(time::OffsetDateTime::now_utc()) else {
            tracing::error!("no policy yet; can't bootstrap database roles");
            return (0, 1);
        };
        let labels = self.credentials().labels.clone();
        let plans =
            db::bootstrap_plans(&snapshot.policy, &labels, self.allow_insecure_db_targets()).await;
        let (mut changes, mut failures) = (0, 0);
        for (name, plan) in plans {
            let result = match plan {
                Ok(plan) => db::bootstrap::reconcile(&plan, Some(&self.audit), apply).await,
                Err(e) => Err(e),
            };
            match result {
                Ok(report) => {
                    for a in &report.actions {
                        let state = match (&a.error, a.applied) {
                            (Some(e), _) => format!("FAILED: {e}"),
                            (None, true) => "done".to_owned(),
                            (None, false) => "needed".to_owned(),
                        };
                        tracing::info!(resource = %name, role = %a.role, database = %a.database, action = a.kind, "{} [{state}]", a.detail);
                    }
                    failures += report.failed().len();
                    changes += report.actions.len();
                    if report.actions.is_empty() {
                        tracing::info!(resource = %name, "database roles match policy; nothing to change");
                    }
                }
                Err(e) => {
                    tracing::error!(resource = %name, error = %e, "database role bootstrap failed");
                    failures += 1;
                }
            }
        }
        (changes, failures)
    }

    /// Ship the audit spool to the control plane and wait (up to `timeout`)
    /// until nothing is pending. For one-shot runs, which exit right after
    /// their last event. Returns whether the spool drained.
    pub async fn drain_audit(&self, timeout: Duration) -> bool {
        let (stop, rx) = watch::channel(false);
        let shipper = self.clone();
        let task = tokio::spawn(limen_component::audit::ship(
            self.audit_spool.clone(),
            move || shipper.control_plane(),
            rx,
        ));
        let deadline = Instant::now() + timeout;
        let drained = loop {
            if self
                .audit_spool
                .pending(limen_component::audit::TO_CONTROL_PLANE)
                == 0
            {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        let _ = stop.send(true);
        let _ = task.await;
        drained
    }

    /// Fetch the policy from the control plane once.
    pub async fn fetch_policy_once(&self) -> anyhow::Result<i64> {
        let mut client =
            limen_proto::v1::policy_sync_client::PolicySyncClient::new(self.control_plane()?);
        let signed = client
            .get_policy_snapshot(limen_proto::v1::GetPolicySnapshotRequest {})
            .await?
            .into_inner();
        let snapshot = self
            .policy
            .update(&signed, &self.credentials().internal_ca()?)?;
        Ok(snapshot.version)
    }

    /// AWS credentials from the default chain, loaded on first use.
    pub(crate) async fn aws_credentials(&self) -> Result<db::sigv4::Credentials, String> {
        let source = self
            .aws
            .get_or_init(db::iam::CredentialSource::from_environment)
            .await;
        match source {
            Ok(s) => s.get().await,
            Err(e) => Err(e.clone()),
        }
    }

    pub(crate) fn allow_insecure_db_targets(&self) -> bool {
        self.config.allow_insecure_db_targets
    }

    pub(crate) fn allow_insecure_web_targets(&self) -> bool {
        self.config.allow_insecure_web_targets
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

    /// Sessions refused because this worker was draining.
    #[must_use]
    pub fn sessions_refused_draining(&self) -> u64 {
        self.refused_draining.load(Ordering::SeqCst)
    }

    /// Flips when the drain timeout is up and open sessions must end.
    pub(crate) fn end_sessions(&self) -> watch::Receiver<bool> {
        self.end_sessions.subscribe()
    }

    /// Whether the worker is shutting down (it takes no new sessions).
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn policy_version(&self) -> Option<i64> {
        self.policy.latest().map(|s| s.version)
    }

    /// The name given at enrollment, if any.
    #[must_use]
    pub fn name(&self) -> Option<String> {
        self.creds.borrow().name.clone()
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
    /// Told whenever a slot is given back.
    released: Arc<Notify>,
    /// Sessions refused at the cap, since start.
    refused: Arc<AtomicU64>,
    /// 0: no cap.
    max: usize,
}

impl SessionSlots {
    pub(crate) fn new(max: u32) -> Self {
        Self {
            count: Arc::default(),
            released: Arc::default(),
            refused: Arc::default(),
            max: usize::try_from(max).unwrap_or(usize::MAX),
        }
    }

    /// Wait until no slot is held, or `until`. Whether none is held.
    pub(crate) async fn wait_idle(&self, until: tokio::time::Instant) -> bool {
        loop {
            // Registered before the check, so a release in between is seen.
            let released = self.released.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            if self.active() == 0 {
                return true;
            }
            if tokio::time::timeout_at(until, released).await.is_err() {
                return self.active() == 0;
            }
        }
    }

    /// A slot, or `None` at the cap. Check and increment are one atomic step,
    /// so concurrent sessions can't overshoot.
    #[cfg(test)]
    pub(crate) fn try_acquire(&self) -> Option<SessionGuard> {
        let slot = self.acquire();
        if slot.is_none() {
            self.count_refusal();
        }
        slot
    }

    /// [`try_acquire`](Self::try_acquire) without counting a refusal.
    fn acquire(&self) -> Option<SessionGuard> {
        let max = self.max;
        self.count
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (max == 0 || n < max).then_some(n + 1)
            })
            .ok()
            .map(|_| {
                metrics::gauge!("limen_worker_sessions_active").increment(1.0);
                SessionGuard {
                    count: Arc::clone(&self.count),
                    released: Arc::clone(&self.released),
                }
            })
    }

    /// A session refused at the cap.
    fn count_refusal(&self) {
        self.refused.fetch_add(1, Ordering::SeqCst);
        metrics::counter!("limen_worker_sessions_refused_total", "reason" => "capacity")
            .increment(1);
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
pub(crate) struct SessionGuard {
    count: Arc<AtomicUsize>,
    released: Arc<Notify>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::SeqCst);
        metrics::gauge!("limen_worker_sessions_active").decrement(1.0);
        self.released.notify_waiters();
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

/// Why a new session was refused before anything was read.
#[derive(Debug, PartialEq, Eq)]
enum Refused {
    Draining,
    Full,
}

/// A slot for a new session, unless the worker is draining or full.
///
/// The slot is taken first and `draining` read after, while the drain in
/// [`run`] sets `draining` first and reads the count after (all `SeqCst`).
/// So a SIGTERM that lands in between is caught by one side or the other:
/// the drain sees this session and waits for it, or this session sees
/// `draining` and gives its slot back. Never neither, which would let the
/// worker exit under a session it just admitted.
///
/// `between` runs between the two steps (a test seam; `|| {}` otherwise).
fn take_slot(
    draining: &AtomicBool,
    slots: &SessionSlots,
    between: impl FnOnce(),
) -> Result<SessionGuard, Refused> {
    let slot = slots.acquire();
    between();
    if draining.load(Ordering::SeqCst) {
        drop(slot);
        return Err(Refused::Draining);
    }
    slot.ok_or_else(|| {
        slots.count_refusal();
        Refused::Full
    })
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
        let slot = match take_slot(&self.0.draining, &self.0.sessions, || {}) {
            Ok(slot) => slot,
            Err(Refused::Draining) => {
                // Before anything is read: the proxy may try another worker.
                self.0.refused_draining.fetch_add(1, Ordering::SeqCst);
                metrics::counter!("limen_worker_sessions_refused_total", "reason" => "draining")
                    .increment(1);
                tracing::info!("session refused: draining");
                return Err(limen_tunnel::refusal::draining());
            }
            Err(Refused::Full) => {
                tracing::info!(
                    max_sessions = self.0.sessions.max(),
                    "session refused: at the session cap"
                );
                return Err(Status::resource_exhausted(format!(
                    "no capacity: this worker is at its limit of {} sessions",
                    self.0.sessions.max()
                )));
            }
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
                tracing::error!(error = %e, "the worker's CA or identity is unusable; not opening tunnels");
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
                        server_name: None,
                        client_certs: Vec::new(),
                    };
                    // On shutdown, close gracefully (GOAWAY) so the closing
                    // frames of sessions that just ended still go out, but
                    // don't wait for a stuck stream for long.
                    let (mut stop, mut cut) = (shutdown.clone(), shutdown.clone());
                    let served = tokio::select! {
                        r = serve_h2_until(tls, peer, routes.clone(), H2Settings::default(), async move {
                            let _ = stop.wait_for(|s| *s).await;
                        }) => r.map_err(anyhow::Error::from),
                        () = async move {
                            let _ = cut.wait_for(|s| *s).await;
                            tokio::time::sleep(TUNNEL_CLOSE_GRACE).await;
                        } => Ok(()),
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

/// On shutdown, how long a tunnel waits for its open streams to finish.
const TUNNEL_CLOSE_GRACE: Duration = Duration::from_secs(5);
/// Once the drain timeout is up, how long the ended sessions get to close:
/// each waits up to [`ssh::END_WITHIN`] for SSH to close, then up to
/// [`session::PUMP_WAIT`] for its output, then finishes its recording and
/// sends its closing frame.
const SESSION_END_GRACE: Duration =
    Duration::from_secs(ssh::END_WITHIN.as_secs() + session::PUMP_WAIT.as_secs());
/// Once no session is left, how long closing the tunnels (at most
/// [`TUNNEL_CLOSE_GRACE`]) and the last recording and audit uploads may
/// take. What isn't uploaded by then stays on disk and goes on the next
/// start.
const FINAL_FLUSH: Duration = Duration::from_secs(10);
/// The most a drain takes past `--drain-timeout-secs`: what the
/// orchestrator's grace period must allow on top of it.
const DRAIN_OVERHEAD: Duration =
    Duration::from_secs(SESSION_END_GRACE.as_secs() + FINAL_FLUSH.as_secs());
const _: () = assert!(
    SESSION_END_GRACE.as_secs() >= ssh::END_WITHIN.as_secs() + session::PUMP_WAIT.as_secs()
        && TUNNEL_CLOSE_GRACE.as_secs() <= FINAL_FLUSH.as_secs(),
    "the drain's waits must nest"
);

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

/// Run until `shutdown` flips, then drain: take no new sessions, let open
/// ones finish until the drain timeout, end the rest (`worker_drain`), close
/// the tunnels, upload what is left, and return.
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

    // Tunnels and uploads stop only once the sessions are over, so they get
    // their own signals: `flush` (finish up, then stop) and `deadline` (stop
    // now; what is left stays on disk for the next start).
    let (flush_tx, flush) = watch::channel(false);
    let (deadline_tx, deadline) = watch::channel(false);
    let tunnels: Vec<_> = (0..worker.config.tunnels.max(1))
        .map(|index| tokio::spawn(tunnel_loop(worker.clone(), index, flush.clone())))
        .collect();
    tokio::spawn(policy_refresh(worker.clone(), flush.clone()));
    let shipper = worker.clone();
    let audit = tokio::spawn(limen_component::audit::ship_until(
        worker.audit_spool.clone(),
        move || shipper.control_plane(),
        flush.clone(),
        deadline,
    ));
    let uploads = tokio::spawn(recordings::upload_loop(worker.clone(), flush.clone()));
    if let Some(every) = worker.config.db_bootstrap_interval {
        tokio::spawn(bootstrap_loop(worker.clone(), every, flush.clone()));
    }
    let admin = tokio::spawn(serve_admin(worker.clone()));
    // Scale signals: sessions against the cap, and whether we are draining.
    metrics::gauge!("limen_worker_sessions_max").set(f64::from(
        u32::try_from(worker.sessions.max()).unwrap_or(u32::MAX),
    ));
    metrics::gauge!("limen_worker_draining").set(0.0);
    // Exist at 0 so "no tunnels" is alertable for a worker that never connects.
    metrics::gauge!("limen_worker_tunnels_up").set(0.0);
    tracing::info!(id = %worker.id(), name = worker.name().as_deref(), tunnels = worker.config.tunnels, "worker running");

    let _ = shutdown.wait_for(|stop| *stop).await;
    // From here pings say `draining` (proxies stop choosing us) and new
    // sessions are refused.
    worker.draining.store(true, Ordering::SeqCst);
    metrics::gauge!("limen_worker_draining").set(1.0);
    let (drain, _) = worker.config.drain_timeout();
    tracing::info!(sessions = worker.sessions.active(), timeout = ?drain, then_at_most = ?DRAIN_OVERHEAD, "draining");
    let now = tokio::time::Instant::now();
    if !worker.sessions.wait_idle(now + drain).await {
        tracing::warn!(
            sessions = worker.sessions.active(),
            "drain timeout reached; ending the open sessions"
        );
        let _ = worker.end_sessions.send(true);
        if !worker
            .sessions
            .wait_idle(tokio::time::Instant::now() + SESSION_END_GRACE)
            .await
        {
            tracing::warn!(
                sessions = worker.sessions.active(),
                "sessions still open after being ended; closing the tunnels anyway"
            );
        }
    }

    tracing::info!("sessions over; closing the tunnels and uploading what is left");
    let _ = flush_tx.send(true);
    let finished = tokio::time::timeout(FINAL_FLUSH, async {
        futures::future::join_all(tunnels).await;
        let _ = uploads.await;
        let _ = audit.await;
    })
    .await;
    if finished.is_err() {
        tracing::warn!(
            "not everything was uploaded in time; recordings and audit events left on disk go on the next start"
        );
    }
    let _ = deadline_tx.send(true);
    admin.abort();
    Ok(())
}

/// Opt-in periodic reconcile of database roles (ADR-0033 section 6).
async fn bootstrap_loop(worker: Worker, every: Duration, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(every.max(Duration::from_secs(10)));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.changed() => return,
        }
        let (changes, failures) = worker.bootstrap_databases(true).await;
        if changes + failures > 0 {
            tracing::warn!(
                changes,
                failures,
                "database roles were out of line with policy"
            );
        }
    }
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
                let draining = ready.is_draining();
                async move {
                    if draining {
                        (StatusCode::SERVICE_UNAVAILABLE, "draining".to_owned())
                    } else if up > 0 {
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
mod drain_flag_tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[derive(Debug, Parser)]
    struct Cli {
        #[command(flatten)]
        config: Config,
    }

    fn parse(extra: &[&str]) -> Result<Config, clap::Error> {
        let mut argv = vec!["limen-worker", "--proxy-addr=proxy:3443"];
        argv.extend_from_slice(extra);
        Cli::try_parse_from(argv).map(|c| c.config)
    }

    #[test]
    fn the_default_is_ten_minutes() {
        let config = parse(&[]).expect("valid");
        assert_eq!(config.drain_timeout(), (Duration::from_mins(10), None));
    }

    #[test]
    fn the_seconds_flag_sets_it() {
        let config = parse(&["--drain-timeout-secs=20"]).expect("valid");
        assert_eq!(config.drain_timeout(), (Duration::from_secs(20), None));
    }

    #[test]
    fn the_legacy_duration_is_a_deprecated_fallback() {
        let config = parse(&["--drain-timeout=2m"]).expect("valid");
        let (timeout, warning) = config.drain_timeout();
        assert_eq!(timeout, Duration::from_mins(2));
        let warning = warning.expect("a deprecation warning");
        assert!(
            warning.contains("LIMEN_DRAIN_TIMEOUT")
                && warning.contains("deprecated")
                && warning.contains("LIMEN_DRAIN_TIMEOUT_SECS"),
            "{warning}"
        );
    }

    #[test]
    fn the_seconds_flag_wins_over_the_legacy_one() {
        let config = parse(&["--drain-timeout=2m", "--drain-timeout-secs=30"]).expect("valid");
        let (timeout, warning) = config.drain_timeout();
        assert_eq!(timeout, Duration::from_secs(30));
        let warning = warning.expect("still told the legacy setting is ignored");
        assert!(warning.contains("ignored"), "{warning}");
    }

    #[test]
    fn invalid_values_are_refused_clearly() {
        for (args, expect) in [
            (
                &["--drain-timeout-secs=ten"][..],
                "invalid value 'ten' for '--drain-timeout-secs",
            ),
            (
                &["--drain-timeout-secs=-5"][..],
                "invalid value '-5' for '--drain-timeout-secs",
            ),
            (&["--drain-timeout=10"][..], "missing unit"),
            (&["--drain-timeout=10d"][..], "use s, m, or h"),
        ] {
            let err = parse(args).expect_err("refused").to_string();
            assert!(err.contains(expect), "{args:?}: {err}");
        }
    }

    #[test]
    fn the_legacy_setting_is_read_from_its_old_env_var_and_hidden() {
        let command = Cli::command();
        let arg = |id: &str| {
            command
                .get_arguments()
                .find(|a| a.get_id() == id)
                .unwrap_or_else(|| panic!("no {id}"))
                .clone()
        };
        let legacy = arg("legacy_drain_timeout");
        assert_eq!(legacy.get_long(), Some("drain-timeout"));
        assert_eq!(
            legacy.get_env().and_then(|e| e.to_str()),
            Some("LIMEN_DRAIN_TIMEOUT")
        );
        assert!(legacy.is_hide_set());
        let current = arg("drain_timeout_secs");
        assert_eq!(
            current.get_env().and_then(|e| e.to_str()),
            Some("LIMEN_DRAIN_TIMEOUT_SECS")
        );
        let help = current
            .get_help()
            .map(ToString::to_string)
            .unwrap_or_default();
        assert!(
            help.contains("600") && help.contains(&format!("{} s", DRAIN_OVERHEAD.as_secs())),
            "{help}"
        );
    }
}

#[cfg(test)]
mod drain_timing_tests {
    use super::*;

    #[test]
    fn ended_sessions_get_long_enough_to_close() {
        // An ended session waits up to END_WITHIN for SSH to close, then up
        // to PUMP_WAIT for its output; only then does it send its closing
        // frame and give its slot back.
        assert!(SESSION_END_GRACE >= ssh::END_WITHIN + session::PUMP_WAIT);
        // The docs and the flag's help quote this figure.
        assert_eq!(DRAIN_OVERHEAD, Duration::from_secs(18));
    }
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
    fn the_session_gauge_is_exported() {
        let _ = limen_core::metrics::install();
        let slots = SessionSlots::new(5);
        let slot = slots.acquire().expect("room");
        assert!(
            limen_core::metrics::render().contains("limen_worker_sessions_active"),
            "a taken slot shows up as a metric"
        );
        drop(slot);
    }

    /// SIGTERM landing while a session is being admitted, on an idle worker:
    /// the drain sets `draining` and then looks at the count, as `run` does.
    /// Either the drain sees the session (and waits for it) or the session
    /// sees `draining` (and is refused); never neither.
    #[test]
    fn a_session_admitted_during_sigterm_is_seen_by_the_drain_or_refused() {
        let draining = AtomicBool::new(false);
        let slots = SessionSlots::new(5);
        let mut drain_saw = None;
        let result = take_slot(&draining, &slots, || {
            draining.store(true, Ordering::SeqCst);
            drain_saw = Some(slots.active());
        });
        let drain_saw = drain_saw.expect("the seam ran");
        match result {
            Ok(_slot) => assert!(
                drain_saw > 0,
                "admitted, but the drain saw an idle worker and would exit under it"
            ),
            Err(refused) => {
                assert_eq!(refused, Refused::Draining);
                assert_eq!(slots.active(), 0, "the refused session gave its slot back");
            }
        }
    }

    #[test]
    fn a_draining_worker_refuses_as_draining_even_when_full() {
        let draining = AtomicBool::new(true);
        let slots = SessionSlots::new(1);
        let _held = slots.try_acquire().expect("slot");
        assert_eq!(
            take_slot(&draining, &slots, || {}).err(),
            Some(Refused::Draining)
        );
        assert_eq!(
            slots.refused.load(Ordering::SeqCst),
            0,
            "not a capacity refusal"
        );
        assert_eq!(slots.active(), 1);
    }

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

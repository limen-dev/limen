//! Limen proxy: the public entry point. It authenticates clients, relays
//! the API to the control plane, and holds worker reverse tunnels
//! (ADR-0002 through ADR-0005).

pub mod config;
mod kube;
mod peer;
pub mod relay;
mod sessions;
pub mod tunnels;
mod web;

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context as _;
use axum::Json;
use axum::http::StatusCode;
use axum::routing::get;
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use limen_component::ComponentCredentials;
use limen_core::identity::ComponentKind;
use limen_proto::v1::registry_client::RegistryClient;
use limen_proto::v1::worker_tunnel_client::WorkerTunnelClient;
use limen_proto::v1::{PingRequest, ReportTunnelsRequest, TunnelReport};
use limen_tunnel::connect::{SharedClientConfig, channel, retry_if_went_away};
use limen_tunnel::serve::{H2Settings, serve_h2};
use limen_tunnel::tls::{ClientAuth, client_config, server_config};
use limen_tunnel::tunnel::TunnelChannel;
use limen_tunnel::{PeerInfo, alpn};
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tonic::transport::Channel;

pub use config::Config;
use tunnels::{Tunnel, Tunnels};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const PING_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 20_000;
/// After the last connection is gone, how long the proxy may spend shipping
/// its audit spool to the control plane before it exits.
const FINAL_FLUSH: Duration = Duration::from_secs(10);

/// State shared by every connection.
#[derive(Debug, Clone)]
pub struct Proxy {
    pub config: Arc<Config>,
    creds: watch::Receiver<Arc<ComponentCredentials>>,
    tls: Arc<RwLock<Arc<ServerConfig>>>,
    cp: Arc<RwLock<Channel>>,
    pub tunnels: Tunnels,
    accept_limiter: Arc<DefaultKeyedRateLimiter<IpAddr>>,
    active: Arc<AtomicUsize>,
    last_report_ok: Arc<AtomicI64>,
    pub(crate) policy: limen_session::snapshot::PolicyCache,
    signer: Arc<RwLock<Arc<limen_session::envelope::EnvelopeSigner>>>,
    pub(crate) audit: limen_audit::Emitter,
    audit_spool: limen_audit::spool::Spool,
    pub(crate) peers: Arc<peer::PeerState>,
}

impl Proxy {
    /// Load or enroll this proxy's identity and build its TLS configuration.
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
        let cp_addr = config.control_plane_addr.clone();
        let cp_name = config.control_plane_name.clone();
        let own_name = limen_component::parse_name(config.name.as_deref())?;
        let creds = limen_component::load_or_enroll(
            &config.data_dir,
            "proxy",
            config.join_token.as_ref(),
            &config.dns_names,
            own_name.as_deref(),
            || {
                let ca = bootstrap_ca
                    .as_deref()
                    .context("--ca-file is required to enroll")?;
                let roots = limen_tunnel::tls::certs_from_pem(ca)?;
                let tls = client_config(&roots, None, &[alpn::H2])?;
                Ok(channel(&cp_addr, &cp_name, SharedClientConfig::new(tls)))
            },
        )
        .await?;
        let tls = Arc::new(RwLock::new(Arc::new(build_server_config(&creds)?)));
        let cp = Arc::new(RwLock::new(build_cp_channel(&config, &creds)?));
        let signer = Arc::new(RwLock::new(Arc::new(build_signer(&creds)?)));
        let policy = limen_session::snapshot::PolicyCache::new(
            Duration::from_secs(config.policy_grace_secs),
            Some(config.data_dir.join("policy.snapshot")),
        );
        policy.load(&creds.internal_ca()?);
        let (audit, audit_spool) = limen_component::audit::open(
            &config.data_dir.join("spool"),
            config.audit_spool_max_bytes,
            "proxy",
            &creds.id,
            config.audit_failure_mode,
        )?;
        let (tx, rx) = watch::channel(Arc::new(creds));
        let quota = Quota::per_second(
            NonZeroU32::new(config.accept_rate_per_second).unwrap_or(NonZeroU32::MIN),
        )
        .allow_burst(NonZeroU32::new(config.accept_burst).unwrap_or(NonZeroU32::MIN));
        Ok((
            Self {
                config: Arc::new(config),
                creds: rx,
                tls,
                cp,
                tunnels: Tunnels::default(),
                accept_limiter: Arc::new(RateLimiter::keyed(quota)),
                active: Arc::new(AtomicUsize::new(0)),
                last_report_ok: Arc::new(AtomicI64::new(0)),
                policy,
                signer,
                audit,
                audit_spool,
                peers: Arc::default(),
            },
            tx,
        ))
    }

    pub(crate) fn signer(&self) -> Arc<limen_session::envelope::EnvelopeSigner> {
        Arc::clone(
            &self
                .signer
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Version of the policy snapshot this proxy decides from, if any.
    #[must_use]
    pub fn policy_version(&self) -> Option<i64> {
        self.policy.latest().map(|s| s.version)
    }

    #[must_use]
    pub fn id(&self) -> String {
        self.creds.borrow().id.clone()
    }

    /// The name given at enrollment, if any.
    #[must_use]
    pub fn name(&self) -> Option<String> {
        self.creds.borrow().name.clone()
    }

    /// Current channel to the control plane, presenting this proxy's cert.
    #[must_use]
    pub fn cp_channel(&self) -> Channel {
        self.cp
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    #[must_use]
    pub fn credentials(&self) -> Arc<ComponentCredentials> {
        Arc::clone(&self.creds.borrow())
    }

    fn server_config(&self) -> Arc<ServerConfig> {
        Arc::clone(
            &self
                .tls
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

fn build_server_config(creds: &ComponentCredentials) -> anyhow::Result<ServerConfig> {
    let chain = format!("{}{}", creds.cert_pem, creds.internal_ca_pem);
    let identity = limen_tunnel::tls::Identity::from_pem(&chain, creds.key_pem.expose())?;
    // Users present user-CA certs, workers internal-CA certs. Anonymous
    // clients (login, enrollment) present none. Each route checks which it got.
    Ok(server_config(
        identity,
        &[creds.user_ca()?, creds.internal_ca()?],
        ClientAuth::Optional,
        &[
            alpn::TUNNEL,
            alpn::PEER,
            alpn::SSH,
            alpn::DB,
            alpn::REDIS,
            alpn::MONGO,
            alpn::SEARCH,
            alpn::MQ,
            alpn::KAFKA,
            alpn::TCP,
            alpn::H2,
            alpn::HTTP1,
        ],
    )?)
}

fn build_signer(
    creds: &ComponentCredentials,
) -> anyhow::Result<limen_session::envelope::EnvelopeSigner> {
    let cert = limen_tunnel::tls::certs_from_pem(&creds.cert_pem)?
        .into_iter()
        .next()
        .context("no certificate")?;
    Ok(limen_session::envelope::EnvelopeSigner::new(
        creds.key_pem.expose(),
        cert.to_vec(),
    )?)
}

fn build_cp_channel(config: &Config, creds: &ComponentCredentials) -> anyhow::Result<Channel> {
    let tls = client_config(
        &[creds.internal_ca()?],
        Some(creds.tls_identity()?),
        &[alpn::H2],
    )?;
    Ok(channel(
        &config.control_plane_addr,
        &config.control_plane_name,
        SharedClientConfig::new(tls),
    ))
}

/// Run until `shutdown` flips. `creds_tx` is the sender returned by [`Proxy::start`].
pub async fn run(
    proxy: Proxy,
    creds_tx: watch::Sender<Arc<ComponentCredentials>>,
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    // Background jobs hold clones of the proxy (and so of its audit spool,
    // whose lock must be free once `run` returns): stopped at the end.
    let mut background = tokio::task::JoinSet::new();
    background.spawn(apply_renewals(proxy.clone()));
    let data_dir = proxy.config.data_dir.clone();
    let renew_proxy = proxy.clone();
    background.spawn(limen_component::renewal_loop(
        data_dir,
        creds_tx,
        move |creds| build_cp_channel(&renew_proxy.config, creds),
    ));
    background.spawn(report_tunnels(proxy.clone(), shutdown.clone()));
    background.spawn(policy_refresh(proxy.clone(), shutdown.clone()));
    // Sessions go on writing audit events (their `session.end`) until the
    // drain is over, so the shipper outlives the shutdown signal: `flush`
    // (ship what is left, then stop) once the connections are done, and
    // `deadline` (stop now; the rest stays in the spool) if that takes too long.
    let (flush_tx, flush) = watch::channel(false);
    let (deadline_tx, deadline) = watch::channel(false);
    let shipper = proxy.clone();
    let audit = tokio::spawn(limen_component::audit::ship_until(
        proxy.audit_spool.clone(),
        move || Ok(shipper.cp_channel()),
        flush,
        deadline,
    ));
    let admin = tokio::spawn(serve_admin(proxy.clone(), shutdown.clone()));

    tracing::info!(addr = %listener.local_addr()?, id = %proxy.id(), name = proxy.name().as_deref(), "proxy listening");
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let (tcp, remote) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    continue;
                }
            },
            _ = shutdown.changed() => break,
        };
        if proxy.accept_limiter.check_key(&remote.ip()).is_err()
            || proxy.active.load(Ordering::Relaxed) >= MAX_CONNECTIONS
        {
            tracing::debug!(%remote, "connection rejected by rate limit");
            continue;
        }
        let proxy = proxy.clone();
        let conn_shutdown = shutdown.clone();
        proxy.active.fetch_add(1, Ordering::SeqCst);
        // Reap finished connections so the set doesn't grow forever.
        while connections.try_join_next().is_some() {}
        connections.spawn(async move {
            // Boxed: the connection's state is large and lives as long as it does.
            Box::pin(handle_connection(&proxy, tcp, remote, conn_shutdown)).await;
            proxy.active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    tracing::info!(
        connections = proxy.active.load(Ordering::SeqCst),
        "shutting down: draining"
    );
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(proxy.config.drain_timeout_secs);
    while proxy.active.load(Ordering::SeqCst) > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // Whatever is still open after the drain period is cut off.
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    // No more events can be written: ship what is spooled, within a bound.
    // What does not make it stays in the spool for the next start (and is
    // lost if the proxy's disk goes with it, as on an emptyDir).
    let _ = flush_tx.send(true);
    let mut audit = audit;
    if tokio::time::timeout(FINAL_FLUSH, &mut audit).await.is_err() {
        tracing::warn!(
            pending = proxy
                .audit_spool
                .pending(limen_component::audit::TO_CONTROL_PLANE),
            "audit events still unshipped after the final flush"
        );
        let _ = deadline_tx.send(true);
        audit.abort();
        // A completed handle must not be awaited again (it panics): only
        // here, after the abort, is the second await needed.
        let _ = audit.await;
    }
    admin.abort();
    let _ = admin.await;
    background.abort_all();
    while background.join_next().await.is_some() {}
    Ok(())
}

async fn handle_connection(
    proxy: &Proxy,
    tcp: TcpStream,
    remote: SocketAddr,
    shutdown: watch::Receiver<bool>,
) {
    let _ = tcp.set_nodelay(true);
    let tls = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        TlsAcceptor::from(proxy.server_config()).accept(tcp),
    )
    .await
    {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => return tracing::debug!(error = %e, %remote, "TLS handshake failed"),
        Err(_) => return tracing::debug!(%remote, "TLS handshake timed out"),
    };
    let peer = PeerInfo::from_tls(&tls, Some(remote));
    let protocol = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    match protocol.as_deref() {
        Some(p) if p == alpn::TUNNEL => accept_tunnel(proxy, tls, peer, shutdown).await,
        Some(p) if p == alpn::SSH => {
            sessions::handle(proxy, tls, peer, sessions::Protocol::Ssh).await;
        }
        Some(p) if p == alpn::DB => {
            sessions::handle(proxy, tls, peer, sessions::Protocol::Db).await;
        }
        Some(p) if p == alpn::REDIS => {
            sessions::handle(proxy, tls, peer, sessions::Protocol::Redis).await;
        }
        Some(p) if p == alpn::MONGO => {
            sessions::handle(proxy, tls, peer, sessions::Protocol::Mongo).await;
        }
        Some(p) if p == alpn::SEARCH => {
            sessions::handle(proxy, tls, peer, sessions::Protocol::Search).await;
        }
        Some(p) if p == alpn::MQ => {
            sessions::handle(proxy, tls, peer, sessions::Protocol::Mq).await;
        }
        Some(p) if p == alpn::KAFKA => {
            sessions::handle(proxy, tls, peer, sessions::Protocol::Kafka).await;
        }
        Some(p) if p == alpn::TCP => {
            sessions::handle(proxy, tls, peer, sessions::Protocol::Tcp).await;
        }
        Some(p) if p == alpn::PEER => peer::serve(proxy, tls, peer).await,
        Some(p) if p == alpn::H2 => {
            let mut shutdown = shutdown;
            let drain = Duration::from_secs(proxy.config.drain_timeout_secs);
            let serve = serve_h2(
                tls,
                peer,
                relay::RelayService::new(proxy.clone()),
                H2Settings::default(),
            );
            tokio::pin!(serve);
            tokio::select! {
                result = &mut serve => {
                    if let Err(e) = result {
                        tracing::debug!(error = %e, %remote, "API connection ended with error");
                    }
                }
                _ = shutdown.changed() => {
                    let _ = tokio::time::timeout(drain, serve).await;
                }
            }
        }
        Some(p) if p == alpn::HTTP1 => serve_http1(proxy, tls, peer, remote).await,
        // No ALPN at all means HTTP/1.1 (RFC 7301). kubectl opens its exec,
        // attach, and port-forward connections that way.
        None => serve_http1(proxy, tls, peer, remote).await,
        other => {
            tracing::debug!(%remote, alpn = ?other.map(String::from_utf8_lossy), "unsupported or missing ALPN; closing");
        }
    }
}

/// HTTP/1.1: browsers (the relay answers only `/console/`) and kubectl streams
/// (`/k8s/<cluster>/`, which may upgrade).
async fn serve_http1(
    proxy: &Proxy,
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    peer: PeerInfo,
    remote: SocketAddr,
) {
    if let Err(e) =
        limen_tunnel::serve::serve_http1(tls, peer, relay::RelayService::new(proxy.clone())).await
    {
        tracing::debug!(error = %e, %remote, "HTTP/1.1 connection ended with error");
    }
}

/// A worker dialed in. Verify it, flip roles, and keep the tunnel until it dies.
async fn accept_tunnel(
    proxy: &Proxy,
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    peer: PeerInfo,
    mut shutdown: watch::Receiver<bool>,
) {
    let creds = proxy.credentials();
    let Ok(internal_ca) = creds.internal_ca() else {
        return;
    };
    let worker = match peer
        .leaf()
        .map(|leaf| limen_ca::verify::verify_component(leaf, &internal_ca, false))
    {
        Some(Ok(id)) if id.kind == ComponentKind::Worker => id,
        other => {
            tracing::warn!(remote = ?peer.remote_addr, result = ?other.map(|r| r.map(|i| i.kind)), "rejected tunnel: not a worker certificate");
            return;
        }
    };
    if proxy
        .policy
        .latest()
        .is_some_and(|s| s.restrictions.is_revoked(&worker.id))
    {
        tracing::warn!(worker = %worker.id, "rejected tunnel: the worker was revoked");
        return;
    }
    let (channel, connection) = match TunnelChannel::handshake(tls, H2Settings::default()).await {
        Ok(pair) => pair,
        Err(e) => return tracing::warn!(error = %e, worker = %worker.id, "tunnel handshake failed"),
    };
    let tunnel_id = uuid::Uuid::now_v7().simple().to_string();
    let mut connection = tokio::spawn(connection);

    // The tunnel must answer a ping before it is used.
    let mut client = WorkerTunnelClient::new(channel.clone());
    let first = match tokio::time::timeout(PING_TIMEOUT, client.ping(PingRequest {})).await {
        Ok(Ok(pong)) if pong.get_ref().worker_id == worker.id => pong.into_inner(),
        result => {
            tracing::warn!(worker = %worker.id, ?result, "tunnel failed its first ping");
            connection.abort();
            return;
        }
    };
    proxy.tunnels.insert(Tunnel {
        worker_id: worker.id.clone(),
        labels: worker.labels.clone(),
        tunnel_id: tunnel_id.clone(),
        connected_at: time::OffsetDateTime::now_utc(),
        channel,
    });
    proxy
        .tunnels
        .record_ping(&worker.id, first.active_sessions, first.max_sessions);
    tracing::info!(worker = %worker.id, worker_name = limen_core::names::from_labels(&worker.labels), tunnel = %tunnel_id, remote = ?peer.remote_addr, "tunnel up");

    let mut tick = tokio::time::interval(Duration::from_secs(proxy.config.ping_interval_secs));
    tick.tick().await;
    // Revocation arrives with the policy snapshot; check the cached copy.
    let mut revocation = tokio::time::interval(Duration::from_secs(1));
    let reason = loop {
        tokio::select! {
            result = &mut connection => break format!("connection closed: {result:?}"),
            _ = shutdown.changed() => break "proxy shutting down".to_owned(),
            _ = revocation.tick() => {
                if proxy.policy.latest().is_some_and(|s| s.restrictions.is_revoked(&worker.id)) {
                    break "worker revoked".to_owned();
                }
            }
            _ = tick.tick() => {
                match tokio::time::timeout(PING_TIMEOUT, client.ping(PingRequest {})).await {
                    Ok(Ok(pong)) if pong.get_ref().draining => {
                        // Leave the tunnel up for in-flight sessions, but stop advertising it.
                        proxy.tunnels.remove(&tunnel_id);
                    }
                    Ok(Ok(pong)) => {
                        // Load for worker selection (old workers report 0/0: unknown).
                        let pong = pong.get_ref();
                        proxy.tunnels.record_ping(&worker.id, pong.active_sessions, pong.max_sessions);
                    }
                    other => break format!("ping failed: {other:?}"),
                }
            }
        }
    };
    connection.abort();
    proxy.tunnels.remove(&tunnel_id);
    tracing::info!(worker = %worker.id, tunnel = %tunnel_id, %reason, "tunnel down");
}

/// Apply renewed credentials: new server config and control plane channel.
async fn apply_renewals(proxy: Proxy) {
    let mut rx = proxy.creds.clone();
    while rx.changed().await.is_ok() {
        let creds = Arc::clone(&rx.borrow_and_update());
        match (
            build_server_config(&creds),
            build_cp_channel(&proxy.config, &creds),
            build_signer(&creds),
        ) {
            (Ok(tls), Ok(cp), Ok(signer)) => {
                *proxy
                    .tls
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(tls);
                *proxy
                    .cp
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = cp;
                *proxy
                    .signer
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(signer);
                tracing::info!("applied renewed certificate");
            }
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                tracing::error!(error = %e, "failed to apply renewed certificate");
            }
        }
    }
}

/// Fetch a fresh signed policy snapshot every 10 seconds (ADR-0011).
async fn policy_refresh(proxy: Proxy, mut shutdown: watch::Receiver<bool>) {
    let mut tick =
        tokio::time::interval(Duration::from_secs(proxy.config.policy_refresh_secs.max(1)));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        let result = async {
            let signed = retry_if_went_away("policy snapshot", || {
                let mut client =
                    limen_proto::v1::policy_sync_client::PolicySyncClient::new(proxy.cp_channel());
                async move {
                    client
                        .get_policy_snapshot(limen_proto::v1::GetPolicySnapshotRequest {})
                        .await
                }
            })
            .await?
            .into_inner();
            proxy
                .policy
                .update(&signed, &proxy.credentials().internal_ca()?)?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            let age = proxy
                .policy
                .latest()
                .map(|s| (time::OffsetDateTime::now_utc() - s.issued_at).whole_seconds());
            tracing::warn!(error = %e, snapshot_age_secs = ?age, "policy refresh failed; using the cached snapshot within the grace period");
        }
        if let Some(snapshot) = proxy.policy.latest() {
            #[allow(clippy::cast_precision_loss)]
            metrics::gauge!("limen_policy_snapshot_age_seconds")
                .set((time::OffsetDateTime::now_utc() - snapshot.issued_at).whole_seconds() as f64);
        }
    }
}

/// Tell the control plane which tunnels this proxy holds (ADR-0004).
async fn report_tunnels(proxy: Proxy, mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(proxy.config.report_interval_secs));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            () = proxy.tunnels.changed.notified() => {}
            _ = shutdown.changed() => return,
        }
        #[allow(clippy::cast_precision_loss)]
        metrics::gauge!("limen_proxy_tunnels").set(proxy.tunnels.summaries().len() as f64);
        let tunnels = proxy
            .tunnels
            .summaries()
            .into_iter()
            .map(|t| TunnelReport {
                worker_id: t.worker_id,
                tunnel_id: t.tunnel_id,
                active_sessions: t.active_sessions,
                max_sessions: t.max_sessions,
            })
            .collect();
        let req = ReportTunnelsRequest {
            tunnels,
            peer_address: proxy.config.peer_address.clone().unwrap_or_default(),
        };
        let result = retry_if_went_away("report tunnels", || {
            let mut client = RegistryClient::new(proxy.cp_channel());
            let req = req.clone();
            async move { client.report_tunnels(req).await }
        })
        .await;
        match result {
            Ok(_) => proxy.last_report_ok.store(
                time::OffsetDateTime::now_utc().unix_timestamp(),
                Ordering::SeqCst,
            ),
            Err(e) => tracing::warn!(error = %e, "failed to report tunnels to the control plane"),
        }
    }
}

/// `/healthz`, `/readyz` (control plane reached in the last minute), and `/tunnels`.
async fn serve_admin(proxy: Proxy, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
    let ready = proxy.clone();
    let listing = proxy.clone();
    let app = axum::Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(|| async { limen_core::metrics::render() }))
        .route(
            "/readyz",
            get(move || {
                let last = ready.last_report_ok.load(Ordering::SeqCst);
                async move {
                    if time::OffsetDateTime::now_utc().unix_timestamp() - last < 60 {
                        (StatusCode::OK, "ready")
                    } else {
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            "control plane not reached in the last minute",
                        )
                    }
                }
            }),
        )
        .route(
            "/tunnels",
            get(move || async move { Json(listing.tunnels.summaries()) }),
        );
    let listener = TcpListener::bind(proxy.config.admin_listen).await?;
    tracing::info!(addr = %listener.local_addr()?, "admin endpoints listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await?;
    Ok(())
}

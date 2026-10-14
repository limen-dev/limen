//! Limen proxy: the public entry point. It authenticates clients, relays
//! the API to the control plane, and holds worker reverse tunnels
//! (ADR-0002 through ADR-0005).

pub mod config;
pub mod relay;
pub mod tunnels;

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
use limen_tunnel::connect::{SharedClientConfig, channel};
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
const PING_INTERVAL: Duration = Duration::from_secs(15);
const PING_TIMEOUT: Duration = Duration::from_secs(10);
const REPORT_INTERVAL: Duration = Duration::from_secs(15);
const MAX_CONNECTIONS: usize = 20_000;

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
        let creds = limen_component::load_or_enroll(
            &config.data_dir,
            "proxy",
            config.join_token.as_ref(),
            &config.dns_names,
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
        let (tx, rx) = watch::channel(Arc::new(creds));
        let quota = Quota::per_second(NonZeroU32::new(50).unwrap_or(NonZeroU32::MIN))
            .allow_burst(NonZeroU32::new(200).unwrap_or(NonZeroU32::MIN));
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
            },
            tx,
        ))
    }

    #[must_use]
    pub fn id(&self) -> String {
        self.creds.borrow().id.clone()
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
        &[alpn::TUNNEL, alpn::H2],
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
    tokio::spawn(apply_renewals(proxy.clone()));
    let data_dir = proxy.config.data_dir.clone();
    let renew_proxy = proxy.clone();
    tokio::spawn(limen_component::renewal_loop(
        data_dir,
        creds_tx,
        move |creds| build_cp_channel(&renew_proxy.config, creds),
    ));
    tokio::spawn(report_tunnels(proxy.clone(), shutdown.clone()));
    let admin = tokio::spawn(serve_admin(proxy.clone(), shutdown.clone()));

    tracing::info!(addr = %listener.local_addr()?, id = %proxy.id(), "proxy listening");
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
        tokio::spawn(async move {
            handle_connection(&proxy, tcp, remote, conn_shutdown).await;
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
    admin.abort();
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
        other => {
            tracing::debug!(%remote, alpn = ?other.map(String::from_utf8_lossy), "unsupported or missing ALPN; closing");
        }
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
    let (channel, connection) = match TunnelChannel::handshake(tls, H2Settings::default()).await {
        Ok(pair) => pair,
        Err(e) => return tracing::warn!(error = %e, worker = %worker.id, "tunnel handshake failed"),
    };
    let tunnel_id = uuid::Uuid::now_v7().simple().to_string();
    let mut connection = tokio::spawn(connection);

    // The tunnel must answer a ping before it is used.
    let mut client = WorkerTunnelClient::new(channel.clone());
    match tokio::time::timeout(PING_TIMEOUT, client.ping(PingRequest {})).await {
        Ok(Ok(pong)) if pong.get_ref().worker_id == worker.id => {}
        result => {
            tracing::warn!(worker = %worker.id, ?result, "tunnel failed its first ping");
            connection.abort();
            return;
        }
    }
    proxy.tunnels.insert(Tunnel {
        worker_id: worker.id.clone(),
        tunnel_id: tunnel_id.clone(),
        connected_at: time::OffsetDateTime::now_utc(),
        channel,
    });
    tracing::info!(worker = %worker.id, tunnel = %tunnel_id, remote = ?peer.remote_addr, "tunnel up");

    let mut tick = tokio::time::interval(PING_INTERVAL);
    tick.tick().await;
    let reason = loop {
        tokio::select! {
            result = &mut connection => break format!("connection closed: {result:?}"),
            _ = shutdown.changed() => break "proxy shutting down".to_owned(),
            _ = tick.tick() => {
                match tokio::time::timeout(PING_TIMEOUT, client.ping(PingRequest {})).await {
                    Ok(Ok(pong)) if pong.get_ref().draining => {
                        // Leave the tunnel up for in-flight sessions, but stop advertising it.
                        proxy.tunnels.remove(&tunnel_id);
                    }
                    Ok(Ok(_)) => {}
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
        ) {
            (Ok(tls), Ok(cp)) => {
                *proxy
                    .tls
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(tls);
                *proxy
                    .cp
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = cp;
                tracing::info!("applied renewed certificate");
            }
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "failed to apply renewed certificate");
            }
        }
    }
}

/// Tell the control plane which tunnels this proxy holds (ADR-0004).
async fn report_tunnels(proxy: Proxy, mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(REPORT_INTERVAL);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            () = proxy.tunnels.changed.notified() => {}
            _ = shutdown.changed() => return,
        }
        let tunnels = proxy
            .tunnels
            .summaries()
            .into_iter()
            .map(|t| TunnelReport {
                worker_id: t.worker_id,
                tunnel_id: t.tunnel_id,
            })
            .collect();
        let req = ReportTunnelsRequest {
            tunnels,
            peer_address: proxy.config.peer_address.clone().unwrap_or_default(),
        };
        match RegistryClient::new(proxy.cp_channel())
            .report_tunnels(req)
            .await
        {
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

//! Listeners: the mTLS gRPC API and the plain-HTTP health endpoints.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use limen_ca::ComponentCertRequest;
use limen_core::identity::ComponentKind;
use limen_proto::v1::admin_server::AdminServer;
use limen_proto::v1::audit_ingest_server::AuditIngestServer;
use limen_proto::v1::auth_server::AuthServer;
use limen_proto::v1::enrollment_server::EnrollmentServer;
use limen_proto::v1::policy_sync_server::PolicySyncServer;
use limen_proto::v1::registry_server::RegistryServer;
use limen_proto::v1::resources_server::ResourcesServer;
use limen_proto::v1::ssh_certificates_server::SshCertificatesServer;
use limen_tunnel::PeerInfo;
use limen_tunnel::serve::{H2Settings, serve_h2_until};
use limen_tunnel::tls::{ClientAuth, Identity, server_config};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use crate::services::admin::AdminService;
use crate::services::auth::AuthService;
use crate::services::enrollment::EnrollmentService;
use crate::services::ingest::IngestService;
use crate::services::policy_sync::PolicySyncService;
use crate::services::registry::RegistryService;
use crate::services::resources::ResourcesService;
use crate::services::ssh_certs::SshCertificatesService;
use crate::state::AppState;

const MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Issue this replica's own server certificate from the internal CA.
pub async fn issue_server_config(state: &AppState) -> anyhow::Result<ServerConfig> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let csr = CertificateParams::default().serialize_request(&key)?;
    let issued = state
        .cas
        .internal
        .issue_component(ComponentCertRequest {
            csr_der: csr.der().to_vec(),
            kind: ComponentKind::ControlPlane,
            id: state.config.id.clone(),
            dns_names: state.config.dns_names.clone(),
            labels: std::collections::BTreeMap::new(),
            ttl: state.config.component_cert_ttl,
        })
        .await?;
    let chain = format!("{}{}", issued.pem, state.cas.internal.cert_pem());
    let identity = Identity::from_pem(&chain, &key.serialize_pem())?;
    // The same key signs policy snapshots, so they rotate together.
    let signer =
        limen_session::envelope::EnvelopeSigner::new(&key.serialize_pem(), issued.der.to_vec())?;
    *state
        .snapshot_signer
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(signer));
    // Only components connect directly. A cert is optional because proxies
    // enroll before they have one.
    Ok(server_config(
        identity,
        &[state.cas.internal.cert_der().clone()],
        ClientAuth::Optional,
        &[limen_tunnel::alpn::H2],
    )?)
}

/// Serve the gRPC API until `shutdown` flips, then drain: connections get a
/// GOAWAY (idle ones close at once), and in-flight calls have until
/// `started + crate::ship_budget(drain_timeout)` before they are cut off.
/// `started` is when shutdown began; the first caller to touch it sets it.
pub async fn serve_api(
    state: AppState,
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
    started: Arc<std::sync::OnceLock<tokio::time::Instant>>,
) -> anyhow::Result<()> {
    let tls = Arc::new(RwLock::new(Arc::new(issue_server_config(&state).await?)));
    tokio::spawn(rotate_server_cert(state.clone(), Arc::clone(&tls)));

    let routes = tonic::service::Routes::new(
        AuthServer::new(AuthService(state.clone())).max_decoding_message_size(MAX_MESSAGE_BYTES),
    )
    .add_service(
        ResourcesServer::new(ResourcesService(state.clone()))
            .max_decoding_message_size(MAX_MESSAGE_BYTES),
    )
    .add_service(
        AdminServer::new(AdminService(state.clone())).max_decoding_message_size(MAX_MESSAGE_BYTES),
    )
    .add_service(
        EnrollmentServer::new(EnrollmentService(state.clone()))
            .max_decoding_message_size(MAX_MESSAGE_BYTES),
    )
    .add_service(
        RegistryServer::new(RegistryService(state.clone()))
            .max_decoding_message_size(MAX_MESSAGE_BYTES),
    )
    .add_service(
        AuditIngestServer::new(IngestService(state.clone()))
            .max_decoding_message_size(8 * 1024 * 1024),
    )
    .add_service(
        PolicySyncServer::new(PolicySyncService(state.clone()))
            .max_decoding_message_size(MAX_MESSAGE_BYTES),
    )
    .add_service(
        SshCertificatesServer::new(SshCertificatesService(state.clone()))
            .max_decoding_message_size(MAX_MESSAGE_BYTES),
    )
    .prepare();
    // The console shares the listener: proxies relay browser requests here.
    let routes: axum::Router = match &state.console {
        Some(_) => routes
            .into_axum_router()
            .merge(crate::console::router(state.clone())),
        None => routes.into_axum_router(),
    };

    let active = Arc::new(AtomicUsize::new(0));
    let mut connections = tokio::task::JoinSet::new();
    tracing::info!(addr = %listener.local_addr()?, "control plane API listening");
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
        let config = Arc::clone(
            &tls.read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let routes = routes.clone();
        let active = Arc::clone(&active);
        let mut conn_stop = shutdown.clone();
        active.fetch_add(1, Ordering::SeqCst);
        // Reap finished connections so the set doesn't grow forever.
        while connections.try_join_next().is_some() {}
        connections.spawn(async move {
            let _ = tcp.set_nodelay(true);
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, TlsAcceptor::from(config).accept(tcp))
                .await
            {
                Ok(Ok(stream)) => {
                    let peer = PeerInfo::from_tls(&stream, Some(remote));
                    let stop = async move {
                        let _ = conn_stop.wait_for(|stop| *stop).await;
                    };
                    if let Err(e) =
                        serve_h2_until(stream, peer, routes, H2Settings::default(), stop).await
                    {
                        tracing::debug!(error = %e, %remote, "connection ended with error");
                    }
                }
                Ok(Err(e)) => tracing::debug!(error = %e, %remote, "TLS handshake failed"),
                Err(_) => tracing::debug!(%remote, "TLS handshake timed out"),
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    tracing::info!(
        connections = active.load(Ordering::SeqCst),
        "shutting down: no longer accepting, draining"
    );
    let t0 = *started.get_or_init(tokio::time::Instant::now);
    let deadline = t0 + crate::ship_budget(state.config.drain_timeout);
    while active.load(Ordering::SeqCst) > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // Whatever is still open after the drain period is cut off.
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

/// Reissue the server certificate at half its lifetime.
async fn rotate_server_cert(state: AppState, tls: Arc<RwLock<Arc<ServerConfig>>>) {
    let period = state.config.component_cert_ttl / 2;
    loop {
        tokio::time::sleep(period).await;
        match issue_server_config(&state).await {
            Ok(config) => {
                *tls.write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(config);
                tracing::info!("rotated control plane server certificate");
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to rotate server certificate; retrying in 1 minute");
            }
        }
        if period > Duration::from_mins(1) {
            continue;
        }
        tokio::time::sleep(Duration::from_mins(1)).await;
    }
}

/// `/healthz` (process up) and `/readyz` (database reachable).
pub async fn serve_health(
    state: AppState,
    addr: SocketAddr,
    mut done: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(|| async { limen_core::metrics::render() }))
        .route(
            "/readyz",
            get(move || {
                let db = state.db.clone();
                let draining = Arc::clone(&state.draining);
                async move {
                    if draining.load(Ordering::SeqCst) {
                        return (StatusCode::SERVICE_UNAVAILABLE, "shutting down");
                    }
                    match crate::db::ping(&db).await {
                        Ok(()) => (StatusCode::OK, "ready"),
                        Err(e) => {
                            tracing::warn!(error = %e, "not ready: database unreachable");
                            (StatusCode::SERVICE_UNAVAILABLE, "database unreachable")
                        }
                    }
                }
            }),
        );
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "health endpoints listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = done.wait_for(|done| *done).await;
        })
        .await?;
    Ok(())
}

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
use limen_proto::v1::access_server::AccessServer;
use limen_proto::v1::admin_server::AdminServer;
use limen_proto::v1::audit_handoff_server::AuditHandoffServer;
use limen_proto::v1::audit_ingest_server::AuditIngestServer;
use limen_proto::v1::audit_search_server::AuditSearchServer;
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
use tonic::server::NamedService;

use crate::services::access::AccessService;
use crate::services::admin::AdminService;
use crate::services::audit_search::AuditSearchService;
use crate::services::auth::AuthService;
use crate::services::enrollment::EnrollmentService;
use crate::services::handoff::HandoffService;
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
    let jwks = signer.jwks()?;
    let signing_jwk = jwks
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .and_then(|keys| keys.first())
        .ok_or_else(|| anyhow::anyhow!("control-plane signer has no public JWK"))?;
    let kid = signing_jwk
        .get("kid")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("control-plane signer JWK has no key id"))?;
    crate::console::store::register_web_identity_jwk(&state.db, kid, signing_jwk, issued.not_after)
        .await?;
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

/// The gRPC services the API serves (the names clients put in the path).
fn grpc_services() -> [&'static str; 11] {
    [
        AuditSearchServer::<AuditSearchService>::NAME,
        AccessServer::<AccessService>::NAME,
        AuthServer::<AuthService>::NAME,
        ResourcesServer::<ResourcesService>::NAME,
        AdminServer::<AdminService>::NAME,
        EnrollmentServer::<EnrollmentService>::NAME,
        RegistryServer::<RegistryService>::NAME,
        AuditIngestServer::<IngestService>::NAME,
        AuditHandoffServer::<HandoffService>::NAME,
        PolicySyncServer::<PolicySyncService>::NAME,
        SshCertificatesServer::<SshCertificatesService>::NAME,
    ]
}

/// The `service` label of the latency histogram: one of the gRPC services
/// above, or `http` for everything else (browser requests, probes, and any
/// path a client invents). A fixed set, so no client can add series: the
/// API accepts connections without a certificate.
fn service_label(path: &str) -> &'static str {
    let name = path.strip_prefix('/').and_then(|p| p.split('/').next());
    grpc_services()
        .into_iter()
        .find(|service| Some(*service) == name)
        .unwrap_or("http")
}

/// Scale signal: API latency per service, for target-tracking policies.
async fn record_latency(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let service = service_label(request.uri().path());
    let started = std::time::Instant::now();
    let response = next.run(request).await;
    metrics::histogram!("limen_api_request_seconds", "service" => service)
        .record(started.elapsed().as_secs_f64());
    response
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
        AccessServer::new(AccessService(state.clone()))
            .max_decoding_message_size(MAX_MESSAGE_BYTES),
    )
    .add_service(
        AuditSearchServer::new(AuditSearchService(state.clone()))
            .max_decoding_message_size(MAX_MESSAGE_BYTES),
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
        AuditHandoffServer::new(HandoffService(state.clone()))
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
    }
    .layer(axum::middleware::from_fn(record_latency));

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
        let max_age = connection_age(
            Duration::from_secs(state.config.max_connection_age_secs),
            rand::random(),
        );
        let grace = Duration::from_secs(state.config.connection_age_grace_secs);
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
                    let (aged_tx, aged) = tokio::sync::oneshot::channel();
                    let stop = async move {
                        tokio::select! {
                            _ = conn_stop.wait_for(|stop| *stop) => {}
                            () = sleep_or_forever(max_age) => {
                                tracing::debug!(%remote, "connection reached its maximum age; closing it gracefully");
                                let _ = aged_tx.send(());
                            }
                        }
                    };
                    let serve = serve_h2_until(stream, peer, routes, H2Settings::default(), stop);
                    // After a GOAWAY for age, in-flight calls get `grace`.
                    let cut = async move {
                        if aged.await.is_ok() {
                            tokio::time::sleep(grace).await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    };
                    tokio::select! {
                        result = serve => if let Err(e) = result {
                            tracing::debug!(error = %e, %remote, "connection ended with error");
                        },
                        () = cut => tracing::debug!(%remote, "connection still busy after the age grace period; cut"),
                    }
                }
                Ok(Err(e)) => tracing::debug!(error = %e, %remote, "TLS handshake failed"),
                Err(_) => tracing::debug!(%remote, "TLS handshake timed out"),
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    // Close the port now: a client dialing the shared name gets "refused"
    // and tries the next replica, rather than waiting in our backlog.
    drop(listener);
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

/// How long one connection may live: `max_age` ±10 %, from `unit` (uniform
/// in [0, 1), clamped). Jitter keeps connections opened together (say,
/// after a restart) from all closing together. Never zero; `None` when
/// `max_age` is zero (disabled). Never panics: an age too large to jitter
/// is used as is (the flag is bounded anyway).
fn connection_age(max_age: Duration, unit: f64) -> Option<Duration> {
    if max_age.is_zero() {
        return None;
    }
    let factor = 0.9 + 0.2 * unit.clamp(0.0, 1.0);
    let age = Duration::try_from_secs_f64(max_age.as_secs_f64() * factor).unwrap_or(max_age);
    Some(age.max(Duration::from_millis(1)))
}

async fn sleep_or_forever(after: Option<Duration>) {
    match after {
        Some(after) => tokio::time::sleep(after).await,
        None => std::future::pending().await,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_age_jitter_stays_within_ten_percent_and_is_never_zero() {
        let max = Duration::from_mins(5);
        for unit in [0.0, 0.25, 0.5, 0.75, 0.999_999] {
            let age = connection_age(max, unit).expect("enabled");
            assert!(
                age >= Duration::from_secs(270) && age <= Duration::from_secs(330),
                "{age:?} for {unit}"
            );
        }
        assert_eq!(connection_age(max, 0.0), Some(Duration::from_secs(270)));
        assert_eq!(connection_age(max, 0.5), Some(max));
        // Out-of-range jitter is clamped, not trusted.
        assert_eq!(connection_age(max, 7.0), Some(Duration::from_secs(330)));
        assert_eq!(connection_age(max, -1.0), Some(Duration::from_secs(270)));
        // The smallest age that can be configured is still not zero.
        let tiny = connection_age(Duration::from_secs(1), 0.0).expect("enabled");
        assert!(tiny >= Duration::from_millis(900));
        assert!(connection_age(Duration::from_nanos(1), 0.0).is_some_and(|d| !d.is_zero()));
    }

    #[test]
    fn huge_ages_never_panic() {
        assert!(connection_age(Duration::MAX, 1.0).is_some());
        assert!(connection_age(Duration::from_secs(u64::MAX), 0.0).is_some());
    }

    #[test]
    fn zero_disables_the_connection_age() {
        assert_eq!(connection_age(Duration::ZERO, 0.5), None);
    }
}

#[cfg(test)]
mod latency_tests {
    use axum::Router;
    use axum::routing::get;
    use tower::ServiceExt;

    use super::{record_latency, service_label};

    #[test]
    fn only_known_grpc_services_become_labels() {
        assert_eq!(service_label("/limen.v1.Auth/Login"), "limen.v1.Auth");
        assert_eq!(
            service_label("/limen.v1.Admin/ApplyPolicy"),
            "limen.v1.Admin"
        );
        // Paths a client invents never become label values.
        assert_eq!(service_label("/limen.v1.Auth"), "limen.v1.Auth");
        assert_eq!(service_label("/limen.v1.Nope/x1"), "http");
        assert_eq!(service_label("/limen.x/y"), "http");
        assert_eq!(service_label("/console/sessions/123"), "http");
        assert_eq!(service_label("/"), "http");
        assert_eq!(service_label(""), "http");
    }

    #[tokio::test]
    async fn requests_are_timed_per_method() {
        let _ = limen_core::metrics::install();
        let app = Router::new()
            .route("/limen.v1.Auth/Ping", get(|| async { "ok" }))
            .route("/console/home", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(record_latency));
        for path in ["/limen.v1.Auth/Ping", "/console/home", "/limen.v1.Nope/x1"] {
            let request = axum::http::Request::get(path)
                .body(axum::body::Body::empty())
                .expect("request");
            app.clone().oneshot(request).await.expect("response");
        }
        let text = limen_core::metrics::render();
        assert!(text.contains("limen_api_request_seconds"), "{text}");
        assert!(text.contains(r#"service="limen.v1.Auth""#), "{text}");
        assert!(text.contains(r#"service="http""#), "{text}");
        assert!(!text.contains("/console/home"), "paths must not be labels");
        assert!(
            !text.contains("Nope"),
            "invented services must not be labels"
        );
    }
}

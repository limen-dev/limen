//! Serving HTTP/2 (gRPC) over already-established connections, with the
//! TLS peer attached to every request.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use http::{Request, Response};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use rustls_pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{Service, ServiceExt};

use crate::TransportError;

/// The authenticated peer of a connection, inserted into every request's
/// extensions. Handlers read it with `request.extensions().get::<PeerInfo>()`.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub remote_addr: Option<SocketAddr>,
    /// TLS SNI, when the client sent one. HTTP app routing binds this to Host.
    pub server_name: Option<String>,
    /// The client certificate chain rustls verified, leaf first. Empty when
    /// the client presented none.
    pub client_certs: Vec<CertificateDer<'static>>,
}

impl PeerInfo {
    #[must_use]
    pub fn leaf(&self) -> Option<&CertificateDer<'static>> {
        self.client_certs.first()
    }

    /// Peer info from a server-side TLS stream.
    #[must_use]
    pub fn from_tls<IO>(
        stream: &tokio_rustls::server::TlsStream<IO>,
        remote_addr: Option<SocketAddr>,
    ) -> Self {
        let client_certs = stream
            .get_ref()
            .1
            .peer_certificates()
            .map(<[_]>::to_vec)
            .unwrap_or_default();
        Self {
            remote_addr,
            server_name: stream.get_ref().1.server_name().map(str::to_owned),
            client_certs,
        }
    }
}

/// How long a browser connection may take to send request headers.
const HTTP1_HEADER_TIMEOUT: Duration = Duration::from_secs(15);

/// Serve `service` over HTTP/1.1 on one connection (browsers that did not
/// negotiate `h2`). Every request gets `peer` in its extensions. Keep-alive
/// is on, and upgrades (`kubectl exec`'s WebSocket and SPDY) are allowed: the
/// handler decides what to do with a request that asks for one.
pub async fn serve_http1<IO, S, B>(io: IO, peer: PeerInfo, service: S) -> Result<(), TransportError>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    S: Service<Request<Incoming>, Response = Response<B>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let service = service.map_request(move |mut req: Request<Incoming>| {
        req.extensions_mut().insert(peer.clone());
        req
    });
    hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HTTP1_HEADER_TIMEOUT)
        .serve_connection(TokioIo::new(io), TowerToHyperService::new(service))
        .with_upgrades()
        .await?;
    Ok(())
}

/// HTTP/2 tuning shared by every Limen gRPC surface.
#[derive(Debug, Clone, Copy)]
pub struct H2Settings {
    pub keepalive_interval: Duration,
    pub keepalive_timeout: Duration,
    pub max_concurrent_streams: u32,
}

impl Default for H2Settings {
    fn default() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(15),
            keepalive_timeout: Duration::from_secs(45),
            max_concurrent_streams: 1024,
        }
    }
}

/// Serve `service` on one connection until the connection closes. Every
/// request gets `peer` in its extensions.
pub async fn serve_h2<IO, S, B>(
    io: IO,
    peer: PeerInfo,
    service: S,
    settings: H2Settings,
) -> Result<(), TransportError>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    S: Service<Request<Incoming>, Response = Response<B>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    serve_h2_until(io, peer, service, settings, std::future::pending()).await
}

/// Like [`serve_h2`], but when `stop` resolves the connection shuts down
/// gracefully: it sends GOAWAY, lets in-flight requests finish, then closes
/// (an idle connection closes at once).
pub async fn serve_h2_until<IO, S, B>(
    io: IO,
    peer: PeerInfo,
    service: S,
    settings: H2Settings,
    stop: impl std::future::Future<Output = ()>,
) -> Result<(), TransportError>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    S: Service<Request<Incoming>, Response = Response<B>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let service = service.map_request(move |mut req: Request<Incoming>| {
        req.extensions_mut().insert(peer.clone());
        req
    });
    let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(settings.keepalive_interval))
        .keep_alive_timeout(settings.keepalive_timeout)
        .max_concurrent_streams(settings.max_concurrent_streams)
        .serve_connection(TokioIo::new(io), TowerToHyperService::new(service));
    let mut conn = std::pin::pin!(conn);
    tokio::select! {
        r = conn.as_mut() => r?,
        () = stop => {
            conn.as_mut().graceful_shutdown();
            conn.await?;
        }
    }
    Ok(())
}

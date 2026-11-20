//! Relays CLI and worker API calls to the control plane (design §3).
//!
//! Client-supplied `x-limen-*` headers are stripped, then the proxy adds the
//! forwarded marker, the client address, and the client certificate it
//! verified. The control plane re-verifies that certificate itself.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use base64::Engine as _;
use http::{HeaderValue, Request, Response};
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use limen_proto::relay;
use limen_tunnel::PeerInfo;
use tower::{Service, ServiceExt};

use crate::Proxy;

/// API services the proxy relays. `Registry` is deliberately absent: only
/// proxies call it, directly. `PolicySync` and `SshCertificates` are for
/// workers; the control plane rejects other callers. `Access`, `AuditSearch`,
/// `Reviews` and `Controls` are for people (each call checks the caller's roles);
/// `Discovery` and `Watch` are for workers. `ManagementService` is for
/// admins and bot writers (ADR-0042); the control plane checks each call.
const RELAYED_PREFIXES: [&str; 14] = [
    "/limen.v1.AuditIngest/",
    "/limen.v1.Auth/",
    "/limen.v1.Resources/",
    "/limen.v1.Admin/",
    "/limen.v1.Access/",
    "/limen.v1.AuditSearch/",
    "/limen.v1.Reviews/",
    "/limen.v1.Controls/",
    "/limen.v1.Discovery/",
    "/limen.v1.Watch/",
    "/limen.v1.Enrollment/",
    "/limen.v1.PolicySync/",
    "/limen.v1.SshCertificates/",
    "/limen.manage.v1.ManagementService/",
];

#[derive(Debug, Clone)]
pub struct RelayService {
    proxy: Proxy,
}

impl RelayService {
    #[must_use]
    pub fn new(proxy: Proxy) -> Self {
        Self { proxy }
    }
}

impl Service<Request<Incoming>> for RelayService {
    type Response = Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        if crate::web::candidate(&self.proxy, &req) {
            let proxy = self.proxy.clone();
            return Box::pin(async move { Ok(crate::web::handle(&proxy, req).await) });
        }
        if req.uri().path().starts_with(crate::kube::PREFIX) {
            let proxy = self.proxy.clone();
            return Box::pin(async move { Ok(crate::kube::handle(&proxy, req).await) });
        }
        let channel = self.proxy.cp_channel();
        Box::pin(async move { Ok(relay(channel, req).await) })
    }
}

/// Headers that describe one hop, not the message. HTTP/2 forbids them.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
    "host",
];

/// Browser traffic for the web console (ADR-0017). Unlike API calls it keeps
/// the query string, and no client certificate is forwarded: the console
/// authenticates with its own session cookie.
async fn relay_console(
    channel: limen_tunnel::connect::TracedChannel,
    req: Request<Incoming>,
) -> Response<tonic::body::Body> {
    let peer = req.extensions().get::<PeerInfo>().cloned();
    let (mut parts, body) = req.into_parts();
    let strip: Vec<_> = parts
        .headers
        .keys()
        .filter(|k| k.as_str().starts_with("x-limen-") || HOP_BY_HOP.contains(&k.as_str()))
        .cloned()
        .collect();
    for name in strip {
        parts.headers.remove(&name);
    }
    parts
        .headers
        .insert(relay::FORWARDED, HeaderValue::from_static("1"));
    if let Some(addr) = peer
        .and_then(|p| p.remote_addr)
        .and_then(|a| HeaderValue::from_str(&a.to_string()).ok())
    {
        parts.headers.insert(relay::CLIENT_ADDR, addr);
    }
    let Some(path_and_query) = parts.uri.path_and_query().cloned() else {
        return plain(http::StatusCode::BAD_REQUEST, "bad request");
    };
    parts.uri = match http::Uri::builder().path_and_query(path_and_query).build() {
        Ok(uri) => uri,
        Err(_) => return plain(http::StatusCode::BAD_REQUEST, "bad request"),
    };
    parts.extensions = http::Extensions::new();
    match forward(channel, Request::from_parts(parts, body), |e| {
        limen_tunnel::connect::went_away_error(e)
    })
    .await
    {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(error = %e, "control plane unreachable for the console");
            plain(
                http::StatusCode::SERVICE_UNAVAILABLE,
                "the control plane is unreachable",
            )
        }
    }
}

/// A request body the relay can take back if the transport never read it.
struct Reclaimable<B> {
    slot: Arc<Mutex<Option<B>>>,
    polled: Arc<AtomicBool>,
}

impl<B> Body for Reclaimable<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        self.polled.store(true, Ordering::SeqCst);
        let mut slot = self
            .slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match slot.as_mut() {
            Some(body) => Pin::new(body).poll_frame(cx),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_none_or(Body::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        self.slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map_or_else(|| SizeHint::with_exact(0), Body::size_hint)
    }
}

/// Send `req` to the control plane, resending it once if it failed before
/// the control plane could have acted on it. The channel then dials again,
/// by name, and reaches a live replica. This covers a replica that is
/// shutting down: its GOAWAY can fail a request the channel had already
/// queued on that connection.
///
/// Invariant for the resend: the transport never polled the request's body,
/// and one of these holds.
/// - The body is not already at end of stream (every gRPC call: it needs its
///   request message). Unpolled then means nothing was sent, whatever the
///   error.
/// - It is a GET or HEAD, whose empty body is never polled even when the
///   request was delivered in full (hyper sends it as HEADERS with
///   `END_STREAM`). So the error itself must show the connection went away
///   before the control plane could act (`went_away`: GOAWAY, refused
///   stream, closed before sending). Any other error might come after the
///   control plane acted, and a GET such as the console's sign-in callback
///   has effects.
///
/// An empty POST may have been delivered in full too, and is never resent.
async fn forward<S, B>(
    channel: S,
    req: Request<B>,
    went_away: impl Fn(&S::Error) -> bool,
) -> Result<Response<tonic::body::Body>, S::Error>
where
    S: Service<Request<tonic::body::Body>, Response = Response<tonic::body::Body>> + Clone,
    S::Error: std::fmt::Display,
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, body) = req.into_parts();
    let has_body = !body.is_end_stream();
    let resendable =
        has_body || parts.method == http::Method::GET || parts.method == http::Method::HEAD;
    let slot = Arc::new(Mutex::new(Some(body)));
    let mut first_error = None;
    for _ in 0..2 {
        let polled = Arc::new(AtomicBool::new(false));
        let mut request = Request::new(tonic::body::Body::new(Reclaimable {
            slot: Arc::clone(&slot),
            polled: Arc::clone(&polled),
        }));
        *request.method_mut() = parts.method.clone();
        *request.uri_mut() = parts.uri.clone();
        *request.version_mut() = parts.version;
        *request.headers_mut() = parts.headers.clone();
        match channel.clone().oneshot(request).await {
            Ok(response) => return Ok(response),
            Err(e)
                if resendable
                    && first_error.is_none()
                    && !polled.load(Ordering::SeqCst)
                    && (has_body || went_away(&e)) =>
            {
                tracing::info!(error = %e, path = %parts.uri.path(), "control plane connection went away before the request was sent; sending it again");
                first_error = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(first_error.expect("set before a second attempt"))
}

fn plain(status: http::StatusCode, text: &'static str) -> Response<tonic::body::Body> {
    use axum::response::IntoResponse as _;
    let (parts, body) = (status, text).into_response().into_parts();
    Response::from_parts(parts, tonic::body::Body::new(body))
}

async fn relay(
    channel: limen_tunnel::connect::TracedChannel,
    req: Request<Incoming>,
) -> Response<tonic::body::Body> {
    let path = req.uri().path().to_owned();
    // The console, and SCIM from the IdP (ADR-0048): plain HTTP requests, passed
    // on without credentials of the proxy's own. The control plane serves
    // `/scim/` only when it has a SCIM token, and checks it on every request.
    if path == "/console" || path.starts_with("/console/") || path.starts_with("/scim/") {
        return relay_console(channel, req).await;
    }
    if !RELAYED_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return tonic::Status::unimplemented(format!("{path} is not served here")).into_http();
    }
    let peer = req.extensions().get::<PeerInfo>().cloned();
    let (mut parts, body) = req.into_parts();

    let spoofed: Vec<_> = parts
        .headers
        .keys()
        .filter(|k| k.as_str().starts_with("x-limen-"))
        .cloned()
        .collect();
    for name in spoofed {
        parts.headers.remove(&name);
    }
    parts
        .headers
        .insert(relay::FORWARDED, HeaderValue::from_static("1"));
    if let Some(peer) = &peer {
        if let Some(addr) = peer
            .remote_addr
            .and_then(|a| HeaderValue::from_str(&a.to_string()).ok())
        {
            parts.headers.insert(relay::CLIENT_ADDR, addr);
        }
        if let Some(leaf) = peer.leaf()
            && let Ok(value) = HeaderValue::from_str(
                &base64::engine::general_purpose::STANDARD.encode(leaf.as_ref()),
            )
        {
            parts.headers.insert(relay::CLIENT_CERT, value);
        }
    }
    parts.uri = match path.parse() {
        Ok(uri) => uri,
        Err(_) => return tonic::Status::invalid_argument("bad path").into_http(),
    };
    parts.extensions = http::Extensions::new();
    match forward(channel, Request::from_parts(parts, body), |e| {
        limen_tunnel::connect::went_away_error(e)
    })
    .await
    {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(error = %e, %path, "control plane unreachable");
            tonic::Status::unavailable("control plane unreachable").into_http()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use http_body_util::BodyExt as _;

    use super::*;

    type BoxError = Box<dyn std::error::Error + Send + Sync>;

    /// Stands in for the control plane channel. `fail_first` decides what
    /// the first call does before failing: drop the request unread (like a
    /// connection that got GOAWAY before the stream opened) or read the body.
    #[derive(Clone)]
    struct Upstream {
        calls: Arc<AtomicUsize>,
        read_body_then_fail: bool,
    }

    impl Service<Request<tonic::body::Body>> for Upstream {
        type Response = Response<tonic::body::Body>;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<tonic::body::Body>) -> Self::Future {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            let read_then_fail = self.read_body_then_fail;
            Box::pin(async move {
                if n == 0 {
                    if read_then_fail {
                        let _ = req.into_body().frame().await;
                    }
                    return Err("transport error".into());
                }
                let body = req.into_body().collect().await?.to_bytes();
                Ok(Response::new(tonic::body::Body::new(
                    http_body_util::Full::new(body).map_err(|e| match e {}),
                )))
            })
        }
    }

    fn request() -> Request<http_body_util::Full<hyper::body::Bytes>> {
        Request::builder()
            .method(http::Method::POST)
            .uri("/limen.v1.Resources/ListResources")
            .header("x-limen-forwarded", "1")
            .body(http_body_util::Full::new(hyper::body::Bytes::from_static(
                b"message",
            )))
            .expect("request")
    }

    /// The CLI reaches `limen admin selftest` through the proxy (ADR-0053).
    #[test]
    fn the_controls_api_is_relayed() {
        assert!(RELAYED_PREFIXES.contains(&"/limen.v1.Controls/"));
        assert!(RELAYED_PREFIXES.contains(&"/limen.v1.Reviews/"));
    }

    #[tokio::test]
    async fn a_request_the_transport_never_read_is_sent_again() {
        let upstream = Upstream {
            calls: Arc::default(),
            read_body_then_fail: false,
        };
        let response = forward(upstream.clone(), request(), |_| false)
            .await
            .expect("retried on a fresh connection");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        assert_eq!(&body[..], b"message", "the same body, intact");
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
    }

    /// hyper sends an empty body as HEADERS with `END_STREAM` and never polls
    /// it, so "never polled" proves nothing: such a POST is not resent.
    #[tokio::test]
    async fn an_empty_body_post_is_not_resent() {
        let upstream = Upstream {
            calls: Arc::default(),
            read_body_then_fail: false,
        };
        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/console/api/kill")
            .body(http_body_util::Full::new(hyper::body::Bytes::new()))
            .expect("request");
        assert!(forward(upstream.clone(), req, |_| true).await.is_err());
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    }

    fn get(path: &'static str) -> Request<http_body_util::Full<hyper::body::Bytes>> {
        Request::builder()
            .method(http::Method::GET)
            .uri(path)
            .body(http_body_util::Full::new(hyper::body::Bytes::new()))
            .expect("request")
    }

    /// A GET's empty body is never polled, delivered or not, so only an error
    /// that shows the connection went away before the control plane acted
    /// allows a resend. Otherwise a GET with effects (the sign-in callback,
    /// which spends a one-time code) could be replayed.
    #[tokio::test]
    async fn a_get_is_resent_only_after_an_error_showing_the_connection_went_away() {
        let upstream = Upstream {
            calls: Arc::default(),
            read_body_then_fail: false,
        };
        assert!(
            forward(upstream.clone(), get("/console/callback"), |_| false)
                .await
                .is_err(),
            "an unexplained transport error may have come after the control plane acted"
        );
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);

        let upstream = Upstream {
            calls: Arc::default(),
            read_body_then_fail: false,
        };
        forward(upstream.clone(), get("/console/sessions"), |_| true)
            .await
            .expect("the connection went away before the request: sent again");
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
    }

    /// A stand-in control plane (plain HTTP/2) that reports the headers of
    /// every request it receives.
    async fn recording_upstream() -> (
        limen_tunnel::connect::TracedChannel,
        tokio::sync::mpsc::UnboundedReceiver<(String, http::HeaderMap)>,
    ) {
        use hyper_util::rt::{TokioExecutor, TokioIo};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let tx = tx.clone();
                let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let _ = tx.send((req.uri().path().to_owned(), req.headers().clone()));
                    async {
                        Ok::<_, Infallible>(Response::new(http_body_util::Empty::<Bytes>::new()))
                    }
                });
                tokio::spawn(
                    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tcp), service),
                );
            }
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .expect("endpoint")
            .connect_lazy();
        (limen_tunnel::connect::TracedChannel::new(channel), rx)
    }

    /// Send `req` through [`relay`] as if it arrived on a TLS connection
    /// from `peer`, and return the `grpc-status` the client got (`None` for
    /// a plain response, as the stand-in upstream sends).
    async fn through_relay(
        channel: limen_tunnel::connect::TracedChannel,
        peer: PeerInfo,
        req: Request<http_body_util::Full<Bytes>>,
    ) -> Option<String> {
        use hyper_util::rt::{TokioExecutor, TokioIo};
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let service = hyper::service::service_fn(move |mut req: Request<Incoming>| {
            req.extensions_mut().insert(peer.clone());
            let channel = channel.clone();
            async move { Ok::<_, Infallible>(relay(channel, req).await) }
        });
        tokio::spawn(
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(server_io), service),
        );
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client_io))
                .await
                .expect("handshake");
        tokio::spawn(conn);
        let response =
            tokio::time::timeout(std::time::Duration::from_secs(10), sender.send_request(req))
                .await
                .expect("the relay answers")
                .expect("response");
        assert_eq!(response.status(), http::StatusCode::OK);
        response
            .headers()
            .get("grpc-status")
            .map(|v| v.to_str().expect("ascii").to_owned())
    }

    const PEER_ADDR: &str = "192.0.2.7:4242";

    fn peer(leaf: Option<&[u8]>) -> PeerInfo {
        PeerInfo {
            remote_addr: Some(PEER_ADDR.parse().expect("addr")),
            server_name: None,
            client_certs: leaf
                .map(|der| rustls_pki_types::CertificateDer::from(der.to_vec()))
                .into_iter()
                .collect(),
        }
    }

    /// A request that claims, in its own headers, to have been forwarded
    /// already, from another address, with someone else's certificate.
    fn spoofed(path: &str) -> Request<http_body_util::Full<Bytes>> {
        Request::builder()
            .method(http::Method::POST)
            .uri(path)
            .header("content-type", "application/grpc")
            .header(
                relay::CLIENT_CERT,
                base64::engine::general_purpose::STANDARD.encode(b"forged admin certificate"),
            )
            .header(relay::FORWARDED, "0")
            .header(relay::CLIENT_ADDR, "10.9.9.9:1")
            .header("x-limen-anything", "smuggled")
            .body(http_body_util::Full::new(Bytes::from_static(b"message")))
            .expect("request")
    }

    fn limen_headers(headers: &http::HeaderMap) -> Vec<(String, String)> {
        let mut out: Vec<_> = headers
            .iter()
            .filter(|(k, _)| k.as_str().starts_with("x-limen-"))
            .map(|(k, v)| (k.as_str().to_owned(), v.to_str().expect("ascii").to_owned()))
            .collect();
        out.sort();
        out
    }

    /// An anonymous caller can't pass itself off as a certificate holder:
    /// every client-supplied `x-limen-*` header is dropped, and the control
    /// plane sees only what the proxy itself vouches for.
    #[tokio::test]
    async fn an_anonymous_caller_cannot_forge_a_forwarded_certificate() {
        let (channel, mut seen) = recording_upstream().await;
        let status = through_relay(channel, peer(None), spoofed("/limen.v1.Auth/Login")).await;
        assert_eq!(status, None, "relayed, not refused");
        let (path, headers) = seen.recv().await.expect("relayed");
        assert_eq!(path, "/limen.v1.Auth/Login");
        assert_eq!(
            limen_headers(&headers),
            [
                (relay::CLIENT_ADDR.to_owned(), PEER_ADDR.to_owned()),
                (relay::FORWARDED.to_owned(), "1".to_owned()),
            ],
            "no forged certificate, address or other limen header reaches the control plane"
        );
    }

    /// A caller with a certificate is forwarded with that certificate only,
    /// never with a second one it put in the headers itself.
    #[tokio::test]
    async fn a_caller_is_forwarded_with_its_own_certificate_only() {
        let (channel, mut seen) = recording_upstream().await;
        let leaf = b"the verified leaf certificate";
        let status = through_relay(
            channel,
            peer(Some(leaf)),
            spoofed("/limen.v1.Resources/ListResources"),
        )
        .await;
        assert_eq!(status, None, "relayed, not refused");
        let (_, headers) = seen.recv().await.expect("relayed");
        let certs: Vec<_> = headers.get_all(relay::CLIENT_CERT).iter().collect();
        assert_eq!(
            certs,
            [base64::engine::general_purpose::STANDARD
                .encode(leaf)
                .as_str()],
            "exactly the certificate from the TLS handshake"
        );
        assert!(headers.get("x-limen-anything").is_none());
        assert_eq!(headers.get(relay::FORWARDED).expect("marker"), "1");
    }

    /// The console authenticates with its own cookie: no client certificate
    /// is forwarded on that path, verified or forged.
    #[tokio::test]
    async fn console_traffic_carries_no_client_certificate() {
        let (channel, mut seen) = recording_upstream().await;
        let status = through_relay(
            channel,
            peer(Some(b"a verified user certificate")),
            spoofed("/console/api/sessions"),
        )
        .await;
        assert_eq!(status, None, "relayed, not refused");
        let (path, headers) = seen.recv().await.expect("relayed");
        assert_eq!(path, "/console/api/sessions");
        assert_eq!(
            limen_headers(&headers),
            [
                (relay::CLIENT_ADDR.to_owned(), PEER_ADDR.to_owned()),
                (relay::FORWARDED.to_owned(), "1".to_owned()),
            ]
        );
    }

    /// `Registry` is for proxies calling directly; it and any other service
    /// not on the list are refused at the proxy and never reach the control plane.
    #[tokio::test]
    async fn services_off_the_list_are_not_relayed() {
        let (channel, mut seen) = recording_upstream().await;
        for path in [
            "/limen.v1.Registry/ListTunnels",
            "/limen.v1.Unknown/Call",
            "/limen.v1.AuthX/Login",
        ] {
            let status = through_relay(channel.clone(), peer(None), spoofed(path)).await;
            let unimplemented = (tonic::Code::Unimplemented as i32).to_string();
            assert_eq!(status.as_deref(), Some(unimplemented.as_str()), "{path}");
        }
        // Prove the upstream works, then that it saw only this one call.
        assert_eq!(
            through_relay(channel, peer(None), spoofed("/limen.v1.Auth/Login")).await,
            None
        );
        let (path, _) = seen.recv().await.expect("relayed");
        assert_eq!(path, "/limen.v1.Auth/Login", "nothing off the list arrived");
        assert!(seen.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_request_that_may_have_reached_the_control_plane_is_not_repeated() {
        let upstream = Upstream {
            calls: Arc::default(),
            read_body_then_fail: true,
        };
        assert!(
            forward(upstream.clone(), request(), |_| true)
                .await
                .is_err()
        );
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    }
}

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
/// and `Reviews` are for people (each call checks the caller's roles);
/// `Discovery` and `Watch` are for workers.
const RELAYED_PREFIXES: [&str; 12] = [
    "/limen.v1.AuditIngest/",
    "/limen.v1.Auth/",
    "/limen.v1.Resources/",
    "/limen.v1.Admin/",
    "/limen.v1.Access/",
    "/limen.v1.AuditSearch/",
    "/limen.v1.Reviews/",
    "/limen.v1.Discovery/",
    "/limen.v1.Watch/",
    "/limen.v1.Enrollment/",
    "/limen.v1.PolicySync/",
    "/limen.v1.SshCertificates/",
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
    if path == "/console" || path.starts_with("/console/") {
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

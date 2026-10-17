//! Relays CLI and worker API calls to the control plane (design §3).
//!
//! Client-supplied `x-limen-*` headers are stripped, then the proxy adds the
//! forwarded marker, the client address, and the client certificate it
//! verified. The control plane re-verifies that certificate itself.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine as _;
use http::{HeaderValue, Request, Response};
use hyper::body::Incoming;
use limen_proto::relay;
use limen_tunnel::PeerInfo;
use tower::{Service, ServiceExt};

use crate::Proxy;

/// API services the proxy relays. `Registry` is deliberately absent: only
/// proxies call it, directly. `PolicySync` and `SshCertificates` are for
/// workers; the control plane rejects other callers.
const RELAYED_PREFIXES: [&str; 7] = [
    "/limen.v1.AuditIngest/",
    "/limen.v1.Auth/",
    "/limen.v1.Resources/",
    "/limen.v1.Admin/",
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
    channel: tonic::transport::Channel,
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
    let forwarded = Request::from_parts(parts, tonic::body::Body::new(body));
    match channel.oneshot(forwarded).await {
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

fn plain(status: http::StatusCode, text: &'static str) -> Response<tonic::body::Body> {
    use axum::response::IntoResponse as _;
    let (parts, body) = (status, text).into_response().into_parts();
    Response::from_parts(parts, tonic::body::Body::new(body))
}

async fn relay(
    channel: tonic::transport::Channel,
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
    let forwarded = Request::from_parts(parts, tonic::body::Body::new(body));
    match channel.oneshot(forwarded).await {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(error = %e, %path, "control plane unreachable");
            tonic::Status::unavailable("control plane unreachable").into_http()
        }
    }
}

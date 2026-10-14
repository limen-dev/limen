//! The reverse tunnel (ADR-0003).
//!
//! The worker dials the proxy, and after the TLS handshake the roles flip:
//! the worker serves gRPC over that connection with [`crate::serve::serve_h2`],
//! and the proxy is the client through [`TunnelChannel`].

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::{Request, Response};
use hyper::body::Incoming;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::TransportError;
use crate::serve::H2Settings;

/// A gRPC client transport over one tunnel connection. Cheap to clone. Fails
/// once the connection is gone, and is never re-established: the worker
/// dials a new tunnel instead.
#[derive(Debug, Clone)]
pub struct TunnelChannel {
    sender: SendRequest<tonic::body::Body>,
}

impl TunnelChannel {
    /// Do the HTTP/2 client handshake over `io`. The returned future drives
    /// the connection and completes when it closes. Spawn it.
    pub async fn handshake<IO>(
        io: IO,
        settings: H2Settings,
    ) -> Result<(Self, impl Future<Output = Result<(), hyper::Error>> + Send), TransportError>
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .keep_alive_interval(Some(settings.keepalive_interval))
            .keep_alive_timeout(settings.keepalive_timeout)
            .keep_alive_while_idle(true)
            .handshake(TokioIo::new(io))
            .await?;
        Ok((Self { sender }, connection))
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
}

impl tower::Service<Request<tonic::body::Body>> for TunnelChannel {
    type Response = Response<Incoming>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.sender.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<tonic::body::Body>) -> Self::Future {
        // hyper's HTTP/2 client needs an absolute URI with scheme and authority.
        let path = req
            .uri()
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str)
            .to_owned();
        if let Ok(uri) = http::Uri::builder()
            .scheme("http")
            .authority("worker.limen.invalid")
            .path_and_query(path)
            .build()
        {
            *req.uri_mut() = uri;
        }
        let fut = self.sender.send_request(req);
        Box::pin(fut)
    }
}

//! A tonic connector that dials TCP and does TLS with our own rustls config,
//! so every Limen client uses the same TLS setup.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};

use http::Uri;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Shared, swappable client TLS config. Swapped when a component renews its
/// certificate. Existing connections keep their old config.
#[derive(Debug, Clone)]
pub struct SharedClientConfig(Arc<RwLock<Arc<ClientConfig>>>);

impl SharedClientConfig {
    #[must_use]
    pub fn new(config: ClientConfig) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(config))))
    }

    #[must_use]
    pub fn get(&self) -> Arc<ClientConfig> {
        Arc::clone(
            &self
                .0
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    pub fn set(&self, config: ClientConfig) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(config);
    }
}

/// Dial `addr` (`host:port`) and do TLS, checking the server certificate against `server_name`.
pub async fn dial(
    addr: &str,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> std::io::Result<TlsStream<TcpStream>> {
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    TlsConnector::from(config).connect(name, tcp).await
}

/// `tower::Service<Uri>` for `tonic::transport::Endpoint::connect_with_connector`.
/// It ignores the URI and always dials the configured address.
#[derive(Debug, Clone)]
pub struct TlsConnectorService {
    addr: Arc<str>,
    server_name: Arc<str>,
    config: SharedClientConfig,
}

impl TlsConnectorService {
    #[must_use]
    pub fn new(addr: &str, server_name: &str, config: SharedClientConfig) -> Self {
        Self {
            addr: addr.into(),
            server_name: server_name.into(),
            config,
        }
    }
}

impl tower::Service<Uri> for TlsConnectorService {
    type Response = TokioIo<TlsStream<TcpStream>>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let (addr, name, config) = (
            Arc::clone(&self.addr),
            Arc::clone(&self.server_name),
            self.config.get(),
        );
        Box::pin(async move { dial(&addr, &name, config).await.map(TokioIo::new) })
    }
}

/// A lazily connecting tonic channel over our TLS, with HTTP/2 keepalives.
#[must_use]
pub fn channel(
    addr: &str,
    server_name: &str,
    config: SharedClientConfig,
) -> tonic::transport::Channel {
    // The scheme is http because TLS is done by the connector, not by tonic.
    tonic::transport::Endpoint::from_static("http://limen.invalid")
        .connect_timeout(std::time::Duration::from_secs(10))
        .http2_keep_alive_interval(std::time::Duration::from_secs(15))
        .keep_alive_timeout(std::time::Duration::from_secs(45))
        .keep_alive_while_idle(true)
        .connect_with_connector_lazy(TlsConnectorService::new(addr, server_name, config))
}

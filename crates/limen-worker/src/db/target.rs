//! Connecting to a database target (ADR-0033 section 2): TCP, then TLS with
//! `verify-full` against the CA bundle the resource names.

use std::sync::Arc;
use std::time::Duration;

use limen_policy::model::DbTarget;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// A boxed byte stream to the target.
pub type BoxedIo = Box<dyn Io>;

/// Where and how to reach one database.
#[derive(Debug, Clone)]
pub struct Target {
    /// `host:port`.
    pub endpoint: String,
    host: String,
    /// `None` only for `insecure_dev` targets.
    tls: Option<Arc<ClientConfig>>,
}

impl Target {
    /// Build the connection settings from the resource. `allow_insecure` is
    /// the worker's `--allow-insecure-db-targets`.
    pub async fn from_spec(spec: &DbTarget, allow_insecure: bool) -> Result<Self, String> {
        let host = match &spec.tls_server_name {
            Some(name) => name.clone(),
            None => spec
                .endpoint
                .rsplit_once(':')
                .map(|(h, _)| h.trim_matches(['[', ']']).to_owned())
                .ok_or("endpoint must be host:port")?,
        };
        if spec.insecure_dev {
            if !allow_insecure {
                return Err("this resource disables TLS (insecure_dev) but the worker was not started with --allow-insecure-db-targets".into());
            }
            return Ok(Self {
                endpoint: spec.endpoint.clone(),
                host,
                tls: None,
            });
        }
        let path = spec
            .tls_ca_file
            .as_deref()
            .ok_or("tls_ca_file is required: Limen verifies the database's certificate (set insecure_dev only in the local profile)")?;
        let pem = tokio::fs::read(path)
            .await
            .map_err(|e| format!("reading tls_ca_file {path}: {e}"))?;
        let mut roots = RootCertStore::empty();
        let mut count = 0;
        for cert in CertificateDer::pem_slice_iter(&pem) {
            let cert = cert.map_err(|e| format!("tls_ca_file {path}: {e}"))?;
            roots
                .add(cert)
                .map_err(|e| format!("tls_ca_file {path}: {e}"))?;
            count += 1;
        }
        if count == 0 {
            return Err(format!("tls_ca_file {path} holds no certificates"));
        }
        let config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            endpoint: spec.endpoint.clone(),
            host,
            tls: Some(Arc::new(config)),
        })
    }

    /// Whether the connection will be encrypted.
    #[must_use]
    pub fn uses_tls(&self) -> bool {
        self.tls.is_some()
    }

    pub async fn dial(&self) -> std::io::Result<TcpStream> {
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.endpoint))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")
            })??;
        tcp.set_nodelay(true)?;
        Ok(tcp)
    }

    /// Run the TLS handshake on `tcp`. Only valid when `uses_tls()`.
    pub async fn start_tls(&self, tcp: TcpStream) -> std::io::Result<BoxedIo> {
        let config = self.tls.clone().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "TLS is not configured")
        })?;
        let name = ServerName::try_from(self.host.clone())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let tls = tokio::time::timeout(
            CONNECT_TIMEOUT,
            TlsConnector::from(config).connect(name, tcp),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out")
        })??;
        Ok(Box::new(tls))
    }
}

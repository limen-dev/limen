//! Connecting to a database target (ADR-0033 section 2): TCP, then TLS with
//! `verify-full` against the CA bundle the resource names.

use std::sync::Arc;
use std::time::Duration;

use limen_policy::model::{DbTarget, MongoTarget};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The host part of `host:port` (brackets of an IPv6 address removed).
fn host_of(endpoint: &str) -> Result<String, String> {
    endpoint
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(['[', ']']).to_owned())
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "endpoint must be host:port".to_owned())
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// A boxed byte stream to the target.
pub type BoxedIo = Box<dyn Io>;

/// A client certificate and key, for servers that log the worker in by its
/// certificate (MongoDB `MONGODB-X509`).
pub struct ClientIdentity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientIdentity([REDACTED])")
    }
}

/// What every protocol's resource says about reaching its server.
struct Params<'a> {
    endpoint: &'a str,
    tls_server_name: Option<&'a str>,
    tls_ca_file: Option<&'a str>,
    insecure_dev: bool,
}

/// Where and how to reach one database.
#[derive(Debug, Clone)]
pub struct Target {
    /// `host:port`.
    pub endpoint: String,
    host: String,
    /// The resource names the certificate's name, so it stays when the
    /// endpoint changes (following a replica set primary).
    fixed_name: bool,
    /// `None` only for `insecure_dev` targets.
    tls: Option<Arc<ClientConfig>>,
    /// Set for a resource built from a profile (ADR-0042): what the worker
    /// may dial. Kept when the endpoint follows a replica set primary.
    guard: Option<limen_policy::model::Delegated>,
}

impl Target {
    /// Build the connection settings from the resource. `allow_insecure` is
    /// the worker's `--allow-insecure-db-targets`.
    pub async fn from_spec(spec: &DbTarget, allow_insecure: bool) -> Result<Self, String> {
        Self::build(
            &Params {
                endpoint: &spec.endpoint,
                tls_server_name: spec.tls_server_name.as_deref(),
                tls_ca_file: spec.tls_ca_file.as_deref(),
                insecure_dev: spec.insecure_dev,
            },
            allow_insecure,
            None,
        )
        .await
    }

    /// The same for a MongoDB-compatible server, optionally presenting a
    /// client certificate.
    pub async fn from_mongo(
        spec: &MongoTarget,
        allow_insecure: bool,
        identity: Option<ClientIdentity>,
    ) -> Result<Self, String> {
        Self::build(
            &Params {
                endpoint: &spec.endpoint,
                tls_server_name: spec.tls_server_name.as_deref(),
                tls_ca_file: spec.tls_ca_file.as_deref(),
                insecure_dev: spec.insecure_dev,
            },
            allow_insecure,
            identity,
        )
        .await
    }

    async fn build(
        spec: &Params<'_>,
        allow_insecure: bool,
        identity: Option<ClientIdentity>,
    ) -> Result<Self, String> {
        let host = match spec.tls_server_name {
            Some(name) => name.to_owned(),
            None => host_of(spec.endpoint)?,
        };
        let fixed_name = spec.tls_server_name.is_some();
        if spec.insecure_dev {
            if !allow_insecure {
                return Err("this resource disables TLS (insecure_dev) but the worker was not started with --allow-insecure-db-targets".into());
            }
            return Ok(Self {
                endpoint: spec.endpoint.to_owned(),
                host,
                fixed_name,
                tls: None,
                guard: None,
            });
        }
        let path = spec
            .tls_ca_file
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
        let builder = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots);
        let config = match identity {
            Some(id) => builder
                .with_client_auth_cert(id.chain, id.key)
                .map_err(|e| format!("client certificate: {e}"))?,
            None => builder.with_no_client_auth(),
        };
        Ok(Self {
            endpoint: spec.endpoint.to_owned(),
            host,
            fixed_name,
            tls: Some(Arc::new(config)),
            guard: None,
        })
    }

    /// The same target, dialed only where `guard` allows (ADR-0042).
    #[must_use]
    pub fn guarded(mut self, guard: Option<limen_policy::model::Delegated>) -> Self {
        self.guard = guard;
        self
    }

    /// The same settings for another `host:port` (a replica set's primary).
    /// The certificate name follows the new host unless the resource fixed it.
    pub fn with_endpoint(&self, endpoint: &str) -> Result<Self, String> {
        let mut next = self.clone();
        if !self.fixed_name {
            next.host = host_of(endpoint)?;
        }
        endpoint.clone_into(&mut next.endpoint);
        Ok(next)
    }

    /// Whether the connection will be encrypted.
    #[must_use]
    pub fn uses_tls(&self) -> bool {
        self.tls.is_some()
    }

    pub async fn dial(&self) -> std::io::Result<TcpStream> {
        let tcp = tokio::time::timeout(
            CONNECT_TIMEOUT,
            crate::dial::connect(&self.endpoint, self.guard.as_ref()),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))??;
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

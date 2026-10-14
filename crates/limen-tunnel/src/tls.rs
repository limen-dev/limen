//! rustls configuration. TLS 1.3 only, aws-lc-rs provider (ADR-0012).

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::TransportError;

#[must_use]
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// A certificate chain and its private key.
#[derive(Debug)]
pub struct Identity {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Self {
            certs: self.certs.clone(),
            key: self.key.clone_key(),
        }
    }
}

impl Identity {
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, TransportError> {
        Ok(Self {
            certs: certs_from_pem(cert_pem)?,
            key: PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
                .map_err(|e| TransportError::Tls(format!("private key: {e}")))?,
        })
    }
}

/// All `CERTIFICATE` blocks in a PEM string.
pub fn certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, TransportError> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TransportError::Tls(format!("certificate PEM: {e}")))?;
    if certs.is_empty() {
        return Err(TransportError::Tls("no certificates in PEM".into()));
    }
    Ok(certs)
}

fn root_store(roots: &[CertificateDer<'static>]) -> Result<Arc<RootCertStore>, TransportError> {
    let mut store = RootCertStore::empty();
    for root in roots {
        store
            .add(root.clone())
            .map_err(|e| TransportError::Tls(format!("trust anchor: {e}")))?;
    }
    Ok(Arc::new(store))
}

/// How a server treats client certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    /// A client certificate chaining to one of the roots is required.
    Required,
    /// A certificate is verified if presented, but not required. Handlers
    /// must then authorize anonymous callers explicitly.
    Optional,
}

/// Server config with client verification against `client_roots`.
///
/// rustls checks that a presented client certificate chains to *one of* the
/// roots. Callers must still check which CA issued it, and the identity in it
/// (`limen_ca::verify`).
pub fn server_config(
    identity: Identity,
    client_roots: &[CertificateDer<'static>],
    client_auth: ClientAuth,
    alpn: &[&[u8]],
) -> Result<ServerConfig, TransportError> {
    let provider = provider();
    let verifier = WebPkiClientVerifier::builder_with_provider(
        root_store(client_roots)?,
        Arc::clone(&provider),
    );
    let verifier = match client_auth {
        ClientAuth::Required => verifier.build(),
        ClientAuth::Optional => verifier.allow_unauthenticated().build(),
    }
    .map_err(|e| TransportError::Tls(e.to_string()))?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TransportError::Tls(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(identity.certs, identity.key)
        .map_err(|e| TransportError::Tls(e.to_string()))?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

/// Client config trusting only `roots`, optionally presenting `identity`.
pub fn client_config(
    roots: &[CertificateDer<'static>],
    identity: Option<Identity>,
    alpn: &[&[u8]],
) -> Result<ClientConfig, TransportError> {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TransportError::Tls(e.to_string()))?
        .with_root_certificates(root_store(roots)?);
    let mut config = match identity {
        Some(id) => builder
            .with_client_auth_cert(id.certs, id.key)
            .map_err(|e| TransportError::Tls(e.to_string()))?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

//! Signing backends for CA keys.

use std::path::Path;

use futures::future::BoxFuture;
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData, SigningKey};

use crate::CaError;

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("signing backend unavailable: {0}")]
    Unavailable(String),
    #[error("signing backend rejected the request: {0}")]
    Rejected(String),
}

/// A CA private key that can sign but never reveals itself.
///
/// All keys are ECDSA P-256 with SHA-256 (KMS key spec `ECC_NIST_P256`).
pub trait Signer: Send + Sync + std::fmt::Debug {
    /// Raw public key bytes: the uncompressed EC point, as stored in the
    /// SubjectPublicKeyInfo BIT STRING.
    fn public_key_raw(&self) -> &[u8];

    /// Sign `message`. The signer hashes it, so callers must not pre-hash.
    /// Returns a DER-encoded ECDSA signature, which is what KMS returns.
    fn sign<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, SignError>>;
}

/// A P-256 key in a PKCS#8 PEM file. For development and tests only: the
/// key is in process memory and on disk.
#[derive(Debug)]
pub struct FileSigner {
    key: KeyPair,
}

impl FileSigner {
    /// Generate a fresh in-memory key.
    pub fn generate() -> Result<Self, CaError> {
        Ok(Self {
            key: KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, CaError> {
        let key = KeyPair::from_pem(pem)?;
        if key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
            return Err(CaError::InvalidRequest("CA key must be ECDSA P-256".into()));
        }
        Ok(Self { key })
    }

    /// Load the key at `path`, creating it (mode 0600) if it doesn't exist.
    pub fn load_or_create(path: &Path) -> Result<Self, CaError> {
        match std::fs::read_to_string(path) {
            Ok(pem) => Self::from_pem(&pem),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let signer = Self::generate()?;
                write_private(path, &signer.key.serialize_pem())
                    .map_err(|e| CaError::Internal(format!("writing {}: {e}", path.display())))?;
                tracing::info!(path = %path.display(), "generated new CA key");
                Ok(signer)
            }
            Err(e) => Err(CaError::Internal(format!(
                "reading {}: {e}",
                path.display()
            ))),
        }
    }
}

impl Signer for FileSigner {
    fn public_key_raw(&self) -> &[u8] {
        self.key.der_bytes()
    }

    fn sign<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, SignError>> {
        Box::pin(async move {
            self.key
                .sign(message)
                .map_err(|e| SignError::Rejected(e.to_string()))
        })
    }
}

/// Write `contents` to `path` so that only the owner can read it.
pub fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()
}

/// Adapts an async [`Signer`] to rcgen's synchronous [`SigningKey`].
///
/// rcgen calls `sign` synchronously, so this must run on a thread where
/// blocking is allowed, such as [`tokio::task::spawn_blocking`]. The
/// authority takes care of that.
pub(crate) struct BlockingSigner<'a> {
    pub(crate) inner: &'a dyn Signer,
    pub(crate) runtime: tokio::runtime::Handle,
}

impl PublicKeyData for BlockingSigner<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.inner.public_key_raw()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for BlockingSigner<'_> {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.runtime.block_on(self.inner.sign(msg)).map_err(|e| {
            tracing::error!(error = %e, "CA signing failed");
            rcgen::Error::RemoteKeyError
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn file_signer_persists_and_reloads() {
        let dir = limen_testkit::temp_dir().expect("tempdir");
        let path = dir.path().join("ca/user.key");
        let a = FileSigner::load_or_create(&path).expect("create");
        let b = FileSigner::load_or_create(&path).expect("reload");
        assert_eq!(a.public_key_raw(), b.public_key_raw());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let sig = a.sign(b"hello").await.expect("sign");
        assert_eq!(sig[0], 0x30, "ECDSA signature must be DER (SEQUENCE)");
    }
}

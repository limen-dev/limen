//! Certificate authority.
//!
//! Every CA key sits behind [`Signer`], so the same issuance code runs
//! against a local file key in development and AWS KMS in production
//! (see ADR-0007). Issuance itself arrives in Phase 1.

use std::future::Future;

/// Each purpose has its own key, so compromising one doesn't compromise the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaPurpose {
    /// Issues mTLS certificates to control plane, proxy, and workers.
    Internal,
    /// Issues short-lived X.509 client certificates to users.
    UserX509,
    /// Issues short-lived OpenSSH user certificates.
    UserSsh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA over NIST P-256 with SHA-256. KMS key spec `ECC_NIST_P256`.
    EcdsaP256Sha256,
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("signing backend unavailable: {0}")]
    Unavailable(String),
    #[error("signing backend rejected the request: {0}")]
    Rejected(String),
}

/// A CA private key that can sign but never reveals itself.
pub trait Signer: Send + Sync {
    fn algorithm(&self) -> SignatureAlgorithm;

    /// DER-encoded SubjectPublicKeyInfo of the signing key.
    fn public_key_der(&self) -> &[u8];

    /// Sign `message`. The signer hashes it, so callers must not pre-hash.
    /// Returns a DER-encoded ECDSA signature, which is what KMS returns.
    fn sign(&self, message: &[u8]) -> impl Future<Output = Result<Vec<u8>, SignError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purposes_are_distinct() {
        assert_ne!(CaPurpose::Internal, CaPurpose::UserX509);
        assert_ne!(CaPurpose::UserX509, CaPurpose::UserSsh);
    }
}

//! Certificate authority.
//!
//! Every CA private key sits behind [`Signer`], so the same issuance code runs
//! against a local file key in development and AWS KMS in production
//! (ADR-0007). Identities are encoded as URI SANs (see
//! [`limen_core::identity`]) and can be verified offline with [`verify`].

pub mod authority;
#[cfg(feature = "kms")]
pub mod kms;
pub mod signer;
pub mod ssh;
pub mod verify;

pub use authority::{CertificateAuthority, ComponentCertRequest, IssuedCert, UserCertRequest};
pub use signer::{FileSigner, SignError, Signer};
pub use verify::{ComponentIdentity, UserIdentity, VerifyError};

/// Each purpose has its own key, so compromising one doesn't compromise the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaPurpose {
    /// Issues mTLS certificates to the control plane, proxies, and workers.
    Internal,
    /// Issues short-lived X.509 client certificates to users.
    UserX509,
    /// Signs per-session OpenSSH user certificates. Targets trust it via
    /// `TrustedUserCAKeys`. Only the control plane can use it, and only for a
    /// session a proxy has granted.
    UserSsh,
    /// Signs per-session OpenSSH host certificates for workers. The CLI's
    /// known_hosts trusts it, so the proxy can't man-in-the-middle SSH.
    HostSsh,
}

impl CaPurpose {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CaPurpose::Internal => "internal",
            CaPurpose::UserX509 => "user_x509",
            CaPurpose::UserSsh => "user_ssh",
            CaPurpose::HostSsh => "host_ssh",
        }
    }

    #[must_use]
    pub fn common_name(self) -> &'static str {
        match self {
            CaPurpose::Internal => "Limen Internal CA",
            CaPurpose::UserX509 => "Limen User CA",
            CaPurpose::UserSsh => "Limen SSH User CA",
            CaPurpose::HostSsh => "Limen SSH Host CA",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("signing failed: {0}")]
    Sign(#[from] SignError),
    #[error("certificate generation failed: {0}")]
    Generate(#[from] rcgen::Error),
    #[error("invalid certificate signing request: {0}")]
    InvalidCsr(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("internal error: {0}")]
    Internal(String),
}

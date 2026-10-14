//! Signed artifacts that let components trust each other's decisions:
//!
//! - [`envelope`]: sign a payload with a component key and verify it against
//!   the internal CA, with domain separation;
//! - [`grant`]: the session grant a proxy issues and workers verify (ADR-0002);
//! - [`snapshot`]: signed policy snapshots and the grace-period cache (ADR-0011).

pub mod envelope;
pub mod grant;
pub mod snapshot;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("bad signature or signer: {0}")]
    Signature(String),
    #[error("malformed payload: {0}")]
    Malformed(String),
    #[error("grant rejected: {0}")]
    Grant(String),
    #[error("policy snapshot is {age_secs}s old, beyond the {grace_secs}s grace period")]
    Stale { age_secs: i64, grace_secs: i64 },
    #[error("no policy snapshot yet")]
    NoSnapshot,
}

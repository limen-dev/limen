//! Shared domain types used by every Limen component.

pub mod backoff;
pub mod identity;
pub mod labels;
pub mod resource;
pub mod secret;
pub mod shutdown;
pub mod telemetry;

/// Version of the running binary, taken from the workspace package version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

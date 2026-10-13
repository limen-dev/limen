//! Process-wide tracing setup shared by all binaries.
//!
//! Phase 0 only configures structured logging. OpenTelemetry export and
//! metrics are added in later phases (see ADR-0011).

use tracing_subscriber::{EnvFilter, fmt};

/// Log output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable, for local development.
    #[default]
    Text,
    /// One JSON object per line, for production log shipping.
    Json,
}

/// Install the global tracing subscriber. Respects `RUST_LOG`, defaulting to `info`.
///
/// Calling it more than once is harmless: later calls are ignored.
pub fn init(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = fmt().with_env_filter(filter).with_writer(std::io::stderr);
    let _ = match format {
        LogFormat::Text => builder.try_init(),
        LogFormat::Json => builder.json().flatten_event(true).try_init(),
    };
}

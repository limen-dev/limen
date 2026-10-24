//! Process-wide tracing setup shared by all binaries.
//!
//! Phase 0 only configures structured logging. OpenTelemetry export and
//! metrics are added in later phases (see ADR-0011).

use clap::{Args, ValueEnum};
use tracing_subscriber::{EnvFilter, fmt};

/// Logging flags shared by every server binary, so they are configured the same way.
///
/// Levels: `error` is a failure that needs an operator, `warn` a degraded or
/// rejected-but-handled condition, `info` lifecycle events, `debug` per-request
/// detail, `trace` wire-level detail. `RUST_LOG`, when set, overrides `--log-level`.
/// Never log a credential: wrap it in `limen_core::secret::Secret`.
#[derive(Debug, Clone, Args)]
pub struct LogArgs {
    /// Log verbosity (a `tracing` filter such as `info` or `info,h2=debug`).
    #[arg(long, env = "LIMEN_LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    /// Log output format.
    #[arg(long, env = "LIMEN_LOG_FORMAT", value_enum)]
    pub log_format: Option<LogFormat>,

    /// Deprecated alias for `--log-format json`.
    #[arg(long, env = "LIMEN_LOG_JSON", hide = true)]
    pub log_json: bool,
}

impl LogArgs {
    /// The effective format: `--log-format` wins over the legacy `--log-json`.
    #[must_use]
    pub fn format(&self) -> LogFormat {
        self.log_format.unwrap_or(if self.log_json {
            LogFormat::Json
        } else {
            LogFormat::Text
        })
    }

    /// Install the global subscriber from these flags.
    pub fn init(&self) {
        init_with_default(self.format(), &self.log_level);
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
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
    init_with_default(format, "info");
}

/// Like [`init`], with a different default filter when `RUST_LOG` is unset.
pub fn init_with_default(format: LogFormat, default_filter: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    let builder = fmt().with_env_filter(filter).with_writer(std::io::stderr);
    let _ = match format {
        LogFormat::Text => builder.try_init(),
        LogFormat::Json => builder.json().flatten_event(true).try_init(),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        log: LogArgs,
    }

    #[test]
    fn defaults_to_info_text() {
        let cli = Cli::parse_from(["x"]);
        assert_eq!(cli.log.log_level, "info");
        assert_eq!(cli.log.format(), LogFormat::Text);
    }

    #[test]
    fn format_flag_beats_legacy_json_flag() {
        let cli = Cli::parse_from(["x", "--log-json"]);
        assert_eq!(cli.log.format(), LogFormat::Json);
        let cli = Cli::parse_from(["x", "--log-json", "--log-format", "text"]);
        assert_eq!(cli.log.format(), LogFormat::Text);
    }
}

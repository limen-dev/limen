//! Limen control plane: API, identity, policy, CA, worker registry, and audit ingestion.

use clap::Parser;
use limen_core::telemetry::{self, LogFormat};

#[derive(Debug, Parser)]
#[command(name = "limen-control-plane", version = limen_core::VERSION, about = "Limen control plane: API, identity, policy, CA, worker registry, and audit ingestion.")]
struct Args {
    /// Emit logs as JSON lines instead of human-readable text.
    #[arg(long, env = "LIMEN_LOG_JSON")]
    log_json: bool,
}

fn main() {
    let args = Args::parse();
    telemetry::init(if args.log_json {
        LogFormat::Json
    } else {
        LogFormat::Text
    });
    tracing::info!(
        version = limen_core::VERSION,
        "limen-control-plane starting (Phase 0 skeleton: no services yet)"
    );
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        super::Args::command().debug_assert();
    }
}

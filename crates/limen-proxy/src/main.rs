//! Limen proxy: the public entry point that authenticates, authorizes, and routes sessions.

use clap::Parser;
use limen_core::telemetry::{self, LogFormat};

#[derive(Debug, Parser)]
#[command(name = "limen-proxy", version = limen_core::VERSION, about = "Limen proxy: the public entry point that authenticates, authorizes, and routes sessions.")]
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
        "limen-proxy starting (Phase 0 skeleton: no services yet)"
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

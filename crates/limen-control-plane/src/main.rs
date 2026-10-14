//! Limen control plane: API, identity, policy, CA, worker registry, and audit.

use clap::Parser;
use limen_control_plane::Config;
use limen_core::telemetry::{self, LogFormat};

#[derive(Debug, Parser)]
#[command(name = "limen-control-plane", version = limen_core::VERSION, about)]
struct Args {
    /// Emit logs as JSON lines instead of human-readable text.
    #[arg(long, env = "LIMEN_LOG_JSON")]
    log_json: bool,

    #[command(flatten)]
    config: Config,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    telemetry::init(if args.log_json {
        LogFormat::Json
    } else {
        LogFormat::Text
    });
    tracing::info!(version = limen_core::VERSION, id = %args.config.id, "control plane starting");

    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        limen_core::shutdown::signal().await;
        tracing::info!("shutdown signal received");
        let _ = tx.send(true);
    });

    let listener = tokio::net::TcpListener::bind(args.config.listen).await?;
    let state = limen_control_plane::build_state(args.config).await?;
    limen_control_plane::run(state, listener, rx).await?;
    tracing::info!("control plane stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        super::Args::command().debug_assert();
    }
}

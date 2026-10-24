//! Limen control plane: API, identity, policy, CA, worker registry, and audit.

use clap::Parser;
use limen_control_plane::Config;
use limen_core::telemetry::LogArgs;

#[derive(Debug, Parser)]
#[command(name = "limen-control-plane", version = limen_core::VERSION, about)]
struct Args {
    #[command(flatten)]
    log: LogArgs,

    #[command(flatten)]
    config: Config,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    limen_core::metrics::install();
    let _telemetry = args.log.init("limen-control-plane");
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

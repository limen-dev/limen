//! Limen proxy: the public entry point.

use clap::Parser;
use limen_core::telemetry::{self, LogFormat};
use limen_proxy::{Config, Proxy};

#[derive(Debug, Parser)]
#[command(name = "limen-proxy", version = limen_core::VERSION, about)]
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
    limen_core::metrics::install();
    telemetry::init(if args.log_json {
        LogFormat::Json
    } else {
        LogFormat::Text
    });
    tracing::info!(version = limen_core::VERSION, "proxy starting");
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        limen_core::shutdown::signal().await;
        tracing::info!("shutdown signal received");
        let _ = tx.send(true);
    });
    let listener = tokio::net::TcpListener::bind(args.config.listen).await?;
    let (proxy, creds_tx) = Proxy::start(args.config).await?;
    limen_proxy::run(proxy, creds_tx, listener, rx).await?;
    tracing::info!("proxy stopped");
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

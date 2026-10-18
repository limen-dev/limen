//! Limen worker: runs inside target networks and terminates resource protocols.

use clap::Parser;
use limen_core::telemetry::{self, LogFormat};
use limen_worker::{Config, Worker};

#[derive(Debug, Parser)]
#[command(name = "limen-worker", version = limen_core::VERSION, about)]
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
    tracing::info!(version = limen_core::VERSION, "worker starting");
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        limen_core::shutdown::signal().await;
        tracing::info!("shutdown signal received");
        let _ = tx.send(true);
    });
    let once = args.config.db_bootstrap_once;
    let check = args.config.db_bootstrap_check;
    let (worker, creds_tx) = Worker::start(args.config).await?;
    if once {
        // A one-shot task: enroll, fetch policy, reconcile, report, exit.
        let version = worker.fetch_policy_once().await?;
        tracing::info!(version, check, "reconciling database roles");
        let (changes, failures) = worker.bootstrap_databases(!check).await;
        tracing::info!(changes, failures, "database role bootstrap finished");
        if !worker.drain_audit(std::time::Duration::from_secs(30)).await {
            tracing::error!("the audit events of this run were not delivered to the control plane");
            std::process::exit(1);
        }
        if failures > 0 || (check && changes > 0) {
            std::process::exit(if failures > 0 { 1 } else { 2 });
        }
        return Ok(());
    }
    limen_worker::run(worker, creds_tx, rx).await?;
    tracing::info!("worker stopped");
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

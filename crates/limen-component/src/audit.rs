//! Audit for proxies and workers: events go to a local spool, then are
//! shipped to the control plane (ADR-0009). An event counts as written once
//! it's fsynced in the local spool, so the control plane being down doesn't
//! lose or block events until the spool fills.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use limen_audit::ship::{ConsumerConfig, ShipError, SpoolSink, run_consumer};
use limen_audit::spool::{Spool, SpoolConfig};
use limen_audit::{Emitter, FailureMode};
use limen_proto::v1::IngestRequest;
use limen_proto::v1::audit_ingest_client::AuditIngestClient;
use tokio::sync::watch;
use tonic::transport::Channel;

pub const TO_CONTROL_PLANE: &str = "control-plane";

/// Open the spool under `dir` and an emitter writing to it.
pub fn open(
    dir: &Path,
    max_bytes: u64,
    component: &str,
    id: &str,
    mode: FailureMode,
) -> anyhow::Result<(Emitter, Spool)> {
    let mut config = SpoolConfig::new(dir, &[TO_CONTROL_PLANE]);
    config.max_bytes = max_bytes;
    let spool = Spool::open(config)?;
    spool.start();
    let emitter = Emitter::new(component, id, Arc::new(SpoolSink(spool.clone())), mode);
    Ok((emitter, spool))
}

/// Ship the spool to the control plane until `shutdown` flips. `channel`
/// returns a channel presenting the component's current certificate.
pub async fn ship<F>(spool: Spool, channel: F, shutdown: watch::Receiver<bool>)
where
    F: Fn() -> anyhow::Result<Channel> + Send + Sync + 'static,
{
    let channel = Arc::new(channel);
    let consumer = ConsumerConfig {
        name: TO_CONTROL_PLANE.into(),
        batch_max: 500,
        linger: Duration::from_millis(50),
    };
    run_consumer(
        spool,
        consumer,
        move |batch| {
            let channel = Arc::clone(&channel);
            async move {
                let ch = channel().map_err(|e| ShipError::Retry(e.to_string()))?;
                let events = batch.into_iter().map(|(_, e)| e).collect();
                AuditIngestClient::new(ch)
                    .ingest(IngestRequest { events })
                    .await
                    .map(|_| ())
                    .map_err(|s| ShipError::Retry(format!("{:?}: {}", s.code(), s.message())))
            }
        },
        shutdown,
    )
    .await;
}

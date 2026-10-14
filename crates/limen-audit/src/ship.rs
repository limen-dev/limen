//! Moving records out of a spool: the spool-backed sink producers write to,
//! and the consumer loop that ships batches somewhere and commits offsets.

use std::future::Future;
use std::time::Duration;

use futures::future::BoxFuture;
use limen_core::backoff::Backoff;

use crate::spool::{Spool, SpoolError};
use crate::{AuditSink, Event};

/// Writes events to a spool. `write` returns once the event is durable.
#[derive(Debug, Clone)]
pub struct SpoolSink(pub Spool);

impl AuditSink for SpoolSink {
    fn write<'a>(&'a self, event: &'a Event) -> BoxFuture<'a, std::io::Result<()>> {
        Box::pin(async move {
            let line = serde_json::to_vec(event)?;
            self.0.append(&line).await.map(|_| ()).map_err(|e| match e {
                SpoolError::Io(io) => io,
                other => std::io::Error::other(other),
            })
        })
    }
}

/// Why a batch wasn't delivered.
#[derive(Debug, thiserror::Error)]
pub enum ShipError {
    /// Worth retrying: network, 5xx, throttling.
    #[error("{0}")]
    Retry(String),
}

#[derive(Debug, Clone)]
pub struct ConsumerConfig {
    pub name: String,
    pub batch_max: usize,
    /// Wait this long for a batch to fill before shipping what there is.
    pub linger: Duration,
}

// Metrics take f64; precision loss past 2^52 records is irrelevant.
#[allow(clippy::cast_precision_loss)]
/// Ship `consumer`'s records with `send` until `shutdown` flips. A batch is
/// committed only after `send` succeeds, so delivery is at-least-once.
/// Failures are retried with jittered backoff; records are never skipped.
pub async fn run_consumer<F, Fut>(
    spool: Spool,
    config: ConsumerConfig,
    send: F,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) where
    F: Fn(Vec<(u64, Vec<u8>)>) -> Fut + Send,
    Fut: Future<Output = Result<(), ShipError>> + Send,
{
    let mut backoff = Backoff::new(Duration::from_millis(200), Duration::from_secs(30));
    loop {
        if *shutdown.borrow() {
            return;
        }
        let batch = match spool.read(&config.name, config.batch_max) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(consumer = %config.name, error = %e, "spool read failed");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if batch.is_empty() {
            tokio::select! {
                () = spool.wait_for_data(Duration::from_secs(1)) => {}
                _ = shutdown.changed() => {}
            }
            continue;
        }
        // Give a small batch a moment to grow, unless it's already full.
        let batch = if batch.len() < config.batch_max && !config.linger.is_zero() {
            tokio::time::sleep(config.linger).await;
            spool.read(&config.name, config.batch_max).unwrap_or(batch)
        } else {
            batch
        };
        let upto = batch.last().map_or(0, |(i, _)| i + 1);
        let count = batch.len();
        match send(batch).await {
            Ok(()) => {
                backoff.reset();
                if let Err(e) = spool.commit(&config.name, upto) {
                    tracing::error!(consumer = %config.name, error = %e, "spool commit failed; the batch will be shipped again");
                }
                metrics::counter!("limen_audit_shipped_total", "consumer" => config.name.clone())
                    .increment(count as u64);
            }
            Err(ShipError::Retry(reason)) => {
                let delay = backoff.next_delay(rand::random());
                metrics::counter!("limen_audit_ship_errors_total", "consumer" => config.name.clone()).increment(1);
                tracing::warn!(consumer = %config.name, %reason, pending = spool.pending(&config.name), retry_in = ?delay, "audit shipping failed; retrying");
                tokio::select! {
                    () = tokio::time::sleep(delay) => {}
                    _ = shutdown.changed() => {}
                }
            }
        }
        metrics::gauge!("limen_audit_spool_pending", "consumer" => config.name.clone())
            .set(spool.pending(&config.name) as f64);
        metrics::gauge!("limen_audit_spool_bytes").set(spool.used_bytes() as f64);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::spool::SpoolConfig;

    #[tokio::test]
    async fn retries_until_delivered_and_never_skips() {
        let dir = tempfile::tempdir().expect("dir");
        let mut c = SpoolConfig::new(dir.path(), &["out"]);
        c.fsync_interval = Duration::from_millis(2);
        let spool = Spool::open(c).expect("open");
        spool.start();
        for i in 0..25u32 {
            spool.append(&i.to_be_bytes()).await.expect("append");
        }
        let delivered = Arc::new(std::sync::Mutex::new(Vec::new()));
        let attempts = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = tokio::sync::watch::channel(false);
        let (d, a) = (Arc::clone(&delivered), Arc::clone(&attempts));
        let task = tokio::spawn(run_consumer(
            spool.clone(),
            ConsumerConfig {
                name: "out".into(),
                batch_max: 10,
                linger: Duration::ZERO,
            },
            move |batch| {
                let (d, a) = (Arc::clone(&d), Arc::clone(&a));
                async move {
                    // Every other attempt fails, like a flaky sink.
                    if a.fetch_add(1, Ordering::SeqCst) % 2 == 0 {
                        return Err(ShipError::Retry("sink down".into()));
                    }
                    d.lock()
                        .expect("lock")
                        .extend(batch.into_iter().map(|(i, _)| i));
                    Ok(())
                }
            },
            rx,
        ));
        for _ in 0..200 {
            if delivered.lock().expect("lock").len() >= 25 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _ = tx.send(true);
        let _ = task.await;
        assert_eq!(
            *delivered.lock().expect("lock"),
            (0..25).collect::<Vec<u64>>()
        );
        assert_eq!(spool.pending("out"), 0);
    }
}

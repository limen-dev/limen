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

/// Resolves once the flag is true. A dropped sender counts as true when
/// `closed_means_set`, and as never otherwise.
async fn flipped(rx: &mut tokio::sync::watch::Receiver<bool>, closed_means_set: bool) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            if closed_means_set {
                return;
            }
            std::future::pending::<()>().await;
        }
    }
}

// Metrics take f64; precision loss past 2^52 records is irrelevant.
#[allow(clippy::cast_precision_loss)]
/// Ship `consumer`'s records with `send`. A batch is committed only after
/// `send` succeeds, so delivery is at-least-once. Failures are retried with
/// jittered backoff; records are never skipped.
///
/// When `shutdown` flips the consumer keeps shipping until its backlog is
/// empty, then returns. When `deadline` flips it returns at once, even in
/// the middle of a `send` (which is abandoned, so an unreachable sink can't
/// hold shutdown up); the records stay in the spool.
pub async fn run_consumer<F, Fut>(
    spool: Spool,
    config: ConsumerConfig,
    send: F,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    mut deadline: tokio::sync::watch::Receiver<bool>,
) where
    F: Fn(Vec<(u64, Vec<u8>)>) -> Fut + Send,
    Fut: Future<Output = Result<(), ShipError>> + Send,
{
    let mut backoff = Backoff::new(Duration::from_millis(200), Duration::from_secs(30));
    loop {
        if *deadline.borrow() {
            return;
        }
        let stopping = *shutdown.borrow() || shutdown.has_changed().is_err();
        let batch = match spool.read(&config.name, config.batch_max) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(consumer = %config.name, error = %e, "spool read failed");
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_secs(1)) => {}
                    () = flipped(&mut deadline, false) => {}
                }
                continue;
            }
        };
        if batch.is_empty() {
            if stopping {
                return;
            }
            tokio::select! {
                () = spool.wait_for_data(Duration::from_secs(1)) => {}
                () = flipped(&mut shutdown, true) => {}
                () = flipped(&mut deadline, false) => {}
            }
            continue;
        }
        // Give a small batch a moment to grow, unless it's already full or
        // we are draining.
        let batch = if batch.len() < config.batch_max && !config.linger.is_zero() && !stopping {
            tokio::select! {
                () = tokio::time::sleep(config.linger) => {}
                () = flipped(&mut shutdown, true) => {}
                () = flipped(&mut deadline, false) => {}
            }
            spool.read(&config.name, config.batch_max).unwrap_or(batch)
        } else {
            batch
        };
        let upto = batch.last().map_or(0, |(i, _)| i + 1);
        let count = batch.len();
        let outcome = tokio::select! {
            r = send(batch) => r,
            () = flipped(&mut deadline, false) => return,
        };
        match outcome {
            Ok(()) => {
                backoff.reset();
                if let Err(e) = spool.commit(&config.name, upto) {
                    tracing::error!(consumer = %config.name, error = %e, "spool commit failed; the batch will be shipped again");
                }
                metrics::counter!("limen_audit_shipped_total", "consumer" => config.name.clone())
                    .increment(count as u64);
            }
            Err(ShipError::Retry(reason)) => {
                let mut delay = backoff.next_delay(rand::random());
                if *shutdown.borrow() {
                    // Draining: the clock is running, so retry briskly.
                    delay = delay.min(Duration::from_secs(1));
                }
                metrics::counter!("limen_audit_ship_errors_total", "consumer" => config.name.clone()).increment(1);
                tracing::warn!(consumer = %config.name, %reason, pending = spool.pending(&config.name), retry_in = ?delay, "audit shipping failed; retrying");
                if stopping {
                    tokio::select! {
                        () = tokio::time::sleep(delay) => {}
                        () = flipped(&mut deadline, false) => {}
                    }
                } else {
                    tokio::select! {
                        () = tokio::time::sleep(delay) => {}
                        () = flipped(&mut shutdown, true) => {}
                        () = flipped(&mut deadline, false) => {}
                    }
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
        let (_deadline_tx, deadline_rx) = tokio::sync::watch::channel(false);
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
            deadline_rx,
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

    async fn spool_with(dir: &std::path::Path, n: u32) -> Spool {
        let mut c = SpoolConfig::new(dir, &["out"]);
        c.fsync_interval = Duration::from_millis(2);
        let spool = Spool::open(c).expect("open");
        spool.start();
        for i in 0..n {
            spool.append(&i.to_be_bytes()).await.expect("append");
        }
        spool
    }

    fn config(batch_max: usize) -> ConsumerConfig {
        ConsumerConfig {
            name: "out".into(),
            batch_max,
            linger: Duration::from_millis(50),
        }
    }

    #[tokio::test]
    async fn drains_to_zero_after_shutdown() {
        let dir = tempfile::tempdir().expect("dir");
        let spool = spool_with(dir.path(), 25).await;
        let delivered = Arc::new(AtomicUsize::new(0));
        let (_tx, rx) = tokio::sync::watch::channel(true); // already shutting down
        let (_dtx, drx) = tokio::sync::watch::channel(false);
        let d = Arc::clone(&delivered);
        run_consumer(
            spool.clone(),
            config(10),
            move |batch| {
                let d = Arc::clone(&d);
                async move {
                    d.fetch_add(batch.len(), Ordering::SeqCst);
                    Ok(())
                }
            },
            rx,
            drx,
        )
        .await;
        assert_eq!(delivered.load(Ordering::SeqCst), 25);
        assert_eq!(spool.pending("out"), 0);
    }

    #[tokio::test]
    async fn gives_up_at_deadline_with_records_left() {
        let dir = tempfile::tempdir().expect("dir");
        let spool = spool_with(dir.path(), 5).await;
        let (_tx, rx) = tokio::sync::watch::channel(true);
        let (dtx, drx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(run_consumer(
            spool.clone(),
            config(10),
            |_| async { Err(ShipError::Retry("down".into())) },
            rx,
            drx,
        ));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!task.is_finished(), "must keep retrying until the deadline");
        let _ = dtx.send(true);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("returns shortly after the deadline")
            .expect("join");
        assert_eq!(spool.pending("out"), 5);
    }

    #[tokio::test]
    async fn a_hung_send_is_abandoned_at_the_deadline() {
        let dir = tempfile::tempdir().expect("dir");
        let spool = spool_with(dir.path(), 5).await;
        let (_tx, rx) = tokio::sync::watch::channel(true);
        let (dtx, drx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(run_consumer(
            spool.clone(),
            config(10),
            |_| std::future::pending::<Result<(), ShipError>>(),
            rx,
            drx,
        ));
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = dtx.send(true);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("a send that never returns can't hang shutdown")
            .expect("join");
        assert_eq!(spool.pending("out"), 5);
    }
}

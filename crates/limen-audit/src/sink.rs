//! Audit sinks. Phase 1 has a local JSONL file and an in-memory sink for tests.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use futures::future::BoxFuture;
use tokio::io::AsyncWriteExt;

use crate::Event;

/// Somewhere audit events go. `write` returns only once the event is durable
/// at this sink.
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    fn write<'a>(&'a self, event: &'a Event) -> BoxFuture<'a, std::io::Result<()>>;
}

/// Appends one JSON object per line and fsyncs after every event.
///
/// This is the Phase 1 stub. It is durable but neither batched nor shipped
/// anywhere. Phase 3 replaces it with the segmented spool.
#[derive(Debug)]
pub struct JsonlFileSink {
    path: PathBuf,
    file: tokio::sync::Mutex<tokio::fs::File>,
}

impl JsonlFileSink {
    pub async fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        Ok(Self {
            path: path.to_owned(),
            file: tokio::sync::Mutex::new(file),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for JsonlFileSink {
    fn write<'a>(&'a self, event: &'a Event) -> BoxFuture<'a, std::io::Result<()>> {
        Box::pin(async move {
            let mut line = serde_json::to_vec(event)?;
            line.push(b'\n');
            let mut file = self.file.lock().await;
            file.write_all(&line).await?;
            file.sync_data().await
        })
    }
}

/// Keeps events in memory. For tests. Can be told to fail.
#[derive(Debug, Default)]
pub struct MemorySink {
    events: Mutex<Vec<Event>>,
    failing: std::sync::atomic::AtomicBool,
}

impl MemorySink {
    /// A snapshot of the events written so far.
    ///
    /// # Panics
    /// If the lock is poisoned, which only happens after a panic in another test thread.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn events(&self) -> Vec<Event> {
        self.events.lock().expect("memory sink lock").clone()
    }

    pub fn set_failing(&self, failing: bool) {
        self.failing
            .store(failing, std::sync::atomic::Ordering::SeqCst);
    }
}

impl AuditSink for MemorySink {
    fn write<'a>(&'a self, event: &'a Event) -> BoxFuture<'a, std::io::Result<()>> {
        Box::pin(async move {
            if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(std::io::Error::other("memory sink set to fail"));
            }
            self.events
                .lock()
                .map_err(|_| std::io::Error::other("poisoned"))?
                .push(event.clone());
            Ok(())
        })
    }
}

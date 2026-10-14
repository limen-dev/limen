//! Builds audit events and writes them to a sink.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use uuid::Uuid;

use crate::{AuditSink, Event, EventKind, Producer};

/// What to do when an event can't be written (ADR-0009).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FailureMode {
    /// The action being audited fails too. This is the default.
    #[default]
    FailClosed,
    /// The action goes ahead. The failure is logged at error level and counted.
    Degrade,
}

impl std::str::FromStr for FailureMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "fail_closed" => Ok(FailureMode::FailClosed),
            "degrade" => Ok(FailureMode::Degrade),
            _ => Err(format!(
                "unknown audit failure mode {s:?}; use fail_closed or degrade"
            )),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit sink unavailable: {0}")]
    SinkUnavailable(#[from] std::io::Error),
}

/// Emits audit events for one component instance.
#[derive(Debug, Clone)]
pub struct Emitter {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    component: String,
    /// `<component id>/<boot id>`. A new boot ID on every start means a
    /// (`instance_id`, `seq`) pair is unique even though `seq` restarts at zero.
    instance_id: String,
    seq: AtomicU64,
    sink: Arc<dyn AuditSink>,
    failure_mode: FailureMode,
    degraded_failures: AtomicU64,
}

/// Optional context attached to an event.
#[derive(Debug, Clone, Default)]
pub struct Context {
    pub user: Option<String>,
    pub session_id: Option<Uuid>,
}

impl Emitter {
    pub fn new(
        component: &str,
        component_id: &str,
        sink: Arc<dyn AuditSink>,
        failure_mode: FailureMode,
    ) -> Self {
        let boot = Uuid::now_v7().simple().to_string();
        Self {
            inner: Arc::new(Inner {
                component: component.to_owned(),
                instance_id: format!("{component_id}/{}", &boot[boot.len() - 12..]),
                seq: AtomicU64::new(0),
                sink,
                failure_mode,
                degraded_failures: AtomicU64::new(0),
            }),
        }
    }

    /// Write an event. Under [`FailureMode::FailClosed`] an error means the
    /// caller must not go ahead with the action it was auditing.
    pub async fn emit(
        &self,
        kind: EventKind,
        context: Context,
        data: serde_json::Value,
    ) -> Result<Uuid, AuditError> {
        let seq = self.inner.seq.fetch_add(1, Ordering::SeqCst);
        let producer = Producer {
            component: self.inner.component.clone(),
            instance_id: self.inner.instance_id.clone(),
            seq,
        };
        let mut event = Event::new(kind, producer, data);
        event.user = context.user;
        event.session_id = context.session_id;
        let id = event.event_id;
        match self.inner.sink.write(&event).await {
            Ok(()) => Ok(id),
            Err(e) if self.inner.failure_mode == FailureMode::Degrade => {
                let n = self.inner.degraded_failures.fetch_add(1, Ordering::SeqCst) + 1;
                tracing::error!(error = %e, event_id = %id, kind = ?kind, degraded_failures = n, "AUDIT EVENT LOST: sink unavailable and failure mode is degrade");
                Ok(id)
            }
            Err(e) => Err(AuditError::SinkUnavailable(e)),
        }
    }

    /// Events lost while in degrade mode since start.
    #[must_use]
    pub fn degraded_failures(&self) -> u64 {
        self.inner.degraded_failures.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JsonlFileSink, MemorySink};

    #[tokio::test]
    async fn assigns_increasing_seq_and_context() {
        let sink = Arc::new(MemorySink::default());
        let emitter = Emitter::new(
            "control-plane",
            "cp-1",
            sink.clone(),
            FailureMode::FailClosed,
        );
        let ctx = Context {
            user: Some("admin".into()),
            session_id: None,
        };
        emitter
            .emit(
                EventKind::AuthLogin,
                ctx.clone(),
                serde_json::json!({"a": 1}),
            )
            .await
            .expect("emit");
        emitter
            .emit(EventKind::AuthDenied, ctx, serde_json::json!({}))
            .await
            .expect("emit");
        let events = sink.events();
        assert_eq!(
            events.iter().map(|e| e.producer.seq).collect::<Vec<_>>(),
            [0, 1]
        );
        assert!(events.iter().all(|e| e.user.as_deref() == Some("admin")));
        assert!(events[0].producer.instance_id.starts_with("cp-1/"));
    }

    #[tokio::test]
    async fn fail_closed_returns_error_and_degrade_does_not() {
        let sink = Arc::new(MemorySink::default());
        sink.set_failing(true);
        let closed = Emitter::new("proxy", "p", sink.clone(), FailureMode::FailClosed);
        assert!(
            closed
                .emit(
                    EventKind::AuthLogin,
                    Context::default(),
                    serde_json::Value::Null
                )
                .await
                .is_err()
        );
        let degrade = Emitter::new("proxy", "p", sink.clone(), FailureMode::Degrade);
        assert!(
            degrade
                .emit(
                    EventKind::AuthLogin,
                    Context::default(),
                    serde_json::Value::Null
                )
                .await
                .is_ok()
        );
        assert_eq!(degrade.degraded_failures(), 1);
    }

    #[tokio::test]
    async fn jsonl_sink_appends_parseable_lines() {
        let dir = limen_testkit::temp_dir().expect("tempdir");
        let path = dir.path().join("audit/events.jsonl");
        let sink = Arc::new(JsonlFileSink::open(&path).await.expect("open"));
        let emitter = Emitter::new("worker", "w-1", sink, FailureMode::FailClosed);
        for _ in 0..3 {
            emitter
                .emit(
                    EventKind::WorkerEnroll,
                    Context::default(),
                    serde_json::json!({"x": true}),
                )
                .await
                .expect("emit");
        }
        // A second sink on the same file appends rather than truncating.
        let again = Arc::new(JsonlFileSink::open(&path).await.expect("reopen"));
        Emitter::new("worker", "w-1", again, FailureMode::FailClosed)
            .emit(
                EventKind::WorkerEnroll,
                Context::default(),
                serde_json::Value::Null,
            )
            .await
            .expect("emit");
        let text = std::fs::read_to_string(&path).expect("read");
        let events: Vec<Event> = text
            .lines()
            .map(|l| serde_json::from_str(l).expect("valid JSON line"))
            .collect();
        assert_eq!(events.len(), 4);
        assert!(events.iter().all(|e| e.kind == EventKind::WorkerEnroll));
    }
}

//! Audit ingest from proxies and workers (ADR-0009).

use limen_audit::Event;
use limen_audit::EventKind;
use limen_core::identity::ComponentKind;
use limen_proto::v1::audit_ingest_server::AuditIngest;
use limen_proto::v1::{IngestRequest, IngestResponse, RecordingChunk, UploadRecordingResponse};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};

use crate::caller;
use crate::state::{AppState, internal};

const MAX_EVENTS: usize = 1000;
const MAX_RECORDING_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct IngestService(pub AppState);

fn component_name(kind: ComponentKind) -> &'static str {
    match kind {
        ComponentKind::Proxy => "proxy",
        ComponentKind::Worker => "worker",
        ComponentKind::ControlPlane => "control-plane",
    }
}

/// The event kinds a component may send through `Ingest`. Everything else is
/// written by the control plane itself, so a compromised worker or proxy
/// cannot forge a login, a policy change, an access decision or a recording
/// link. (A worker may still send its own kinds for a session it serves; the
/// projection keeps the first identity a session was given.)
fn may_send(kind: ComponentKind, event: EventKind) -> bool {
    use EventKind::{
        AuthDenied, DbBootstrap, DbQuery, DbQueryEnd, KafkaRequest, KafkaSummary, KubeRequest,
        MongoCommand, MongoCommandEnd, MqOperation, MqSummary, RedisCommand, SearchRequest,
        SearchResponse, SessionEnd, SessionStart, SshExec, WebRequest, WebResponse, WebSocket,
    };
    match kind {
        ComponentKind::ControlPlane => true,
        ComponentKind::Worker => matches!(
            event,
            AuthDenied
                | DbBootstrap
                | DbQuery
                | DbQueryEnd
                | KafkaRequest
                | KafkaSummary
                | KubeRequest
                | MongoCommand
                | MongoCommandEnd
                | MqOperation
                | MqSummary
                | RedisCommand
                | SearchRequest
                | SearchResponse
                | SessionEnd
                | SessionStart
                | SshExec
        ),
        ComponentKind::Proxy => matches!(
            event,
            AuthDenied | SessionEnd | SessionStart | WebRequest | WebResponse | WebSocket
        ),
    }
}

/// Whether a `session.start` / `session.end` from this component describes a
/// session it can speak for. Workers write them for Kubernetes streams only
/// (and name themselves); proxies write them for every other kind, and a
/// start names the proxy that sent it. Other event kinds pass.
fn session_event_is_its_own(kind: ComponentKind, id: &str, event: &Event) -> bool {
    if !matches!(event.kind, EventKind::SessionStart | EventKind::SessionEnd) {
        return true;
    }
    let text = |key: &str| event.data.get(key).and_then(serde_json::Value::as_str);
    match kind {
        ComponentKind::ControlPlane => true,
        ComponentKind::Worker => text("kind") == Some("kube") && text("worker_id") == Some(id),
        ComponentKind::Proxy => {
            text("kind") != Some("kube")
                && (event.kind == EventKind::SessionEnd || text("proxy_id") == Some(id))
        }
    }
}

/// Whether `raw` has no line break (compact JSON never does: line breaks
/// inside strings are escaped).
pub(crate) fn is_single_line(raw: &[u8]) -> bool {
    !raw.iter().any(|b| matches!(b, b'\n' | b'\r'))
}

#[tonic::async_trait]
impl AuditIngest for IngestService {
    async fn ingest(
        &self,
        request: Request<IngestRequest>,
    ) -> Result<Response<IngestResponse>, Status> {
        self.0.refuse_if_draining()?;
        let caller = caller::resolve(&request, &self.0.cas)?;
        let component = caller.component()?.clone();
        let events = request.into_inner().events;
        if events.len() > MAX_EVENTS {
            return Err(Status::invalid_argument("too many events in one batch"));
        }
        // Validate everything before appending anything.
        for raw in &events {
            // Records are shipped one per line and counted by line. JSON the
            // components produce is compact; whitespace between tokens would
            // split one record across lines and break the batch's verification.
            if !is_single_line(raw) {
                return Err(Status::invalid_argument(
                    "malformed event: it must be one line of JSON",
                ));
            }
            let event: Event = serde_json::from_slice(raw)
                .map_err(|e| Status::invalid_argument(format!("malformed event: {e}")))?;
            let own_instance =
                event.producer.instance_id.split('/').next() == Some(component.id.as_str());
            if !session_event_is_its_own(component.kind, &component.id, &event) {
                return Err(Status::permission_denied(format!(
                    "{} {} can't submit session events for another component's sessions",
                    component.kind, component.id
                )));
            }
            if !may_send(component.kind, event.kind) {
                return Err(Status::permission_denied(format!(
                    "{} {} can't submit {:?} events",
                    component.kind, component.id, event.kind
                )));
            }
            if event.producer.component != component_name(component.kind) || !own_instance {
                return Err(Status::permission_denied(format!(
                    "{} {} can't submit events as {} {}",
                    component.kind,
                    component.id,
                    event.producer.component,
                    event.producer.instance_id
                )));
            }
        }
        // Appended together, in order: each append writes at once and then
        // waits for the spool's group fsync, so a batch costs one fsync
        // instead of one per event (a busy Redis session ships thousands).
        // A failure refuses the batch; events already appended are
        // idempotent by id when the sender retries.
        let spool = &self.0.pipeline.spool;
        let appended = futures::future::join_all(events.iter().map(|raw| spool.append(raw))).await;
        if let Some(e) = appended.into_iter().find_map(Result::err) {
            tracing::error!(error = %e, "audit spool append failed; refusing the batch");
            return Err(Status::unavailable(format!("audit spool: {e}")));
        }
        Ok(Response::new(IngestResponse {
            accepted: u32::try_from(events.len()).unwrap_or(u32::MAX),
        }))
    }

    async fn upload_recording(
        &self,
        request: Request<Streaming<RecordingChunk>>,
    ) -> Result<Response<UploadRecordingResponse>, Status> {
        self.0.refuse_if_draining()?;
        let caller = caller::resolve(&request, &self.0.cas)?;
        let worker = caller.component()?.clone();
        if worker.kind != ComponentKind::Worker {
            return Err(Status::permission_denied("only workers upload recordings"));
        }
        let mut stream = request.into_inner();
        let dir = self.0.config.audit_spool_dir.join("incoming-recordings");
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| internal("recording staging", e))?;
        let tmp = dir.join(format!("{}.part", uuid::Uuid::now_v7().simple()));
        let mut file = tokio::fs::File::create(&tmp)
            .await
            .map_err(|e| internal("recording staging", e))?;
        let (mut session_id, mut claimed, mut hasher, mut bytes) =
            (String::new(), String::new(), Sha256::new(), 0u64);
        let result: Result<(), Status> = async {
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                if session_id.is_empty() {
                    session_id = chunk.session_id;
                    uuid::Uuid::parse_str(&session_id)
                        .map_err(|_| Status::invalid_argument("session_id must be a UUID"))?;
                }
                bytes += chunk.data.len() as u64;
                if bytes > MAX_RECORDING_BYTES {
                    return Err(Status::invalid_argument("recording too large"));
                }
                hasher.update(&chunk.data);
                file.write_all(&chunk.data)
                    .await
                    .map_err(|e| internal("recording staging", e))?;
                if !chunk.sha256.is_empty() {
                    claimed = chunk.sha256;
                }
            }
            file.sync_all()
                .await
                .map_err(|e| internal("recording staging", e))?;
            Ok(())
        }
        .await;
        if let Err(e) = result {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
        let digest = hasher
            .finalize()
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            });
        if claimed != digest {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(Status::data_loss("recording checksum mismatch"));
        }
        let uri = self
            .0
            .pipeline
            .recordings
            .put(&session_id, &tmp)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "storing a recording failed; the worker will retry");
                Status::unavailable("recording store unavailable")
            });
        // With --search-recordings, the text on screen becomes searchable. Best
        // effort: the recording is stored either way.
        if uri.is_ok()
            && self.0.config.search_recordings
            && let Ok(id) = uuid::Uuid::parse_str(&session_id)
            && let Err(e) = crate::search::index::index_recording(&self.0.db, id, &tmp).await
        {
            tracing::warn!(session = %id, error = %e, "couldn't index a recording's text");
        }
        let _ = tokio::fs::remove_file(&tmp).await;
        let uri = uri?;
        let ctx = limen_audit::Context {
            user: None,
            session_id: uuid::Uuid::parse_str(&session_id).ok(),
        };
        let mut data = json!({ "recording_uri": uri, "sha256": digest, "bytes": bytes, "worker_id": worker.id });
        if let Some(name) = limen_core::names::from_labels(&worker.labels) {
            data["worker_name"] = json!(name);
        }
        self.0
            .audit
            .emit(EventKind::SessionRecording, ctx, data)
            .await
            .map_err(|_| Status::unavailable("audit unavailable"))?;
        tracing::info!(session = %session_id, %uri, bytes, "stored session recording");
        Ok(Response::new(UploadRecordingResponse { uri }))
    }
}

#[cfg(test)]
mod tests {
    use limen_audit::{Event, EventKind, Producer};
    use limen_core::identity::ComponentKind;
    use serde_json::json;

    use super::{is_single_line, may_send, session_event_is_its_own};

    #[test]
    fn an_event_is_one_line_of_json() {
        assert!(is_single_line(br#"{"a":1,"b":"x\ny"}"#), "escaped is fine");
        assert!(!is_single_line(b"{\"a\":1,\n\"b\":2}"));
        assert!(!is_single_line(b"{\"a\":1,\r\n\"b\":2}"));
        assert!(!is_single_line(b"{\"a\":1}\n"));
    }

    #[test]
    fn components_send_only_their_own_kinds() {
        for forged in [
            EventKind::AuthLogin,
            EventKind::PolicyChange,
            EventKind::AccessApprove,
            EventKind::SessionRecording,
            EventKind::UserUnlock,
            EventKind::ComponentRevoke,
        ] {
            assert!(!may_send(ComponentKind::Worker, forged), "{forged:?}");
            assert!(!may_send(ComponentKind::Proxy, forged), "{forged:?}");
        }
        assert!(may_send(ComponentKind::Worker, EventKind::SshExec));
        assert!(may_send(ComponentKind::Worker, EventKind::SessionEnd));
        assert!(!may_send(ComponentKind::Worker, EventKind::WebRequest));
        assert!(may_send(ComponentKind::Proxy, EventKind::WebRequest));
        assert!(!may_send(ComponentKind::Proxy, EventKind::DbQuery));
    }

    fn session_event(kind: EventKind, producer: &str, data: serde_json::Value) -> Event {
        Event::new(
            kind,
            Producer {
                component: producer.into(),
                instance_id: "x/1".into(),
                seq: 0,
            },
            data,
        )
    }

    #[test]
    fn a_component_speaks_only_for_its_own_sessions() {
        let own_kube = session_event(
            EventKind::SessionStart,
            "worker",
            json!({ "kind": "kube", "worker_id": "w1" }),
        );
        assert!(session_event_is_its_own(
            ComponentKind::Worker,
            "w1",
            &own_kube
        ));
        // Another worker's id, or a kind a worker never starts.
        assert!(!session_event_is_its_own(
            ComponentKind::Worker,
            "w2",
            &own_kube
        ));
        let ssh = session_event(
            EventKind::SessionStart,
            "worker",
            json!({ "kind": "ssh", "worker_id": "w1" }),
        );
        assert!(!session_event_is_its_own(ComponentKind::Worker, "w1", &ssh));
        let end_no_worker =
            session_event(EventKind::SessionEnd, "worker", json!({ "kind": "kube" }));
        assert!(!session_event_is_its_own(
            ComponentKind::Worker,
            "w1",
            &end_no_worker
        ));
        // A proxy's start names itself and is never a kube stream.
        let start = session_event(
            EventKind::SessionStart,
            "proxy",
            json!({ "kind": "ssh", "proxy_id": "p1", "worker_id": "w1" }),
        );
        assert!(session_event_is_its_own(ComponentKind::Proxy, "p1", &start));
        assert!(!session_event_is_its_own(
            ComponentKind::Proxy,
            "p2",
            &start
        ));
        let kube = session_event(
            EventKind::SessionStart,
            "proxy",
            json!({ "kind": "kube", "proxy_id": "p1" }),
        );
        assert!(!session_event_is_its_own(ComponentKind::Proxy, "p1", &kube));
        // Other kinds are not this check's business.
        let query = session_event(EventKind::DbQuery, "worker", json!({}));
        assert!(session_event_is_its_own(
            ComponentKind::Worker,
            "w1",
            &query
        ));
    }
}

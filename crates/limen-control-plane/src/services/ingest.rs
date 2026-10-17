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
            let event: Event = serde_json::from_slice(raw)
                .map_err(|e| Status::invalid_argument(format!("malformed event: {e}")))?;
            let own_instance =
                event.producer.instance_id.split('/').next() == Some(component.id.as_str());
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
        for raw in &events {
            self.0.pipeline.spool.append(raw).await.map_err(|e| {
                tracing::error!(error = %e, "audit spool append failed; refusing the batch");
                Status::unavailable(format!("audit spool: {e}"))
            })?;
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

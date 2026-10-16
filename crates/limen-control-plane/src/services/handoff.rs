//! Receiving audit records a peer replica hands off on shutdown (design §A).
//!
//! Only a live peer may call: a control plane certificate, presented
//! directly, whose id has a fresh row in the replica registry. Records are
//! appended to this replica's own spool and acked once durable; they keep
//! their `event_id` and producer, so they are not checked against the caller
//! (a peer hands off events from every proxy and worker that used it).

use limen_audit::Event;
use limen_core::identity::ComponentKind;
use limen_proto::v1::audit_handoff_server::AuditHandoff;
use limen_proto::v1::{HandoffAck, HandoffBatch};
use tokio_stream::StreamExt as _;
use tonic::{Request, Response, Status, Streaming};

use crate::caller::{self, Caller};
use crate::handoff_client::BATCH_MAX;
use crate::replicas;
use crate::state::{AppState, internal};

#[derive(Debug, Clone)]
pub struct HandoffService(pub AppState);

type AckStream =
    std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<HandoffAck, Status>> + Send>>;

impl HandoffService {
    /// The caller's id, if it is a live peer replica.
    async fn authorize<T>(&self, request: &Request<T>) -> Result<String, Status> {
        let caller = caller::resolve(request, &self.0.cas)?;
        let id = match &caller {
            Caller::Component {
                identity,
                via_proxy: false,
                ..
            } if identity.kind == ComponentKind::ControlPlane => identity.id.clone(),
            _ => {
                return Err(Status::permission_denied(
                    "only a peer control plane may hand off audit records",
                ));
            }
        };
        let peers = replicas::live_peers(&self.0.db, &self.0.config.id)
            .await
            .map_err(|e| internal("replica registry", e))?;
        if !peers.iter().any(|p| p.id == id) {
            tracing::warn!(caller = %caller.describe(), "refused an audit handoff from a control plane that is not a live replica");
            return Err(Status::permission_denied(
                "the caller is not a live replica in the registry",
            ));
        }
        Ok(id)
    }

    /// Validate and durably append one batch. Nothing is acked unless every
    /// record is on disk.
    async fn accept(&self, batch: &HandoffBatch) -> Result<(), Status> {
        self.0.refuse_if_draining()?;
        if batch.events.is_empty() {
            return Err(Status::invalid_argument("empty batch"));
        }
        if batch.events.len() > BATCH_MAX {
            return Err(Status::invalid_argument("too many events in one batch"));
        }
        for raw in &batch.events {
            serde_json::from_slice::<Event>(raw)
                .map_err(|e| Status::invalid_argument(format!("malformed event: {e}")))?;
        }
        // Appended together so they share an fsync.
        let spool = &self.0.pipeline.spool;
        let results = futures::future::join_all(batch.events.iter().map(|r| spool.append(r))).await;
        if let Some(Err(e)) = results.into_iter().find(Result::is_err) {
            tracing::error!(error = %e, "audit spool append failed; refusing the handoff batch");
            return Err(Status::unavailable(format!("audit spool: {e}")));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl AuditHandoff for HandoffService {
    type HandoffStream = AckStream;

    async fn handoff(
        &self,
        request: Request<Streaming<HandoffBatch>>,
    ) -> Result<Response<Self::HandoffStream>, Status> {
        self.0.refuse_if_draining()?;
        let peer = self.authorize(&request).await?;
        let mut batches = request.into_inner();
        let service = self.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            let mut received = 0usize;
            while let Some(batch) = batches.next().await {
                let result = match batch {
                    Ok(batch) => service.accept(&batch).await.map(|()| {
                        received += batch.events.len();
                        metrics::counter!("limen_audit_handoff_records_total", "direction" => "received")
                            .increment(batch.events.len() as u64);
                        HandoffAck {
                            durable_upto: batch.last_index,
                        }
                    }),
                    Err(e) => Err(e),
                };
                let failed = result.is_err();
                if tx.send(result).await.is_err() || failed {
                    break;
                }
            }
            tracing::info!(%peer, received, "received audit records handed off by a peer");
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

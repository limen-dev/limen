//! Signed policy snapshots for proxies and workers (ADR-0008, ADR-0011).

use limen_proto::v1::policy_sync_server::PolicySync;
use limen_proto::v1::{GetPolicySnapshotRequest, Signed};
use time::OffsetDateTime;
use tonic::{Request, Response, Status};

use crate::caller;
use crate::state::{AppState, internal};

#[derive(Debug, Clone)]
pub struct PolicySyncService(pub AppState);

#[tonic::async_trait]
impl PolicySync for PolicySyncService {
    async fn get_policy_snapshot(
        &self,
        request: Request<GetPolicySnapshotRequest>,
    ) -> Result<Response<Signed>, Status> {
        // Proxies directly, workers through a proxy. Users don't get the full policy.
        caller::resolve(&request, &self.0.cas)?.component()?;
        let key = self
            .0
            .snapshot_signer
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| Status::unavailable("snapshot signer not ready"))?;
        let loaded = self.0.policy.current();
        let signed = limen_session::snapshot::sign(
            &key,
            loaded.version,
            &loaded.policy,
            OffsetDateTime::now_utc(),
        )
        .map_err(|e| internal("signing policy snapshot", e))?;
        Ok(Response::new(signed))
    }
}

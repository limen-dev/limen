//! Signed policy snapshots for proxies and workers (ADR-0008, ADR-0011).

use limen_proto::v1::policy_sync_server::PolicySync;
use limen_proto::v1::{GetPolicySnapshotRequest, Signed};
use limen_session::snapshot::Restrictions;
use time::OffsetDateTime;
use tonic::{Request, Response, Status};

use crate::caller;
use crate::db;
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
        // Locks and kills come from the database on every request, so they
        // reach every proxy and worker within one refresh (10 s).
        let restrictions = Restrictions {
            locked_users: db::active_locks(&self.0.db)
                .await
                .map_err(|e| internal("reading locks", e))?
                .into_iter()
                .map(|l| l.username)
                .collect(),
            killed_sessions: db::recent_kills(&self.0.db)
                .await
                .map_err(|e| internal("reading session kills", e))?
                .into_iter()
                .collect(),
        };
        let signed = limen_session::snapshot::sign(
            &key,
            loaded.version,
            &loaded.policy,
            &restrictions,
            OffsetDateTime::now_utc(),
        )
        .map_err(|e| internal("signing policy snapshot", e))?;
        Ok(Response::new(signed))
    }
}

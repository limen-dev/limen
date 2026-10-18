//! Tunnel registry: which proxy holds which worker's tunnels (ADR-0004).

use limen_proto::v1::registry_server::Registry;
use limen_proto::v1::{
    ListTunnelsRequest, ListTunnelsResponse, PeerTunnel, ReportTunnelsRequest,
    ReportTunnelsResponse,
};
use tonic::{Request, Response, Status};

use crate::caller;
use crate::db;
use crate::state::{AppState, TUNNEL_LEASE, internal};

const MAX_TUNNELS_PER_REPORT: usize = 10_000;

#[derive(Debug, Clone)]
pub struct RegistryService(pub AppState);

#[tonic::async_trait]
impl Registry for RegistryService {
    async fn report_tunnels(
        &self,
        request: Request<ReportTunnelsRequest>,
    ) -> Result<Response<ReportTunnelsResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let proxy = caller.direct_proxy()?.clone();
        let req = request.into_inner();
        if req.tunnels.len() > MAX_TUNNELS_PER_REPORT {
            return Err(Status::invalid_argument("too many tunnels in one report"));
        }
        let reported: Vec<db::ReportedTunnel> = req
            .tunnels
            .into_iter()
            .map(|t| db::ReportedTunnel {
                tunnel_id: t.tunnel_id,
                worker_id: t.worker_id,
                active_sessions: t.active_sessions,
                max_sessions: t.max_sessions,
            })
            .collect();
        let peer_address = Some(req.peer_address.as_str()).filter(|s| !s.is_empty());
        let skipped =
            db::replace_tunnels(&self.0.db, &proxy.id, peer_address, &reported, TUNNEL_LEASE)
                .await
                .map_err(|e| internal("recording tunnels", e))?;
        if !skipped.is_empty() {
            tracing::warn!(proxy = %proxy.id, ?skipped, "ignored tunnels from unknown or revoked workers");
        }
        Ok(Response::new(ReportTunnelsResponse {
            lease_seconds: u32::try_from(TUNNEL_LEASE.as_secs()).unwrap_or(45),
        }))
    }

    async fn list_tunnels(
        &self,
        request: Request<ListTunnelsRequest>,
    ) -> Result<Response<ListTunnelsResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let proxy = caller.direct_proxy()?.clone();
        let rows = db::live_peer_tunnels(&self.0.db)
            .await
            .map_err(|e| internal("listing tunnels", e))?;
        let tunnels = rows
            .into_iter()
            .filter(|r| r.proxy_id != proxy.id)
            .map(|r| PeerTunnel {
                worker_id: r.worker_id,
                worker_labels: serde_json::from_value(r.worker_labels).unwrap_or_default(),
                proxy_id: r.proxy_id,
                peer_address: r.peer_address,
                active_sessions: r.active_sessions,
                max_sessions: r.max_sessions,
                worker_name: r.worker_name.unwrap_or_default(),
                proxy_name: r.proxy_name.unwrap_or_default(),
            })
            .collect();
        Ok(Response::new(ListTunnelsResponse { tunnels }))
    }
}

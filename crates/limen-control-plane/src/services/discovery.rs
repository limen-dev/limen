//! The `Discovery` API: workers report what they found (ADR-0027). The rules
//! are in [`crate::discovery`].

use limen_core::identity::ComponentKind;
use limen_proto::v1::discovery_server::Discovery;
use limen_proto::v1::{ReportDiscoveryRequest, ReportDiscoveryResponse};
use tonic::{Request, Response, Status};

use crate::caller;
use crate::state::AppState;

#[derive(Debug, Clone)]
pub struct DiscoveryService(pub AppState);

#[tonic::async_trait]
impl Discovery for DiscoveryService {
    async fn report(
        &self,
        request: Request<ReportDiscoveryRequest>,
    ) -> Result<Response<ReportDiscoveryResponse>, Status> {
        self.0.refuse_if_draining()?;
        let caller = caller::resolve(&request, &self.0.cas)?;
        let worker = caller.component()?.clone();
        if worker.kind != ComponentKind::Worker {
            return Err(Status::permission_denied("only workers report discoveries"));
        }
        crate::discovery::report(&self.0, &worker, request.into_inner())
            .await
            .map(Response::new)
    }
}

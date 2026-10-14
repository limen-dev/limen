//! Listing the resources a user can access.

use limen_proto::v1::resources_server::Resources;
use limen_proto::v1::{ListResourcesRequest, ListResourcesResponse, Resource};
use tonic::{Request, Response, Status};

use crate::caller;
use crate::state::AppState;

#[derive(Debug, Clone)]
pub struct ResourcesService(pub AppState);

#[tonic::async_trait]
impl Resources for ResourcesService {
    async fn list_resources(
        &self,
        request: Request<ListResourcesRequest>,
    ) -> Result<Response<ListResourcesResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.user()?;
        let loaded = self.0.policy.current();
        let resources = loaded
            .policy
            .accessible(&user.roles)
            .into_iter()
            .map(|r| Resource {
                name: r.name,
                kind: r.kind.as_str().to_owned(),
                labels: r.labels.into_iter().collect(),
                principals: r.principals,
            })
            .collect();
        Ok(Response::new(ListResourcesResponse {
            resources,
            policy_version: loaded.version,
        }))
    }
}

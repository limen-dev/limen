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
            .map(|r| {
                let default_database = loaded
                    .policy
                    .resource(&r.name)
                    .and_then(|doc| {
                        let s = &doc.spec;
                        s.postgres
                            .as_ref()
                            .or(s.mysql.as_ref())
                            .or(s.redshift.as_ref())
                    })
                    .and_then(|t| t.default_database.clone())
                    .or_else(|| {
                        loaded
                            .policy
                            .resource(&r.name)
                            .and_then(|doc| doc.spec.mongodb.as_ref())
                            .and_then(|t| t.default_database.clone())
                    })
                    .unwrap_or_default();
                let web_url = loaded
                    .policy
                    .resource(&r.name)
                    .and_then(|doc| doc.spec.web.as_ref())
                    .map(|target| web_url(&self.0, &target.host))
                    .unwrap_or_default();
                Resource {
                    name: r.name,
                    kind: r.kind.as_str().to_owned(),
                    labels: r.labels.into_iter().collect(),
                    principals: r.principals,
                    default_database,
                    web_url,
                }
            })
            .collect();
        Ok(Response::new(ListResourcesResponse {
            resources,
            policy_version: loaded.version,
        }))
    }
}

fn web_url(state: &AppState, host: &str) -> String {
    let Some(console) = &state.console else {
        return String::new();
    };
    let Ok(mut url) = url::Url::parse(&console.origin) else {
        return String::new();
    };
    if url.set_host(Some(host)).is_err() {
        return String::new();
    }
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    url.into()
}

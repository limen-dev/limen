//! `AuditSearch`: the CLI's way into the search of ADR-0026. The rules are in
//! [`crate::search`].

use limen_proto::v1::audit_search_server::AuditSearch;
use limen_proto::v1::{SearchHit, SearchRequest, SearchResponse};
use tonic::{Request, Response, Status};

use crate::caller;
use crate::search::{self, Searcher};
use crate::state::AppState;

#[derive(Debug, Clone)]
pub struct AuditSearchService(pub AppState);

#[tonic::async_trait]
impl AuditSearch for AuditSearchService {
    async fn search(
        &self,
        request: Request<SearchRequest>,
    ) -> Result<Response<SearchResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        // Admins and auditors only. Anyone else reads as not allowed, and the
        // attempt isn't a search, so it isn't audited as one.
        let user = caller.reader()?;
        let req = request.into_inner();
        let results = search::search(
            &self.0,
            Searcher {
                username: &user.username,
                via: "api",
            },
            &req.query,
            req.limit,
        )
        .await?;
        let history_url = self
            .0
            .config
            .search_history_url
            .as_deref()
            .zip(search::query::parse(&req.query, time::OffsetDateTime::now_utc()).ok())
            .map(|(template, q)| search::history_link(template, &req.query, &q))
            .unwrap_or_default();
        Ok(Response::new(SearchResponse {
            hits: results.hits.iter().map(hit).collect(),
            truncated: results.truncated,
            history_url,
        }))
    }
}

fn hit(h: &search::Hit) -> SearchHit {
    SearchHit {
        at_unix: h.at.unix_timestamp(),
        kind: h.kind.clone(),
        user: h.user.clone().unwrap_or_default(),
        session_id: h.session_id.map(|s| s.to_string()).unwrap_or_default(),
        resource: h.resource.clone().unwrap_or_default(),
        outcome: h.outcome.clone(),
        before: h.snippet.before.clone(),
        matched: h.snippet.hit.clone(),
        after: h.snippet.after.clone(),
        recording_offset_secs: h.recording_offset_secs.unwrap_or(-1),
    }
}

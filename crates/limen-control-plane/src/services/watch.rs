//! The `Watch` API (ADR-0030): workers ask who is being watched and publish
//! the output of those sessions. Thin: the rules are in [`crate::watch`].

use limen_core::identity::ComponentKind;
use limen_proto::v1::watch_server::Watch;
use limen_proto::v1::{
    WatchPollRequest, WatchPollResponse, WatchPublishRequest, WatchPublishResponse,
};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::caller;
use crate::state::{AppState, internal};
use crate::live;

/// Most sessions one poll may ask about.
const MAX_IDS: usize = 1_000;

#[derive(Debug, Clone)]
pub struct WatchService(pub AppState);

fn worker(request: &Request<impl Sized>, state: &AppState) -> Result<String, Status> {
    let caller = caller::resolve(request, &state.cas)?;
    let c = caller.component()?;
    if c.kind != ComponentKind::Worker {
        return Err(Status::permission_denied("only workers use this"));
    }
    Ok(c.id.clone())
}

#[tonic::async_trait]
impl Watch for WatchService {
    async fn poll(&self, request: Request<WatchPollRequest>) -> Result<Response<WatchPollResponse>, Status> {
        let worker_id = worker(&request, &self.0)?;
        let ids: Vec<Uuid> = request
            .into_inner()
            .session_ids
            .iter()
            .take(MAX_IDS)
            .filter_map(|s| Uuid::parse_str(s).ok())
            .collect();
        let watched = live::watched_among(&self.0.db, &worker_id, &ids)
            .await
            .map_err(|e| internal("checking watchers", e))?;
        Ok(Response::new(WatchPollResponse {
            watched: watched.iter().map(ToString::to_string).collect(),
        }))
    }

    async fn publish(&self, request: Request<WatchPublishRequest>) -> Result<Response<WatchPublishResponse>, Status> {
        let worker_id = worker(&request, &self.0)?;
        let r = request.into_inner();
        let id = Uuid::parse_str(&r.session_id).map_err(|_| Status::invalid_argument("bad session id"))?;
        let watched = live::publish(&self.0.db, &worker_id, id, &r.text, r.elapsed_ms, r.cols, r.rows).await?;
        Ok(Response::new(WatchPublishResponse { watched }))
    }
}

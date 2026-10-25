//! The `Reviews` API (ADR-0029). Thin: the rules are in [`crate::reviews`]
//! and [`crate::evidence`].

use limen_core::identity::{ADMIN_ROLE, AUDITOR_ROLE};
use limen_proto::v1::reviews_server::Reviews;
use limen_proto::v1::{
    DecideReviewItemRequest, ExportEvidenceRequest, ExportEvidenceResponse, LiftDenyRequest,
    LiftDenyResponse, ListDeniesRequest, ListDeniesResponse, ListReviewItemsRequest,
    ListReviewItemsResponse, ListReviewsRequest, ListReviewsResponse, ReviewInfo, ReviewItemInfo,
    StartReviewRequest,
};
use tonic::{Request, Response, Status};

use crate::caller;
use crate::reviews::{self, Who};
use crate::state::AppState;

#[derive(Debug, Clone)]
pub struct ReviewsService(pub AppState);

fn who(u: &limen_ca::verify::UserIdentity) -> Who<'_> {
    Who {
        username: &u.username,
        is_admin: u.has_role(ADMIN_ROLE),
        is_auditor: u.has_role(AUDITOR_ROLE),
        via: "api",
    }
}

#[tonic::async_trait]
impl Reviews for ReviewsService {
    async fn start_review(
        &self,
        request: Request<StartReviewRequest>,
    ) -> Result<Response<ReviewInfo>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.admin()?;
        self.0.refuse_if_draining()?;
        let r = request.into_inner();
        reviews::start(&self.0, &who(user), &r.name, r.due_days, r.override_days)
            .await
            .map(Response::new)
    }

    async fn list_reviews(
        &self,
        request: Request<ListReviewsRequest>,
    ) -> Result<Response<ListReviewsResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.user()?;
        let all = request.into_inner().scope == "all";
        Ok(Response::new(ListReviewsResponse {
            reviews: reviews::list(&self.0, &who(user), all).await?,
        }))
    }

    async fn list_review_items(
        &self,
        request: Request<ListReviewItemsRequest>,
    ) -> Result<Response<ListReviewItemsResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.user()?;
        let r = request.into_inner();
        Ok(Response::new(ListReviewItemsResponse {
            items: reviews::items(&self.0, &who(user), &r.review_id, r.mine, r.open_only).await?,
        }))
    }

    async fn decide_review_item(
        &self,
        request: Request<DecideReviewItemRequest>,
    ) -> Result<Response<ReviewItemInfo>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.user()?;
        self.0.refuse_if_draining()?;
        let r = request.into_inner();
        reviews::decide(&self.0, &who(user), &r.item_id, r.certify, &r.comment)
            .await
            .map(Response::new)
    }

    async fn list_denies(
        &self,
        request: Request<ListDeniesRequest>,
    ) -> Result<Response<ListDeniesResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.user()?;
        Ok(Response::new(ListDeniesResponse {
            denies: reviews::list_denies(&self.0, &who(user), request.into_inner().include_ended)
                .await?,
        }))
    }

    async fn lift_deny(
        &self,
        request: Request<LiftDenyRequest>,
    ) -> Result<Response<LiftDenyResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.admin()?;
        let r = request.into_inner();
        Ok(Response::new(LiftDenyResponse {
            lifted: reviews::lift_deny(&self.0, &who(user), &r.id, &r.reason).await?,
        }))
    }

    async fn export_evidence(
        &self,
        request: Request<ExportEvidenceRequest>,
    ) -> Result<Response<ExportEvidenceResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.reader()?;
        let r = request.into_inner();
        let (pack, manifest_sha256) =
            crate::evidence::export(&self.0, &user.username, r.from_unix, r.to_unix).await?;
        Ok(Response::new(ExportEvidenceResponse {
            pack,
            manifest_sha256,
        }))
    }
}

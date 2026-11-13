//! The `Controls` API (ADR-0053). Thin: the rules are in [`crate::selftest`].

use limen_proto::v1::controls_server::Controls;
use limen_proto::v1::{
    GetControlsReportRequest, GetControlsReportResponse, ListSelfTestRunsRequest,
    ListSelfTestRunsResponse, RunSelfTestRequest, SelfTestRunInfo,
};
use tonic::{Request, Response, Status};

use crate::selftest::{self, RunRow, Started, Trigger};
use crate::{caller, state::AppState};

#[derive(Debug, Clone)]
pub struct ControlsService(pub AppState);

/// A run as the API shows it.
#[must_use]
pub fn info(r: &RunRow, already_running: bool) -> SelfTestRunInfo {
    let count = |n: i32| u32::try_from(n).unwrap_or(0);
    SelfTestRunInfo {
        id: r.id.to_string(),
        trigger: r.trigger.clone(),
        requested_by: r.requested_by.clone(),
        status: r.status.clone(),
        started_at_unix: r.started_at.unix_timestamp(),
        finished_at_unix: r
            .finished_at
            .map_or(0, time::OffsetDateTime::unix_timestamp),
        passed: count(r.passed),
        failed: count(r.failed),
        skipped: count(r.skipped),
        manifest_sha256: r.manifest_sha256.clone().unwrap_or_default(),
        error: r.error.clone().unwrap_or_default(),
        already_running,
    }
}

#[tonic::async_trait]
impl Controls for ControlsService {
    async fn run_self_test(
        &self,
        request: Request<RunSelfTestRequest>,
    ) -> Result<Response<SelfTestRunInfo>, Status> {
        let caller = caller::resolve_current(&request, &self.0).await?;
        let user = caller.admin()?;
        self.0.refuse_if_draining()?;
        match selftest::start(&self.0, Trigger::Manual, &user.username).await? {
            Some(Started::New(r)) => Ok(Response::new(info(&r, false))),
            Some(Started::AlreadyRunning(r)) => Ok(Response::new(info(&r, true))),
            None => Err(Status::aborted(
                "a self-test could not be started; try again",
            )),
        }
    }

    async fn list_self_test_runs(
        &self,
        request: Request<ListSelfTestRunsRequest>,
    ) -> Result<Response<ListSelfTestRunsResponse>, Status> {
        let caller = caller::resolve_current(&request, &self.0).await?;
        caller.reader()?;
        let limit = match request.into_inner().limit {
            0 => 20,
            n => i64::from(n),
        };
        let runs = selftest::list(&self.0, limit).await?;
        Ok(Response::new(ListSelfTestRunsResponse {
            runs: runs.iter().map(|r| info(r, false)).collect(),
        }))
    }

    async fn get_controls_report(
        &self,
        request: Request<GetControlsReportRequest>,
    ) -> Result<Response<GetControlsReportResponse>, Status> {
        let caller = caller::resolve_current(&request, &self.0).await?;
        caller.reader()?;
        let id = uuid::Uuid::parse_str(request.into_inner().id.trim())
            .map_err(|_| Status::invalid_argument("not a run id"))?;
        let (run, report) = selftest::report(&self.0, id).await?;
        Ok(Response::new(GetControlsReportResponse {
            report,
            run: Some(info(&run, false)),
        }))
    }
}

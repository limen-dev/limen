//! The Controls page (ADR-0053): the latest self-test, its checks, the run
//! history, and a signed report to download. Reading is for admins and
//! auditors; starting a run is for admins, over POST with the CSRF token.

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use serde_json::Value;

use super::pages::{action_error, chrome, console};
use super::views::{Chrome, time_text};
use super::{Auth, html};
use crate::selftest::{self, RunRow, Trigger};
use crate::state::AppState;

pub struct RunView {
    pub id: String,
    pub when: String,
    pub trigger: String,
    pub status: String,
    pub tone: &'static str,
    pub summary: String,
    pub has_report: bool,
}

pub struct CheckView {
    pub title: String,
    pub id: String,
    pub status: String,
    pub tone: &'static str,
    pub detail: String,
}

#[derive(Template)]
#[template(path = "controls.html")]
pub struct ControlsPage {
    pub chrome: Chrome,
    pub notice: Option<&'static str>,
    pub error: Option<String>,
    pub runs: Vec<RunView>,
    pub latest: Option<RunView>,
    /// The newest run, when it ended without a report (an error or an
    /// abandoned run) and so is not the result shown below.
    pub newest_without_report: Option<RunView>,
    pub checks: Vec<CheckView>,
    pub attestation: String,
    pub interval: String,
}

#[derive(Deserialize)]
pub struct ControlsQuery {
    done: Option<String>,
    err: Option<String>,
}

fn tone(status: &str) -> &'static str {
    match status {
        "passed" => "ok",
        "failed" | "error" => "bad",
        _ => "warn",
    }
}

fn run_view(r: &RunRow) -> RunView {
    RunView {
        id: r.id.to_string(),
        when: time_text(Some(r.started_at)),
        trigger: if r.trigger == "manual" {
            format!("by {}", r.requested_by)
        } else {
            "scheduled".to_owned()
        },
        status: r.status.clone(),
        tone: tone(&r.status),
        summary: format!(
            "{} passed, {} failed, {} skipped",
            r.passed, r.failed, r.skipped
        ),
        has_report: r.manifest_sha256.is_some(),
    }
}

fn interval_text(secs: u64) -> String {
    match secs {
        0 => "off (runs only when an admin starts one)".to_owned(),
        s if s % 86_400 == 0 => format!("every {} d", s / 86_400),
        s if s % 3600 == 0 => format!("every {} h", s / 3600),
        s => format!("every {} min", (s / 60).max(1)),
    }
}

pub async fn page(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ControlsQuery>,
) -> Response {
    if let Err(r) = auth.reader() {
        return r;
    }
    let runs = match selftest::list(&state, 30).await {
        Ok(r) => r,
        Err(s) => return action_error(&s),
    };
    // The newest run with a report: what the checks table shows.
    let latest = runs.iter().find(|r| r.manifest_sha256.is_some());
    let (mut checks, mut attestation) = (Vec::new(), String::new());
    if let Some(r) = latest
        && let Ok((_, bytes)) = selftest::report(&state, r.id).await
        && let Ok(doc) = serde_json::from_slice::<Value>(&bytes)
    {
        doc["sections"]["meta"]["attestation"]
            .as_str()
            .unwrap_or_default()
            .clone_into(&mut attestation);
        for c in doc["sections"]["checks"].as_array().into_iter().flatten() {
            let status = c["status"].as_str().unwrap_or("").to_owned();
            checks.push(CheckView {
                title: c["title"].as_str().unwrap_or("").to_owned(),
                id: c["id"].as_str().unwrap_or("").to_owned(),
                tone: tone(&status),
                status,
                detail: c["detail"].as_str().unwrap_or("").to_owned(),
            });
        }
    }
    let notice = match q.done.as_deref() {
        Some("started") => Some("Self-test started. Reload in a few seconds."),
        Some("running") => Some("A self-test is already running."),
        _ => None,
    };
    html(
        ControlsPage {
            chrome: chrome(&state, &auth, "controls"),
            notice,
            error: q.err.map(|e| e.chars().take(300).collect()),
            runs: runs.iter().map(run_view).collect(),
            newest_without_report: runs
                .first()
                .filter(|r| r.manifest_sha256.is_none() && r.status != "running")
                .map(run_view),
            latest: latest.map(run_view),
            checks,
            attestation,
            interval: interval_text(state.config.selftest_interval.as_secs()),
        }
        .render(),
    )
}

#[derive(Deserialize)]
pub struct RunForm {
    csrf: String,
}

pub async fn run(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Form(f): Form<RunForm>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = auth.check_post(console, &headers, &f.csrf) {
        return r;
    }
    if let Err(s) = state.refuse_if_draining() {
        return action_error(&s);
    }
    match selftest::start(&state, Trigger::Manual, &auth.username).await {
        Ok(Some(selftest::Started::New(_))) => {
            Redirect::to("/console/controls?done=started").into_response()
        }
        Ok(_) => Redirect::to("/console/controls?done=running").into_response(),
        Err(s) => {
            let msg: String = s.message().chars().take(200).collect();
            Redirect::to(&format!(
                "/console/controls?err={}",
                super::views::path_segment(&msg)
            ))
            .into_response()
        }
    }
}

pub async fn report(State(state): State<AppState>, auth: Auth, Path(id): Path<String>) -> Response {
    if let Err(r) = auth.reader() {
        return r;
    }
    let Ok(id) = uuid::Uuid::parse_str(&id) else {
        return super::views::error_page(
            axum::http::StatusCode::NOT_FOUND,
            "Not found",
            "There is no such run.",
        );
    };
    match selftest::report(&state, id).await {
        Ok((_, bytes)) => (
            [
                (CONTENT_TYPE, "application/json"),
                (CACHE_CONTROL, "no-store"),
                (
                    CONTENT_DISPOSITION,
                    "attachment; filename=\"limen-controls.json\"",
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(s) => action_error(&s),
    }
}

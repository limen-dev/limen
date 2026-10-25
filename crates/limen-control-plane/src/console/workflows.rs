//! Console pages for the Phase 13 workflows: access requests and approvals,
//! access reviews and evidence, discovered resources, and watching a live
//! session. Each is a small handler over the same functions the CLI uses, so
//! the console and the API can't disagree about the rules.
//!
//! **Why these are where they are.** Requests and reviews are workflows with
//! queues, so each has its own page (Access, Reviews). Everything that is a
//! *view of something that already has a page* is integrated there instead:
//! search lives in the Audit trail, "who can reach this" and "request access"
//! on the resource, discovered resources as a tab of Resources, the policy
//! simulator on the Policy page, and watching on the session.

use std::convert::Infallible;
use std::time::Duration;

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Redirect, Response};
use limen_proto::v1::{ListAccessRequestsRequest, ReviewInfo, ReviewItemInfo};
use serde::Deserialize;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use super::pages::{action_error, chrome, console, db_error};
use super::views::{Chip, Chrome, chip_color, error_page, path_segment, time_text};
use super::{Auth, html};
use crate::access::{self, Who as AccessWho};
use crate::reviews::{self, Who as ReviewWho};
use crate::state::AppState;

fn access_who(auth: &Auth) -> AccessWho<'_> {
    AccessWho {
        username: &auth.username,
        is_admin: auth.is_admin,
        is_auditor: auth.is_auditor,
        via: "console",
    }
}

fn review_who(auth: &Auth) -> ReviewWho<'_> {
    ReviewWho {
        username: &auth.username,
        is_admin: auth.is_admin,
        is_auditor: auth.is_auditor,
        via: "console",
    }
}

fn chip(text: &str) -> Chip {
    Chip {
        text: text.to_owned(),
        c: chip_color(text),
    }
}

fn when(unix: i64) -> String {
    if unix <= 0 {
        return "—".to_owned();
    }
    time_text(time::OffsetDateTime::from_unix_timestamp(unix).ok())
}

/// "in 12 min" / "3 h ago".
fn relative(unix: i64) -> String {
    let secs = unix - time::OffsetDateTime::now_utc().unix_timestamp();
    let n = secs.unsigned_abs();
    let text = match n {
        0..=89 => format!("{n} s"),
        90..=5399 => format!("{} min", n / 60),
        5400..=129_599 => format!("{} h", n / 3600),
        _ => format!("{} d", n / 86_400),
    };
    if secs < 0 {
        format!("{text} ago")
    } else {
        format!("in {text}")
    }
}

fn duration_text(secs: u32) -> String {
    limen_policy::duration::DurationStr(Duration::from_secs(u64::from(secs))).to_string()
}

/// Fixed messages for `?done=`, so no page reflects arbitrary text.
fn done_text(code: Option<&str>) -> Option<&'static str> {
    Some(match code? {
        "requested" => "Request sent. Approvers have been told.",
        "granted" => "Granted. Proxies and workers pick it up within about 20 seconds.",
        "approved" => "Your approval is recorded.",
        "denied" => "Denied.",
        "cancelled" => "Request withdrawn.",
        "revoked" => "Grant revoked. The sessions it allowed end within about 10 seconds.",
        "started" => "Review started. Owners have been assigned their items.",
        "certified" => "Certified.",
        "flagged" => "Flagged. The role is withheld from them now.",
        "lifted" => "Lifted.",
        "accepted" => "Accepted. Roles that select its labels can reach it now.",
        "rejected" => "Rejected.",
        _ => return None,
    })
}

#[derive(Deserialize)]
pub struct PageQuery {
    tab: Option<String>,
    resource: Option<String>,
    done: Option<String>,
    err: Option<String>,
    from: Option<String>,
    to: Option<String>,
    /// Which items a review page lists: waiting, kept, or removed.
    show: Option<String>,
}

/// Where a failed form goes back to, with the reason kept short and escaped by the template.
fn back_with_error(path: &str, status: &tonic::Status) -> Response {
    let msg: String = status.message().chars().take(200).collect();
    Redirect::to(&format!(
        "{path}{}err={}",
        if path.contains('?') { '&' } else { '?' },
        path_segment(&msg)
    ))
    .into_response()
}

// ---- access -----------------------------------------------------------------------------

pub struct RequestView {
    pub id: String,
    pub requester: String,
    pub role: Chip,
    pub resource: String,
    pub resource_path: String,
    pub reason: String,
    pub duration: String,
    pub status: String,
    pub tone: &'static str,
    pub break_glass: bool,
    pub approvals: String,
    pub approvers: Vec<(String, bool, String)>,
    pub created: String,
    pub lapses: String,
    pub ends: String,
    pub can_decide: bool,
    pub can_cancel: bool,
    pub sessions_30d: u32,
    pub last_session: String,
}

fn request_view(r: &limen_proto::v1::AccessRequestInfo, auth: &Auth) -> RequestView {
    let approved = r
        .approvals
        .iter()
        .filter(|a| a.decision == "approve")
        .count();
    RequestView {
        id: r.id.clone(),
        requester: r.requester.clone(),
        role: chip(&r.role),
        resource_path: path_segment(&r.resource),
        resource: r.resource.clone(),
        reason: r.reason.clone(),
        duration: duration_text(r.duration_seconds),
        tone: match r.status.as_str() {
            "approved" => "ok",
            "pending" => "warn",
            "denied" | "revoked" => "bad",
            _ => "",
        },
        status: r.status.clone(),
        break_glass: r.break_glass,
        approvals: format!("{approved} of {}", r.approvals_required),
        approvers: r
            .approvals
            .iter()
            .map(|a| {
                (
                    a.approver.clone(),
                    a.decision == "approve",
                    a.comment.clone(),
                )
            })
            .collect(),
        created: when(r.created_at_unix),
        lapses: relative(r.expires_at_unix),
        ends: if r.grant_expires_at_unix > 0 {
            relative(r.grant_expires_at_unix)
        } else {
            String::new()
        },
        can_decide: r.can_decide,
        can_cancel: r.status == "pending" && r.requester.eq_ignore_ascii_case(&auth.username),
        sessions_30d: r.requester_sessions_30d,
        last_session: if r.requester_last_session_unix > 0 {
            relative(r.requester_last_session_unix)
        } else {
            String::new()
        },
    }
}

pub struct GrantView {
    pub id: String,
    pub user: String,
    pub role: Chip,
    pub resource: String,
    pub reason: String,
    pub break_glass: bool,
    pub approvers: String,
    pub ends: String,
}

pub struct AskView {
    pub name: String,
    pub kind: String,
    pub roles: Vec<String>,
}

#[derive(Template)]
#[template(path = "access.html")]
pub struct AccessPage {
    pub chrome: Chrome,
    pub notice: Option<&'static str>,
    pub error: Option<String>,
    pub tab: &'static str,
    pub reader: bool,
    pub prefill: String,
    pub mine: Vec<RequestView>,
    pub approvals: Vec<RequestView>,
    pub grants: Vec<GrantView>,
    pub all: Vec<RequestView>,
    pub requestable: Vec<AskView>,
    pub breakglass_active: usize,
}

pub async fn access_page(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<PageQuery>,
) -> Response {
    let who = access_who(&auth);
    let list = |scope: &str| ListAccessRequestsRequest {
        scope: scope.into(),
        status: String::new(),
        limit: 100,
    };
    let mine = match access::list_requests(&state, &who, &list("mine")).await {
        Ok(v) => v.iter().map(|r| request_view(r, &auth)).collect::<Vec<_>>(),
        Err(s) => return action_error(&s),
    };
    let approvals = match access::list_requests(&state, &who, &list("approvable")).await {
        Ok(v) => v.iter().map(|r| request_view(r, &auth)).collect::<Vec<_>>(),
        Err(s) => return action_error(&s),
    };
    let (grants, all) = if auth.reads_record() {
        let g = match access::list_grants(&state, &who, false).await {
            Ok(v) => v,
            Err(s) => return action_error(&s),
        };
        let a = match access::list_requests(&state, &who, &list("all")).await {
            Ok(v) => v.iter().map(|r| request_view(r, &auth)).collect(),
            Err(s) => return action_error(&s),
        };
        (g, a)
    } else {
        (Vec::new(), Vec::new())
    };
    let requestable = match access::requestable_for(&state, &auth.username, &auth.roles).await {
        Ok(v) => v
            .into_iter()
            .map(|r| AskView {
                name: r.name,
                kind: r.kind.as_str().to_owned(),
                roles: r.roles,
            })
            .collect(),
        Err(e) => return db_error("reading groups", &e),
    };
    let tab = match q.tab.as_deref() {
        Some("approvals") => "approvals",
        Some("grants") if auth.reads_record() => "grants",
        Some("all") if auth.reads_record() => "all",
        _ => "mine",
    };
    let breakglass_active = grants.iter().filter(|g| g.break_glass).count();
    html(
        AccessPage {
            chrome: chrome(&state, &auth, "access"),
            notice: done_text(q.done.as_deref()),
            error: q.err.as_deref().map(shown_error),
            tab,
            reader: auth.reads_record(),
            prefill: q
                .resource
                .clone()
                .unwrap_or_default()
                .chars()
                .take(128)
                .collect(),
            mine,
            approvals,
            grants: grants
                .iter()
                .map(|g| GrantView {
                    id: g.request_id.clone(),
                    user: g.username.clone(),
                    role: chip(&g.role),
                    resource: g.resource.clone(),
                    reason: g.reason.clone(),
                    break_glass: g.break_glass,
                    approvers: if g.break_glass {
                        "none (break-glass)".into()
                    } else {
                        g.approvers.join(", ")
                    },
                    ends: relative(g.expires_at_unix),
                })
                .collect(),
            all,
            requestable,
            breakglass_active,
        }
        .render(),
    )
}

#[derive(Template)]
#[template(path = "access_detail.html")]
pub struct AccessDetailPage {
    pub chrome: Chrome,
    pub notice: Option<&'static str>,
    pub error: Option<String>,
    pub r: RequestView,
}

pub async fn access_detail(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<PageQuery>,
) -> Response {
    match access::get_request(&state, &access_who(&auth), &id).await {
        Ok(info) => html(
            AccessDetailPage {
                chrome: chrome(&state, &auth, "access"),
                notice: done_text(q.done.as_deref()),
                error: q.err.as_deref().map(shown_error),
                r: request_view(&info, &auth),
            }
            .render(),
        ),
        Err(_) => error_page(
            StatusCode::NOT_FOUND,
            "Not found",
            "There is no such request.",
        ),
    }
}

#[derive(Deserialize)]
pub struct RequestForm {
    csrf: String,
    resource: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    duration: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    break_glass: Option<String>,
}

pub async fn access_request(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Form(f): Form<RequestForm>,
) -> Response {
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = auth.check_post(console, &headers, &f.csrf) {
        return r;
    }
    let secs = if f.duration.trim().is_empty() {
        0
    } else {
        match limen_policy::duration::DurationStr::parse(f.duration.trim()) {
            Ok(d) => d.0.as_secs(),
            Err(e) => {
                return back_with_error("/console/access", &tonic::Status::invalid_argument(e));
            }
        }
    };
    let result = access::request_access(
        &state,
        &access_who(&auth),
        access::NewAccess {
            resource: f.resource,
            role: f.role,
            duration_secs: secs,
            reason: f.reason,
            break_glass: f.break_glass.is_some(),
        },
    )
    .await;
    match result {
        Ok(info) => Redirect::to(&format!(
            "/console/access/{}?done={}",
            path_segment(&info.id),
            if info.status == "approved" {
                "granted"
            } else {
                "requested"
            }
        ))
        .into_response(),
        Err(s) => back_with_error("/console/access", &s),
    }
}

#[derive(Deserialize)]
pub struct DecideForm {
    csrf: String,
    decision: String,
    #[serde(default)]
    comment: String,
}

pub async fn access_decide(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<DecideForm>,
) -> Response {
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = auth.check_post(console, &headers, &f.csrf) {
        return r;
    }
    let approve = f.decision == "approve";
    let back = format!("/console/access/{}", path_segment(&id));
    match access::decide(&state, &access_who(&auth), &id, approve, &f.comment).await {
        Ok(_) => Redirect::to(&format!(
            "{back}?done={}",
            if approve { "approved" } else { "denied" }
        ))
        .into_response(),
        Err(s) => back_with_error(&back, &s),
    }
}

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf: String,
}

pub async fn access_cancel(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = auth.check_post(console, &headers, &f.csrf) {
        return r;
    }
    match access::cancel(&state, &access_who(&auth), &id).await {
        Ok(_) => Redirect::to("/console/access?done=cancelled").into_response(),
        Err(s) => back_with_error("/console/access", &s),
    }
}

#[derive(Deserialize)]
pub struct ReasonForm {
    csrf: String,
    reason: String,
}

pub async fn access_revoke(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<ReasonForm>,
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
    match access::revoke_grant(&state, &access_who(&auth), &id, &f.reason).await {
        Ok(_) => Redirect::to("/console/access?tab=grants&done=revoked").into_response(),
        Err(s) => back_with_error("/console/access?tab=grants", &s),
    }
}

// ---- reviews ----------------------------------------------------------------------------

pub struct ReviewView {
    pub id: String,
    pub name: String,
    pub status: String,
    pub overdue: bool,
    pub progress: String,
    pub percent: u32,
    pub flagged: u32,
    pub kept: u32,
    pub waiting: u32,
    pub silent: u32,
    pub due: String,
    pub started_by: String,
}

fn review_view(r: &ReviewInfo) -> ReviewView {
    ReviewView {
        id: r.id.clone(),
        name: r.name.clone(),
        status: r.status.clone(),
        overdue: r.overdue,
        progress: format!("{} of {} decided", r.decided, r.items),
        percent: (r.decided * 100).checked_div(r.items).unwrap_or(100),
        flagged: r.flagged,
        kept: r.decided.saturating_sub(r.flagged),
        waiting: r.items.saturating_sub(r.decided),
        silent: r.certified_silently,
        due: relative(r.due_at_unix),
        started_by: r.started_by.clone(),
    }
}

pub struct DenyView {
    pub id: String,
    pub user: String,
    pub role: Chip,
    pub reason: String,
    pub until: String,
}

#[derive(Template)]
#[template(path = "reviews.html")]
pub struct ReviewsPage {
    pub chrome: Chrome,
    pub notice: Option<&'static str>,
    pub error: Option<String>,
    pub reviews: Vec<ReviewView>,
    pub reader: bool,
    pub denies: Vec<DenyView>,
    pub from: String,
    pub to: String,
}

pub async fn reviews_page(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<PageQuery>,
) -> Response {
    let who = review_who(&auth);
    let list = match reviews::list(&state, &who, auth.reads_record()).await {
        Ok(v) => v.iter().map(review_view).collect(),
        Err(s) => return action_error(&s),
    };
    let denies = if auth.reads_record() {
        match reviews::list_denies(&state, &who, false).await {
            Ok(v) => v
                .iter()
                .map(|d| DenyView {
                    id: d.id.clone(),
                    user: d.username.clone(),
                    role: chip(&d.role),
                    reason: d.reason.clone(),
                    until: relative(d.expires_at_unix),
                })
                .collect(),
            Err(s) => return action_error(&s),
        }
    } else {
        Vec::new()
    };
    let today = time::OffsetDateTime::now_utc().date();
    html(
        ReviewsPage {
            chrome: chrome(&state, &auth, "reviews"),
            notice: done_text(q.done.as_deref()),
            error: q.err.as_deref().map(shown_error),
            reviews: list,
            reader: auth.reads_record(),
            denies,
            from: q
                .from
                .clone()
                .unwrap_or_else(|| (today - time::Duration::days(90)).to_string()),
            to: q
                .to
                .clone()
                .unwrap_or_else(|| (today + time::Duration::days(1)).to_string()),
        }
        .render(),
    )
}

/// Resources listed on an item before "and N more".
const REACHES_SHOWN: usize = 6;

#[allow(clippy::struct_excessive_bools)] // flags a template reads, not a state machine
pub struct ItemView {
    pub id: String,
    pub subject: String,
    pub subject_type: String,
    pub role: Chip,
    pub via: String,
    pub reaches: Vec<String>,
    /// How many more it reaches than are listed.
    pub reaches_more: usize,
    /// The viewer's own access: someone else has to review it.
    pub own: bool,
    pub usage: String,
    pub unused: bool,
    pub reviewer: String,
    pub decision: String,
    pub comment: String,
    pub decided_by: String,
    pub can_decide: bool,
    /// Nobody has decided it yet.
    pub pending: bool,
}

fn item_view(i: &ReviewItemInfo) -> ItemView {
    ItemView {
        id: i.id.clone(),
        subject: i.subject.clone(),
        subject_type: i.subject_type.clone(),
        role: chip(&i.role),
        via: i.via.clone(),
        reaches: i
            .reaches
            .iter()
            .take(REACHES_SHOWN)
            .map(|r| format!("{} ({})", r.name, r.principals.join(", ")))
            .collect(),
        reaches_more: i.reaches.len().saturating_sub(REACHES_SHOWN),
        own: false,
        usage: if i.sessions_90d == 0 {
            "not used in 90 days".into()
        } else {
            format!(
                "{} sessions, last {}",
                i.sessions_90d,
                relative(i.last_used_unix)
            )
        },
        unused: i.unused,
        reviewer: if i.reviewer == reviews::ADMIN_POOL {
            "any admin".into()
        } else {
            i.reviewer.clone()
        },
        decision: i.decision.clone(),
        comment: i.comment.clone(),
        decided_by: i.decided_by.clone(),
        can_decide: i.can_decide,
        pending: i.decision.is_empty(),
    }
}

#[derive(Template)]
#[template(path = "review.html")]
pub struct ReviewPage {
    pub chrome: Chrome,
    pub notice: Option<&'static str>,
    pub error: Option<String>,
    pub review: ReviewView,
    pub items: Vec<ItemView>,
    pub to_decide: usize,
    pub decided_n: usize,
    /// The filter in force: `waiting`, `kept`, `removed`, or empty for all.
    pub show: String,
    pub mine_only: bool,
}

pub async fn review_page(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Query(q): Query<PageQuery>,
) -> Response {
    let who = review_who(&auth);
    let reviews_list = match reviews::list(&state, &who, auth.reads_record()).await {
        Ok(v) => v,
        Err(s) => return action_error(&s),
    };
    let Some(info) = reviews_list.iter().find(|r| r.id == id) else {
        return error_page(
            StatusCode::NOT_FOUND,
            "Not found",
            "There is no such review.",
        );
    };
    let items: Vec<ItemView> = match reviews::items(&state, &who, &id, false, false).await {
        Ok(v) => v
            .iter()
            .map(|i| ItemView {
                own: i.subject.eq_ignore_ascii_case(&auth.username),
                ..item_view(i)
            })
            .collect(),
        Err(s) => return action_error(&s),
    };
    // The cards above the list filter it.
    let show = match q.show.as_deref() {
        Some(k @ ("waiting" | "kept" | "removed")) => k.to_owned(),
        _ => String::new(),
    };
    let items: Vec<ItemView> = items
        .into_iter()
        .filter(|i| match show.as_str() {
            "waiting" => i.pending,
            "kept" => i.decision == "certify",
            "removed" => i.decision == "flag",
            _ => true,
        })
        .collect();
    html(
        ReviewPage {
            chrome: chrome(&state, &auth, "reviews"),
            notice: done_text(q.done.as_deref()),
            error: q.err.as_deref().map(shown_error),
            review: review_view(info),
            to_decide: items.iter().filter(|i| i.pending).count(),
            decided_n: items.iter().filter(|i| !i.pending).count(),
            items,
            show,
            mine_only: !auth.reads_record(),
        }
        .render(),
    )
}

#[derive(Deserialize)]
pub struct StartForm {
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    due_days: u32,
    #[serde(default)]
    override_days: u32,
}

pub async fn review_start(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Form(f): Form<StartForm>,
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
    match reviews::start(
        &state,
        &review_who(&auth),
        &f.name,
        f.due_days,
        f.override_days,
    )
    .await
    {
        Ok(info) => Redirect::to(&format!(
            "/console/reviews/{}?done=started",
            path_segment(&info.id)
        ))
        .into_response(),
        Err(s) => back_with_error("/console/reviews", &s),
    }
}

#[derive(Deserialize)]
pub struct ItemForm {
    csrf: String,
    decision: String,
    #[serde(default)]
    comment: String,
    review: String,
}

pub async fn review_decide(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Path(item): Path<String>,
    Form(f): Form<ItemForm>,
) -> Response {
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = auth.check_post(console, &headers, &f.csrf) {
        return r;
    }
    let certify = f.decision == "certify";
    let back = format!("/console/reviews/{}", path_segment(&f.review));
    match reviews::decide(&state, &review_who(&auth), &item, certify, &f.comment).await {
        Ok(_) => Redirect::to(&format!(
            "{back}?done={}",
            if certify { "certified" } else { "flagged" }
        ))
        .into_response(),
        Err(s) => back_with_error(&back, &s),
    }
}

pub async fn deny_lift(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<ReasonForm>,
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
    match reviews::lift_deny(&state, &review_who(&auth), &id, &f.reason).await {
        Ok(_) => Redirect::to("/console/reviews?done=lifted").into_response(),
        Err(s) => back_with_error("/console/reviews", &s),
    }
}

/// `GET /console/reviews/evidence?from=2026-01-01&to=2026-04-01`: the pack, as a download.
pub async fn evidence(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<PageQuery>,
) -> Response {
    if let Err(r) = auth.reader() {
        return r;
    }
    let day = |s: &Option<String>| {
        s.as_deref()
            .and_then(|s| {
                time::Date::parse(
                    s,
                    &time::macros::format_description!("[year]-[month]-[day]"),
                )
                .ok()
            })
            .map(|d| d.midnight().assume_utc().unix_timestamp())
    };
    let (Some(from), Some(to)) = (day(&q.from), day(&q.to)) else {
        return back_with_error(
            "/console/reviews",
            &tonic::Status::invalid_argument("dates look like 2026-01-31"),
        );
    };
    match crate::evidence::export(&state, &auth.username, from, to).await {
        Ok((pack, _)) => (
            [
                (CONTENT_TYPE, "application/json"),
                (CACHE_CONTROL, "no-store"),
                (
                    CONTENT_DISPOSITION,
                    "attachment; filename=\"limen-evidence.json\"",
                ),
            ],
            pack,
        )
            .into_response(),
        Err(s) => back_with_error("/console/reviews", &s),
    }
}

// ---- discovered resources ---------------------------------------------------------------

/// The text of a failure passed back in a link. Anyone can put anything in a
/// link, so it is escaped by the template and kept short.
fn shown_error(e: &str) -> String {
    e.chars().take(300).collect()
}

pub struct DiscoveredView {
    pub key: String,
    pub name: String,
    pub kind: String,
    pub icon: &'static str,
    pub kclass: &'static str,
    pub state: String,
    pub tone: &'static str,
    pub labels: Vec<String>,
    pub target: String,
    pub changes: Vec<String>,
    pub blockers: Vec<String>,
    pub document: String,
    pub seen: String,
    pub change_pending: bool,
    pub reviewable: bool,
    /// Digest of what is shown, sent back with the decision.
    pub shown: String,
}

#[derive(Template)]
#[template(path = "discovered.html")]
pub struct DiscoveredPage {
    pub chrome: Chrome,
    pub notice: Option<&'static str>,
    pub error: Option<String>,
    pub items: Vec<DiscoveredView>,
    pub pending: usize,
}

pub async fn discovered_page(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<PageQuery>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let items = match crate::discovery::list(&state.db, "").await {
        Ok(v) => v,
        Err(s) => return action_error(&s),
    };
    let pending = items
        .iter()
        .filter(|i| i.state == "pending" || i.change_pending)
        .count();
    let views = items
        .iter()
        .map(|i| {
            let (icon, kclass) = super::views::kind_icon(&i.kind);
            let mut labels: Vec<String> = i
                .labels
                .iter()
                .filter(|(k, _)| !k.starts_with("limen.io/"))
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            labels.sort();
            DiscoveredView {
                key: i.key.clone(),
                name: i.name.clone(),
                kind: i.kind.clone(),
                icon,
                kclass,
                tone: match (i.state.as_str(), i.change_pending) {
                    ("accepted", false) => "ok",
                    ("stale" | "rejected", _) => "bad",
                    _ => "warn",
                },
                state: if i.change_pending {
                    "change pending".into()
                } else {
                    i.state.clone()
                },
                labels,
                target: i.target.clone(),
                changes: i.changes.clone(),
                blockers: i.blockers.clone(),
                document: i.document.clone(),
                seen: relative(i.last_seen_unix),
                change_pending: i.change_pending,
                reviewable: i.state != "accepted" || i.change_pending,
                shown: crate::discovery::shown_digest(&i.name, &i.kind, &i.labels, &i.target),
            }
        })
        .collect();
    html(
        DiscoveredPage {
            chrome: chrome(&state, &auth, "resources"),
            notice: done_text(q.done.as_deref()),
            error: q.err.as_deref().map(shown_error),
            items: views,
            pending,
        }
        .render(),
    )
}

#[derive(Deserialize)]
pub struct DiscoveredForm {
    csrf: String,
    key: String,
    decision: String,
    #[serde(default)]
    note: String,
    /// What the admin was shown; empty fails an accept.
    #[serde(default)]
    shown: String,
}

pub async fn discovered_review(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Form(f): Form<DiscoveredForm>,
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
    let accept = f.decision == "accept";
    match crate::discovery::review(
        &state,
        &auth.username,
        "console",
        &f.key,
        accept,
        &f.note,
        Some(&f.shown),
    )
    .await
    {
        Ok(_) => Redirect::to(&format!(
            "/console/discovered?done={}",
            if accept { "accepted" } else { "rejected" }
        ))
        .into_response(),
        Err(s) => back_with_error("/console/discovered", &s),
    }
}

// ---- watching a live session --------------------------------------------------------------

#[derive(Template)]
#[template(path = "watch.html")]
pub struct WatchPage {
    pub chrome: Chrome,
    pub id: String,
    pub user: String,
    pub resource: String,
}

fn may_watch(state: &AppState, auth: &Auth) -> bool {
    crate::live::may_watch(state, auth.is_admin, auth.is_auditor)
}

pub async fn watch_page(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> Response {
    if !may_watch(&state, &auth) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Not allowed",
            "Watching a live session is a separate power from reading the record, and you don't have it.",
        );
    }
    let Ok(sid) = Uuid::parse_str(&id) else {
        return error_page(
            StatusCode::NOT_FOUND,
            "Not found",
            "There is no such session.",
        );
    };
    let row = match super::store::session(&state.db, sid).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return error_page(
                StatusCode::NOT_FOUND,
                "Not found",
                "There is no such session.",
            );
        }
        Err(e) => return db_error("reading a session", &e),
    };
    if row.kind.as_deref() != Some("ssh") || row.ended_at.is_some() {
        return error_page(
            StatusCode::CONFLICT,
            "Can't watch this",
            "Only live SSH sessions can be watched. A finished session has a recording to play instead.",
        );
    }
    html(
        WatchPage {
            chrome: chrome(&state, &auth, "sessions"),
            id,
            user: row.username.unwrap_or_default(),
            resource: row.resource.unwrap_or_default(),
        }
        .render(),
    )
}

/// The stream: asciicast events a player reads (`{"cols","rows"}` first, then
/// `[seconds, "o", text]`). Every few seconds it checks that the watch is
/// still allowed (not locked, not signed out, not over) and says it is still
/// here. The user's session never waits on it.
pub async fn watch_stream(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> Response {
    if !may_watch(&state, &auth) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(sid) = Uuid::parse_str(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let watcher = match crate::live::begin(&state, &auth.username, sid, "console").await {
        Ok(w) => w,
        Err(s) => {
            return (
                match s.code() {
                    tonic::Code::NotFound => StatusCode::NOT_FOUND,
                    tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
                    tonic::Code::FailedPrecondition => StatusCode::CONFLICT,
                    _ => StatusCode::SERVICE_UNAVAILABLE,
                },
                s.message().to_owned(),
            )
                .into_response();
        }
    };
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(64);
    let token_hash = auth.token_hash.clone();
    let task_state = state.clone();
    tokio::spawn(async move {
        let state = task_state;
        let mut last: Option<i64> = None;
        let mut sent_header = false;
        let mut why = "closed";
        let mut recheck = tokio::time::Instant::now();
        let mut first_start: Option<i64> = None;
        'stream: loop {
            if recheck.elapsed() >= Duration::from_secs(5) {
                recheck = tokio::time::Instant::now();
                // Still signed in and not locked; the session still going; still ours.
                let signed_in = super::store::console_session(&state.db, &token_hash)
                    .await
                    .ok()
                    .flatten()
                    .is_some();
                let locked = crate::db::is_locked(&state.db, &watcher.observer)
                    .await
                    .unwrap_or(true);
                if !signed_in || locked {
                    why = "authorization ended";
                    break;
                }
                match crate::live::heartbeat(&state.db, &watcher).await {
                    Ok(true) => {}
                    _ => {
                        why = "watch ended";
                        break;
                    }
                }
                if !crate::live::is_live(&state.db, watcher.session_id)
                    .await
                    .unwrap_or(false)
                {
                    let _ = tx
                        .send(Ok(Event::default().event("done").data("the session ended")))
                        .await;
                    why = "session ended";
                    break;
                }
            }
            let Ok(chunks) = crate::live::chunks(&state.db, watcher.session_id, last).await else {
                why = "error";
                break;
            };
            for c in chunks {
                if !sent_header {
                    sent_header = true;
                    let header =
                        serde_json::json!({ "version": 2, "width": c.cols, "height": c.rows });
                    if tx
                        .send(Ok(Event::default().data(header.to_string())))
                        .await
                        .is_err()
                    {
                        break 'stream;
                    }
                    first_start = Some(c.elapsed_ms);
                }
                #[allow(clippy::cast_precision_loss)] // milliseconds into a session fit f64 exactly
                let t = (c.elapsed_ms - first_start.unwrap_or(0)).max(0) as f64 / 1000.0;
                let ev = serde_json::json!([t, "o", c.text]);
                last = Some(c.seq);
                // A slow browser waits here; nothing else does.
                if tx
                    .send(Ok(Event::default().data(ev.to_string())))
                    .await
                    .is_err()
                {
                    break 'stream;
                }
            }
            tokio::time::sleep(crate::live::POLL).await;
            if tx.is_closed() {
                break;
            }
        }
        crate::live::end(&state, &watcher, "console", why).await;
    });
    let mut response = Sse::new(ReceiverStream::new(rx))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(10)))
        .into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, "no-store".parse().expect("static header"));
    response
}

/// What a session page adds for Phase 13: the access requests that allowed it
/// (ADR-0025) and who watched it live (ADR-0030).
pub async fn session_extras(
    state: &AppState,
    session_id: Uuid,
) -> (Vec<String>, Vec<(String, String, String)>) {
    use sqlx::Row as _;
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT request_ids FROM sessions WHERE session_id = $1")
            .bind(session_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
    let watched = sqlx::query(
        "SELECT username, kind, at FROM audit_events WHERE session_id = $1
           AND kind IN ('session.watch.start', 'session.watch.stop') ORDER BY at LIMIT 50",
    )
    .bind(session_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
    .iter()
    .filter_map(|r| {
        let kind: String = r.try_get("kind").ok()?;
        Some((
            r.try_get::<Option<String>, _>("username").ok()??,
            if kind.ends_with("start") {
                "started watching"
            } else {
                "stopped watching"
            }
            .to_owned(),
            time_text(r.try_get("at").ok()),
        ))
    })
    .collect();
    (ids, watched)
}

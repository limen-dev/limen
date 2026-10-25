//! Access requests and just-in-time grants (ADR-0025).
//!
//! A request is a row, not a session. An approved request becomes a
//! time-boxed grant that rides in the signed policy snapshot, so proxies and
//! workers enforce it with no round trip, and a lock still wins. **Approval
//! happens only inside an authenticated Limen session**: notifiers (see
//! [`notify`]) link to the console and never carry the decision.
//!
//! Every state change is audited *before* it commits, so if the trail is
//! unavailable the change is refused.

pub mod notify;
pub mod store;

use std::time::Duration;

use limen_audit::{Context, EventKind};
use limen_policy::model::RequestSpec;
use limen_proto::v1::{
    AccessApproval, AccessGrantInfo, AccessRequestInfo, ListAccessRequestsRequest,
};
use serde_json::json;
use time::OffsetDateTime;
use tonic::Status;
use uuid::Uuid;

use self::notify::{Event, Notice};
use self::store::{GrantRow, NewGrant, NewRequest, RequestRow};
use crate::db;
use crate::services::ops;
use crate::state::{AppState, internal, unix};

/// A pending request lapses after this long unanswered.
pub const REQUEST_LIFETIME: Duration = Duration::from_hours(24);
/// The shortest grant. Anything shorter is gone before it can be used.
pub const MIN_DURATION: Duration = Duration::from_mins(1);
/// What a request asks for when it names no duration, at most.
const DEFAULT_DURATION: Duration = Duration::from_hours(1);
/// Requests one person may have waiting at once, and may make in a day.
const MAX_OPEN: i64 = 20;
const MAX_PER_DAY: i64 = 100;
/// The most requests a list call returns.
const LIST_LIMIT: i64 = 200;

/// Who is acting. Built from a verified user certificate or a console session.
#[derive(Debug, Clone, Copy)]
pub struct Who<'a> {
    pub username: &'a str,
    pub is_admin: bool,
    pub is_auditor: bool,
    /// `api` or `console`.
    pub via: &'static str,
}

/// What a person asks for.
#[derive(Debug, Clone, Default)]
pub struct NewAccess {
    pub resource: String,
    /// Which requestable role, when several reach the resource.
    pub role: String,
    /// Zero means the role's default.
    pub duration_secs: u64,
    pub reason: String,
    pub break_glass: bool,
}

/// Bots hold roles from their policy document and never ask for more: a
/// request needs a person who can answer for it.
fn must_be_person(username: &str) -> Result<(), Status> {
    if limen_core::identity::actor_type(username) == "bot" {
        return Err(Status::permission_denied(
            "bots cannot request access; give the bot a role in its policy document",
        ));
    }
    Ok(())
}

async fn audit(
    state: &AppState,
    kind: EventKind,
    user: &str,
    data: serde_json::Value,
) -> Result<(), Status> {
    state
        .audit
        .emit(
            kind,
            Context {
                user: Some(user.to_owned()),
                session_id: None,
            },
            data,
        )
        .await
        .map(|_| ())
        .map_err(|e| {
            tracing::error!(error = %e, "audit unavailable; refusing an access change");
            Status::unavailable("audit unavailable")
        })
}

fn secs(d: i32) -> u64 {
    u64::try_from(d).unwrap_or(0)
}

fn fmt_time(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn link(state: &AppState, id: Uuid) -> Option<String> {
    state
        .console
        .as_ref()
        .map(|c| format!("{}/console/access/{id}", c.origin))
}

fn notice(state: &AppState, event: Event, r: &RequestRow) -> Notice {
    Notice {
        event,
        request_id: r.id.to_string(),
        link: link(state, r.id),
        requester: r.requester.clone(),
        role: r.role.clone(),
        resource: r.resource.clone(),
        reason: r.reason.clone(),
        duration_secs: secs(r.duration_secs),
    }
}

/// Check a reason against the role's rules. Text only: it is escaped wherever
/// it is shown and never reaches a shell or a query.
fn check_reason(spec: &RequestSpec, break_glass: bool, reason: &str) -> Result<String, Status> {
    let reason = reason.trim();
    if reason.is_empty() && !(spec.require_reason || break_glass) {
        return Ok(String::new());
    }
    let reason = ops::clean_reason(reason).map_err(|_| {
        Status::invalid_argument(
            "a reason is required (up to 500 characters, without control characters)",
        )
    })?;
    if let Some(pattern) = &spec.ticket_pattern {
        // Validated when the policy was loaded; linear-time matching.
        let re = limen_policy::compile_ticket_pattern(pattern)
            .map_err(|e| internal("ticket pattern", e))?;
        if !re.is_match(&reason) {
            return Err(Status::invalid_argument(format!(
                "the reason must carry a ticket id matching {pattern}"
            )));
        }
    }
    Ok(reason)
}

/// Ask for a requestable role on a resource.
#[allow(clippy::too_many_lines)] // one linear sequence of checks, then the write
pub async fn request_access(
    state: &AppState,
    who: &Who<'_>,
    new: NewAccess,
) -> Result<AccessRequestInfo, Status> {
    must_be_person(who.username)?;
    let resource = new.resource.trim();
    let loaded = state.policy.current();
    let policy = &loaded.policy;

    if db::is_locked(&state.db, who.username)
        .await
        .map_err(|e| internal("checking locks", e))?
    {
        return Err(Status::permission_denied("user locked"));
    }
    let groups = store::user_groups(&state.db, who.username)
        .await
        .map_err(|e| internal("reading groups", e))?
        .unwrap_or_default();
    // One answer for a resource that doesn't exist and one nothing the person
    // may ask for reaches: asking must not reveal which resources exist.
    let nothing = || {
        Status::failed_precondition(format!(
            "there is nothing you can request that reaches `{resource}`"
        ))
    };
    let mut candidates: Vec<String> = policy
        .requestable_roles_for_groups(groups.iter().map(String::as_str))
        .into_iter()
        .filter(|role| {
            policy
                .role(role)
                .is_some_and(|r| r.spec.break_glass == new.break_glass)
                && policy
                    .accessible(std::slice::from_ref(role))
                    .iter()
                    .any(|r| r.name == resource)
        })
        .collect();
    if !new.role.is_empty() {
        candidates.retain(|r| *r == new.role);
    }
    let role_name = match candidates.as_slice() {
        [] => return Err(nothing()),
        [one] => one.clone(),
        many => {
            return Err(Status::invalid_argument(format!(
                "more than one role reaches `{resource}`: choose with --role ({})",
                many.join(", ")
            )));
        }
    };
    let role = policy.role(&role_name).ok_or_else(nothing)?;
    let spec = role.spec.request.as_ref().ok_or_else(nothing)?;
    let break_glass = role.spec.break_glass;

    let limit = spec.duration_limit(break_glass);
    let duration = if new.duration_secs == 0 {
        limit.min(DEFAULT_DURATION)
    } else {
        Duration::from_secs(new.duration_secs)
    };
    if duration < MIN_DURATION {
        return Err(Status::invalid_argument(
            "a grant lasts at least one minute",
        ));
    }
    if duration > limit {
        return Err(Status::invalid_argument(format!(
            "this role can be granted for at most {}",
            limen_policy::duration::DurationStr(limit)
        )));
    }
    let reason = check_reason(spec, break_glass, &new.reason)?;

    let (open, day) = store::request_counts(&state.db, who.username)
        .await
        .map_err(|e| internal("counting requests", e))?;
    if open >= MAX_OPEN || day >= MAX_PER_DAY {
        return Err(Status::resource_exhausted(
            "too many access requests; wait for some to be answered",
        ));
    }

    let id = Uuid::now_v7();
    let now = OffsetDateTime::now_utc();
    let duration_secs = i32::try_from(duration.as_secs()).unwrap_or(i32::MAX);
    let approvals_required = if break_glass {
        1
    } else {
        i32::try_from(spec.approvals_required).unwrap_or(1)
    };
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal("starting transaction", e))?;
    let inserted = store::insert_request(
        &mut tx,
        &NewRequest {
            id,
            requester: who.username,
            role: &role_name,
            resource,
            reason: &reason,
            duration_secs,
            break_glass,
            approvals_required,
            expires_at: now + REQUEST_LIFETIME,
        },
    )
    .await
    .map_err(|e| internal("storing request", e))?;
    if !inserted {
        return Err(Status::already_exists(
            "you already have this request waiting for an answer",
        ));
    }
    audit(
        state,
        EventKind::AccessRequest,
        who.username,
        json!({
            "request_id": id, "role": role_name, "resource": resource, "reason": reason,
            "duration_secs": duration_secs, "break_glass": break_glass,
            "approvals_required": approvals_required, "via": who.via,
        }),
    )
    .await?;

    let mut status = "pending";
    if break_glass {
        // Granted at once; the audit trail, the notification, and the review
        // that follows are what stand in for an approver.
        let expires_at = now + duration;
        store::insert_grant(
            &mut tx,
            &NewGrant {
                request_id: id,
                username: who.username,
                role: &role_name,
                resource,
                reason: &reason,
                break_glass: true,
                approvers: &[],
                expires_at,
            },
        )
        .await
        .map_err(|e| internal("storing grant", e))?;
        store::set_status(&mut tx, id, "approved")
            .await
            .map_err(|e| internal("updating request", e))?;
        let grant = json!({
            "request_id": id, "role": role_name, "resource": resource, "reason": reason,
            "expires_at": fmt_time(expires_at), "break_glass": true,
        });
        audit(state, EventKind::AccessGrant, who.username, grant.clone()).await?;
        audit(state, EventKind::AccessBreakGlass, who.username, grant).await?;
        status = "approved";
    }
    tx.commit()
        .await
        .map_err(|e| internal("committing request", e))?;
    metrics::counter!("limen_access_requests_total", "break_glass" => break_glass.to_string())
        .increment(1);
    tracing::info!(request = %id, user = who.username, role = %role_name, resource, break_glass, "access requested");

    let row = store::request(&state.db, id)
        .await
        .map_err(|e| internal("reading request", e))?
        .ok_or_else(|| Status::internal("request vanished"))?;
    state.notifier.send(&notice(
        state,
        if break_glass {
            Event::BreakGlass
        } else {
            Event::Requested
        },
        &row,
    ));
    debug_assert_eq!(row.status, status);
    info(state, &row, who).await
}

/// Approve or deny a pending request.
#[allow(clippy::too_many_lines)] // one linear sequence of checks, then the write
pub async fn decide(
    state: &AppState,
    who: &Who<'_>,
    id: &str,
    approve: bool,
    comment: &str,
) -> Result<AccessRequestInfo, Status> {
    must_be_person(who.username)?;
    let id = parse_id(id)?;
    let comment = comment.trim();
    if comment.len() > 500 || comment.chars().any(char::is_control) {
        return Err(Status::invalid_argument(
            "comment must be at most 500 characters, without control characters",
        ));
    }
    let loaded = state.policy.current();
    let policy = &loaded.policy;
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal("starting transaction", e))?;
    let req = store::request_for_update(&mut tx, id)
        .await
        .map_err(|e| internal("reading request", e))?
        .ok_or_else(|| Status::not_found("no such request"))?;
    if req.status != "pending" {
        return Err(Status::failed_precondition(format!(
            "the request is already {}",
            req.status
        )));
    }
    if req.expires_at <= OffsetDateTime::now_utc() {
        return Err(Status::failed_precondition("the request has lapsed"));
    }
    // Separation of duties: nobody decides their own request. The database
    // refuses it too, in a trigger.
    if req.requester.eq_ignore_ascii_case(who.username) {
        return Err(Status::permission_denied(
            "you cannot approve or deny your own request",
        ));
    }
    if db::is_locked(&state.db, who.username)
        .await
        .map_err(|e| internal("checking locks", e))?
    {
        return Err(Status::permission_denied("user locked"));
    }
    // Checked now, against today's policy and the groups the IdP reported at
    // the approver's latest login, not as they were when the request was made.
    let groups = store::user_groups(&state.db, who.username)
        .await
        .map_err(|e| internal("reading groups", e))?
        .unwrap_or_default();
    if !policy.may_approve(&req.role, who.username, groups.iter().map(String::as_str)) {
        return Err(Status::permission_denied(
            "you are not an approver for this role",
        ));
    }

    if !approve {
        if !store::insert_approval(&mut tx, id, who.username, "deny", comment)
            .await
            .map_err(|e| internal("storing decision", e))?
        {
            return Err(Status::already_exists("you already decided this request"));
        }
        store::set_status(&mut tx, id, "denied")
            .await
            .map_err(|e| internal("updating request", e))?;
        audit(
            state,
            EventKind::AccessDeny,
            who.username,
            json!({ "request_id": id, "requester": req.requester, "role": req.role, "resource": req.resource, "comment": comment, "via": who.via }),
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| internal("committing decision", e))?;
        metrics::counter!("limen_access_decisions_total", "decision" => "deny").increment(1);
        state.notifier.send(&notice(state, Event::Denied, &req));
        return reread(state, id, who).await;
    }

    // The requester has to still be allowed to ask for it.
    let requester_groups = store::user_groups(&state.db, &req.requester)
        .await
        .map_err(|e| internal("reading groups", e))?
        .unwrap_or_default();
    let still_eligible = policy
        .requestable_roles_for_groups(requester_groups.iter().map(String::as_str))
        .contains(&req.role);
    if !still_eligible {
        return Err(Status::failed_precondition(
            "policy no longer lets the requester ask for this role",
        ));
    }
    if !store::insert_approval(&mut tx, id, who.username, "approve", comment)
        .await
        .map_err(|e| internal("storing decision", e))?
    {
        return Err(Status::already_exists("you already decided this request"));
    }
    audit(
        state,
        EventKind::AccessApprove,
        who.username,
        json!({ "request_id": id, "requester": req.requester, "role": req.role, "resource": req.resource, "comment": comment, "via": who.via }),
    )
    .await?;
    let approvers: Vec<String> = store::approvals_in(&mut tx, id)
        .await
        .map_err(|e| internal("reading approvals", e))?
        .into_iter()
        .filter(|a| a.decision == "approve")
        .map(|a| a.approver)
        .collect();
    if i32::try_from(approvers.len()).unwrap_or(i32::MAX) >= req.approvals_required {
        // The grant never outlasts what the role allows *now*.
        let limit = policy
            .role(&req.role)
            .and_then(|r| {
                r.spec
                    .request
                    .as_ref()
                    .map(|s| s.duration_limit(r.spec.break_glass))
            })
            .unwrap_or(Duration::ZERO);
        let duration = Duration::from_secs(secs(req.duration_secs)).min(limit);
        if duration < MIN_DURATION {
            return Err(Status::failed_precondition(
                "policy no longer allows a grant of this length",
            ));
        }
        let expires_at = OffsetDateTime::now_utc() + duration;
        store::insert_grant(
            &mut tx,
            &NewGrant {
                request_id: id,
                username: &req.requester,
                role: &req.role,
                resource: &req.resource,
                reason: &req.reason,
                break_glass: false,
                approvers: &approvers,
                expires_at,
            },
        )
        .await
        .map_err(|e| internal("storing grant", e))?;
        store::set_status(&mut tx, id, "approved")
            .await
            .map_err(|e| internal("updating request", e))?;
        audit(
            state,
            EventKind::AccessGrant,
            &req.requester,
            json!({
                "request_id": id, "role": req.role, "resource": req.resource, "reason": req.reason,
                "approvers": approvers, "expires_at": fmt_time(expires_at), "break_glass": false,
            }),
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| internal("committing decision", e))?;
        metrics::counter!("limen_access_decisions_total", "decision" => "approve").increment(1);
        metrics::counter!("limen_access_grants_total").increment(1);
        state.notifier.send(&notice(state, Event::Approved, &req));
    } else {
        tx.commit()
            .await
            .map_err(|e| internal("committing decision", e))?;
        metrics::counter!("limen_access_decisions_total", "decision" => "approve").increment(1);
    }
    reread(state, id, who).await
}

/// The requester withdraws a request that is still pending.
pub async fn cancel(
    state: &AppState,
    who: &Who<'_>,
    id: &str,
) -> Result<AccessRequestInfo, Status> {
    let id = parse_id(id)?;
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal("starting transaction", e))?;
    let req = store::request_for_update(&mut tx, id)
        .await
        .map_err(|e| internal("reading request", e))?
        .ok_or_else(|| Status::not_found("no such request"))?;
    if !req.requester.eq_ignore_ascii_case(who.username) {
        // Same answer as for a request that doesn't exist.
        return Err(Status::not_found("no such request"));
    }
    if req.status != "pending" {
        return Err(Status::failed_precondition(format!(
            "the request is already {}",
            req.status
        )));
    }
    store::set_status(&mut tx, id, "cancelled")
        .await
        .map_err(|e| internal("updating request", e))?;
    audit(
        state,
        EventKind::AccessCancel,
        who.username,
        json!({ "request_id": id, "role": req.role, "resource": req.resource, "via": who.via }),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|e| internal("committing cancel", e))?;
    reread(state, id, who).await
}

/// End a grant that is in force, and the sessions it allowed.
pub async fn revoke_grant(
    state: &AppState,
    who: &Who<'_>,
    id: &str,
    reason: &str,
) -> Result<(bool, u32), Status> {
    if !who.is_admin {
        return Err(Status::permission_denied(
            "the limen:admin role is required",
        ));
    }
    let id = parse_id(id)?;
    let reason = ops::clean_reason(reason)?;
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal("starting transaction", e))?;
    let Some(grant) = store::revoke_grant(&mut tx, id, who.username, &reason)
        .await
        .map_err(|e| internal("revoking grant", e))?
    else {
        return if store::grant(&state.db, id)
            .await
            .map_err(|e| internal("reading grant", e))?
            .is_some()
        {
            Ok((false, 0))
        } else {
            Err(Status::not_found("no such grant"))
        };
    };
    store::set_status(&mut tx, id, "revoked")
        .await
        .map_err(|e| internal("updating request", e))?;
    let ended = store::kill_sessions_of(
        &mut tx,
        id,
        who.username,
        &format!("grant revoked: {reason}"),
    )
    .await
    .map_err(|e| internal("ending sessions", e))?;
    audit(
        state,
        EventKind::AccessRevoke,
        who.username,
        json!({
            "request_id": id, "target_user": grant.username, "role": grant.role,
            "resource": grant.resource, "reason": reason, "sessions_ended": ended, "via": who.via,
        }),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|e| internal("committing revoke", e))?;
    if let Ok(Some(row)) = store::request(&state.db, id).await {
        state.notifier.send(&notice(state, Event::Revoked, &row));
    }
    Ok((true, u32::try_from(ended).unwrap_or(u32::MAX)))
}

fn parse_id(id: &str) -> Result<Uuid, Status> {
    Uuid::parse_str(id.trim()).map_err(|_| Status::invalid_argument("not a request id"))
}

async fn reread(state: &AppState, id: Uuid, who: &Who<'_>) -> Result<AccessRequestInfo, Status> {
    let row = store::request(&state.db, id)
        .await
        .map_err(|e| internal("reading request", e))?
        .ok_or_else(|| Status::not_found("no such request"))?;
    info(state, &row, who).await
}

/// Requests the caller may see: their own; the ones they may decide; and, for
/// admins and auditors, everything.
pub async fn list_requests(
    state: &AppState,
    who: &Who<'_>,
    req: &ListAccessRequestsRequest,
) -> Result<Vec<AccessRequestInfo>, Status> {
    let limit = match i64::from(req.limit) {
        0 => LIST_LIMIT,
        n => n.min(LIST_LIMIT),
    };
    let status = Some(req.status.as_str()).filter(|s| !s.is_empty());
    let rows = match req.scope.as_str() {
        "" | "mine" => store::list_requests(&state.db, Some(who.username), status, limit).await,
        "all" => {
            if !(who.is_admin || who.is_auditor) {
                return Err(Status::permission_denied(
                    "listing every request needs the limen:admin or limen:auditor role",
                ));
            }
            store::list_requests(&state.db, None, status, limit).await
        }
        "approvable" => {
            let groups = store::user_groups(&state.db, who.username)
                .await
                .map_err(|e| internal("reading groups", e))?
                .unwrap_or_default();
            let policy = state.policy.current();
            let pending = store::pending(&state.db).await;
            pending.map(|rows| {
                rows.into_iter()
                    .filter(|r| {
                        !r.requester.eq_ignore_ascii_case(who.username)
                            && policy.policy.may_approve(
                                &r.role,
                                who.username,
                                groups.iter().map(String::as_str),
                            )
                    })
                    .collect()
            })
        }
        other => {
            return Err(Status::invalid_argument(format!(
                "scope {other:?} is not mine, approvable, or all"
            )));
        }
    }
    .map_err(|e| internal("listing requests", e))?;
    let mut out = Vec::with_capacity(rows.len());
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let approvals = store::approvals_of(&state.db, &ids)
        .await
        .map_err(|e| internal("reading approvals", e))?;
    for row in &rows {
        out.push(build_info(state, row, who, &approvals).await?);
    }
    Ok(out)
}

/// One request, as the caller may see it: their own, one they may decide, or
/// anyone's for an admin or auditor. Anything else reads as missing.
pub async fn get_request(
    state: &AppState,
    who: &Who<'_>,
    id: &str,
) -> Result<AccessRequestInfo, Status> {
    let id = parse_id(id)?;
    let row = store::request(&state.db, id)
        .await
        .map_err(|e| internal("reading request", e))?
        .ok_or_else(|| Status::not_found("no such request"))?;
    let info = info(state, &row, who).await?;
    if row.requester.eq_ignore_ascii_case(who.username)
        || who.is_admin
        || who.is_auditor
        || info.can_decide
    {
        Ok(info)
    } else {
        Err(Status::not_found("no such request"))
    }
}

async fn info(
    state: &AppState,
    row: &RequestRow,
    who: &Who<'_>,
) -> Result<AccessRequestInfo, Status> {
    let approvals = store::approvals_of(&state.db, &[row.id])
        .await
        .map_err(|e| internal("reading approvals", e))?;
    build_info(state, row, who, &approvals).await
}

async fn build_info(
    state: &AppState,
    row: &RequestRow,
    who: &Who<'_>,
    approvals: &[store::ApprovalRow],
) -> Result<AccessRequestInfo, Status> {
    let mine: Vec<&store::ApprovalRow> = approvals
        .iter()
        .filter(|a| a.request_id == row.id)
        .collect();
    let can_decide = row.status == "pending"
        && row.expires_at > OffsetDateTime::now_utc()
        && !row.requester.eq_ignore_ascii_case(who.username)
        && !mine.iter().any(|a| a.approver == who.username)
        && {
            let groups = store::user_groups(&state.db, who.username)
                .await
                .map_err(|e| internal("reading groups", e))?
                .unwrap_or_default();
            state.policy.current().policy.may_approve(
                &row.role,
                who.username,
                groups.iter().map(String::as_str),
            )
        };
    let grant_expires = if row.status == "approved" {
        store::grant(&state.db, row.id)
            .await
            .map_err(|e| internal("reading grant", e))?
            .map_or(0, |g| unix(g.expires_at))
    } else {
        0
    };
    // What the requester did here lately: only shown to those who decide.
    let (sessions, last) = if can_decide || who.is_admin || who.is_auditor {
        store::requester_activity(&state.db, &row.requester, &row.resource)
            .await
            .map_err(|e| internal("reading activity", e))?
    } else {
        (0, None)
    };
    Ok(AccessRequestInfo {
        id: row.id.to_string(),
        requester: row.requester.clone(),
        role: row.role.clone(),
        resource: row.resource.clone(),
        reason: row.reason.clone(),
        duration_seconds: u32::try_from(row.duration_secs).unwrap_or(0),
        status: row.status.clone(),
        break_glass: row.break_glass,
        approvals_required: u32::try_from(row.approvals_required).unwrap_or(1),
        approvals: mine
            .iter()
            .map(|a| AccessApproval {
                approver: a.approver.clone(),
                decision: a.decision.clone(),
                comment: a.comment.clone(),
                decided_at_unix: unix(a.decided_at),
            })
            .collect(),
        created_at_unix: unix(row.created_at),
        expires_at_unix: unix(row.expires_at),
        grant_expires_at_unix: grant_expires,
        can_decide,
        requester_sessions_30d: u32::try_from(sessions).unwrap_or(u32::MAX),
        requester_last_session_unix: last.map_or(0, unix),
    })
}

/// Active grants for admins; `include_ended` adds the last 30 days.
pub async fn list_grants(
    state: &AppState,
    who: &Who<'_>,
    include_ended: bool,
) -> Result<Vec<AccessGrantInfo>, Status> {
    if !(who.is_admin || who.is_auditor) {
        return Err(Status::permission_denied(
            "listing grants needs the limen:admin or limen:auditor role",
        ));
    }
    Ok(store::list_grants(&state.db, include_ended)
        .await
        .map_err(|e| internal("listing grants", e))?
        .iter()
        .map(grant_info)
        .collect())
}

fn grant_info(g: &GrantRow) -> AccessGrantInfo {
    AccessGrantInfo {
        request_id: g.request_id.to_string(),
        username: g.username.clone(),
        role: g.role.clone(),
        resource: g.resource.clone(),
        reason: g.reason.clone(),
        break_glass: g.break_glass,
        granted_at_unix: unix(g.granted_at),
        expires_at_unix: unix(g.expires_at),
        approvers: g.approvers.clone(),
    }
}

/// Lapse requests nobody answered and note grants that reached their
/// deadline. Each event is written once across replicas: rows are locked
/// while their event is written, and a replica that can't write the event
/// leaves the row for the next tick.
pub async fn expire(state: &AppState) -> Result<(), Status> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal("starting transaction", e))?;
    for r in store::lapsed_requests(&mut tx)
        .await
        .map_err(|e| internal("finding lapsed requests", e))?
    {
        audit(
            state,
            EventKind::AccessExpire,
            &r.requester,
            json!({ "request_id": r.id, "what": "request", "role": r.role, "resource": r.resource }),
        )
        .await?;
        store::set_status(&mut tx, r.id, "expired")
            .await
            .map_err(|e| internal("updating request", e))?;
    }
    for g in store::lapsed_grants(&mut tx)
        .await
        .map_err(|e| internal("finding lapsed grants", e))?
    {
        audit(
            state,
            EventKind::AccessExpire,
            &g.username,
            json!({ "request_id": g.request_id, "what": "grant", "role": g.role, "resource": g.resource, "break_glass": g.break_glass }),
        )
        .await?;
        store::note_grant_expired(&mut tx, g.request_id)
            .await
            .map_err(|e| internal("noting expiry", e))?;
    }
    tx.commit()
        .await
        .map_err(|e| internal("committing expiry", e))
}

/// The grants in force, in the form the snapshot carries.
pub async fn active_for_snapshot(
    state: &AppState,
) -> Result<Vec<limen_session::snapshot::ActiveGrant>, sqlx::Error> {
    Ok(store::active_grants(&state.db)
        .await?
        .into_iter()
        .map(|g| limen_session::snapshot::ActiveGrant {
            request_id: g.request_id.to_string(),
            username: g.username,
            role: g.role,
            resource: g.resource,
            expires_at_unix: unix(g.expires_at),
        })
        .collect())
}

/// Whether the person takes part in access requests: they may ask for a role
/// or approve one. They may sign in without holding any role.
#[must_use]
pub fn takes_part(state: &AppState, username: &str, groups: &[String]) -> bool {
    state
        .policy
        .current()
        .policy
        .takes_part_in_requests(username, groups.iter().map(String::as_str))
}

/// The roles that decide `resource` for `username` right now: the certificate's
/// plus those of active grants, read from the database so an approval or a
/// revocation counts at once (ADR-0025). The control plane's own checks use
/// this; proxies and workers use the same logic on the snapshot.
pub async fn effective_roles_now(
    state: &AppState,
    username: &str,
    cert_roles: &[String],
    resource: &str,
) -> Result<limen_session::snapshot::EffectiveRoles, sqlx::Error> {
    let restrictions = limen_session::snapshot::Restrictions {
        grants: active_for_snapshot(state)
            .await?
            .into_iter()
            .filter(|g| g.username == username && g.resource == resource)
            .collect(),
        ..Default::default()
    };
    Ok(restrictions.effective_roles(
        username,
        cert_roles,
        resource,
        OffsetDateTime::now_utc().unix_timestamp(),
    ))
}

/// Every resource `username` reaches right now: through the roles in their
/// certificate, and through active grants, each with the deadline of the
/// grant it depends on (0 for standing access). Used by `limen ls`.
pub async fn reachable(
    state: &AppState,
    username: &str,
    cert_roles: &[String],
) -> Result<Vec<(limen_policy::AccessibleResource, i64)>, sqlx::Error> {
    let loaded = state.policy.current();
    let policy = &loaded.policy;
    let mut out: std::collections::BTreeMap<String, (limen_policy::AccessibleResource, i64)> =
        policy
            .accessible(cert_roles)
            .into_iter()
            .map(|r| (r.name.clone(), (r, 0)))
            .collect();
    let denied = state_denied_roles(state, username);
    let grants: Vec<_> = store::active_grants(&state.db)
        .await?
        .into_iter()
        .filter(|g| g.username == username && !denied.contains(&g.role))
        .collect();
    for g in grants {
        let mut roles = cert_roles.to_vec();
        roles.push(g.role.clone());
        let Some(res) = policy
            .accessible(&roles)
            .into_iter()
            .find(|r| r.name == g.resource)
        else {
            continue;
        };
        let until = unix(g.expires_at);
        match out.get_mut(&res.name) {
            // Already reachable by standing access: the grant adds principals
            // but the access doesn't end with it.
            Some((existing, 0)) => {
                existing.principals = res.principals;
            }
            Some((existing, deadline)) => {
                existing.principals = res.principals;
                *deadline = (*deadline).max(until);
            }
            None => {
                out.insert(res.name.clone(), (res, until));
            }
        }
    }
    Ok(out.into_values().collect())
}

/// Roles withheld from the user by an access review. (None yet; reviews add
/// them in ADR-0029.)
fn state_denied_roles(_state: &AppState, _username: &str) -> Vec<String> {
    Vec::new()
}

/// What the user could get by asking, for `limen ls`.
pub async fn requestable_for(
    state: &AppState,
    username: &str,
    cert_roles: &[String],
) -> Result<Vec<limen_policy::RequestableResource>, sqlx::Error> {
    if limen_core::identity::actor_type(username) == "bot" {
        return Ok(Vec::new());
    }
    let groups = store::user_groups(&state.db, username)
        .await?
        .unwrap_or_default();
    let policy = state.policy.current();
    let eligible: Vec<String> = policy
        .policy
        .requestable_roles_for_groups(groups.iter().map(String::as_str))
        .into_iter()
        .collect();
    Ok(policy.policy.requestable_resources(cert_roles, &eligible))
}

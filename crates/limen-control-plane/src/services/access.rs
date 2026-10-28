//! The `Access` API: requests, approvals, grants, and `explain` (ADR-0025,
//! ADR-0028). Thin: the rules are in [`crate::access`].

use limen_core::identity::{ADMIN_ROLE, AUDITOR_ROLE};
use limen_policy::{AccessRequest, Principal};
use limen_proto::v1::access_server::Access;
use limen_proto::v1::{
    AccessRequestInfo, CancelAccessRequestRequest, DecideAccessRequestRequest, ExplainRequest,
    ExplainResponse, ListAccessGrantsRequest, ListAccessGrantsResponse, ListAccessRequestsRequest,
    ListAccessRequestsResponse, RequestAccessRequest, RevokeAccessGrantRequest,
    RevokeAccessGrantResponse,
};
use time::OffsetDateTime;
use tonic::{Request, Response, Status};

use crate::access::{self, Who, store};
use crate::caller;
use crate::db;
use crate::state::{AppState, internal};

#[derive(Debug, Clone)]
pub struct AccessService(pub AppState);

fn who(user: &limen_ca::verify::UserIdentity) -> Who<'_> {
    Who {
        username: &user.username,
        is_admin: user.has_role(ADMIN_ROLE),
        is_auditor: user.has_role(AUDITOR_ROLE),
        via: "api",
    }
}

#[tonic::async_trait]
impl Access for AccessService {
    async fn request_access(
        &self,
        request: Request<RequestAccessRequest>,
    ) -> Result<Response<AccessRequestInfo>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.user()?;
        self.0.refuse_if_draining()?;
        let r = request.into_inner();
        access::request_access(
            &self.0,
            &who(user),
            access::NewAccess {
                resource: r.resource,
                role: r.role,
                duration_secs: u64::from(r.duration_seconds),
                reason: r.reason,
                break_glass: r.break_glass,
            },
        )
        .await
        .map(Response::new)
    }

    async fn list_access_requests(
        &self,
        request: Request<ListAccessRequestsRequest>,
    ) -> Result<Response<ListAccessRequestsResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.user()?;
        let requests = access::list_requests(&self.0, &who(user), &request.into_inner()).await?;
        Ok(Response::new(ListAccessRequestsResponse { requests }))
    }

    async fn decide_access_request(
        &self,
        request: Request<DecideAccessRequestRequest>,
    ) -> Result<Response<AccessRequestInfo>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.user()?;
        self.0.refuse_if_draining()?;
        let r = request.into_inner();
        access::decide(&self.0, &who(user), &r.id, r.approve, &r.comment)
            .await
            .map(Response::new)
    }

    async fn cancel_access_request(
        &self,
        request: Request<CancelAccessRequestRequest>,
    ) -> Result<Response<AccessRequestInfo>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.user()?;
        access::cancel(&self.0, &who(user), &request.into_inner().id)
            .await
            .map(Response::new)
    }

    async fn list_access_grants(
        &self,
        request: Request<ListAccessGrantsRequest>,
    ) -> Result<Response<ListAccessGrantsResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.user()?;
        let grants =
            access::list_grants(&self.0, &who(user), request.into_inner().include_ended).await?;
        Ok(Response::new(ListAccessGrantsResponse { grants }))
    }

    async fn revoke_access_grant(
        &self,
        request: Request<RevokeAccessGrantRequest>,
    ) -> Result<Response<RevokeAccessGrantResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.admin()?;
        let r = request.into_inner();
        let (revoked, sessions_ended) =
            access::revoke_grant(&self.0, &who(user), &r.request_id, &r.reason).await?;
        Ok(Response::new(RevokeAccessGrantResponse {
            revoked,
            sessions_ended,
        }))
    }

    async fn explain(
        &self,
        request: Request<ExplainRequest>,
    ) -> Result<Response<ExplainResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.user()?;
        let r = request.into_inner();
        let admin_view = !r.user.is_empty();
        if admin_view {
            caller.admin()?;
        }
        let principal = if r.principal.is_empty() {
            None
        } else {
            Some(Principal::parse(&r.principal, &r.database).map_err(Status::invalid_argument)?)
        };
        let (subject, roles) = if admin_view {
            let row = crate::console::store::user(&self.0.db, &r.user)
                .await
                .map_err(|e| internal("reading user", e))?
                .ok_or_else(|| Status::not_found("no such user"))?;
            (row.username, row.roles)
        } else {
            (user.username.clone(), user.roles.clone())
        };
        let resource = r.resource.trim();
        let (lines, worker_connected) = explain(
            &self.0,
            &subject,
            &roles,
            resource,
            principal.as_ref(),
            admin_view,
        )
        .await
        .map_err(|e| internal("explaining access", e))?;
        Ok(Response::new(ExplainResponse {
            lines,
            full_trace: admin_view,
            worker_connected,
        }))
    }
}

/// Why `subject` can or cannot reach `resource`. Users get an answer that
/// names nothing about resources they can't see; admins get the full trace.
/// Also whether a worker for it is connected, when `subject` can reach it.
pub async fn explain(
    state: &AppState,
    subject: &str,
    cert_roles: &[String],
    resource: &str,
    principal: Option<&Principal>,
    full_trace: bool,
) -> Result<(Vec<String>, Option<bool>), sqlx::Error> {
    let loaded = state.policy.current();
    let policy = &loaded.policy;
    let now = OffsetDateTime::now_utc();
    // The roles that decide this resource, as enforcement sees them: the
    // certificate's, plus grants, minus what a review withheld.
    let held = crate::access::effective_roles_now(state, subject, cert_roles, resource)
        .await?
        .roles;
    let groups = store::user_groups(&state.db, subject)
        .await?
        .unwrap_or_default();
    let eligible: Vec<String> = policy
        .requestable_roles_for_groups(groups.iter().map(String::as_str))
        .into_iter()
        .filter(|r| !held.contains(r))
        .collect();

    let mut lines = if full_trace {
        let mut lines = vec![format!(
            "Explaining {subject} (roles {}, groups {})",
            join_or_none(&held),
            join_or_none(&groups)
        )];
        match principal {
            Some(principal) => lines.extend(
                policy
                    .trace(
                        &AccessRequest {
                            roles: &held,
                            resource,
                            principal: principal.clone(),
                        },
                        &eligible,
                    )
                    .render(),
            ),
            None => lines.extend(policy.explain_resource(&held, &eligible, resource)),
        }
        lines
    } else {
        policy.explain_for_user(&held, &eligible, resource, principal)
    };
    if db::is_locked(&state.db, subject).await? {
        lines.push(format!(
            "{subject} is locked: a lock beats every role and grant."
        ));
    }
    for r in cert_roles.iter().filter(|r| !held.contains(r)) {
        lines.push(format!(
            "The role {r} is withheld from {subject} by an access review."
        ));
    }
    let grants: Vec<_> = store::active_grants(&state.db)
        .await?
        .into_iter()
        .filter(|g| g.username == subject && g.resource == resource && held.contains(&g.role))
        .collect();
    for g in &grants {
        let left = g.expires_at - now;
        lines.push(format!(
            "A grant ({}) gives {} on this resource for another {} minutes.",
            g.request_id,
            g.role,
            left.whole_minutes().max(0)
        ));
    }
    let reachable = policy.accessible(&held).iter().any(|r| r.name == resource);
    if !reachable
        && grants.is_empty()
        && let Some(g) = store::recently_ended_grant(&state.db, subject, resource).await?
    {
        // Their own grant: nothing they didn't know is revealed.
        let ended = g.revoked_at.unwrap_or(g.expires_at);
        let how = if g.revoked_at.is_some() {
            "was revoked"
        } else {
            "expired"
        };
        lines.push(format!(
            "Your grant ({}) of {} on `{resource}` {how} {} minutes ago. Ask again to get it back.",
            g.request_id,
            g.role,
            (now - ended).whole_minutes().max(0)
        ));
    }
    // Only for a resource they can reach: whether it is served says nothing
    // about resources they can't see.
    let worker_connected = if reachable {
        let connected = db::live_worker_labels(&state.db)
            .await?
            .iter()
            .any(|labels| policy.worker_may_serve(resource, labels));
        if !connected {
            lines.push(format!(
                "No worker that can reach `{resource}` is connected right now, so sessions to it fail until one is. Tell an admin."
            ));
        }
        Some(connected)
    } else {
        None
    };
    Ok((lines, worker_connected))
}

fn join_or_none(v: &[String]) -> String {
    if v.is_empty() {
        "none".to_owned()
    } else {
        v.join(", ")
    }
}

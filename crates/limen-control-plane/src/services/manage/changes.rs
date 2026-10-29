//! Changes held for approval (ADR-0042 §6): reading them, and the decisions.
//! Only people decide: an admin, or a member of the author grant's approver
//! groups. Never the author, and never the person who started the run.

use std::sync::Arc;

use limen_core::identity::ADMIN_ROLE;
use limen_proto::manage::v1 as pb;
use prost::Message as _;
use serde_json::json;
use time::OffsetDateTime;
use tonic::{Code, Request, Status};
use uuid::Uuid;

use super::{ManageService, error, store_error, targets_of, writer_guard};
use crate::caller;
use crate::config::PolicyTests;
use crate::policy_changes::{self, Decision, Held, State};
use crate::policy_store::{self, StoreError};
use crate::state::{AppState, LoadedPolicy, internal, unix};

const MAX_NOTE: usize = 1000;
const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 200;

/// Who is looking at, or deciding, changes.
struct Viewer {
    username: String,
    bot: bool,
    admin: bool,
    /// The IdP groups at the person's latest login.
    groups: Vec<String>,
    policy: Arc<LoadedPolicy>,
}

impl Viewer {
    /// A member of the approver groups of the grant `held`'s author writes
    /// with, as the policy says now.
    fn approver_of(&self, held: &Held) -> bool {
        !self.bot
            && held
                .author
                .strip_prefix("bot:")
                .and_then(|bot| self.policy.policy.writer_for_bot(bot))
                .is_some_and(|grant| {
                    grant
                        .spec
                        .approvers
                        .groups
                        .iter()
                        .any(|g| self.groups.contains(g))
                })
    }

    /// Usernames compared without case, as for access requests.
    fn is_author(&self, held: &Held) -> bool {
        self.username.eq_ignore_ascii_case(&held.author)
    }

    fn may_see(&self, held: &Held) -> bool {
        self.admin || self.is_author(held) || self.approver_of(held)
    }

    /// Whether this person may decide `held`, and why not.
    fn may_decide(&self, held: &Held) -> Result<(), Status> {
        if self.bot {
            return Err(Status::permission_denied(
                "only people decide held changes; bots never do",
            ));
        }
        if !self.admin && !self.approver_of(held) {
            return Err(Status::permission_denied(format!(
                "deciding this change needs the {ADMIN_ROLE} role or its writer's approver groups"
            )));
        }
        let refused = |why: &str| {
            Err(error(
                Code::FailedPrecondition,
                pb::ErrorReason::ChangeNotDecidable,
                why,
                &[("state", held.state.as_str().to_owned())],
            ))
        };
        if held.state != State::Pending {
            return refused(&format!("the change is {}", held.state.as_str()));
        }
        if self.is_author(held) {
            return refused("its author can't decide it: ask another person");
        }
        if policy_changes::started_the_run(&self.username, &held.author_ci) {
            return refused("you started the CI run that made it: ask another person");
        }
        Ok(())
    }
}

fn state_value(state: State) -> i32 {
    use pb::policy_change::State as S;
    match state {
        State::Pending => S::Pending,
        State::Applied => S::Applied,
        State::Rejected => S::Rejected,
        State::Cancelled => S::Cancelled,
        State::Expired => S::Expired,
        State::Superseded => S::Superseded,
    }
    .into()
}

fn state_of(value: i32) -> Result<State, Status> {
    use pb::policy_change::State as S;
    Ok(match S::try_from(value) {
        Ok(S::Unspecified | S::Pending) => State::Pending,
        Ok(S::Applied) => State::Applied,
        Ok(S::Rejected) => State::Rejected,
        Ok(S::Cancelled) => State::Cancelled,
        Ok(S::Expired) => State::Expired,
        Ok(S::Superseded) => State::Superseded,
        Err(_) => return Err(Status::invalid_argument("unknown state")),
    })
}

pub(super) fn to_pb(held: &Held) -> pb::PolicyChange {
    pb::PolicyChange {
        id: held.id.to_string(),
        state: state_value(held.state),
        author: held.author.clone(),
        author_ci: held.author_ci.clone().into_iter().collect(),
        writes: pb::BatchWriteRequest::decode(held.writes.as_slice())
            .map(|b| b.writes)
            .unwrap_or_default(),
        impact: pb::Impact::decode(held.impact.as_slice()).ok(),
        base_policy_version: held.base_policy_version,
        reason: held.reason.clone(),
        source_ref: held.source_ref.clone(),
        create_time_unix: unix(held.created_at),
        expire_time_unix: unix(held.expires_at),
        decided_by: held.decided_by.clone().unwrap_or_default(),
        decision_note: held.decision_note.clone().unwrap_or_default(),
        decide_time_unix: held.decided_at.map_or(0, unix),
        applied_policy_version: held.applied_policy_version.unwrap_or(0),
    }
}

pub(super) fn held_error(e: &policy_changes::Error) -> Status {
    match e {
        policy_changes::Error::AuditUnavailable => store_error(&StoreError::AuditUnavailable),
        other => internal("policy changes", other),
    }
}

fn change_id(id: &str) -> Result<Uuid, Status> {
    Uuid::parse_str(id).map_err(|_| Status::invalid_argument("id is not a change id"))
}

fn note_of(note: &str) -> Result<&str, Status> {
    if note.len() > MAX_NOTE {
        return Err(Status::invalid_argument(format!(
            "note exceeds {MAX_NOTE} characters"
        )));
    }
    Ok(note)
}

fn encode_token(held: &Held) -> String {
    format!("{}.{}", held.created_at.unix_timestamp_nanos(), held.id)
}

fn decode_token(token: &str) -> Result<(OffsetDateTime, Uuid), Status> {
    let bad = || Status::invalid_argument("page_token is not one this server issued");
    let (at, id) = token.split_once('.').ok_or_else(bad)?;
    let at = at
        .parse::<i128>()
        .ok()
        .and_then(|n| OffsetDateTime::from_unix_timestamp_nanos(n).ok())
        .ok_or_else(bad)?;
    Ok((at, Uuid::parse_str(id).map_err(|_| bad())?))
}

impl ManageService {
    async fn viewer<T>(&self, request: &Request<T>) -> Result<Viewer, Status> {
        let resolved = caller::resolve(request, &self.0.cas)?;
        let id = resolved.user()?;
        let groups = if id.bot {
            Vec::new()
        } else {
            crate::access::store::user_groups(&self.0.db, &id.username)
                .await
                .map_err(|e| internal("reading groups", e))?
                .unwrap_or_default()
        };
        Ok(Viewer {
            username: id.username.clone(),
            bot: id.bot,
            admin: !id.bot && id.has_role(ADMIN_ROLE),
            groups,
            policy: self.latest().await?,
        })
    }

    /// The change, if this viewer may see it. One it may not reads exactly
    /// like one that doesn't exist.
    async fn visible(&self, viewer: &Viewer, id: &str) -> Result<Held, Status> {
        let id = change_id(id)?;
        policy_changes::get(&self.0.db, id)
            .await
            .map_err(|e| held_error(&e))?
            .filter(|h| viewer.may_see(h))
            .ok_or_else(|| Status::not_found(format!("change {id} doesn't exist")))
    }

    pub(super) async fn get_change_rpc(
        &self,
        request: Request<pb::GetChangeRequest>,
    ) -> Result<pb::GetChangeResponse, Status> {
        let viewer = self.viewer(&request).await?;
        let held = self.visible(&viewer, &request.get_ref().id).await?;
        Ok(pb::GetChangeResponse {
            change: Some(to_pb(&held)),
        })
    }

    pub(super) async fn list_changes_rpc(
        &self,
        request: Request<pb::ListChangesRequest>,
    ) -> Result<pb::ListChangesResponse, Status> {
        policy_changes::expire(&self.0).await;
        let viewer = self.viewer(&request).await?;
        let req = request.into_inner();
        let state = state_of(req.state)?;
        let size = super::page_size(req.page_size, DEFAULT_PAGE, MAX_PAGE)?;
        let before = if req.page_token.is_empty() {
            None
        } else {
            Some(decode_token(&req.page_token)?)
        };
        // Admins see every change; anyone else, their own and the ones they
        // approve. Bots see only their own.
        let author = (viewer.bot).then_some(viewer.username.as_str());
        let limit = i64::try_from(size + 1).unwrap_or(i64::MAX);
        let rows = policy_changes::list(&self.0.db, state, author, before, limit)
            .await
            .map_err(|e| held_error(&e))?;
        let next_page_token = match (rows.len() > size, rows.get(size - 1)) {
            (true, Some(last)) => encode_token(last),
            _ => String::new(),
        };
        Ok(pb::ListChangesResponse {
            changes: rows
                .iter()
                .take(size)
                .filter(|h| viewer.may_see(h))
                .map(to_pb)
                .collect(),
            next_page_token,
        })
    }

    pub(super) async fn approve_change_rpc(
        &self,
        request: Request<pb::ApproveChangeRequest>,
    ) -> Result<pb::ApproveChangeResponse, Status> {
        policy_changes::expire(&self.0).await;
        let viewer = self.viewer(&request).await?;
        let req = request.into_inner();
        let note = note_of(&req.note)?;
        let held = self.visible(&viewer, &req.id).await?;
        viewer.may_decide(&held)?;
        let Some(held) = policy_changes::claim(&self.0.db, held.id)
            .await
            .map_err(|e| held_error(&e))?
        else {
            return Err(error(
                Code::FailedPrecondition,
                pb::ErrorReason::ChangeNotDecidable,
                "the change was decided, expired, or is being applied by another approver",
                &[],
            ));
        };
        let written = apply(&self.0, &held, &viewer.username, note).await;
        let decision = match written {
            Ok(outcome) if outcome.held => Decision {
                to: State::Superseded,
                by: &viewer.username,
                note: "the policy changed since it was reviewed: it would now give access nobody reviewed",
                applied_version: None,
            },
            Ok(outcome) if !outcome.applied => Decision {
                to: State::Superseded,
                by: &viewer.username,
                note: "the policy already has what it writes",
                applied_version: None,
            },
            Ok(outcome) => Decision {
                to: State::Applied,
                by: &viewer.username,
                note,
                applied_version: Some(outcome.version),
            },
            Err(e @ (StoreError::Internal(_) | StoreError::AuditUnavailable)) => {
                policy_changes::release(&self.0.db, held.id).await;
                return Err(store_error(&e));
            }
            Err(e) => {
                let why = format!("it can't be applied as reviewed: {e}");
                return self.superseded(held.id, &viewer.username, &why).await;
            }
        };
        let decided = policy_changes::decide(&self.0, held.id, &decision)
            .await
            .map_err(|e| held_error(&e))?
            .ok_or_else(|| internal("deciding a change", "the claim was lost"))?;
        Ok(pb::ApproveChangeResponse {
            change: Some(to_pb(&decided)),
        })
    }

    async fn superseded(
        &self,
        id: Uuid,
        by: &str,
        why: &str,
    ) -> Result<pb::ApproveChangeResponse, Status> {
        let decision = Decision {
            to: State::Superseded,
            by,
            note: why,
            applied_version: None,
        };
        let decided = policy_changes::decide(&self.0, id, &decision)
            .await
            .map_err(|e| held_error(&e))?
            .ok_or_else(|| internal("deciding a change", "the claim was lost"))?;
        Ok(pb::ApproveChangeResponse {
            change: Some(to_pb(&decided)),
        })
    }

    pub(super) async fn reject_change_rpc(
        &self,
        request: Request<pb::RejectChangeRequest>,
    ) -> Result<pb::RejectChangeResponse, Status> {
        policy_changes::expire(&self.0).await;
        let viewer = self.viewer(&request).await?;
        let req = request.into_inner();
        let note = note_of(&req.note)?;
        if note.trim().is_empty() {
            return Err(Status::invalid_argument("note is required: say why"));
        }
        let held = self.visible(&viewer, &req.id).await?;
        viewer.may_decide(&held)?;
        let decision = Decision {
            to: State::Rejected,
            by: &viewer.username,
            note,
            applied_version: None,
        };
        let decided = self.decided(held.id, &decision).await?;
        Ok(pb::RejectChangeResponse {
            change: Some(to_pb(&decided)),
        })
    }

    pub(super) async fn cancel_change_rpc(
        &self,
        request: Request<pb::CancelChangeRequest>,
    ) -> Result<pb::CancelChangeResponse, Status> {
        policy_changes::expire(&self.0).await;
        let viewer = self.viewer(&request).await?;
        let held = self.visible(&viewer, &request.get_ref().id).await?;
        if !viewer.is_author(&held) {
            return Err(Status::permission_denied(
                "only its author withdraws a change; approvers reject it",
            ));
        }
        let decision = Decision {
            to: State::Cancelled,
            by: &viewer.username,
            note: "",
            applied_version: None,
        };
        let decided = self.decided(held.id, &decision).await?;
        Ok(pb::CancelChangeResponse {
            change: Some(to_pb(&decided)),
        })
    }

    async fn decided(&self, id: Uuid, decision: &Decision<'_>) -> Result<Held, Status> {
        policy_changes::decide(&self.0, id, decision)
            .await
            .map_err(|e| held_error(&e))?
            .ok_or_else(|| {
                error(
                    Code::FailedPrecondition,
                    pb::ErrorReason::ChangeNotDecidable,
                    "the change was decided or expired, or is being applied",
                    &[],
                )
            })
    }
}

/// Write a held change on the current policy, as its author, with the
/// author's grant checked again and a hold that stops it if it would give
/// access the approver didn't review.
async fn apply(
    state: &AppState,
    held: &Held,
    approver: &str,
    note: &str,
) -> Result<policy_store::Outcome, StoreError> {
    let grant = held.author.strip_prefix("bot:").map(|bot| {
        let (targets, transfers) = targets_of(&held.plan.changes);
        writer_guard(bot.to_owned(), targets, transfers)
    });
    let guard = policy_store::both(
        policy_store::unchanged_since(held.plan.basis.clone()),
        grant,
    );
    policy_store::write(
        state,
        policy_store::Request {
            actor: held.author.clone(),
            changes: held.plan.changes.clone(),
            dry_run: false,
            require_tests: held.plan.require_tests,
            keep_tests_passing: state.config.policy_tests == PolicyTests::Required,
            source_ref: Some(held.source_ref.clone()).filter(|s| !s.is_empty()),
            expected_version: None,
            guard: Some(guard),
            hold: Some(policy_changes::unreviewed(&held.plan.gains)),
            approval: Some(json!({
                "change_id": held.id,
                "approved_by": approver,
                "note": note,
                "author_ci": held.author_ci,
            })),
        },
    )
    .await
}

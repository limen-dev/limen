//! Changes held for approval (ADR-0042 §6): reading them, and the decisions.
//! Only people decide: an admin, or a member of the author grant's approver
//! groups. Never the author, and never the person who started the run.
//!
//! The decisions are functions of the state and a `Viewer`, so the API here
//! and the console's pages decide alike.

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

pub(crate) const MAX_NOTE: usize = 1000;
const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 200;

/// Who is looking at, or deciding, changes.
#[derive(Debug, Clone)]
pub(crate) struct Viewer {
    pub username: String,
    pub bot: bool,
    pub admin: bool,
    /// The IdP groups at the person's latest login.
    pub groups: Vec<String>,
    pub policy: Arc<LoadedPolicy>,
}

/// Why a read or a decision was refused.
#[derive(Debug)]
pub(crate) enum Refusal {
    /// Doesn't exist, or isn't this viewer's to see.
    NotFound,
    Forbidden(String),
    /// Not pending any more, or the viewer is its author or started its run.
    NotDecidable {
        why: String,
        state: State,
    },
    Invalid(String),
    Store(StoreError),
    Changes(policy_changes::Error),
}

impl Refusal {
    fn status(&self) -> Status {
        match self {
            Refusal::NotFound => Status::not_found("no such change"),
            Refusal::Forbidden(m) => Status::permission_denied(m.clone()),
            Refusal::NotDecidable { why, state } => error(
                Code::FailedPrecondition,
                pb::ErrorReason::ChangeNotDecidable,
                why.clone(),
                &[("state", state.as_str().to_owned())],
            ),
            Refusal::Invalid(m) => Status::invalid_argument(m.clone()),
            Refusal::Store(e) => store_error(e),
            Refusal::Changes(e) => held_error(e),
        }
    }

    /// In a sentence, for a page.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Refusal::NotFound => "There is no such change, or it isn't yours to see.".into(),
            Refusal::Forbidden(m) | Refusal::Invalid(m) => m.clone(),
            Refusal::NotDecidable { why, .. } => format!("This change can't be decided: {why}."),
            Refusal::Store(e) => e.to_string(),
            Refusal::Changes(e) => e.to_string(),
        }
    }
}

impl From<policy_changes::Error> for Refusal {
    fn from(e: policy_changes::Error) -> Self {
        Refusal::Changes(e)
    }
}

impl Viewer {
    /// A person, as the console knows them: the groups come from their
    /// latest login, the policy is the latest in the database.
    pub(crate) async fn person(
        state: &AppState,
        username: &str,
        admin: bool,
    ) -> Result<Self, String> {
        let groups = crate::access::store::user_groups(&state.db, username)
            .await
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        let mut conn = state.db.acquire().await.map_err(|e| e.to_string())?;
        let policy = state
            .policy
            .latest(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self {
            username: username.to_owned(),
            bot: false,
            admin,
            groups,
            policy,
        })
    }

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

    /// Whether this person approves for any writer grant: they see the
    /// changes page.
    #[must_use]
    pub(crate) fn approves_any(&self) -> bool {
        self.admin
            || self.policy.policy.documents().iter().any(|d| match d {
                limen_policy::Document::PolicyWriter(w) => w
                    .spec
                    .approvers
                    .groups
                    .iter()
                    .any(|g| self.groups.contains(g)),
                _ => false,
            })
    }

    /// Usernames compared without case, as for access requests.
    pub(crate) fn is_author(&self, held: &Held) -> bool {
        self.username.eq_ignore_ascii_case(&held.author)
    }

    pub(crate) fn may_see(&self, held: &Held) -> bool {
        self.admin || self.is_author(held) || self.approver_of(held)
    }

    /// Whether this person may decide `held`, and why not.
    pub(crate) fn may_decide(&self, held: &Held) -> Result<(), Refusal> {
        if self.bot {
            return Err(Refusal::Forbidden(
                "only people decide held changes; bots never do".into(),
            ));
        }
        if !self.admin && !self.approver_of(held) {
            return Err(Refusal::Forbidden(format!(
                "deciding this change needs the {ADMIN_ROLE} role or its writer's approver groups"
            )));
        }
        let refused = |why: &str| {
            Err(Refusal::NotDecidable {
                why: why.to_owned(),
                state: held.state,
            })
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

fn note_of(note: &str) -> Result<&str, Refusal> {
    if note.len() > MAX_NOTE {
        return Err(Refusal::Invalid(format!(
            "the note exceeds {MAX_NOTE} characters"
        )));
    }
    Ok(note)
}

/// The change, if `viewer` may see it. One they may not reads exactly like
/// one that doesn't exist.
pub(crate) async fn visible(state: &AppState, viewer: &Viewer, id: Uuid) -> Result<Held, Refusal> {
    policy_changes::get(&state.db, id)
        .await?
        .filter(|h| viewer.may_see(h))
        .ok_or(Refusal::NotFound)
}

/// Changes in `state` that `viewer` may see, newest first.
pub(crate) async fn list(
    state: &AppState,
    viewer: &Viewer,
    wanted: State,
    before: Option<(OffsetDateTime, Uuid)>,
    size: usize,
) -> Result<(Vec<Held>, Option<Held>), Refusal> {
    policy_changes::expire(state).await;
    // Bots see only their own; admins and approvers are filtered below.
    let author = viewer.bot.then_some(viewer.username.as_str());
    let limit = i64::try_from(size + 1).unwrap_or(i64::MAX);
    let mut rows = policy_changes::list(&state.db, wanted, author, before, limit).await?;
    let more = rows.len() > size;
    rows.truncate(size);
    let last = rows.last().cloned().filter(|_| more);
    rows.retain(|h| viewer.may_see(h));
    Ok((rows, last))
}

/// Approve a change: apply it on the current policy, or supersede it when it
/// can't be applied as reviewed. Either way the change is decided.
pub(crate) async fn approve(
    state: &AppState,
    viewer: &Viewer,
    id: Uuid,
    note: &str,
) -> Result<Held, Refusal> {
    policy_changes::expire(state).await;
    let note = note_of(note)?;
    let held = visible(state, viewer, id).await?;
    viewer.may_decide(&held)?;
    let Some(held) = policy_changes::claim(&state.db, held.id).await? else {
        return Err(Refusal::NotDecidable {
            why: "it was decided, expired, or is being applied by another approver".into(),
            state: held.state,
        });
    };
    let by = viewer.username.as_str();
    let (to, why, applied_version) = match apply(state, &held, by, note).await {
        Ok(outcome) if outcome.held => (
            State::Superseded,
            "the policy changed since it was reviewed: it would now give access nobody reviewed"
                .to_owned(),
            None,
        ),
        Ok(outcome) if !outcome.applied => (
            State::Superseded,
            "the policy already has what it writes".to_owned(),
            None,
        ),
        Ok(outcome) => (State::Applied, note.to_owned(), Some(outcome.version)),
        Err(e @ (StoreError::Internal(_) | StoreError::AuditUnavailable)) => {
            policy_changes::release(&state.db, held.id).await;
            return Err(Refusal::Store(e));
        }
        Err(e) => (
            State::Superseded,
            format!("it can't be applied as reviewed: {e}"),
            None,
        ),
    };
    let decision = Decision {
        to,
        by,
        note: &why,
        applied_version,
    };
    policy_changes::decide(state, held.id, &decision)
        .await?
        .ok_or_else(|| Refusal::Store(StoreError::Internal("the claim was lost".into())))
}

/// Refuse a change, with a reason.
pub(crate) async fn reject(
    state: &AppState,
    viewer: &Viewer,
    id: Uuid,
    note: &str,
) -> Result<Held, Refusal> {
    policy_changes::expire(state).await;
    let note = note_of(note)?;
    if note.trim().is_empty() {
        return Err(Refusal::Invalid("a note is required: say why".into()));
    }
    let held = visible(state, viewer, id).await?;
    viewer.may_decide(&held)?;
    let decision = Decision {
        to: State::Rejected,
        by: &viewer.username,
        note,
        applied_version: None,
    };
    decided(state, &held, &decision).await
}

/// The author withdraws a change.
pub(crate) async fn cancel(state: &AppState, viewer: &Viewer, id: Uuid) -> Result<Held, Refusal> {
    policy_changes::expire(state).await;
    let held = visible(state, viewer, id).await?;
    if !viewer.is_author(&held) {
        return Err(Refusal::Forbidden(
            "only its author withdraws a change; approvers reject it".into(),
        ));
    }
    let decision = Decision {
        to: State::Cancelled,
        by: &viewer.username,
        note: "",
        applied_version: None,
    };
    decided(state, &held, &decision).await
}

async fn decided(state: &AppState, held: &Held, decision: &Decision<'_>) -> Result<Held, Refusal> {
    policy_changes::decide(state, held.id, decision)
        .await?
        .ok_or_else(|| Refusal::NotDecidable {
            why: "it was decided or expired, or is being applied".into(),
            state: held.state,
        })
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

// ---- The API ----------------------------------------------------------------

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

pub(crate) fn to_pb(held: &Held) -> pb::PolicyChange {
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

    pub(super) async fn get_change_rpc(
        &self,
        request: Request<pb::GetChangeRequest>,
    ) -> Result<pb::GetChangeResponse, Status> {
        let viewer = self.viewer(&request).await?;
        let id = change_id(&request.get_ref().id)?;
        let held = visible(&self.0, &viewer, id)
            .await
            .map_err(|r| r.status())?;
        Ok(pb::GetChangeResponse {
            change: Some(to_pb(&held)),
        })
    }

    pub(super) async fn list_changes_rpc(
        &self,
        request: Request<pb::ListChangesRequest>,
    ) -> Result<pb::ListChangesResponse, Status> {
        let viewer = self.viewer(&request).await?;
        let req = request.into_inner();
        let wanted = state_of(req.state)?;
        let size = super::page_size(req.page_size, DEFAULT_PAGE, MAX_PAGE)?;
        let before = if req.page_token.is_empty() {
            None
        } else {
            Some(decode_token(&req.page_token)?)
        };
        let (rows, last) = list(&self.0, &viewer, wanted, before, size)
            .await
            .map_err(|r| r.status())?;
        Ok(pb::ListChangesResponse {
            changes: rows.iter().map(to_pb).collect(),
            next_page_token: last.as_ref().map(encode_token).unwrap_or_default(),
        })
    }

    pub(super) async fn approve_change_rpc(
        &self,
        request: Request<pb::ApproveChangeRequest>,
    ) -> Result<pb::ApproveChangeResponse, Status> {
        let viewer = self.viewer(&request).await?;
        let req = request.into_inner();
        let id = change_id(&req.id)?;
        let decided = approve(&self.0, &viewer, id, &req.note)
            .await
            .map_err(|r| r.status())?;
        Ok(pb::ApproveChangeResponse {
            change: Some(to_pb(&decided)),
        })
    }

    pub(super) async fn reject_change_rpc(
        &self,
        request: Request<pb::RejectChangeRequest>,
    ) -> Result<pb::RejectChangeResponse, Status> {
        let viewer = self.viewer(&request).await?;
        let req = request.into_inner();
        let id = change_id(&req.id)?;
        let decided = reject(&self.0, &viewer, id, &req.note)
            .await
            .map_err(|r| r.status())?;
        Ok(pb::RejectChangeResponse {
            change: Some(to_pb(&decided)),
        })
    }

    pub(super) async fn cancel_change_rpc(
        &self,
        request: Request<pb::CancelChangeRequest>,
    ) -> Result<pb::CancelChangeResponse, Status> {
        let viewer = self.viewer(&request).await?;
        let id = change_id(&request.get_ref().id)?;
        let decided = cancel(&self.0, &viewer, id).await.map_err(|r| r.status())?;
        Ok(pb::CancelChangeResponse {
            change: Some(to_pb(&decided)),
        })
    }
}

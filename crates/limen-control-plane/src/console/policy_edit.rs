//! Editing policy in the console, and deciding changes held for approval
//! (ADR-0042 §13). Writes go through `policy_store` like every other channel,
//! as the console's own owner: documents another owner manages are
//! read-only here. Decisions use the same functions as the management API.

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use uuid::Uuid;

use super::pages::console;
use super::views::{Chrome, error_page};
use super::{Auth, html};
use crate::config::PolicyTests;
use crate::policy_changes::{self, Held, State as ChangeState};
use crate::policy_store::{self, Change, Channel, Input, Owner, StoreError};
use crate::services::manage::changes::{self, Refusal, Viewer};
use crate::state::AppState;

const MAX_YAML: usize = 256 * 1024;

/// Who the console writes as: one source in the default namespace.
#[must_use]
pub fn console_owner() -> Owner {
    Owner {
        channel: Channel::Console,
        source: "console".into(),
        namespace: "default".into(),
    }
}

/// What a console write did.
#[derive(Debug)]
pub enum Done {
    Applied(i64),
    Unchanged,
    Held(Uuid),
}

impl Done {
    /// The `done=` code the policy page turns into a notice.
    fn code(&self) -> String {
        match self {
            Done::Applied(v) => format!("applied-{v}"),
            Done::Unchanged => "unchanged".into(),
            Done::Held(id) => format!("held-{id}"),
        }
    }
}

/// The notice for a `done=` code, if it is one of ours.
#[must_use]
pub fn notice(done: &str) -> Option<String> {
    if let Some(v) = done.strip_prefix("applied-") {
        return Some(format!("Applied: policy version {v} is active."));
    }
    if let Some(id) = done.strip_prefix("held-") {
        let id = Uuid::parse_str(id).ok()?;
        return Some(format!(
            "Held for approval: it widens standing access, so another admin approves change {id} on the Policy changes page."
        ));
    }
    (done == "unchanged").then(|| "Nothing changed: the document already said that.".to_owned())
}

/// One write by a person in the console, with the guardrails every channel
/// has: tests with `--policy-tests=required`, and a second admin with
/// `--widening-approval=all`.
async fn write(state: &AppState, auth: &Auth, changes: Vec<Change>) -> Result<Done, String> {
    // The same per-person limit as the API's writes.
    if !state.limits.allow_policy_write(&auth.username, false) {
        return Err("Too many policy writes; wait a moment and try again.".into());
    }
    let outcome = policy_store::write(
        state,
        policy_store::Request {
            actor: auth.username.clone(),
            changes: changes.clone(),
            dry_run: false,
            require_tests: false,
            keep_tests_passing: state.config.policy_tests == PolicyTests::Required,
            source_ref: Some("console".into()),
            expected_version: None,
            guard: None,
            hold: policy_changes::hold_for(None, state.config.widening_approval),
            approval: None,
        },
    )
    .await
    .map_err(|e| store_message(&e))?;
    if outcome.held {
        let new = policy_changes::New {
            author: auth.username.clone(),
            author_ci: std::collections::BTreeMap::new(),
            plan: policy_changes::Plan {
                changes,
                require_tests: false,
                gains: policy_changes::widening_gains(&outcome),
                basis: outcome.basis.clone(),
            },
            writes: Vec::new(),
            impact: prost::Message::encode_to_vec(&crate::services::manage::impact(&outcome)),
            base_policy_version: outcome.version,
            reason: String::new(),
            source_ref: "console".into(),
        };
        let held = policy_changes::hold(state, new, state.config.policy_change_ttl)
            .await
            .map_err(|e| e.to_string())?;
        return Ok(Done::Held(held.id));
    }
    Ok(if outcome.applied {
        Done::Applied(outcome.version)
    } else {
        Done::Unchanged
    })
}

fn store_message(e: &StoreError) -> String {
    match e {
        StoreError::AuditUnavailable => {
            "The audit trail can't record the change, so it wasn't made. Try again shortly.".into()
        }
        StoreError::Internal(_) => "Limen couldn't write the policy. Try again shortly.".into(),
        other => other.to_string(),
    }
}

/// The one document in `yaml`, as an input.
fn one_document(yaml: &str) -> Result<Input, String> {
    if yaml.len() > MAX_YAML {
        return Err(format!("A document is limited to {} KiB.", MAX_YAML / 1024));
    }
    let docs = limen_policy::Policy::parse_yaml_documents([("console.yaml", yaml)])
        .map_err(|e| e.to_string())?;
    let [doc] = docs.as_slice() else {
        return Err(format!(
            "Paste exactly one document; this has {}. Use limen admin apply for several.",
            docs.len()
        ));
    };
    Input::document(doc).map_err(|e| e.to_string())
}

#[derive(Deserialize)]
pub struct SaveForm {
    csrf: String,
    yaml: String,
    /// Set when editing: the document's kind, name, and etag as read.
    #[serde(default)]
    kind: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    etag: String,
}

/// Create a document the console will own, or replace one it owns.
pub async fn save_document(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Form(form): Form<SaveForm>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = auth.check_post(console, &headers, &form.csrf) {
        return r;
    }
    let editing = !form.etag.is_empty();
    let result = match one_document(&form.yaml) {
        Err(e) => Err(e),
        Ok(input) if editing && (input.kind != form.kind || input.name != form.name) => {
            Err(format!(
                "This edits {}/{}; the YAML is {}/{}. Renaming is a new document and a delete.",
                form.kind, form.name, input.kind, input.name
            ))
        }
        Ok(input) => {
            let change = if editing {
                Change::Update {
                    owner: console_owner(),
                    input,
                    etag: form.etag.clone(),
                }
            } else {
                Change::Create {
                    owner: console_owner(),
                    input,
                }
            };
            write(&state, &auth, vec![change]).await
        }
    };
    match result {
        Ok(done) => Redirect::to(&format!("/console/policy?done={}", done.code())).into_response(),
        Err(message) => {
            let draft = if editing { String::new() } else { form.yaml };
            super::pages::policy_page_with(&state, &auth, draft, Some(message)).await
        }
    }
}

#[derive(Deserialize)]
pub struct DeleteForm {
    csrf: String,
    kind: String,
    name: String,
    etag: String,
}

/// Delete a document the console owns.
pub async fn delete_document(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Form(form): Form<DeleteForm>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = auth.check_post(console, &headers, &form.csrf) {
        return r;
    }
    let change = Change::Delete {
        owner: console_owner(),
        key: (form.kind, form.name),
        etag: Some(form.etag),
        allow_missing: false,
    };
    match write(&state, &auth, vec![change]).await {
        Ok(done) => Redirect::to(&format!("/console/policy?done={}", done.code())).into_response(),
        Err(message) => {
            super::pages::policy_page_with(&state, &auth, String::new(), Some(message)).await
        }
    }
}

// ---- Held changes -----------------------------------------------------------

/// One held change, for a page.
pub struct ChangeRow {
    pub id: String,
    pub state: &'static str,
    pub author: String,
    /// Who started the CI run, for a bot's change.
    pub run_by: String,
    pub reason: String,
    pub created: String,
    pub expires: String,
    pub gains: Vec<String>,
    pub decided_by: String,
    pub decision_note: String,
}

impl ChangeRow {
    fn of(held: &Held) -> Self {
        Self {
            id: held.id.to_string(),
            state: held.state.as_str(),
            author: held.author.clone(),
            run_by: ["actor", "user_login"]
                .iter()
                .find_map(|k| held.author_ci.get(*k).cloned())
                .unwrap_or_default(),
            reason: held.reason.clone(),
            created: super::views::time_text(Some(held.created_at)),
            expires: super::views::time_text(Some(held.expires_at)),
            gains: held.plan.gains.clone(),
            decided_by: held.decided_by.clone().unwrap_or_default(),
            decision_note: held.decision_note.clone().unwrap_or_default(),
        }
    }
}

#[derive(Template)]
#[template(path = "changes.html")]
pub struct ChangesPage {
    pub chrome: Chrome,
    pub state: &'static str,
    pub rows: Vec<ChangeRow>,
}

#[derive(Template)]
#[template(path = "change.html")]
pub struct ChangePage {
    pub chrome: Chrome,
    pub change: ChangeRow,
    /// `key: value` facts of the CI run behind a bot's change.
    pub ci: Vec<(String, String)>,
    /// The writes, one line each.
    pub writes: Vec<String>,
    /// Why this viewer can't decide it, or empty if they can.
    pub cant_decide: String,
    pub is_author: bool,
    pub error: Option<String>,
}

async fn viewer(state: &AppState, auth: &Auth) -> Result<Viewer, Response> {
    let viewer = Viewer::person(state, &auth.username, auth.is_admin)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "reading the viewer for policy changes");
            error_page(
                StatusCode::SERVICE_UNAVAILABLE,
                "Unavailable",
                "The console can't reach its database. Try again shortly.",
            )
        })?;
    if !viewer.approves_any() {
        return Err(error_page(
            StatusCode::FORBIDDEN,
            "Not an approver",
            "Policy changes are decided by admins and by the approver groups of writer grants.",
        ));
    }
    Ok(viewer)
}

fn chrome(state: &AppState, auth: &Auth) -> Chrome {
    Chrome::new(auth, "changes", state.policy.base().version)
}

fn refusal_page(r: &Refusal) -> Response {
    let status = match r {
        Refusal::NotFound => StatusCode::NOT_FOUND,
        Refusal::Forbidden(_) => StatusCode::FORBIDDEN,
        Refusal::NotDecidable { .. } => StatusCode::CONFLICT,
        Refusal::Invalid(_) => StatusCode::BAD_REQUEST,
        Refusal::Store(_) | Refusal::Changes(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    error_page(status, "Not done", &r.message())
}

#[derive(Deserialize)]
pub struct ChangesQuery {
    state: Option<String>,
}

pub async fn changes_page(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ChangesQuery>,
) -> Response {
    let viewer = match viewer(&state, &auth).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let wanted = match q.state.as_deref() {
        None | Some("pending") => ChangeState::Pending,
        Some("applied") => ChangeState::Applied,
        Some("rejected") => ChangeState::Rejected,
        Some("cancelled") => ChangeState::Cancelled,
        Some("expired") => ChangeState::Expired,
        Some("superseded") => ChangeState::Superseded,
        Some(_) => {
            return error_page(
                StatusCode::BAD_REQUEST,
                "No such list",
                "Pick a state from the tabs.",
            );
        }
    };
    match changes::list(&state, &viewer, wanted, None, 100).await {
        Ok((rows, _)) => html(
            ChangesPage {
                chrome: chrome(&state, &auth),
                state: wanted.as_str(),
                rows: rows.iter().map(ChangeRow::of).collect(),
            }
            .render(),
        ),
        Err(r) => refusal_page(&r),
    }
}

/// The writes of a held change, one line each.
fn write_lines(held: &Held) -> Vec<String> {
    held.plan
        .changes
        .iter()
        .map(|c| match c {
            Change::Create { input, .. } => format!("create {}/{}", input.kind, input.name),
            Change::Update { input, .. } => format!("update {}/{}", input.kind, input.name),
            Change::Delete { key, .. } => format!("delete {}/{}", key.0, key.1),
            Change::Transfer { key, to, .. } => {
                format!("move {}/{} to {}", key.0, key.1, to.describe())
            }
            Change::ReplaceSource { owner, documents } => format!(
                "replace {} with {} document(s)",
                owner.describe(),
                documents.len()
            ),
        })
        .collect()
}

async fn change_page_for(
    state: &AppState,
    auth: &Auth,
    viewer: &Viewer,
    id: Uuid,
    error: Option<String>,
) -> Response {
    let held = match changes::visible(state, viewer, id).await {
        Ok(h) => h,
        Err(r) => return refusal_page(&r),
    };
    let cant_decide = viewer
        .may_decide(&held)
        .err()
        .map(|r| r.message())
        .unwrap_or_default();
    html(
        ChangePage {
            chrome: chrome(state, auth),
            ci: held
                .author_ci
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            writes: write_lines(&held),
            is_author: viewer.is_author(&held),
            change: ChangeRow::of(&held),
            cant_decide,
            error,
        }
        .render(),
    )
}

pub async fn change_detail(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> Response {
    let viewer = match viewer(&state, &auth).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return refusal_page(&Refusal::NotFound);
    };
    change_page_for(&state, &auth, &viewer, id, None).await
}

#[derive(Deserialize)]
pub struct DecideForm {
    csrf: String,
    /// `approve`, `reject`, or `cancel`.
    decision: String,
    #[serde(default)]
    note: String,
}

pub async fn change_decide(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<DecideForm>,
) -> Response {
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = auth.check_post(console, &headers, &form.csrf) {
        return r;
    }
    let viewer = match viewer(&state, &auth).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return refusal_page(&Refusal::NotFound);
    };
    let decided = match form.decision.as_str() {
        "approve" => Box::pin(changes::approve(&state, &viewer, id, &form.note)).await,
        "reject" => changes::reject(&state, &viewer, id, &form.note).await,
        "cancel" => changes::cancel(&state, &viewer, id).await,
        _ => Err(Refusal::Invalid("Unknown decision.".into())),
    };
    match decided {
        Ok(_) => Redirect::to(&format!("/console/changes/{id}")).into_response(),
        // A refusal the person can act on stays on the change's page.
        Err(r @ (Refusal::Invalid(_) | Refusal::NotDecidable { .. } | Refusal::Forbidden(_))) => {
            change_page_for(&state, &auth, &viewer, id, Some(r.message())).await
        }
        Err(r) => refusal_page(&r),
    }
}

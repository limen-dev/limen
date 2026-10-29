//! The management API (ADR-0042): `limen.manage.v1.ManagementService`.
//!
//! Callers are people with `limen:admin`, or bots with a `policy_writer`
//! grant. It serves reads of every kind and writes of resources; a writer
//! only completes the profiles its grant names. Every write goes through
//! `policy_store`, whose guard checks the grant and quota again, inside the
//! transaction, against the latest policy. A write that widens standing
//! access beyond what a grant approves is held for a person (`changes`).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use limen_audit::{Context, EventKind};
use limen_core::identity::ADMIN_ROLE;
use limen_policy::Policy;
use limen_policy::delegation::{self, PolicyWriterDoc, WriterResource, WriterSpec};
use limen_policy::tooling::{ChangeKind, Subject, Via};
use limen_proto::manage::v1 as pb;
use limen_proto::manage::v1::management_service_server::ManagementService;
use prost::Message as _;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tonic::{Code, Request, Response, Status};
use tonic_types::{ErrorDetails, StatusExt};

use crate::caller;
use crate::config::PolicyTests;
use crate::policy_changes;
use crate::policy_store::{self, Change, Channel, Head, Input, Key, Owner, StoreError};
use crate::state::{AppState, internal, unix};

mod changes;

const DOMAIN: &str = "manage.limen.dev";
const MAX_SPEC_BYTES: usize = 256 * 1024;
const MAX_DESCRIPTION: usize = 4096;
const MAX_REASON: usize = 1000;
const MAX_REQUEST_ID: usize = 128;
const MAX_BATCH: usize = 100;
const MAX_FILES_BYTES: usize = 1024 * 1024;
const MAX_IMPACT: usize = 500;
const DEFAULT_PAGE: usize = 100;
const MAX_PAGE: usize = 500;

#[derive(Debug, Clone)]
pub struct ManageService(pub AppState);

/// Who is calling, decided against a policy.
#[derive(Debug, Clone)]
enum Who {
    Admin {
        username: String,
    },
    Writer {
        username: String,
        grant: Box<PolicyWriterDoc>,
        /// The CI run behind the login (ADR-0019).
        ci: BTreeMap<String, String>,
    },
    Other {
        username: String,
    },
}

impl Who {
    fn username(&self) -> &str {
        match self {
            Who::Admin { username } | Who::Writer { username, .. } | Who::Other { username } => {
                username
            }
        }
    }

    fn grant(&self) -> Option<&WriterSpec> {
        match self {
            Who::Writer { grant, .. } => Some(&grant.spec),
            _ => None,
        }
    }
}

fn who<T>(state: &AppState, request: &Request<T>, policy: &Policy) -> Result<Who, Status> {
    let resolved = caller::resolve(request, &state.cas)?;
    let id = resolved.user()?;
    let username = id.username.clone();
    if id.bot {
        let bot = id.username.strip_prefix("bot:").unwrap_or(&id.username);
        return Ok(match policy.writer_for_bot(bot) {
            Some(grant) => Who::Writer {
                username,
                grant: Box::new(grant.clone()),
                ci: id.ci.clone(),
            },
            None => Who::Other { username },
        });
    }
    Ok(if id.has_role(ADMIN_ROLE) {
        Who::Admin { username }
    } else {
        Who::Other { username }
    })
}

fn writers_and_admins(who: &Who) -> Result<(), Status> {
    match who {
        Who::Other { .. } => Err(Status::permission_denied(format!(
            "the management API needs the {ADMIN_ROLE} role, or a bot with a policy_writer grant"
        ))),
        _ => Ok(()),
    }
}

fn admins(who: &Who) -> Result<(), Status> {
    match who {
        Who::Admin { .. } => Ok(()),
        _ => Err(Status::permission_denied(format!(
            "the {ADMIN_ROLE} role is required"
        ))),
    }
}

// ---- Errors -----------------------------------------------------------------

fn error(
    code: Code,
    reason: pb::ErrorReason,
    message: impl Into<String>,
    metadata: &[(&str, String)],
) -> Status {
    let reason = reason
        .as_str_name()
        .strip_prefix("ERROR_REASON_")
        .unwrap_or_default()
        .to_owned();
    let metadata: HashMap<String, String> = metadata
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    Status::with_error_details(
        code,
        message,
        ErrorDetails::with_error_info(reason, DOMAIN, metadata),
    )
}

fn store_error(e: &StoreError) -> Status {
    use pb::ErrorReason as R;
    let message = e.to_string();
    match e {
        StoreError::Invalid(_) => error(Code::InvalidArgument, R::InvalidDocument, message, &[]),
        StoreError::OwnedElsewhere { owner, .. } => error(
            Code::FailedPrecondition,
            R::OwnedElsewhere,
            message,
            &[
                ("channel", owner.channel.as_str().to_owned()),
                ("source", owner.source.clone()),
                ("namespace", owner.namespace.clone()),
            ],
        ),
        StoreError::EtagMismatch { current, .. } => error(
            Code::FailedPrecondition,
            R::EtagMismatch,
            message,
            &[("current_etag", current.clone())],
        ),
        StoreError::NotFound(_) => Status::not_found(message),
        StoreError::AlreadyExists(_) => Status::already_exists(message),
        StoreError::InUse { used_by, .. } => error(
            Code::FailedPrecondition,
            R::InUse,
            message,
            &[("used_by", used_by.join(","))],
        ),
        StoreError::TestsFailed(_) => error(Code::FailedPrecondition, R::TestsFailed, message, &[]),
        StoreError::Denied { rule, .. } => error(
            Code::PermissionDenied,
            R::OutsideGrant,
            message,
            &[("rule", (*rule).to_owned())],
        ),
        StoreError::QuotaExceeded { .. } => {
            error(Code::ResourceExhausted, R::QuotaExceeded, message, &[])
        }
        StoreError::VersionMismatch { current, .. } => error(
            Code::FailedPrecondition,
            R::PolicyVersionMismatch,
            message,
            &[("current_version", current.to_string())],
        ),
        StoreError::AuditUnavailable => error(
            Code::Unavailable,
            R::AuditUnavailable,
            "audit unavailable; nothing was changed, retry with the same request_id",
            &[],
        ),
        StoreError::Internal(m) => internal("writing policy", m),
    }
}

fn denied(rule: &'static str, message: impl Into<String>) -> StoreError {
    StoreError::Denied {
        rule,
        message: message.into(),
    }
}

// ---- Kinds and documents ----------------------------------------------------

fn kind_name(kind: i32) -> Option<&'static str> {
    use pb::DocumentKind as K;
    Some(match K::try_from(kind).ok()? {
        K::Role => "role",
        K::RoleMapping => "role_mapping",
        K::Resource => "resource",
        K::Bot => "bot",
        K::Discovery => "discovery",
        K::PolicyTest => "policy_test",
        K::ResourceProfile => "resource_profile",
        K::PolicyWriter => "policy_writer",
        K::Unspecified => return None,
    })
}

fn kind_value(name: &str) -> i32 {
    use pb::DocumentKind as K;
    match name {
        "role" => K::Role,
        "role_mapping" => K::RoleMapping,
        "resource" => K::Resource,
        "bot" => K::Bot,
        "discovery" => K::Discovery,
        "policy_test" => K::PolicyTest,
        "resource_profile" => K::ResourceProfile,
        "policy_writer" => K::PolicyWriter,
        _ => K::Unspecified,
    }
    .into()
}

fn required_kind(kind: i32) -> Result<&'static str, Status> {
    kind_name(kind).ok_or_else(|| Status::invalid_argument("kind is required"))
}

fn channel_value(channel: Channel) -> i32 {
    match channel {
        Channel::Git => pb::Channel::Git,
        Channel::Console => pb::Channel::Console,
        Channel::Api => pb::Channel::Api,
    }
    .into()
}

fn ownership(owner: &Owner) -> pb::Ownership {
    pb::Ownership {
        channel: channel_value(owner.channel),
        source: owner.source.clone(),
        namespace: owner.namespace.clone(),
    }
}

/// Effective documents by key, as JSON.
fn effective_index(policy: &Policy) -> BTreeMap<Key, Value> {
    policy
        .documents()
        .into_iter()
        .map(|d| {
            (
                (d.kind().to_owned(), d.name().to_owned()),
                serde_json::to_value(&d).unwrap_or(Value::Null),
            )
        })
        .collect()
}

fn labels_of(value: Option<&Value>) -> HashMap<String, String> {
    value
        .and_then(|v| v.get("metadata"))
        .and_then(|m| m.get("labels"))
        .and_then(Value::as_object)
        .map(|labels| {
            labels
                .iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

fn document(head: &Head, effective: &BTreeMap<Key, Value>) -> pb::Document {
    let key = (head.kind.clone(), head.name.clone());
    let eff = effective.get(&key);
    let spec = |v: Option<&Value>| {
        v.and_then(|v| v.get("spec"))
            .map_or_else(|| "{}".to_owned(), Value::to_string)
    };
    pb::Document {
        kind: kind_value(&head.kind),
        name: head.name.clone(),
        description: head
            .input
            .get("metadata")
            .and_then(|m| m.get("description"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        labels: labels_of(Some(&head.input)),
        spec_json: spec(Some(&head.input)),
        profile: head.profile.clone().unwrap_or_default(),
        effective_spec_json: spec(eff),
        ownership: Some(ownership(&head.owner)),
        etag: head.etag.clone(),
        policy_version: head.policy_version,
        create_time_unix: unix(head.created_at),
        update_time_unix: unix(head.updated_at),
        updated_by: head.updated_by.clone(),
        effective_labels: labels_of(eff),
    }
}

/// Whether `who` may see `head`. Admins see everything; a writer sees its
/// namespace and the profiles it may complete.
fn readable(who: &Who, head: &Head) -> bool {
    match who {
        Who::Admin { .. } => true,
        Who::Writer { grant, .. } => {
            head.owner.namespace == grant.spec.namespace
                || (head.kind == "resource_profile" && grant.spec.profiles.contains(&head.name))
        }
        Who::Other { .. } => false,
    }
}

// ---- Writer checks ----------------------------------------------------------

/// What one write touches, for the grant checks.
#[derive(Debug, Clone)]
struct Target {
    kind: &'static str,
    name: String,
    namespace: String,
    /// The profile a create or update completes.
    profile: Completes,
}

/// What a write says about profiles.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Completes {
    /// A delete or a transfer: no profile to check.
    Nothing,
    /// A create or update without a profile (admins only).
    NoProfile,
    Profile(String),
}

impl Completes {
    fn of(input: &Input) -> Self {
        input
            .profile
            .clone()
            .map_or(Completes::NoProfile, Completes::Profile)
    }
}

/// The grant's rules for one target, checked before anything is read, so a
/// writer learns nothing about documents outside its grant.
fn check_grant(grant: &WriterSpec, target: &Target) -> Result<(), StoreError> {
    if target.namespace != grant.namespace {
        return Err(denied(
            "namespace",
            format!(
                "this writer owns namespace {:?}, not {:?}",
                grant.namespace, target.namespace
            ),
        ));
    }
    if !grant.name_allowed(&target.name) {
        return Err(denied(
            "name_pattern",
            format!("{:?} doesn't match {:?}", target.name, grant.names),
        ));
    }
    if !grant.kinds.iter().any(|k| k.as_str() == target.kind) {
        return Err(denied(
            "kind",
            format!("this writer can't write {}", target.kind),
        ));
    }
    if target.kind != "resource" {
        return match target.profile {
            Completes::Profile(_) => Err(denied("profile", "only resources complete profiles")),
            Completes::Nothing | Completes::NoProfile => Ok(()),
        };
    }
    match &target.profile {
        Completes::NoProfile => Err(denied(
            "profile",
            "a writer completes a profile: set profile to one its grant names",
        )),
        Completes::Profile(p) if !grant.profiles.contains(p) => Err(denied(
            "profile",
            format!(
                "profile {p:?} isn't in this writer's grant {:?}",
                grant.profiles
            ),
        )),
        _ => Ok(()),
    }
}

/// A writer's resource against its profile: the settable fields and the
/// labels. Refusals are about the grant, so they say which rule.
fn check_fields(policy: &Policy, input: &Input) -> Result<(), StoreError> {
    let Some(profile_name) = &input.profile else {
        return Ok(());
    };
    let Some(profile) = policy.profile(profile_name) else {
        return Err(denied(
            "profile",
            format!("unknown profile {profile_name:?}"),
        ));
    };
    let resource = writer_resource(input);
    delegation::materialize(profile, &resource)
        .map(|_| ())
        .map_err(|e| {
            let message = e.to_string();
            let rule = if message.contains(": label ") {
                "label"
            } else {
                "field"
            };
            StoreError::Denied { rule, message }
        })
}

/// Built-in roles (`limen:admin`, `limen:auditor`, and any later one) are
/// never a writer's to name or assign.
fn builtin_role(role: &str) -> bool {
    role.starts_with("limen:")
}

/// The escalation rules for what a writer writes (ADR-0042 §4): a role is
/// never built-in, requestable, or break-glass (access by request isn't
/// standing, so it wouldn't wait for a person, and a writer could name its
/// own approvers); a mapping never assigns a built-in role. The roles a
/// mapping assigns must also be the writer's own, checked in the guard.
fn check_content(kind: &str, value: &Value) -> Result<(), StoreError> {
    let spec = value.get("spec");
    match kind {
        "role" => {
            let name = value
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if builtin_role(name) {
                return Err(denied("builtin_role", format!("{name} is a built-in role")));
            }
            let spec = spec.and_then(Value::as_object);
            if spec.is_some_and(|s| s.get("request").is_some_and(|r| !r.is_null())) {
                return Err(denied(
                    "field",
                    "a writer's role can't be requestable: request is for people to set",
                ));
            }
            if spec.is_some_and(|s| s.get("break_glass").and_then(Value::as_bool) == Some(true)) {
                return Err(denied("field", "a writer's role can't be break-glass"));
            }
        }
        "role_mapping" => {
            for role in mapped_roles(value) {
                if builtin_role(role) {
                    return Err(denied(
                        "builtin_role",
                        format!("a writer can't assign the built-in role {role}"),
                    ));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// The roles a `role_mapping` assigns.
fn mapped_roles(value: &Value) -> impl Iterator<Item = &str> {
    value
        .get("spec")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|g| g.get("roles").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
}

fn writer_resource(input: &Input) -> WriterResource {
    let metadata = input.value.get("metadata");
    WriterResource {
        name: input.name.clone(),
        description: metadata
            .and_then(|m| m.get("description"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        labels: labels_of(Some(&input.value)).into_iter().collect(),
        spec: input
            .value
            .get("spec")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default(),
    }
}

/// The guard a writer's write runs inside the transaction: its grant still
/// exists and still allows every target, and it stays within its quota.
fn writer_guard(bot: String, targets: Vec<Target>, transfers: Vec<Key>) -> policy_store::Guard {
    Arc::new(move |latest, before, after| {
        let grant = latest
            .writer_for_bot(&bot)
            .ok_or_else(|| denied("grant", "this bot no longer has a policy_writer grant"))?;
        let spec = &grant.spec;
        for target in &targets {
            check_grant(spec, target)?;
            let Some(head) = after.get(&(target.kind.to_owned(), target.name.clone())) else {
                continue;
            };
            check_content(target.kind, &head.input)?;
            // A mapping assigns only roles this namespace owns, as they
            // stand after the write.
            for role in mapped_roles(&head.input) {
                let owned = after
                    .get(&("role".to_owned(), role.to_owned()))
                    .is_some_and(|r| r.owner.namespace == spec.namespace);
                if !owned {
                    return Err(denied(
                        "role",
                        format!(
                            "{role} isn't a role in namespace {:?}: a writer assigns only its own roles",
                            spec.namespace
                        ),
                    ));
                }
            }
        }
        // A transfer stays inside the namespace on both ends.
        for key in &transfers {
            let inside = |heads: &BTreeMap<Key, Head>| {
                heads
                    .get(key)
                    .is_none_or(|h| h.owner.namespace == spec.namespace)
            };
            if !inside(before) || !inside(after) {
                return Err(denied(
                    "namespace",
                    "a writer moves documents between its own sources only",
                ));
            }
        }
        let count = |heads: &BTreeMap<Key, Head>| {
            heads
                .values()
                .filter(|h| h.owner.namespace == spec.namespace)
                .count()
        };
        let (was, now) = (count(before), count(after));
        let max = usize::try_from(spec.max_documents).unwrap_or(usize::MAX);
        if now > was && now > max {
            return Err(StoreError::QuotaExceeded {
                max: spec.max_documents,
            });
        }
        Ok(())
    })
}

/// The grant targets of stored changes, to check a held change's grant
/// again when it is approved.
fn targets_of(changes: &[Change]) -> (Vec<Target>, Vec<Key>) {
    let kind = |k: &str| kind_name(kind_value(k)).unwrap_or("unknown");
    let (mut targets, mut transfers) = (Vec::new(), Vec::new());
    for change in changes {
        let target = match change {
            Change::Create { owner, input } | Change::Update { owner, input, .. } => Target {
                kind: kind(&input.kind),
                name: input.name.clone(),
                namespace: owner.namespace.clone(),
                profile: Completes::of(input),
            },
            Change::Delete { owner, key, .. } => Target {
                kind: kind(&key.0),
                name: key.1.clone(),
                namespace: owner.namespace.clone(),
                profile: Completes::Nothing,
            },
            Change::Transfer { key, to, .. } => {
                transfers.push(key.clone());
                Target {
                    kind: kind(&key.0),
                    name: key.1.clone(),
                    namespace: to.namespace.clone(),
                    profile: Completes::Nothing,
                }
            }
            // Files are for people; a bot never holds one.
            Change::ReplaceSource { owner, .. } => Target {
                kind: "unknown",
                name: String::new(),
                namespace: owner.namespace.clone(),
                profile: Completes::Nothing,
            },
        };
        targets.push(target);
    }
    (targets, transfers)
}

// ---- Building inputs --------------------------------------------------------

/// A document from a create or update: a writer's half of a resource (with a
/// profile), or a whole resource (admins).
fn input_of(doc: &pb::Document) -> Result<Input, Status> {
    let kind = required_kind(doc.kind)?;
    if doc.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    if doc.spec_json.len() > MAX_SPEC_BYTES {
        return Err(Status::invalid_argument(format!(
            "spec_json exceeds {MAX_SPEC_BYTES} bytes"
        )));
    }
    if doc.description.len() > MAX_DESCRIPTION {
        return Err(Status::invalid_argument(format!(
            "description exceeds {MAX_DESCRIPTION} characters"
        )));
    }
    let spec: Value = if doc.spec_json.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_str(&doc.spec_json)
            .map_err(|e| Status::invalid_argument(format!("spec_json: {e}")))?
    };
    // A mapping's spec is a list of groups; every other kind's is an object.
    let shape_ok = if kind == "role_mapping" {
        spec.is_array()
    } else {
        spec.is_object()
    };
    if !shape_ok {
        return Err(Status::invalid_argument(format!(
            "spec_json for {kind} must be a JSON {}",
            if kind == "role_mapping" {
                "array"
            } else {
                "object"
            }
        )));
    }
    if !doc.profile.is_empty() && kind != "resource" {
        return Err(Status::invalid_argument("profile is for resources only"));
    }
    let labels: BTreeMap<&String, &String> = doc.labels.iter().collect();
    let mut metadata = json!({ "name": doc.name, "labels": labels });
    if !doc.description.is_empty() {
        metadata["description"] = Value::String(doc.description.clone());
    }
    let profile = Some(doc.profile.clone()).filter(|p| !p.is_empty());
    let mut value = json!({ "kind": kind, "metadata": metadata, "spec": spec });
    if profile.is_none() {
        value["version"] = Value::String("v1".into());
    }
    Ok(Input {
        kind: kind.to_owned(),
        name: doc.name.clone(),
        value,
        profile,
    })
}

/// The owner a caller writes as. Writers: their namespace (implied when
/// empty) and a source. Admins: any namespace and source.
fn owner_of(who: &Who, given: Option<&pb::Ownership>) -> Result<Owner, Status> {
    let given = given.cloned().unwrap_or_default();
    if given.source.is_empty() {
        return Err(Status::invalid_argument(
            "ownership.source is required: it names this writer, such as terraform/payments-prod",
        ));
    }
    policy_store::validate_source(&given.source).map_err(Status::invalid_argument)?;
    let namespace = match (who.grant(), given.namespace.is_empty()) {
        (Some(grant), true) => grant.namespace.clone(),
        (None, true) => "default".to_owned(),
        (_, false) => given.namespace,
    };
    if namespace.is_empty() || namespace.len() > 128 {
        return Err(Status::invalid_argument(
            "namespace must be 1..=128 characters",
        ));
    }
    Ok(Owner {
        channel: Channel::Api,
        source: given.source,
        namespace,
    })
}

// ---- Writes -----------------------------------------------------------------

/// One write, with everything the shared path needs.
struct Plan {
    changes: Vec<Change>,
    targets: Vec<Target>,
    transfers: Vec<Key>,
    /// Inputs a writer completes from a profile, checked against it.
    inputs: Vec<Input>,
    options: pb::WriteOptions,
    expected_version: Option<i64>,
    /// The encoded request, for `request_id`.
    body: Vec<u8>,
    /// The writes as sent, for approvers when the write is held.
    writes: Vec<pb::Write>,
}

impl ManageService {
    /// The latest policy, read from the database: who may write is decided
    /// on that, never on this replica's copy, which lags another replica's
    /// apply by up to one refresh.
    async fn latest(&self) -> Result<Arc<crate::state::LoadedPolicy>, Status> {
        let mut conn = self
            .0
            .db
            .acquire()
            .await
            .map_err(|e| internal("reading the policy", e))?;
        self.0
            .policy
            .latest(&mut conn)
            .await
            .map_err(|e| internal("reading the policy", e))
    }

    async fn audit_denied(&self, who: &Who, err: &StoreError, validate_only: bool) {
        let StoreError::Denied { rule, message } = err else {
            return;
        };
        let data = json!({ "rule": rule, "message": message, "validate_only": validate_only });
        if let Err(e) = self
            .0
            .audit
            .emit(
                EventKind::PolicyWriteDenied,
                Context {
                    user: Some(who.username().to_owned()),
                    session_id: None,
                },
                data,
            )
            .await
        {
            // Refused either way; recording the refusal is best effort.
            tracing::warn!(error = %e, "couldn't audit a refused policy write");
        }
    }

    async fn run(&self, who: &Who, plan: Plan) -> Result<pb::WriteResult, Status> {
        writers_and_admins(who)?;
        let options = plan.options;
        if options.reason.len() > MAX_REASON {
            return Err(Status::invalid_argument(format!(
                "reason exceeds {MAX_REASON} characters"
            )));
        }
        if options.source_ref.len() > policy_store::MAX_SOURCE_LEN {
            return Err(Status::invalid_argument("source_ref is too long"));
        }
        // The grant first, before anything is read.
        if let Some(grant) = who.grant() {
            let policy = self.latest().await?;
            let early = plan
                .targets
                .iter()
                .try_for_each(|t| check_grant(grant, t))
                .and_then(|()| {
                    plan.inputs.iter().try_for_each(|i| {
                        check_content(&i.kind, &i.value)?;
                        check_fields(&policy.policy, i)
                    })
                });
            if let Err(e) = early {
                self.audit_denied(who, &e, options.validate_only).await;
                return Err(store_error(&e));
            }
        }
        if !self
            .0
            .limits
            .allow_policy_write(who.username(), options.validate_only)
        {
            let mut details = ErrorDetails::with_error_info(
                "RATE_LIMITED",
                DOMAIN,
                HashMap::<String, String>::new(),
            );
            details.set_retry_info(Some(Duration::from_secs(1)));
            return Err(Status::with_error_details(
                Code::ResourceExhausted,
                "too many policy writes; slow down",
                details,
            ));
        }
        let replay = self.replay(who, &options, &plan.body).await?;
        if let Some(result) = replay {
            return Ok(result);
        }
        let guard = match who {
            Who::Writer { username, .. } => Some(writer_guard(
                username.strip_prefix("bot:").unwrap_or(username).to_owned(),
                plan.targets.clone(),
                plan.transfers.clone(),
            )),
            _ => None,
        };
        let wait = policy_changes::hold_for(
            who.grant().map(|g| g.namespace.as_str()),
            self.0.config.widening_approval,
        );
        let changes = plan.changes.clone();
        let request = policy_store::Request {
            actor: who.username().to_owned(),
            changes: plan.changes,
            dry_run: options.validate_only,
            require_tests: false,
            keep_tests_passing: self.0.config.policy_tests == PolicyTests::Required,
            source_ref: Some(options.source_ref.clone()).filter(|s| !s.is_empty()),
            expected_version: plan.expected_version,
            guard,
            hold: wait,
            approval: None,
        };
        let outcome = match policy_store::write(&self.0, request).await {
            Ok(outcome) => outcome,
            Err(e) => {
                self.audit_denied(who, &e, options.validate_only).await;
                return Err(store_error(&e));
            }
        };
        if outcome.held && options.fail_if_approval_needed {
            return Err(error(
                Code::FailedPrecondition,
                pb::ErrorReason::ApprovalRequired,
                "this write widens standing access and needs a person's approval",
                &[],
            ));
        }
        let effective = effective_index(&outcome.policy);
        let mut impact = impact(&outcome);
        if outcome.held && options.validate_only {
            impact
                .warnings
                .push(policy_changes::WOULD_BE_HELD.to_owned());
        }
        let pending_change = if outcome.held && !options.validate_only {
            let held = self
                .hold(who, &options, &outcome, changes, plan.writes)
                .await?;
            Some(changes::to_pb(&held))
        } else {
            None
        };
        let result = pb::WriteResult {
            outcome: if pending_change.is_some() {
                pb::WriteOutcome::PendingApproval
            } else if options.validate_only {
                pb::WriteOutcome::Validated
            } else if outcome.changed {
                pb::WriteOutcome::Applied
            } else {
                pb::WriteOutcome::Unchanged
            }
            .into(),
            policy_version: outcome.version,
            documents: outcome
                .written
                .iter()
                .map(|h| document(h, &effective))
                .collect(),
            impact: Some(impact),
            pending_change,
        };
        self.remember(who, &options, &plan.body, &result).await;
        Ok(result)
    }

    /// Hold a write for approval (ADR-0042 §6).
    async fn hold(
        &self,
        who: &Who,
        options: &pb::WriteOptions,
        outcome: &policy_store::Outcome,
        changes: Vec<Change>,
        writes: Vec<pb::Write>,
    ) -> Result<policy_changes::Held, Status> {
        let ci = match who {
            Who::Writer { ci, .. } => ci.clone(),
            _ => BTreeMap::new(),
        };
        let new = policy_changes::New {
            author: who.username().to_owned(),
            author_ci: ci,
            plan: policy_changes::Plan {
                changes,
                require_tests: false,
                gains: policy_changes::widening_gains(outcome),
                basis: outcome.basis.clone(),
            },
            writes: pb::BatchWriteRequest {
                writes,
                options: None,
            }
            .encode_to_vec(),
            impact: impact(outcome).encode_to_vec(),
            base_policy_version: outcome.version,
            reason: options.reason.clone(),
            source_ref: options.source_ref.clone(),
        };
        policy_changes::hold(&self.0, new, self.0.config.policy_change_ttl)
            .await
            .map_err(|e| changes::held_error(&e))
    }

    /// A retry with a known `request_id` returns the first result.
    async fn replay(
        &self,
        who: &Who,
        options: &pb::WriteOptions,
        body: &[u8],
    ) -> Result<Option<pb::WriteResult>, Status> {
        if options.request_id.is_empty() || options.validate_only {
            return Ok(None);
        }
        if options.request_id.len() > MAX_REQUEST_ID {
            return Err(Status::invalid_argument("request_id is too long"));
        }
        let row: Option<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT body_hash, response FROM policy_requests
             WHERE principal = $1 AND request_id = $2 AND created_at > now() - interval '24 hours'",
        )
        .bind(who.username())
        .bind(&options.request_id)
        .fetch_optional(&self.0.db)
        .await
        .map_err(|e| internal("reading request ids", e))?;
        let Some((hash, response)) = row else {
            return Ok(None);
        };
        if hash != body_hash(body) {
            return Err(error(
                Code::InvalidArgument,
                pb::ErrorReason::RequestIdReused,
                "this request_id was used with a different request",
                &[],
            ));
        }
        pb::WriteResult::decode(response.as_slice())
            .map(Some)
            .map_err(|e| internal("decoding a stored result", e))
    }

    async fn remember(
        &self,
        who: &Who,
        options: &pb::WriteOptions,
        body: &[u8],
        result: &pb::WriteResult,
    ) {
        if options.request_id.is_empty() || options.validate_only {
            return;
        }
        let stored = sqlx::query(
            "INSERT INTO policy_requests (principal, request_id, body_hash, response)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(who.username())
        .bind(&options.request_id)
        .bind(body_hash(body))
        .bind(result.encode_to_vec())
        .execute(&self.0.db)
        .await;
        if let Err(e) = stored {
            // The write is done; a retry would then find it already applied.
            tracing::warn!(error = %e, "couldn't record a request_id");
        }
    }
}

fn body_hash(body: &[u8]) -> String {
    Sha256::digest(body)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

pub(crate) fn impact(outcome: &policy_store::Outcome) -> pb::Impact {
    let changes = &outcome.access.changes;
    pb::Impact {
        access_changes: changes
            .iter()
            .take(MAX_IMPACT)
            .map(|c| pb::AccessChange {
                direction: match c.change {
                    ChangeKind::Gain => pb::access_change::Direction::Gain,
                    ChangeKind::Loss => pb::access_change::Direction::Loss,
                }
                .into(),
                subject: match &c.subject {
                    Subject::Group(g) => format!("group:{g}"),
                    Subject::Bot(b) => format!("bot:{b}"),
                    Subject::Role(r) => format!("role:{r}"),
                },
                resource: c.resource.clone(),
                principal: c.principals.join(", "),
                standing: c.via == Via::Standing,
                via_role: String::new(),
                text: c.text(),
            })
            .collect(),
        widens_standing_access: changes.iter().any(policy_changes::gives_standing),
        tests: outcome
            .tests
            .results
            .iter()
            .map(|r| pb::TestResult {
                test: r.test.clone(),
                case_number: u32::try_from(r.case).unwrap_or(u32::MAX),
                name: r.name.clone(),
                passed: r.passed,
                expected: r.expected.clone(),
                got: r.got.clone(),
                detail: r.detail.clone(),
            })
            .collect(),
        warnings: outcome.warnings.clone(),
        access_changes_truncated: changes.len() > MAX_IMPACT,
    }
}

/// A create, as a change and its grant target.
fn create_plan(
    who: &Who,
    req: &pb::CreateDocumentRequest,
) -> Result<(Change, Target, Input), Status> {
    let doc = req
        .document
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("document is required"))?;
    let input = input_of(doc)?;
    let owner = owner_of(who, req.ownership.as_ref())?;
    let target = Target {
        kind: required_kind(doc.kind)?,
        name: input.name.clone(),
        namespace: owner.namespace.clone(),
        profile: Completes::of(&input),
    };
    Ok((
        Change::Create {
            owner,
            input: input.clone(),
        },
        target,
        input,
    ))
}

fn update_plan(
    who: &Who,
    req: &pb::UpdateDocumentRequest,
) -> Result<(Change, Target, Input), Status> {
    let doc = req
        .document
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("document is required"))?;
    if req.etag.is_empty() {
        return Err(Status::invalid_argument("etag is required"));
    }
    let input = input_of(doc)?;
    let owner = owner_of(who, req.ownership.as_ref())?;
    let target = Target {
        kind: required_kind(doc.kind)?,
        name: input.name.clone(),
        namespace: owner.namespace.clone(),
        profile: Completes::of(&input),
    };
    Ok((
        Change::Update {
            owner,
            input: input.clone(),
            etag: req.etag.clone(),
        },
        target,
        input,
    ))
}

fn delete_plan(who: &Who, req: &pb::DeleteDocumentRequest) -> Result<(Change, Target), Status> {
    let kind = required_kind(req.kind)?;
    if req.etag.is_empty() && !req.allow_missing {
        return Err(Status::invalid_argument(
            "etag is required unless allow_missing",
        ));
    }
    let owner = owner_of(who, req.ownership.as_ref())?;
    let target = Target {
        kind,
        name: req.name.clone(),
        namespace: owner.namespace.clone(),
        profile: Completes::Nothing,
    };
    Ok((
        Change::Delete {
            owner,
            key: (kind.to_owned(), req.name.clone()),
            etag: Some(req.etag.clone()).filter(|e| !e.is_empty()),
            allow_missing: req.allow_missing,
        },
        target,
    ))
}

// ---- Paging -----------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
struct PageToken {
    /// The policy version the listing reads.
    v: i64,
    /// The last name on the previous page.
    a: String,
    /// The filter the listing started with.
    f: String,
}

fn filter_hash(req: &pb::ListDocumentsRequest) -> String {
    let labels: BTreeMap<&String, &String> = req.label_selector.iter().collect();
    let filter = json!([req.kind, req.namespace, req.source, labels]);
    body_hash(filter.to_string().as_bytes())[..16].to_owned()
}

fn encode_token(token: &PageToken) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(token).unwrap_or_default())
}

fn decode_token(token: &str) -> Result<PageToken, Status> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| Status::invalid_argument("page_token is not one this server issued"))
}

fn page_size(asked: i32, default: usize, max: usize) -> Result<usize, Status> {
    match usize::try_from(asked) {
        Ok(0) => Ok(default),
        Ok(n) if n <= max => Ok(n),
        _ => Err(Status::invalid_argument(format!(
            "page_size must be 1..={max}"
        ))),
    }
}

// ---- The service ------------------------------------------------------------

#[tonic::async_trait]
impl ManagementService for ManageService {
    async fn describe_caller(
        &self,
        request: Request<pb::DescribeCallerRequest>,
    ) -> Result<Response<pb::DescribeCallerResponse>, Status> {
        let (current, heads) = policy_store::snapshot(&self.0)
            .await
            .map_err(|e| store_error(&e))?;
        let who = who(&self.0, &request, &current.policy)?;
        let grant = match &who {
            Who::Writer { grant, .. } => {
                let spec = &grant.spec;
                let owned = heads
                    .values()
                    .filter(|h| h.owner.namespace == spec.namespace)
                    .count();
                Some(pb::WriterGrant {
                    name: grant.metadata.name.clone(),
                    namespace: spec.namespace.clone(),
                    name_patterns: spec.names.clone(),
                    kinds: spec.kinds.iter().map(|k| kind_value(k.as_str())).collect(),
                    profiles: spec.profiles.clone(),
                    max_documents: spec.max_documents,
                    document_count: u32::try_from(owned).unwrap_or(u32::MAX),
                    approver_groups: spec.approvers.groups.clone(),
                })
            }
            _ => None,
        };
        Ok(Response::new(pb::DescribeCallerResponse {
            principal: who.username().to_owned(),
            admin: matches!(who, Who::Admin { .. }),
            grant,
            policy_version: current.version,
        }))
    }

    async fn get_document(
        &self,
        request: Request<pb::GetDocumentRequest>,
    ) -> Result<Response<pb::GetDocumentResponse>, Status> {
        let (current, heads) = policy_store::snapshot(&self.0)
            .await
            .map_err(|e| store_error(&e))?;
        let who = who(&self.0, &request, &current.policy)?;
        writers_and_admins(&who)?;
        let req = request.into_inner();
        if req.policy_version != 0 && req.policy_version != current.version {
            return Err(Status::unimplemented(
                "reading a past policy version comes in a later stage",
            ));
        }
        let kind = required_kind(req.kind)?;
        // A document the caller may not see reads exactly like a missing one.
        let missing = || Status::not_found(format!("{kind}/{} doesn't exist", req.name));
        let head = heads
            .get(&(kind.to_owned(), req.name.clone()))
            .filter(|h| readable(&who, h))
            .ok_or_else(missing)?;
        Ok(Response::new(pb::GetDocumentResponse {
            document: Some(document(head, &effective_index(&current.policy))),
        }))
    }

    async fn list_documents(
        &self,
        request: Request<pb::ListDocumentsRequest>,
    ) -> Result<Response<pb::ListDocumentsResponse>, Status> {
        let (current, heads) = policy_store::snapshot(&self.0)
            .await
            .map_err(|e| store_error(&e))?;
        let who = who(&self.0, &request, &current.policy)?;
        writers_and_admins(&who)?;
        let req = request.into_inner();
        let kind = required_kind(req.kind)?;
        if let Some(grant) = who.grant()
            && !req.namespace.is_empty()
            && req.namespace != grant.namespace
            && kind != "resource_profile"
        {
            return Err(store_error(&denied(
                "namespace",
                format!("this writer reads namespace {:?}", grant.namespace),
            )));
        }
        let size = page_size(req.page_size, DEFAULT_PAGE, MAX_PAGE)?;
        let filter = filter_hash(&req);
        let after = if req.page_token.is_empty() {
            String::new()
        } else {
            let token = decode_token(&req.page_token)?;
            if token.f != filter {
                return Err(Status::invalid_argument(
                    "the filter changed; start the listing again without a page_token",
                ));
            }
            if token.v != current.version {
                return Err(Status::aborted(
                    "the policy changed during the listing; start it again",
                ));
            }
            token.a
        };
        let effective = effective_index(&current.policy);
        let mut matching = heads.values().filter(|h| {
            h.kind == kind
                && h.name > after
                && readable(&who, h)
                && (req.namespace.is_empty() || h.owner.namespace == req.namespace)
                && (req.source.is_empty() || h.owner.source == req.source)
                && {
                    let labels = labels_of(effective.get(&(h.kind.clone(), h.name.clone())));
                    req.label_selector
                        .iter()
                        .all(|(k, v)| labels.get(k) == Some(v))
                }
        });
        let page: Vec<&Head> = matching.by_ref().take(size).collect();
        let next_page_token = match (page.last(), matching.next()) {
            (Some(last), Some(_)) => encode_token(&PageToken {
                v: current.version,
                a: last.name.clone(),
                f: filter,
            }),
            _ => String::new(),
        };
        Ok(Response::new(pb::ListDocumentsResponse {
            documents: page.into_iter().map(|h| document(h, &effective)).collect(),
            next_page_token,
            policy_version: current.version,
        }))
    }

    async fn create_document(
        &self,
        request: Request<pb::CreateDocumentRequest>,
    ) -> Result<Response<pb::CreateDocumentResponse>, Status> {
        let who = who(&self.0, &request, &self.latest().await?.policy)?;
        let req = request.into_inner();
        let (change, target, input) = create_plan(&who, &req)?;
        let result = self
            .run(
                &who,
                Plan {
                    changes: vec![change],
                    targets: vec![target],
                    transfers: Vec::new(),
                    inputs: vec![input],
                    options: req.options.clone().unwrap_or_default(),
                    expected_version: None,
                    body: req.encode_to_vec(),
                    writes: vec![pb::Write {
                        operation: Some(pb::write::Operation::Create(req.clone())),
                    }],
                },
            )
            .await?;
        Ok(Response::new(pb::CreateDocumentResponse {
            result: Some(result),
        }))
    }

    async fn update_document(
        &self,
        request: Request<pb::UpdateDocumentRequest>,
    ) -> Result<Response<pb::UpdateDocumentResponse>, Status> {
        let who = who(&self.0, &request, &self.latest().await?.policy)?;
        let req = request.into_inner();
        let (change, target, input) = update_plan(&who, &req)?;
        let result = self
            .run(
                &who,
                Plan {
                    changes: vec![change],
                    targets: vec![target],
                    transfers: Vec::new(),
                    inputs: vec![input],
                    options: req.options.clone().unwrap_or_default(),
                    expected_version: None,
                    body: req.encode_to_vec(),
                    writes: vec![pb::Write {
                        operation: Some(pb::write::Operation::Update(req.clone())),
                    }],
                },
            )
            .await?;
        Ok(Response::new(pb::UpdateDocumentResponse {
            result: Some(result),
        }))
    }

    async fn delete_document(
        &self,
        request: Request<pb::DeleteDocumentRequest>,
    ) -> Result<Response<pb::DeleteDocumentResponse>, Status> {
        let who = who(&self.0, &request, &self.latest().await?.policy)?;
        let req = request.into_inner();
        let (change, target) = delete_plan(&who, &req)?;
        let result = self
            .run(
                &who,
                Plan {
                    changes: vec![change],
                    targets: vec![target],
                    transfers: Vec::new(),
                    inputs: Vec::new(),
                    options: req.options.clone().unwrap_or_default(),
                    expected_version: None,
                    body: req.encode_to_vec(),
                    writes: vec![pb::Write {
                        operation: Some(pb::write::Operation::Delete(req.clone())),
                    }],
                },
            )
            .await?;
        Ok(Response::new(pb::DeleteDocumentResponse {
            result: Some(result),
        }))
    }

    async fn batch_write(
        &self,
        request: Request<pb::BatchWriteRequest>,
    ) -> Result<Response<pb::BatchWriteResponse>, Status> {
        let who = who(&self.0, &request, &self.latest().await?.policy)?;
        let req = request.into_inner();
        if req.writes.is_empty() || req.writes.len() > MAX_BATCH {
            return Err(Status::invalid_argument(format!(
                "a batch has 1..={MAX_BATCH} writes"
            )));
        }
        let (mut changes, mut targets, mut inputs) = (Vec::new(), Vec::new(), Vec::new());
        let mut keys = std::collections::BTreeSet::new();
        for write in &req.writes {
            let (change, target, input) = match &write.operation {
                Some(pb::write::Operation::Create(c)) => {
                    let (ch, t, i) = create_plan(&who, c)?;
                    (ch, t, Some(i))
                }
                Some(pb::write::Operation::Update(u)) => {
                    let (ch, t, i) = update_plan(&who, u)?;
                    (ch, t, Some(i))
                }
                Some(pb::write::Operation::Delete(d)) => {
                    let (ch, t) = delete_plan(&who, d)?;
                    (ch, t, None)
                }
                None => return Err(Status::invalid_argument("a write needs an operation")),
            };
            if !keys.insert((target.kind, target.name.clone())) {
                return Err(Status::invalid_argument(format!(
                    "{}/{} appears twice in the batch",
                    target.kind, target.name
                )));
            }
            changes.push(change);
            targets.push(target);
            inputs.extend(input);
        }
        let result = self
            .run(
                &who,
                Plan {
                    changes,
                    targets,
                    transfers: Vec::new(),
                    inputs,
                    options: req.options.clone().unwrap_or_default(),
                    expected_version: None,
                    body: req.encode_to_vec(),
                    writes: req.writes.clone(),
                },
            )
            .await?;
        Ok(Response::new(pb::BatchWriteResponse {
            result: Some(result),
        }))
    }

    async fn replace_source(
        &self,
        request: Request<pb::ReplaceSourceRequest>,
    ) -> Result<Response<pb::ReplaceSourceResponse>, Status> {
        let who = who(&self.0, &request, &self.latest().await?.policy)?;
        // Files can hold any kind, so this is for people with limen:admin.
        admins(&who)?;
        let req = request.into_inner();
        let total: usize = req.files.iter().map(|f| f.content.len()).sum();
        if total > MAX_FILES_BYTES {
            return Err(Status::invalid_argument(format!(
                "files exceed {MAX_FILES_BYTES} bytes"
            )));
        }
        let documents = Policy::parse_yaml_documents(
            req.files
                .iter()
                .map(|f| (f.name.as_str(), f.content.as_str())),
        )
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let mut owner = owner_of(&who, req.ownership.as_ref())?;
        // Policy from files, through whichever client: the git channel.
        owner.channel = Channel::Git;
        let inputs = documents
            .iter()
            .map(Input::document)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| store_error(&e))?;
        let result = self
            .run(
                &who,
                Plan {
                    changes: vec![Change::ReplaceSource {
                        owner,
                        documents: inputs,
                    }],
                    targets: Vec::new(),
                    transfers: Vec::new(),
                    inputs: Vec::new(),
                    options: req.options.clone().unwrap_or_default(),
                    expected_version: Some(req.expected_policy_version).filter(|v| *v != 0),
                    body: req.encode_to_vec(),
                    writes: Vec::new(),
                },
            )
            .await?;
        Ok(Response::new(pb::ReplaceSourceResponse {
            result: Some(result),
        }))
    }

    async fn transfer_document(
        &self,
        request: Request<pb::TransferDocumentRequest>,
    ) -> Result<Response<pb::TransferDocumentResponse>, Status> {
        let who = who(&self.0, &request, &self.latest().await?.policy)?;
        let req = request.into_inner();
        let kind = required_kind(req.kind)?;
        if req.etag.is_empty() {
            return Err(Status::invalid_argument("etag is required"));
        }
        let to = owner_of(&who, req.ownership.as_ref())?;
        let targets = match who.grant() {
            Some(_) => vec![Target {
                kind,
                name: req.name.clone(),
                namespace: to.namespace.clone(),
                profile: Completes::Nothing,
            }],
            None => Vec::new(),
        };
        let key = (kind.to_owned(), req.name.clone());
        let result = self
            .run(
                &who,
                Plan {
                    changes: vec![Change::Transfer {
                        from: None,
                        key: key.clone(),
                        etag: req.etag.clone(),
                        to,
                    }],
                    targets,
                    transfers: vec![key],
                    inputs: Vec::new(),
                    options: req.options.clone().unwrap_or_default(),
                    expected_version: None,
                    body: req.encode_to_vec(),
                    writes: Vec::new(),
                },
            )
            .await?;
        Ok(Response::new(pb::TransferDocumentResponse {
            result: Some(result),
        }))
    }

    async fn get_change(
        &self,
        request: Request<pb::GetChangeRequest>,
    ) -> Result<Response<pb::GetChangeResponse>, Status> {
        self.get_change_rpc(request).await.map(Response::new)
    }

    async fn list_changes(
        &self,
        request: Request<pb::ListChangesRequest>,
    ) -> Result<Response<pb::ListChangesResponse>, Status> {
        self.list_changes_rpc(request).await.map(Response::new)
    }

    async fn approve_change(
        &self,
        request: Request<pb::ApproveChangeRequest>,
    ) -> Result<Response<pb::ApproveChangeResponse>, Status> {
        Box::pin(self.approve_change_rpc(request))
            .await
            .map(Response::new)
    }

    async fn reject_change(
        &self,
        request: Request<pb::RejectChangeRequest>,
    ) -> Result<Response<pb::RejectChangeResponse>, Status> {
        self.reject_change_rpc(request).await.map(Response::new)
    }

    async fn cancel_change(
        &self,
        request: Request<pb::CancelChangeRequest>,
    ) -> Result<Response<pb::CancelChangeResponse>, Status> {
        self.cancel_change_rpc(request).await.map(Response::new)
    }

    async fn list_policy_versions(
        &self,
        request: Request<pb::ListPolicyVersionsRequest>,
    ) -> Result<Response<pb::ListPolicyVersionsResponse>, Status> {
        let who = who(&self.0, &request, &self.latest().await?.policy)?;
        admins(&who)?;
        let req = request.into_inner();
        let size = page_size(req.page_size, 50, 200)?;
        let before: i64 = if req.page_token.is_empty() {
            i64::MAX
        } else {
            req.page_token
                .parse()
                .map_err(|_| Status::invalid_argument("page_token is not one this server issued"))?
        };
        let rows: Vec<(i64, String, String, Option<String>, time::OffsetDateTime)> =
            sqlx::query_as(
                "SELECT version, digest, author, source_ref, created_at FROM policy_versions
             WHERE version < $1 ORDER BY version DESC LIMIT $2",
            )
            .bind(before)
            .bind(i64::try_from(size + 1).unwrap_or(i64::MAX))
            .fetch_all(&self.0.db)
            .await
            .map_err(|e| internal("listing policy versions", e))?;
        let more = rows.len() > size;
        let versions: Vec<pb::PolicyVersion> = rows
            .into_iter()
            .take(size)
            .map(
                |(version, digest, author, source_ref, created_at)| pb::PolicyVersion {
                    version,
                    digest,
                    author,
                    source_ref: source_ref.unwrap_or_default(),
                    create_time_unix: unix(created_at),
                    ..pb::PolicyVersion::default()
                },
            )
            .collect();
        let next_page_token = match (more, versions.last()) {
            (true, Some(last)) => last.version.to_string(),
            _ => String::new(),
        };
        Ok(Response::new(pb::ListPolicyVersionsResponse {
            versions,
            next_page_token,
        }))
    }

    async fn get_schema(
        &self,
        _request: Request<pb::GetSchemaRequest>,
    ) -> Result<Response<pb::GetSchemaResponse>, Status> {
        Err(Status::unimplemented(
            "GetSchema comes in a later stage; docs/policy.md lists the settable fields",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> WriterSpec {
        WriterSpec {
            bot: "payments-terraform".into(),
            namespace: "payments".into(),
            names: vec!["payments-*".into()],
            kinds: vec![delegation::WriterKind::Resource],
            profiles: vec!["payments-postgres".into()],
            max_documents: 50,
            approvers: delegation::Approvers::default(),
        }
    }

    fn target(namespace: &str, name: &str, profile: Option<&str>) -> Target {
        Target {
            kind: "resource",
            name: name.into(),
            namespace: namespace.into(),
            profile: profile.map_or(Completes::NoProfile, |p| Completes::Profile(p.to_owned())),
        }
    }

    #[test]
    fn the_grant_is_checked_rule_by_rule() {
        let g = grant();
        check_grant(
            &g,
            &target("payments", "payments-db", Some("payments-postgres")),
        )
        .expect("allowed");
        let rule = |t: Target| match check_grant(&g, &t) {
            Err(StoreError::Denied { rule, .. }) => rule,
            other => panic!("expected a refusal, got {other:?}"),
        };
        assert_eq!(
            rule(target("other", "payments-db", Some("payments-postgres"))),
            "namespace"
        );
        assert_eq!(
            rule(target("payments", "orders-db", Some("payments-postgres"))),
            "name_pattern"
        );
        assert_eq!(rule(target("payments", "payments-db", None)), "profile");
        assert_eq!(
            rule(target("payments", "payments-db", Some("admin-profile"))),
            "profile"
        );
        let mut wrong_kind = target("payments", "payments-db", Some("payments-postgres"));
        wrong_kind.kind = "role";
        assert_eq!(rule(wrong_kind), "kind");
    }

    #[test]
    fn writers_write_the_kinds_their_grant_names() {
        let mut g = grant();
        g.kinds.push(delegation::WriterKind::Role);
        let role = |profile: Completes| Target {
            kind: "role",
            name: "payments-readers".into(),
            namespace: "payments".into(),
            profile,
        };
        check_grant(&g, &role(Completes::NoProfile)).expect("a role");
        check_grant(&g, &role(Completes::Nothing)).expect("a role's delete");
        let refused = check_grant(&g, &role(Completes::Profile("payments-postgres".into())));
        assert!(matches!(
            refused,
            Err(StoreError::Denied {
                rule: "profile",
                ..
            })
        ));
        // People-only kinds have no WriterKind, so no grant can name them.
        for kind in ["bot", "discovery", "resource_profile", "policy_writer"] {
            let t = Target {
                kind,
                ..role(Completes::NoProfile)
            };
            assert!(
                matches!(
                    check_grant(&g, &t),
                    Err(StoreError::Denied { rule: "kind", .. })
                ),
                "{kind}"
            );
        }
    }

    #[test]
    fn writers_never_name_built_in_or_requestable_roles() {
        let rule = |kind: &str, value: Value| match check_content(kind, &value) {
            Err(StoreError::Denied { rule, .. }) => rule,
            other => panic!("expected a refusal, got {other:?}"),
        };
        let writer_role =
            |spec: Value| json!({ "metadata": { "name": "payments-x" }, "spec": spec });
        check_content("role", &writer_role(json!({ "allow": [] }))).expect("a plain role");
        assert_eq!(
            rule(
                "role",
                json!({ "metadata": { "name": "limen:admin" }, "spec": {} })
            ),
            "builtin_role"
        );
        assert_eq!(
            rule(
                "role",
                writer_role(json!({ "request": { "who": { "groups": ["x"] } } }))
            ),
            "field"
        );
        assert_eq!(
            rule("role", writer_role(json!({ "break_glass": true }))),
            "field"
        );
        check_content(
            "role",
            &writer_role(json!({ "request": null, "break_glass": false })),
        )
        .expect("unset is fine");
        let mapping =
            |roles: Value| json!({ "spec": [{ "idp_group": "payments", "roles": roles }] });
        check_content("role_mapping", &mapping(json!(["payments-readers"]))).expect("its own role");
        assert_eq!(
            rule("role_mapping", mapping(json!(["limen:auditor"]))),
            "builtin_role"
        );
        assert_eq!(
            mapped_roles(&mapping(json!(["a", "b"]))).collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    #[test]
    fn error_reasons_carry_their_names() {
        let status = store_error(&denied("namespace", "no"));
        assert_eq!(status.code(), Code::PermissionDenied);
        let info = status.get_details_error_info().expect("error info");
        assert_eq!(info.reason, "OUTSIDE_GRANT");
        assert_eq!(info.domain, DOMAIN);
        assert_eq!(
            info.metadata.get("rule").map(String::as_str),
            Some("namespace")
        );
    }

    #[test]
    fn page_tokens_round_trip_and_reject_junk() {
        let token = PageToken {
            v: 7,
            a: "payments-db".into(),
            f: "abc".into(),
        };
        let back = decode_token(&encode_token(&token)).expect("decode");
        assert_eq!(
            (back.v, back.a, back.f),
            (7, "payments-db".to_owned(), "abc".to_owned())
        );
        assert!(decode_token("not-a-token!").is_err());
    }

    #[test]
    fn inputs_keep_what_the_caller_sent() {
        let doc = pb::Document {
            kind: pb::DocumentKind::Resource.into(),
            name: "payments-db".into(),
            spec_json: r#"{"postgres":{"endpoint":"db.payments.internal:5432"}}"#.into(),
            profile: "payments-postgres".into(),
            labels: HashMap::from([("env".to_owned(), "staging".to_owned())]),
            ..pb::Document::default()
        };
        let input = input_of(&doc).expect("input");
        assert_eq!(input.profile.as_deref(), Some("payments-postgres"));
        assert_eq!(
            input.value["spec"]["postgres"]["endpoint"],
            "db.payments.internal:5432"
        );
        assert_eq!(input.value["metadata"]["labels"]["env"], "staging");
        // Only resources complete profiles; a mapping's spec is a list.
        let role = pb::Document {
            kind: pb::DocumentKind::Role.into(),
            ..doc.clone()
        };
        assert_eq!(
            input_of(&role).expect_err("a role has no profile").code(),
            Code::InvalidArgument
        );
        let mapping = pb::Document {
            kind: pb::DocumentKind::RoleMapping.into(),
            profile: String::new(),
            spec_json: r#"[{"idp_group":"payments","roles":["payments-readers"]}]"#.into(),
            ..doc
        };
        let input = input_of(&mapping).expect("a mapping");
        assert_eq!(input.kind, "role_mapping");
        assert!(input.value["spec"].is_array());
        assert_eq!(input.value["version"], "v1");
    }
}

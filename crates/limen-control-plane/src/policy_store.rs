//! The one write path for policy documents (ADR-0042 §1, §3, §8).
//!
//! Every write holds the policy lock, reads the latest version and the
//! document heads inside its transaction, applies its changes under the
//! ownership and etag rules, rebuilds the documents enforcement uses (resources
//! from profiles included), validates the whole set, and stores the new
//! version, the heads, and the audit event together. `Admin.ApplyPolicy`, the
//! management API, and the console all come through here.

use std::collections::BTreeMap;
use std::sync::Arc;

use limen_audit::{Context, EventKind};
use limen_policy::delegation::{self, WriterResource};
use limen_policy::tooling::AccessDiff;
use limen_policy::{Document, Policy, PolicyDiff, testing};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use time::OffsetDateTime;

use crate::db;
use crate::state::{AppState, LoadedPolicy};

/// How a write arrived (ADR-0042 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Git,
    Console,
    Api,
}

impl Channel {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Git => "git",
            Channel::Console => "console",
            Channel::Api => "api",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "git" => Some(Channel::Git),
            "console" => Some(Channel::Console),
            "api" => Some(Channel::Api),
            _ => None,
        }
    }
}

/// Who manages a document. One per document.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Owner {
    pub channel: Channel,
    pub source: String,
    pub namespace: String,
}

impl Owner {
    /// Policy applied from files without `--source`: everything before
    /// Phase 14 belongs here.
    #[must_use]
    pub fn default_git() -> Self {
        Self {
            channel: Channel::Git,
            source: "default".into(),
            namespace: "default".into(),
        }
    }

    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{} source {:?} in namespace {:?}",
            self.channel.as_str(),
            self.source,
            self.namespace
        )
    }

    fn json(&self) -> Value {
        json!({
            "channel": self.channel.as_str(),
            "source": self.source,
            "namespace": self.namespace,
        })
    }
}

/// Longest source name.
pub const MAX_SOURCE_LEN: usize = 200;

/// A source names a writer, such as `github.com/acme/limen-policy` or
/// `terraform/payments-prod`.
pub fn validate_source(source: &str) -> Result<(), String> {
    let ok = !source.is_empty()
        && source.len() <= MAX_SOURCE_LEN
        && source
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/:@-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "source must be 1..={MAX_SOURCE_LEN} characters of letters, digits, and . _ / : @ -"
        ))
    }
}

/// `(kind, name)`.
pub type Key = (String, String);

fn key_text(key: &Key) -> String {
    format!("{}/{}", key.0, key.1)
}

/// The current revision of one document.
#[derive(Debug, Clone, PartialEq)]
pub struct Head {
    pub kind: String,
    pub name: String,
    pub owner: Owner,
    /// The document as its owner wrote it. For a resource from a profile,
    /// only the writer's half.
    pub input: Value,
    pub profile: Option<String>,
    pub etag: String,
    pub policy_version: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub updated_by: String,
}

impl Head {
    fn key(&self) -> Key {
        (self.kind.clone(), self.name.clone())
    }

    /// Whether `other` is the same revision: same owner, profile, and input.
    fn same_revision(&self, other: &Head) -> bool {
        self.owner == other.owner && self.profile == other.profile && self.input == other.input
    }
}

/// A document to write: a whole document, or, with `profile`, a writer's half
/// of a resource (`{"kind": "resource", "metadata": {..}, "spec": {..}}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Input {
    pub kind: String,
    pub name: String,
    pub value: Value,
    pub profile: Option<String>,
}

impl Input {
    /// A whole document, as `limen admin apply` sends it.
    pub fn document(doc: &Document) -> Result<Self, StoreError> {
        Ok(Self {
            kind: doc.kind().to_owned(),
            name: doc.name().to_owned(),
            value: serde_json::to_value(doc).map_err(|e| StoreError::Internal(e.to_string()))?,
            profile: None,
        })
    }

    fn key(&self) -> Key {
        (self.kind.clone(), self.name.clone())
    }
}

/// One change. Ownership is checked against `owner`: a write to a document
/// that another owner manages is refused.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Change {
    /// Make `owner`'s documents exactly `documents`: create, update, and
    /// delete within that owner only.
    ReplaceSource { owner: Owner, documents: Vec<Input> },
    /// A document that must not exist yet.
    Create { owner: Owner, input: Input },
    /// Replace a document `owner` manages; `etag` from the last read.
    Update {
        owner: Owner,
        input: Input,
        etag: String,
    },
    /// Delete a document `owner` manages.
    Delete {
        owner: Owner,
        key: Key,
        etag: Option<String>,
        allow_missing: bool,
    },
    /// Move a document to `to`. With `from`, only if `from` manages it.
    Transfer {
        from: Option<Owner>,
        key: Key,
        etag: String,
        to: Owner,
    },
}

/// A check that runs inside the write, after the changes are applied, with
/// the latest policy (not this replica's copy) and the heads before and
/// after. Writer grants and quotas are checked here (ADR-0042 §4).
pub type Guard = Arc<
    dyn Fn(&Policy, &BTreeMap<Key, Head>, &BTreeMap<Key, Head>) -> Result<(), StoreError>
        + Send
        + Sync,
>;

/// Decides, from what a write would do and the heads before and after it,
/// that it waits for approval instead (ADR-0042 §6). Runs inside the write,
/// after the guard and the tests.
pub type Hold =
    Arc<dyn Fn(&Outcome, &BTreeMap<Key, Head>, &BTreeMap<Key, Head>) -> bool + Send + Sync>;

/// A write: its changes, applied together as one version.
#[derive(Clone)]
pub struct Request {
    /// The person or `bot:<name>` writing.
    pub actor: String,
    pub changes: Vec<Change>,
    pub dry_run: bool,
    /// Refuse unless the policy's tests exist and pass.
    pub require_tests: bool,
    /// Refuse if the policy has tests and any fails after the write
    /// (`--policy-tests=required`).
    pub keep_tests_passing: bool,
    pub source_ref: Option<String>,
    /// Refuse unless the active version is this one.
    pub expected_version: Option<i64>,
    /// Called as `guard(latest policy, heads before, heads after)`.
    pub guard: Option<Guard>,
    /// When it says so, nothing is written and the outcome is `held`.
    pub hold: Option<Hold>,
    /// For a held change being applied: who approved it, recorded in the
    /// `policy.change` event.
    pub approval: Option<Value>,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("actor", &self.actor)
            .field("changes", &self.changes)
            .field("dry_run", &self.dry_run)
            .field("require_tests", &self.require_tests)
            .field("source_ref", &self.source_ref)
            .field("expected_version", &self.expected_version)
            .field("keep_tests_passing", &self.keep_tests_passing)
            .field("guard", &self.guard.is_some())
            .field("hold", &self.hold.is_some())
            .field("approval", &self.approval)
            .finish()
    }
}

/// What a write did, or would do.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// A new version was stored.
    pub applied: bool,
    /// The new version when applied; otherwise the version checked against.
    pub version: i64,
    pub previous_version: i64,
    pub digest: String,
    pub diff: PolicyDiff,
    pub access: AccessDiff,
    pub warnings: Vec<String>,
    pub tests: testing::Report,
    /// Heads of the documents the changes created or updated, as stored (or
    /// as they would be).
    pub written: Vec<Head>,
    /// Documents the changes deleted.
    pub deleted: Vec<Key>,
    /// Something was stored: a new version, or heads only (a transfer).
    pub changed: bool,
    /// The policy after the write (or as it would be).
    pub policy: Arc<Policy>,
    /// The hold said this write waits for approval: nothing was written.
    pub held: bool,
    /// The etag (or absence) of every document the changes mention, and for
    /// a source every document it owned, before the write: a held change is
    /// applied only while these are unchanged (`unchanged_since`).
    pub basis: Vec<(Key, Option<String>)>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{0}")]
    Invalid(String),
    #[error("{} is managed by {}; change it there", key_text(.key), .owner.describe())]
    OwnedElsewhere { key: Key, owner: Owner },
    #[error("{} changed since it was read; read it again", key_text(.key))]
    EtagMismatch { key: Key, current: String },
    #[error("{} doesn't exist", key_text(.0))]
    NotFound(Key),
    #[error("{} already exists", key_text(.0))]
    AlreadyExists(Key),
    #[error("{} is still used by {}", key_text(.key), .used_by.join(", "))]
    InUse { key: Key, used_by: Vec<String> },
    #[error("{0}")]
    TestsFailed(String),
    #[error("{message}")]
    Denied { rule: &'static str, message: String },
    #[error("the writer owns {max} documents already, its limit")]
    QuotaExceeded { max: u32 },
    #[error("the active policy is version {current}, not {expected}")]
    VersionMismatch { expected: i64, current: i64 },
    #[error("audit unavailable")]
    AuditUnavailable,
    #[error("{0}")]
    Internal(String),
}

impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        StoreError::Internal(format!("database: {e}"))
    }
}

/// Apply `request`. See the module documentation.
pub async fn write(state: &AppState, request: Request) -> Result<Outcome, StoreError> {
    let mut tx = state.db.begin().await?;
    if !request.dry_run {
        db::lock_policy_writes(&mut tx).await?;
    }
    let current = state
        .policy
        .latest(&mut tx)
        .await
        .map_err(|e| StoreError::Internal(format!("loading the latest policy: {e}")))?;
    let stored = load_heads(&mut tx).await?;
    // A replica from before Phase 14 may have applied without heads during a
    // rolling upgrade: then the heads say what the latest version is.
    let before = reconcile(stored.clone(), &current);

    if let Some(expected) = request.expected_version
        && expected != current.version
    {
        return Err(StoreError::VersionMismatch {
            expected,
            current: current.version,
        });
    }
    let mut heads = before.clone();
    let mut touched: Vec<Key> = Vec::new();
    let mut deleted: Vec<Key> = Vec::new();
    for change in &request.changes {
        apply(
            &mut heads,
            change,
            &request.actor,
            &mut touched,
            &mut deleted,
        )?;
    }
    if let Some(guard) = &request.guard {
        guard(&current.policy, &before, &heads)?;
    }
    check_in_use(&before, &heads)?;

    let documents = effective(&heads)?;
    let next = Policy::from_documents(documents).map_err(|e| StoreError::Invalid(e.to_string()))?;
    let diff = current.policy.diff(&next);
    let access = current.policy.access_diff(&next);
    let tests = next.run_tests();
    let warnings = next.warnings();
    let digest = next.digest();
    if request.require_tests && !request.dry_run {
        require_passing(&tests)?;
    }
    if request.keep_tests_passing && !request.dry_run && !tests.ok() {
        require_passing(&tests)?;
    }
    let heads_changed = heads_differ(&stored, &heads);
    let mut outcome = Outcome {
        applied: false,
        version: current.version,
        previous_version: current.version,
        digest,
        diff,
        access,
        warnings,
        tests,
        written: touched
            .iter()
            .filter_map(|k| heads.get(k).cloned())
            .collect(),
        deleted,
        changed: false,
        policy: Arc::new(next.clone()),
        held: false,
        basis: basis(&request.changes, &before),
    };
    outcome.held = !outcome.diff.is_empty()
        && request
            .hold
            .as_ref()
            .is_some_and(|h| h(&outcome, &before, &heads));
    if request.dry_run || outcome.held || (outcome.diff.is_empty() && !heads_changed) {
        return Ok(outcome);
    }

    let version = if outcome.diff.is_empty() {
        // Only who manages what changed (or the heads caught up with a
        // version applied without them): no new policy version.
        current.version
    } else {
        let documents: Vec<serde_json::Value> = next
            .documents()
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Internal(e.to_string()))?;
        db::insert_policy(
            &mut tx,
            &outcome.digest,
            &documents,
            &request.actor,
            request.source_ref.as_deref(),
        )
        .await?
    };
    let now = OffsetDateTime::now_utc();
    for head in heads.values_mut() {
        let unchanged = stored
            .get(&head.key())
            .is_some_and(|s| s.same_revision(head));
        if !unchanged {
            head.policy_version = version;
            head.updated_at = now;
            head.etag = etag(head);
        }
    }
    save_heads(&mut tx, &stored, &heads).await?;
    outcome.written = touched
        .iter()
        .filter_map(|k| heads.get(k).cloned())
        .collect();
    // A resource that's gone ends what it allowed (ADR-0042 §7): its open
    // sessions and its grants, in this transaction.
    let gone: Vec<&str> = outcome
        .deleted
        .iter()
        .filter(|(kind, _)| kind == "resource")
        .map(|(_, name)| name.as_str())
        .collect();
    let (sessions_ended, grants_revoked) =
        end_what_resources_allowed(&mut tx, &gone, &request.actor).await?;

    audit_transfers(state, &request, &stored, &heads).await?;
    if version != current.version {
        // Audit before commit: if the event can't be written, nothing changes.
        audit_change(
            state,
            &request,
            &outcome,
            (version, current.version),
            (sessions_ended, grants_revoked),
        )
        .await?;
    }
    tx.commit().await?;
    outcome.changed = true;
    if version != current.version {
        state.policy.set(LoadedPolicy {
            version,
            digest: outcome.digest.clone(),
            policy: Arc::new(next),
            author: request.actor.clone(),
            created_at: Some(now),
        });
        tracing::info!(version, digest = %outcome.digest, author = %request.actor, "policy applied");
        outcome.applied = true;
        outcome.version = version;
    }
    Ok(outcome)
}

fn basis(changes: &[Change], before: &BTreeMap<Key, Head>) -> Vec<(Key, Option<String>)> {
    let mut keys = std::collections::BTreeSet::new();
    for change in changes {
        match change {
            Change::ReplaceSource { owner, documents } => {
                keys.extend(documents.iter().map(Input::key));
                keys.extend(before.values().filter(|h| &h.owner == owner).map(Head::key));
            }
            Change::Create { input, .. } | Change::Update { input, .. } => {
                keys.insert(input.key());
            }
            Change::Delete { key, .. } | Change::Transfer { key, .. } => {
                keys.insert(key.clone());
            }
        }
    }
    keys.into_iter()
        .map(|k| {
            let etag = before.get(&k).map(|h| h.etag.clone());
            (k, etag)
        })
        .collect()
}

/// A guard that refuses (`EtagMismatch`, or `AlreadyExists` for a document
/// made since) unless every document in `basis` is as it was.
#[must_use]
pub fn unchanged_since(basis: Vec<(Key, Option<String>)>) -> Guard {
    Arc::new(move |_, before, _| {
        for (key, etag) in &basis {
            match (before.get(key), etag) {
                (None, None) => {}
                (Some(_), None) => return Err(StoreError::AlreadyExists(key.clone())),
                (Some(head), Some(etag)) if &head.etag == etag => {}
                (Some(head), Some(_)) => {
                    return Err(StoreError::EtagMismatch {
                        key: key.clone(),
                        current: head.etag.clone(),
                    });
                }
                (None, Some(_)) => return Err(StoreError::NotFound(key.clone())),
            }
        }
        Ok(())
    })
}

/// Both guards, `first` first.
#[must_use]
pub fn both(first: Guard, second: Option<Guard>) -> Guard {
    match second {
        None => first,
        Some(second) => Arc::new(move |policy, before, after| {
            first(policy, before, after)?;
            second(policy, before, after)
        }),
    }
}

/// One `policy.ownership_transfer` event per document a transfer moved,
/// before commit like every other write.
async fn audit_transfers(
    state: &AppState,
    request: &Request,
    stored: &BTreeMap<Key, Head>,
    heads: &BTreeMap<Key, Head>,
) -> Result<(), StoreError> {
    for change in &request.changes {
        let Change::Transfer { key, .. } = change else {
            continue;
        };
        let (Some(was), Some(now)) = (stored.get(key), heads.get(key)) else {
            continue;
        };
        if was.owner == now.owner {
            continue;
        }
        state
            .audit
            .emit(
                EventKind::PolicyOwnershipTransfer,
                Context {
                    user: Some(request.actor.clone()),
                    session_id: None,
                },
                json!({
                    "document": key_text(key),
                    "from": was.owner.json(),
                    "to": now.owner.json(),
                }),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "audit unavailable; refusing ownership transfer");
                StoreError::AuditUnavailable
            })?;
    }
    Ok(())
}

/// The `policy.change` event for a new version.
async fn audit_change(
    state: &AppState,
    request: &Request,
    outcome: &Outcome,
    (version, previous): (i64, i64),
    (sessions_ended, grants_revoked): (u64, u64),
) -> Result<(), StoreError> {
    let owners: Vec<Value> = request
        .changes
        .iter()
        .map(|c| change_owner(c).json())
        .collect();
    let access_changes: Vec<String> = outcome
        .access
        .changes
        .iter()
        .take(200)
        .map(|c| {
            let sign = if c.change == limen_policy::tooling::ChangeKind::Gain {
                '+'
            } else {
                '-'
            };
            format!("{sign} {}", c.text())
        })
        .collect();
    let data = json!({
        "version": version,
        "previous_version": previous,
        "digest": outcome.digest,
        "source_ref": request.source_ref,
        "diff": outcome.diff,
        "access_changes": access_changes,
        "owners": owners,
        "sessions_ended": sessions_ended,
        "grants_revoked": grants_revoked,
        "approval": request.approval,
    });
    state
        .audit
        .emit(
            EventKind::PolicyChange,
            Context {
                user: Some(request.actor.clone()),
                session_id: None,
            },
            data,
        )
        .await
        .map(|_| ())
        .map_err(|e| {
            tracing::error!(error = %e, "audit unavailable; refusing policy change");
            StoreError::AuditUnavailable
        })
}

fn change_owner(change: &Change) -> &Owner {
    match change {
        Change::ReplaceSource { owner, .. }
        | Change::Create { owner, .. }
        | Change::Update { owner, .. }
        | Change::Delete { owner, .. }
        | Change::Transfer { to: owner, .. } => owner,
    }
}

/// Queue a kill for every open session on `resources` and revoke their
/// active grants. Returns how many of each.
async fn end_what_resources_allowed(
    tx: &mut Transaction<'_, Postgres>,
    resources: &[&str],
    by: &str,
) -> Result<(u64, u64), StoreError> {
    if resources.is_empty() {
        return Ok((0, 0));
    }
    let names: Vec<String> = resources.iter().map(|r| (*r).to_owned()).collect();
    let reason = "the resource was deleted";
    let sessions = sqlx::query(
        "INSERT INTO session_kills (session_id, reason, killed_by)
         SELECT session_id::text, $2, $3 FROM sessions
         WHERE resource = ANY($1) AND ended_at IS NULL
         ON CONFLICT DO NOTHING",
    )
    .bind(&names)
    .bind(reason)
    .bind(by)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    let revoked: Vec<uuid::Uuid> = sqlx::query_scalar(
        "UPDATE access_grants SET revoked_at = now(), revoked_by = $2, revoke_reason = $3
         WHERE resource = ANY($1) AND revoked_at IS NULL AND expires_at > now()
         RETURNING request_id",
    )
    .bind(&names)
    .bind(by)
    .bind(reason)
    .fetch_all(&mut **tx)
    .await?;
    if !revoked.is_empty() {
        sqlx::query("UPDATE access_requests SET status = 'revoked' WHERE id = ANY($1)")
            .bind(&revoked)
            .execute(&mut **tx)
            .await?;
    }
    Ok((sessions, u64::try_from(revoked.len()).unwrap_or(u64::MAX)))
}

fn apply(
    heads: &mut BTreeMap<Key, Head>,
    change: &Change,
    actor: &str,
    touched: &mut Vec<Key>,
    deleted: &mut Vec<Key>,
) -> Result<(), StoreError> {
    let new_head = |input: &Input, owner: &Owner, created_at: Option<OffsetDateTime>| Head {
        kind: input.kind.clone(),
        name: input.name.clone(),
        owner: owner.clone(),
        input: input.value.clone(),
        profile: input.profile.clone(),
        etag: String::new(),
        policy_version: 0,
        created_at: created_at.unwrap_or_else(OffsetDateTime::now_utc),
        updated_at: OffsetDateTime::now_utc(),
        updated_by: actor.to_owned(),
    };
    let owned_by = |head: &Head, owner: &Owner| -> Result<(), StoreError> {
        if head.owner == *owner {
            Ok(())
        } else {
            Err(StoreError::OwnedElsewhere {
                key: head.key(),
                owner: head.owner.clone(),
            })
        }
    };
    match change {
        Change::ReplaceSource { owner, documents } => {
            let mut wanted = BTreeMap::new();
            for input in documents {
                if wanted.insert(input.key(), input).is_some() {
                    return Err(StoreError::Invalid(format!(
                        "{} appears twice",
                        key_text(&input.key())
                    )));
                }
            }
            for (key, input) in &wanted {
                let created_at = match heads.get(key) {
                    Some(existing) => {
                        owned_by(existing, owner)?;
                        Some(existing.created_at)
                    }
                    None => None,
                };
                let head = new_head(input, owner, created_at);
                if heads.get(key).is_none_or(|h| !h.same_revision(&head)) {
                    touched.push(key.clone());
                }
                heads.insert(key.clone(), head);
            }
            let gone: Vec<Key> = heads
                .iter()
                .filter(|(k, h)| h.owner == *owner && !wanted.contains_key(*k))
                .map(|(k, _)| k.clone())
                .collect();
            for key in gone {
                heads.remove(&key);
                deleted.push(key);
            }
        }
        Change::Create { owner, input } => {
            if heads.contains_key(&input.key()) {
                return Err(StoreError::AlreadyExists(input.key()));
            }
            heads.insert(input.key(), new_head(input, owner, None));
            touched.push(input.key());
        }
        Change::Update { owner, input, etag } => {
            let existing = heads
                .get(&input.key())
                .ok_or_else(|| StoreError::NotFound(input.key()))?;
            owned_by(existing, owner)?;
            if existing.etag != *etag {
                return Err(StoreError::EtagMismatch {
                    key: input.key(),
                    current: existing.etag.clone(),
                });
            }
            let mut head = new_head(input, owner, Some(existing.created_at));
            if existing.same_revision(&head) {
                head = existing.clone();
            }
            heads.insert(input.key(), head);
            touched.push(input.key());
        }
        Change::Delete {
            owner,
            key,
            etag,
            allow_missing,
        } => {
            let Some(existing) = heads.get(key) else {
                return if *allow_missing {
                    Ok(())
                } else {
                    Err(StoreError::NotFound(key.clone()))
                };
            };
            owned_by(existing, owner)?;
            if etag.as_ref().is_some_and(|e| *e != existing.etag) {
                return Err(StoreError::EtagMismatch {
                    key: key.clone(),
                    current: existing.etag.clone(),
                });
            }
            heads.remove(key);
            deleted.push(key.clone());
        }
        Change::Transfer {
            from,
            key,
            etag,
            to,
        } => {
            let existing = heads
                .get(key)
                .ok_or_else(|| StoreError::NotFound(key.clone()))?;
            if let Some(from) = from {
                owned_by(existing, from)?;
            }
            if existing.etag != *etag {
                return Err(StoreError::EtagMismatch {
                    key: key.clone(),
                    current: existing.etag.clone(),
                });
            }
            let mut head = existing.clone();
            head.owner = to.clone();
            actor.clone_into(&mut head.updated_by);
            heads.insert(key.clone(), head);
            touched.push(key.clone());
        }
    }
    Ok(())
}

/// A profile can't go while a resource still completes it.
/// Refuse to leave a document that something still uses: a profile its
/// resources or a writer grant name, or a bot a writer grant names
/// (ADR-0042 §7). `IN_USE` says who uses it. Only what the write removes
/// counts: naming something that never existed is an invalid document.
fn check_in_use(
    before: &BTreeMap<Key, Head>,
    heads: &BTreeMap<Key, Head>,
) -> Result<(), StoreError> {
    let mut missing: BTreeMap<Key, Vec<String>> = BTreeMap::new();
    let mut need = |key: Key, by: &Head| {
        if before.contains_key(&key) && !heads.contains_key(&key) {
            missing.entry(key).or_default().push(key_text(&by.key()));
        }
    };
    for head in heads.values() {
        if let Some(profile) = &head.profile {
            need(("resource_profile".to_owned(), profile.clone()), head);
        }
        if head.kind == "policy_writer" {
            let spec = head.input.get("spec");
            if let Some(bot) = spec.and_then(|s| s.get("bot")).and_then(Value::as_str) {
                need(("bot".to_owned(), bot.to_owned()), head);
            }
            let profiles = spec
                .and_then(|s| s.get("profiles"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str);
            for profile in profiles {
                need(("resource_profile".to_owned(), profile.to_owned()), head);
            }
        }
    }
    match missing.into_iter().next() {
        Some((key, mut used_by)) => {
            used_by.truncate(20);
            Err(StoreError::InUse { key, used_by })
        }
        None => Ok(()),
    }
}

/// The policy the heads make without the ones `drop` picks.
pub fn policy_without(
    heads: &BTreeMap<Key, Head>,
    drop: impl Fn(&Head) -> bool,
) -> Result<Policy, StoreError> {
    let kept: BTreeMap<Key, Head> = heads
        .iter()
        .filter(|(_, h)| !drop(h))
        .map(|(k, h)| (k.clone(), h.clone()))
        .collect();
    Policy::from_documents(effective(&kept)?).map_err(|e| StoreError::Invalid(e.to_string()))
}

/// The documents enforcement uses: whole documents as written, and resources
/// built from their profiles.
fn effective(heads: &BTreeMap<Key, Head>) -> Result<Vec<Document>, StoreError> {
    let mut docs = Vec::with_capacity(heads.len());
    let mut profiles = BTreeMap::new();
    for head in heads.values().filter(|h| h.profile.is_none()) {
        let doc: Document = serde_json::from_value(head.input.clone())
            .map_err(|e| StoreError::Invalid(format!("{}: {e}", key_text(&head.key()))))?;
        if let Document::ResourceProfile(p) = &doc {
            profiles.insert(p.metadata.name.clone(), p.clone());
        }
        docs.push(doc);
    }
    for head in heads.values() {
        let Some(profile_name) = &head.profile else {
            continue;
        };
        let profile = profiles.get(profile_name).ok_or_else(|| {
            StoreError::Invalid(format!("unknown resource_profile {profile_name:?}"))
        })?;
        let resource = delegation::materialize(profile, &writer_resource(head)?)
            .map_err(|e| StoreError::Invalid(e.to_string()))?;
        docs.push(Document::Resource(resource));
    }
    Ok(docs)
}

/// A writer's half of a resource, from its stored input.
fn writer_resource(head: &Head) -> Result<WriterResource, StoreError> {
    let bad = |m: &str| StoreError::Invalid(format!("{}: {m}", key_text(&head.key())));
    let metadata = head.input.get("metadata").and_then(Value::as_object);
    let labels = metadata
        .and_then(|m| m.get("labels"))
        .map(|l| serde_json::from_value::<BTreeMap<String, String>>(l.clone()))
        .transpose()
        .map_err(|_| bad("metadata.labels must map strings to strings"))?
        .unwrap_or_default();
    let description = metadata
        .and_then(|m| m.get("description"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let spec = head
        .input
        .get("spec")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    Ok(WriterResource {
        name: head.name.clone(),
        description,
        labels,
        spec,
    })
}

/// Heads that agree with the latest version. When they don't (a replica from
/// before Phase 14 applied without them), every document of the latest
/// version gets a head: the owner it had, or `default`, and its document as
/// the version has it.
fn reconcile(heads: BTreeMap<Key, Head>, latest: &LoadedPolicy) -> BTreeMap<Key, Head> {
    let agrees = effective(&heads)
        .ok()
        .and_then(|docs| Policy::from_documents(docs).ok())
        .is_some_and(|p| p.digest() == latest.policy.digest());
    if agrees {
        return heads;
    }
    tracing::warn!(
        version = latest.version,
        "document heads don't match the latest policy version; rebuilding them from it"
    );
    // A resource from a profile, built with the profiles the heads have.
    let profiles: BTreeMap<Key, Head> = heads
        .iter()
        .filter(|(k, _)| k.0 == "resource_profile")
        .map(|(k, h)| (k.clone(), h.clone()))
        .collect();
    let effective_of = |head: &Head| -> Option<Value> {
        let mut alone = profiles.clone();
        alone.insert(head.key(), head.clone());
        let doc = effective(&alone)
            .ok()?
            .into_iter()
            .find(|d| d.kind() == head.kind && d.name() == head.name)?;
        serde_json::to_value(doc).ok()
    };
    let mut rebuilt = BTreeMap::new();
    for doc in latest.policy.documents() {
        let key = (doc.kind().to_owned(), doc.name().to_owned());
        let value = serde_json::to_value(&doc).unwrap_or(Value::Null);
        let head = match heads.get(&key) {
            // A whole document, or a resource from a profile whose result is
            // what the version has: keep it as it is.
            Some(h) if h.profile.is_none() && h.input == value => h.clone(),
            Some(h) if h.profile.is_some() && effective_of(h).as_ref() == Some(&value) => h.clone(),
            Some(h) => Head {
                input: value,
                profile: None,
                ..h.clone()
            },
            None => Head {
                kind: key.0.clone(),
                name: key.1.clone(),
                owner: Owner::default_git(),
                input: value,
                profile: None,
                etag: String::new(),
                policy_version: latest.version,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                updated_by: latest.author.clone(),
            },
        };
        rebuilt.insert(key, head);
    }
    rebuilt
}

fn require_passing(tests: &testing::Report) -> Result<(), StoreError> {
    if tests.results.is_empty() {
        return Err(StoreError::TestsFailed(
            "--require-tests: the policy has no policy_test documents".into(),
        ));
    }
    if !tests.ok() {
        let failed: Vec<String> = tests
            .results
            .iter()
            .filter(|r| !r.passed)
            .map(|r| {
                format!(
                    "{} #{} {}: expected {}, got {} {}",
                    r.test, r.case, r.name, r.expected, r.got, r.detail
                )
            })
            .collect();
        return Err(StoreError::TestsFailed(format!(
            "{} policy test(s) fail after this write:\n{}",
            failed.len(),
            failed.join("\n")
        )));
    }
    Ok(())
}

fn heads_differ(stored: &BTreeMap<Key, Head>, heads: &BTreeMap<Key, Head>) -> bool {
    stored.len() != heads.len()
        || heads
            .iter()
            .any(|(k, h)| stored.get(k).is_none_or(|s| !s.same_revision(h)))
}

/// Opaque, and changes whenever the document or its owner does.
fn etag(head: &Head) -> String {
    let canonical = json!({
        "kind": head.kind,
        "name": head.name,
        "owner": head.owner.json(),
        "profile": head.profile,
        "input": head.input,
    });
    let digest = Sha256::digest(canonical.to_string().as_bytes());
    digest
        .iter()
        .take(16)
        .fold(String::with_capacity(32), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

// ---- Storage ----------------------------------------------------------------

/// Every head, read inside the write's transaction.
pub async fn load_heads(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<BTreeMap<Key, Head>, StoreError> {
    let rows = sqlx::query(
        "SELECT kind, name, channel, source, namespace, input, profile, etag, policy_version, created_at, updated_at, updated_by FROM policy_document_heads",
    )
    .fetch_all(&mut **tx)
    .await?;
    let mut heads = BTreeMap::new();
    for row in rows {
        let head = head_from_row(&row)?;
        heads.insert(head.key(), head);
    }
    Ok(heads)
}

fn head_from_row(row: &sqlx::postgres::PgRow) -> Result<Head, StoreError> {
    let channel: String = row.try_get("channel")?;
    Ok(Head {
        kind: row.try_get("kind")?,
        name: row.try_get("name")?,
        owner: Owner {
            channel: Channel::parse(&channel)
                .ok_or_else(|| StoreError::Internal(format!("unknown channel {channel:?}")))?,
            source: row.try_get("source")?,
            namespace: row.try_get("namespace")?,
        },
        input: row.try_get("input")?,
        profile: row.try_get("profile")?,
        etag: row.try_get("etag")?,
        policy_version: row.try_get("policy_version")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        updated_by: row.try_get("updated_by")?,
    })
}

/// Write the heads that changed and delete the ones that went.
async fn save_heads(
    tx: &mut Transaction<'_, Postgres>,
    stored: &BTreeMap<Key, Head>,
    heads: &BTreeMap<Key, Head>,
) -> Result<(), StoreError> {
    for key in stored.keys().filter(|k| !heads.contains_key(*k)) {
        sqlx::query("DELETE FROM policy_document_heads WHERE kind = $1 AND name = $2")
            .bind(&key.0)
            .bind(&key.1)
            .execute(&mut **tx)
            .await?;
    }
    for head in heads.values() {
        if stored.get(&head.key()).is_some_and(|s| s == head) {
            continue;
        }
        sqlx::query(
            "INSERT INTO policy_document_heads (kind, name, channel, source, namespace, input, profile, etag, policy_version, created_at, updated_at, updated_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (kind, name) DO UPDATE SET channel = EXCLUDED.channel, source = EXCLUDED.source, namespace = EXCLUDED.namespace, \
             input = EXCLUDED.input, profile = EXCLUDED.profile, etag = EXCLUDED.etag, policy_version = EXCLUDED.policy_version, \
             updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by",
        )
        .bind(&head.kind)
        .bind(&head.name)
        .bind(head.owner.channel.as_str())
        .bind(&head.owner.source)
        .bind(&head.owner.namespace)
        .bind(&head.input)
        .bind(&head.profile)
        .bind(&head.etag)
        .bind(head.policy_version)
        .bind(head.created_at)
        .bind(head.updated_at)
        .bind(&head.updated_by)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Every head, outside a write, for reads.
pub async fn heads(db: &db::Db) -> Result<BTreeMap<Key, Head>, StoreError> {
    let mut tx = db.begin().await?;
    load_heads(&mut tx).await
}

/// The latest policy and its heads, read together, for reads. Heads are
/// reconciled the way a write would, without storing anything.
pub async fn snapshot(
    state: &AppState,
) -> Result<(Arc<LoadedPolicy>, BTreeMap<Key, Head>), StoreError> {
    let mut tx = state.db.begin().await?;
    let current = state
        .policy
        .latest(&mut tx)
        .await
        .map_err(|e| StoreError::Internal(format!("loading the latest policy: {e}")))?;
    let heads = reconcile(load_heads(&mut tx).await?, &current);
    Ok((current, heads))
}

#[cfg(test)]
mod tests;

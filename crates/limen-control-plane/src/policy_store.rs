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
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use time::OffsetDateTime;

use crate::db;
use crate::state::{AppState, LoadedPolicy};

/// How a write arrived (ADR-0042 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone)]
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
}

/// A write: its changes, applied together as one version.
#[derive(Debug, Clone)]
pub struct Request {
    /// The person or `bot:<name>` writing.
    pub actor: String,
    pub changes: Vec<Change>,
    pub dry_run: bool,
    /// Refuse unless the policy's tests exist and pass.
    pub require_tests: bool,
    pub source_ref: Option<String>,
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
    check_profiles_in_use(&heads)?;

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
    };
    if request.dry_run || (outcome.diff.is_empty() && !heads_changed) {
        return Ok(outcome);
    }

    let version = if outcome.diff.is_empty() {
        // Only who manages what changed (or the heads caught up with a
        // version applied without them): no new policy version.
        current.version
    } else {
        let documents = serde_json::to_value(next.documents())
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

    if version != current.version {
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
            "previous_version": current.version,
            "digest": outcome.digest,
            "source_ref": request.source_ref,
            "diff": outcome.diff,
            "access_changes": access_changes,
            "owners": owners,
        });
        // Audit before commit: if the event can't be written, nothing changes.
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
            .map_err(|e| {
                tracing::error!(error = %e, "audit unavailable; refusing policy change");
                StoreError::AuditUnavailable
            })?;
    }
    tx.commit().await?;
    if version != current.version {
        state.policy.set(LoadedPolicy {
            version,
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

fn change_owner(change: &Change) -> &Owner {
    match change {
        Change::ReplaceSource { owner, .. }
        | Change::Create { owner, .. }
        | Change::Update { owner, .. }
        | Change::Delete { owner, .. } => owner,
    }
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
    }
    Ok(())
}

/// A profile can't go while a resource still completes it.
fn check_profiles_in_use(heads: &BTreeMap<Key, Head>) -> Result<(), StoreError> {
    let mut missing: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for head in heads.values() {
        if let Some(profile) = &head.profile
            && !heads.contains_key(&("resource_profile".to_owned(), profile.clone()))
        {
            missing
                .entry(profile.as_str())
                .or_default()
                .push(key_text(&head.key()));
        }
    }
    match missing.into_iter().next() {
        Some((profile, mut used_by)) => {
            used_by.truncate(20);
            Err(StoreError::InUse {
                key: ("resource_profile".into(), profile.to_owned()),
                used_by,
            })
        }
        None => Ok(()),
    }
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
            "--require-tests: {} policy test(s) failed:\n{}",
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

#[cfg(test)]
mod tests;

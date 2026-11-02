//! `limen manage`: the management API (ADR-0042) from the command line, for
//! admins and for bots with a `policy_writer` grant (log in with
//! `limen login --bot ...`). Output is JSON, for scripts and CI.

use std::collections::HashMap;

use anyhow::Context as _;
use clap::Subcommand;
use limen_proto::manage::v1 as pb;
use limen_proto::manage::v1::management_service_client::ManagementServiceClient;
use serde_json::{Value, json};

use crate::api;

#[derive(Debug, Subcommand)]
pub enum ManageCommand {
    /// What you may read and write: admin, or your writer grant.
    Whoami,
    /// List documents of one kind (resource, role, resource_profile, ...).
    Ls {
        kind: String,
        /// Only this namespace (a writer's own is implied).
        #[arg(long)]
        namespace: Option<String>,
        /// Only documents this source manages.
        #[arg(long)]
        source: Option<String>,
    },
    /// Show one document, with its owner and etag.
    Get {
        kind: String,
        name: String,
        /// Read it from this past policy version. A revision that is no
        /// longer current comes without its owner and etag (admins only).
        #[arg(long)]
        policy_version: Option<i64>,
    },
    /// Create a resource, or with --etag replace it. A writer completes a
    /// profile: --spec holds only the fields the profile lets it set.
    PutResource {
        name: String,
        /// The profile it completes. Required for bot writers.
        #[arg(long)]
        profile: Option<String>,
        /// The resource spec as JSON, for example
        /// '{"postgres":{"endpoint":"db.internal:5432"}}'.
        #[arg(long)]
        spec: String,
        /// key=value. Repeatable.
        #[arg(long = "label")]
        labels: Vec<String>,
        #[arg(long)]
        description: Option<String>,
        /// Who you write as, such as terraform/payments-prod.
        #[arg(long)]
        source: String,
        /// Defaults to a writer's namespace, or `default` for admins.
        #[arg(long)]
        namespace: Option<String>,
        /// Replace the resource with this etag (from `limen manage get`).
        #[arg(long)]
        etag: Option<String>,
        /// Check everything and show the impact, but change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Makes a retry safe: the same id returns the first result.
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Delete a resource you manage.
    DeleteResource {
        name: String,
        #[arg(long)]
        source: String,
        #[arg(long)]
        namespace: Option<String>,
        /// Required unless --if-exists.
        #[arg(long)]
        etag: Option<String>,
        /// Succeed when it's already gone.
        #[arg(long)]
        if_exists: bool,
    },
    /// Create a document of any kind, or with --etag replace it: a role,
    /// role_mapping, policy_test, bot, discovery, resource_profile, or
    /// policy_writer. Bot writers write only the kinds their grant names.
    Put {
        kind: String,
        name: String,
        /// The spec as JSON (a list for role_mapping), or @file to read it.
        #[arg(long)]
        spec: String,
        /// key=value. Repeatable.
        #[arg(long = "label")]
        labels: Vec<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        source: String,
        #[arg(long)]
        namespace: Option<String>,
        #[arg(long)]
        etag: Option<String>,
        #[arg(long)]
        dry_run: bool,
        /// Why, shown to approvers if the write is held.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Delete a document of any kind you manage.
    Delete {
        kind: String,
        name: String,
        #[arg(long)]
        source: String,
        #[arg(long)]
        namespace: Option<String>,
        /// Required unless --if-exists.
        #[arg(long)]
        etag: Option<String>,
        #[arg(long)]
        if_exists: bool,
    },
    /// Changes held for approval because they widen standing access.
    #[command(subcommand)]
    Changes(ChangesCommand),
}

#[derive(Debug, Subcommand)]
pub enum ChangesCommand {
    /// Held changes, newest first: pending ones unless --state.
    Ls {
        /// pending, applied, rejected, cancelled, expired, or superseded.
        #[arg(long)]
        state: Option<String>,
    },
    /// One change: its writes, the access it gives, and the CI run behind it.
    Show { id: String },
    /// Approve a change and apply it. Not its author, nor whoever started its
    /// CI run. If the policy moved so that it would give access you didn't
    /// see here, it is superseded instead.
    Approve {
        id: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Refuse a change.
    Reject {
        id: String,
        /// Why. Required.
        #[arg(long)]
        note: String,
    },
    /// Withdraw a change you made.
    Cancel { id: String },
}

pub async fn run(proxy: Option<&str>, command: ManageCommand) -> anyhow::Result<()> {
    let (_, channel) = api::authenticated(proxy)?;
    let mut api = ManagementServiceClient::new(channel);
    let out = match command {
        ManageCommand::Whoami => whoami(&mut api).await?,
        ManageCommand::Ls {
            kind,
            namespace,
            source,
        } => ls(&mut api, &kind, namespace, source).await?,
        ManageCommand::Get {
            kind,
            name,
            policy_version,
        } => {
            let doc = api
                .get_document(pb::GetDocumentRequest {
                    kind: kind_value(&kind)?,
                    name,
                    policy_version: policy_version.unwrap_or(0),
                })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner()
                .document
                .context("the server sent no document")?;
            document(&doc)
        }
        ManageCommand::PutResource {
            name,
            profile,
            spec,
            labels,
            description,
            source,
            namespace,
            etag,
            dry_run,
            request_id,
        } => {
            serde_json::from_str::<serde_json::Map<String, Value>>(&spec)
                .context("--spec must be a JSON object")?;
            let doc = pb::Document {
                kind: pb::DocumentKind::Resource.into(),
                name,
                description: description.unwrap_or_default(),
                labels: parse_labels(&labels)?,
                spec_json: spec,
                profile: profile.unwrap_or_default(),
                ..pb::Document::default()
            };
            let options = pb::WriteOptions {
                validate_only: dry_run,
                request_id: request_id.unwrap_or_default(),
                ..pb::WriteOptions::default()
            };
            put(&mut api, doc, ownership(source, namespace), options, etag).await?
        }
        ManageCommand::DeleteResource {
            name,
            source,
            namespace,
            etag,
            if_exists,
        } => {
            delete(
                &mut api,
                pb::DocumentKind::Resource.into(),
                name,
                ownership(source, namespace),
                etag,
                if_exists,
            )
            .await?
        }
        ManageCommand::Put {
            kind,
            name,
            spec,
            labels,
            description,
            source,
            namespace,
            etag,
            dry_run,
            reason,
        } => {
            let spec = match spec.strip_prefix('@') {
                Some(path) => {
                    std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?
                }
                None => spec,
            };
            serde_json::from_str::<Value>(&spec).context("--spec must be JSON")?;
            let doc = pb::Document {
                kind: kind_value(&kind)?,
                name,
                description: description.unwrap_or_default(),
                labels: parse_labels(&labels)?,
                spec_json: spec,
                ..pb::Document::default()
            };
            let options = pb::WriteOptions {
                validate_only: dry_run,
                reason: reason.unwrap_or_default(),
                ..pb::WriteOptions::default()
            };
            put(&mut api, doc, ownership(source, namespace), options, etag).await?
        }
        ManageCommand::Delete {
            kind,
            name,
            source,
            namespace,
            etag,
            if_exists,
        } => {
            delete(
                &mut api,
                kind_value(&kind)?,
                name,
                ownership(source, namespace),
                etag,
                if_exists,
            )
            .await?
        }
        ManageCommand::Changes(command) => changes(&mut api, command).await?,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

type Api = ManagementServiceClient<limen_tunnel::connect::TracedChannel>;

async fn whoami(api: &mut Api) -> anyhow::Result<Value> {
    let me = api
        .describe_caller(pb::DescribeCallerRequest {})
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    Ok(json!({
        "principal": me.principal,
        "admin": me.admin,
        "policy_version": me.policy_version,
        "grant": me.grant.map(|g| json!({
            "name": g.name,
            "namespace": g.namespace,
            "name_patterns": g.name_patterns,
            "kinds": g.kinds.iter().map(|k| kind_name(*k)).collect::<Vec<_>>(),
            "profiles": g.profiles,
            "max_documents": g.max_documents,
            "document_count": g.document_count,
        })),
    }))
}

async fn ls(
    api: &mut Api,
    kind: &str,
    namespace: Option<String>,
    source: Option<String>,
) -> anyhow::Result<Value> {
    let kind = kind_value(kind)?;
    let mut documents = Vec::new();
    let mut page_token = String::new();
    loop {
        let page = api
            .list_documents(pb::ListDocumentsRequest {
                kind,
                namespace: namespace.clone().unwrap_or_default(),
                source: source.clone().unwrap_or_default(),
                page_token: page_token.clone(),
                ..pb::ListDocumentsRequest::default()
            })
            .await
            .map_err(|s| api::status_error(&s))?
            .into_inner();
        documents.extend(page.documents.iter().map(document));
        if page.next_page_token.is_empty() {
            break;
        }
        page_token = page.next_page_token;
    }
    Ok(Value::Array(documents))
}

/// Create, or with an etag replace, a document.
async fn put(
    api: &mut Api,
    doc: pb::Document,
    ownership: pb::Ownership,
    options: pb::WriteOptions,
    etag: Option<String>,
) -> anyhow::Result<Value> {
    let (ownership, options) = (Some(ownership), Some(options));
    let result = match etag {
        None => {
            api.create_document(pb::CreateDocumentRequest {
                document: Some(doc),
                ownership,
                options,
            })
            .await
            .map_err(|s| api::status_error(&s))?
            .into_inner()
            .result
        }
        Some(etag) => {
            api.update_document(pb::UpdateDocumentRequest {
                document: Some(doc),
                etag,
                options,
                ownership,
            })
            .await
            .map_err(|s| api::status_error(&s))?
            .into_inner()
            .result
        }
    };
    Ok(write_result(&result.context("the server sent no result")?))
}

async fn delete(
    api: &mut Api,
    kind: i32,
    name: String,
    ownership: pb::Ownership,
    etag: Option<String>,
    allow_missing: bool,
) -> anyhow::Result<Value> {
    let result = api
        .delete_document(pb::DeleteDocumentRequest {
            kind,
            name,
            etag: etag.unwrap_or_default(),
            allow_missing,
            options: None,
            ownership: Some(ownership),
        })
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner()
        .result
        .context("the server sent no result")?;
    Ok(write_result(&result))
}

async fn changes(api: &mut Api, command: ChangesCommand) -> anyhow::Result<Value> {
    let change = |c: Option<pb::PolicyChange>| -> anyhow::Result<Value> {
        Ok(policy_change(&c.context("the server sent no change")?))
    };
    Ok(match command {
        ChangesCommand::Ls { state } => {
            let state = match state {
                None => pb::policy_change::State::Pending,
                Some(s) => pb::policy_change::State::from_str_name(&format!(
                    "STATE_{}",
                    s.to_ascii_uppercase()
                ))
                .with_context(|| format!("unknown state {s:?}"))?,
            };
            let mut changes = Vec::new();
            let mut page_token = String::new();
            loop {
                let page = api
                    .list_changes(pb::ListChangesRequest {
                        state: state.into(),
                        page_size: 0,
                        page_token: page_token.clone(),
                    })
                    .await
                    .map_err(|s| api::status_error(&s))?
                    .into_inner();
                changes.extend(page.changes.iter().map(policy_change));
                if page.next_page_token.is_empty() {
                    break;
                }
                page_token = page.next_page_token;
            }
            Value::Array(changes)
        }
        ChangesCommand::Show { id } => change(
            api.get_change(pb::GetChangeRequest { id })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner()
                .change,
        )?,
        ChangesCommand::Approve { id, note } => change(
            api.approve_change(pb::ApproveChangeRequest {
                id,
                note: note.unwrap_or_default(),
            })
            .await
            .map_err(|s| api::status_error(&s))?
            .into_inner()
            .change,
        )?,
        ChangesCommand::Reject { id, note } => change(
            api.reject_change(pb::RejectChangeRequest { id, note })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner()
                .change,
        )?,
        ChangesCommand::Cancel { id } => change(
            api.cancel_change(pb::CancelChangeRequest { id })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner()
                .change,
        )?,
    })
}

fn policy_change(c: &pb::PolicyChange) -> Value {
    let impact = c.impact.clone().unwrap_or_default();
    let writes: Vec<Value> = c
        .writes
        .iter()
        .filter_map(|w| match w.operation.as_ref()? {
            pb::write::Operation::Create(r) => r.document.as_ref().map(|d| {
                json!({ "op": "create", "kind": kind_name(d.kind), "name": d.name, "spec": json_or_text(&d.spec_json) })
            }),
            pb::write::Operation::Update(r) => r.document.as_ref().map(|d| {
                json!({ "op": "update", "kind": kind_name(d.kind), "name": d.name, "spec": json_or_text(&d.spec_json) })
            }),
            pb::write::Operation::Delete(r) => {
                Some(json!({ "op": "delete", "kind": kind_name(r.kind), "name": r.name }))
            }
        })
        .collect();
    json!({
        "id": c.id,
        "state": pb::policy_change::State::try_from(c.state)
            .map(|s| s.as_str_name().trim_start_matches("STATE_").to_ascii_lowercase())
            .unwrap_or_default(),
        "author": c.author,
        "author_ci": c.author_ci.iter().collect::<std::collections::BTreeMap<_, _>>(),
        "reason": c.reason,
        "source_ref": c.source_ref,
        "writes": writes,
        "access_changes": impact.access_changes.iter().map(|a| a.text.clone()).collect::<Vec<_>>(),
        "base_policy_version": c.base_policy_version,
        "expires_at": c.expire_time_unix,
        "decided_by": c.decided_by,
        "decision_note": c.decision_note,
        "applied_policy_version": c.applied_policy_version,
    })
}

fn kind_value(kind: &str) -> anyhow::Result<i32> {
    let name = format!("DOCUMENT_KIND_{}", kind.to_ascii_uppercase());
    pb::DocumentKind::from_str_name(&name)
        .filter(|k| *k != pb::DocumentKind::Unspecified)
        .map(i32::from)
        .with_context(|| {
            format!("unknown kind {kind:?}: role, role_mapping, resource, bot, discovery, policy_test, resource_profile, or policy_writer")
        })
}

fn kind_name(kind: i32) -> String {
    pb::DocumentKind::try_from(kind)
        .ok()
        .and_then(|k| {
            k.as_str_name()
                .strip_prefix("DOCUMENT_KIND_")
                .map(str::to_ascii_lowercase)
        })
        .unwrap_or_default()
}

fn ownership(source: String, namespace: Option<String>) -> pb::Ownership {
    pb::Ownership {
        source,
        namespace: namespace.unwrap_or_default(),
        ..pb::Ownership::default()
    }
}

fn parse_labels(labels: &[String]) -> anyhow::Result<HashMap<String, String>> {
    labels
        .iter()
        .map(|l| {
            l.split_once('=')
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .with_context(|| format!("label {l:?} must be key=value"))
        })
        .collect()
}

fn json_or_text(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned()))
}

fn document(doc: &pb::Document) -> Value {
    let owner = doc.ownership.clone().unwrap_or_default();
    json!({
        "kind": kind_name(doc.kind),
        "name": doc.name,
        "description": doc.description,
        "labels": doc.labels,
        "spec": json_or_text(&doc.spec_json),
        "profile": doc.profile,
        "effective_labels": doc.effective_labels,
        "effective_spec": json_or_text(&doc.effective_spec_json),
        "owner": {
            "channel": pb::Channel::try_from(owner.channel)
                .map(|c| c.as_str_name().trim_start_matches("CHANNEL_").to_ascii_lowercase())
                .unwrap_or_default(),
            "source": owner.source,
            "namespace": owner.namespace,
        },
        "etag": doc.etag,
        "policy_version": doc.policy_version,
        "updated_by": doc.updated_by,
    })
}

fn write_result(result: &pb::WriteResult) -> Value {
    let impact = result.impact.clone().unwrap_or_default();
    json!({
        "outcome": pb::WriteOutcome::try_from(result.outcome)
            .map(|o| o.as_str_name().trim_start_matches("WRITE_OUTCOME_").to_ascii_lowercase())
            .unwrap_or_default(),
        "policy_version": result.policy_version,
        "documents": result.documents.iter().map(document).collect::<Vec<_>>(),
        "access_changes": impact.access_changes.iter().map(|c| c.text.clone()).collect::<Vec<_>>(),
        "widens_standing_access": impact.widens_standing_access,
        "warnings": impact.warnings,
        "pending_change": result.pending_change.as_ref().map(policy_change),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_read_like_the_yaml() {
        assert_eq!(
            kind_value("resource").expect("ok"),
            i32::from(pb::DocumentKind::Resource)
        );
        assert_eq!(
            kind_name(kind_value("resource_profile").expect("ok")),
            "resource_profile"
        );
        assert!(kind_value("unspecified").is_err());
        assert!(kind_value("bogus").is_err());
    }

    #[test]
    fn labels_are_key_value() {
        let labels = parse_labels(&["env=staging".into()]).expect("ok");
        assert_eq!(labels.get("env").map(String::as_str), Some("staging"));
        assert!(parse_labels(&["nope".into()]).is_err());
    }
}

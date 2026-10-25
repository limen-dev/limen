//! Discovered resources (ADR-0027).
//!
//! Workers describe a cloud account and report facts; this module turns them
//! into proposals with the `discovery` document and holds them for an admin.
//! Discovery never grants access: only *accepted* resources become ones policy
//! can select, and then roles still have to select them. The risk is a tag
//! someone can write steering a resource into a role, so:
//!
//! - only the document's allow-listed tags become labels;
//! - a new resource, and any change to an accepted one's name, labels, or
//!   target, waits as *pending* (labels named in `auto_accept` excepted);
//! - a resource not seen for several complete scans goes *stale* and is
//!   refused, then removed after a while, never from under an open session.

use std::collections::BTreeMap;

use limen_audit::{Context, EventKind};
use limen_ca::verify::ComponentIdentity;
use limen_policy::discovery::{DiscoveryDoc, Found, Proposal, Source, propose};
use limen_proto::v1::{
    DiscoveredInfo, DiscoveredItem, ReportDiscoveryRequest, ReportDiscoveryResponse,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row as _, Transaction};
use time::OffsetDateTime;
use tonic::Status;

use crate::db::Db;
use crate::state::{AppState, internal, unix};

/// The most items one report may carry.
const MAX_ITEMS: usize = 5_000;
/// The largest number of rows a document may keep, so a runaway scan can't
/// fill the table.
const MAX_ROWS_PER_DOCUMENT: i64 = 20_000;

#[derive(Debug, Clone)]
pub struct Row {
    pub key: String,
    pub document: String,
    pub matcher: i32,
    pub source: String,
    pub account: String,
    pub region: String,
    pub provider_id: String,
    pub found: Value,
    pub proposal: Value,
    pub state: String,
    pub accepted: Option<Value>,
    pub accepted_by: Option<String>,
    pub change_pending: bool,
    pub announced: Option<String>,
    pub first_seen_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub missed_cycles: i32,
    pub stale_since: Option<OffsetDateTime>,
    pub reported_by: String,
}

macro_rules! cols {
    () => {
        "key, document, matcher, source, account, region, provider_id, found, proposal, state, accepted, accepted_by, change_pending, announced, first_seen_at, last_seen_at, missed_cycles, stale_since, reported_by"
    };
}

fn row_from(r: &sqlx::postgres::PgRow) -> Result<Row, sqlx::Error> {
    Ok(Row {
        key: r.try_get("key")?,
        document: r.try_get("document")?,
        matcher: r.try_get("matcher")?,
        source: r.try_get("source")?,
        account: r.try_get("account")?,
        region: r.try_get("region")?,
        provider_id: r.try_get("provider_id")?,
        found: r.try_get("found")?,
        proposal: r.try_get("proposal")?,
        state: r.try_get("state")?,
        accepted: r.try_get("accepted")?,
        accepted_by: r.try_get("accepted_by")?,
        change_pending: r.try_get("change_pending")?,
        announced: r.try_get("announced")?,
        first_seen_at: r.try_get("first_seen_at")?,
        last_seen_at: r.try_get("last_seen_at")?,
        missed_cycles: r.try_get("missed_cycles")?,
        stale_since: r.try_get("stale_since")?,
        reported_by: r.try_get("reported_by")?,
    })
}

fn proposal_of(row: &Row) -> Option<Proposal> {
    serde_json::from_value(row.proposal.clone()).ok()
}

/// What is in force for an accepted resource: name, labels, and spec.
fn accepted_view(p: &Proposal) -> Value {
    json!({ "name": p.name, "labels": p.labels, "spec": p.spec })
}

fn digest(v: &Value) -> String {
    use std::fmt::Write as _;
    Sha256::digest(v.to_string().as_bytes())
        .iter()
        .take(8)
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// What changed between the accepted view and a new proposal, one line each.
fn changes(accepted: &Value, new: &Proposal) -> Vec<String> {
    let mut out = Vec::new();
    if accepted["name"] != json!(new.name) {
        out.push(format!(
            "name {} → {}",
            accepted["name"].as_str().unwrap_or("?"),
            new.name
        ));
    }
    if accepted["spec"] != new.spec {
        out.push(format!("target changed to {}", new.target));
    }
    let old: BTreeMap<String, String> =
        serde_json::from_value(accepted["labels"].clone()).unwrap_or_default();
    for (k, v) in &new.labels {
        match old.get(k) {
            None => out.push(format!("label {k}={v} added")),
            Some(o) if o != v => out.push(format!("label {k}: {o} → {v}")),
            Some(_) => {}
        }
    }
    for k in old.keys().filter(|k| !new.labels.contains_key(*k)) {
        out.push(format!("label {k} removed"));
    }
    out
}

/// Whether a change can be applied without an admin: only labels changed, and
/// all of them are keys the document auto-accepts.
fn auto_acceptable(doc: &DiscoveryDoc, accepted: &Value, new: &Proposal) -> bool {
    if accepted["name"] != json!(new.name) || accepted["spec"] != new.spec {
        return false;
    }
    let old: BTreeMap<String, String> =
        serde_json::from_value(accepted["labels"].clone()).unwrap_or_default();
    let allowed = |k: &str| doc.spec.auto_accept.iter().any(|a| a == k);
    new.labels
        .iter()
        .filter(|(k, v)| old.get(*k) != Some(v))
        .map(|(k, _)| k)
        .chain(old.keys().filter(|k| !new.labels.contains_key(*k)))
        .all(|k| allowed(k))
}

async fn audit(
    state: &AppState,
    kind: EventKind,
    user: Option<&str>,
    data: Value,
) -> Result<(), Status> {
    state
        .audit
        .emit(
            kind,
            Context {
                user: user.map(str::to_owned),
                session_id: None,
            },
            data,
        )
        .await
        .map(|_| ())
        .map_err(|e| {
            tracing::error!(error = %e, "audit unavailable; refusing a discovery change");
            Status::unavailable("audit unavailable")
        })
}

fn found_of(item: &DiscoveredItem) -> Option<Found> {
    Some(Found {
        source: Source::parse(&item.source)?,
        account: item.account.clone(),
        region: item.region.clone(),
        provider_id: item.provider_id.clone(),
        target: item.target.clone(),
        tags: item
            .tags
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        facts: item
            .facts
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    })
}

/// Take a worker's report. Returns how many items were kept and how many
/// dropped for not matching the document.
#[allow(clippy::too_many_lines)] // one pass: validate, upsert, then the lifecycle
pub async fn report(
    state: &AppState,
    worker: &ComponentIdentity,
    req: ReportDiscoveryRequest,
) -> Result<ReportDiscoveryResponse, Status> {
    let base = state.policy.base();
    let doc = base
        .policy
        .discovery()
        .find(|d| d.metadata.name == req.document)
        .cloned()
        .ok_or_else(|| Status::not_found("no such discovery document"))?;
    // A worker only reports for documents that name it.
    if !doc.spec.worker_runs(&worker.labels) {
        return Err(Status::permission_denied(
            "this worker doesn't run that discovery document",
        ));
    }
    if req.items.len() > MAX_ITEMS {
        return Err(Status::invalid_argument(format!(
            "at most {MAX_ITEMS} items per report"
        )));
    }
    let (mut kept, mut dropped) = (0u32, 0u32);
    let mut seen_keys: Vec<String> = Vec::new();
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal("starting transaction", e))?;
    // Only a resource not stored yet counts toward the cap: re-seeing a known
    // one adds nothing.
    let mut known: std::collections::HashSet<String> =
        sqlx::query_scalar("SELECT key FROM discovered_resources WHERE document = $1")
            .bind(&doc.metadata.name)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| internal("counting discovered resources", e))?
            .into_iter()
            .collect();
    for item in &req.items {
        let matcher = usize::try_from(item.matcher).unwrap_or(usize::MAX);
        let proposal = found_of(item)
            .ok_or_else(|| "unknown source".to_owned())
            .and_then(|found| propose(&doc, matcher, &found).map(|p| (found, p)));
        let (found, proposal) = match proposal {
            Ok(p) => p,
            Err(why) => {
                dropped += 1;
                tracing::warn!(worker = %worker.id, document = %doc.metadata.name, %why, "dropped a discovery report");
                continue;
            }
        };
        let key = found.key();
        if seen_keys.contains(&key) {
            continue;
        }
        if !known.contains(&key)
            && i64::try_from(known.len()).unwrap_or(i64::MAX) >= MAX_ROWS_PER_DOCUMENT
        {
            return Err(Status::resource_exhausted(
                "too many discovered resources for this document",
            ));
        }
        known.insert(key.clone());
        seen_keys.push(key.clone());
        kept += 1;
        upsert(
            state, &mut tx, &doc, &worker.id, &key, matcher, &found, proposal,
        )
        .await?;
    }
    // Resources not seen in a scope that was scanned to the end.
    for scope in &req.complete {
        let matcher = i32::try_from(scope.matcher).unwrap_or(i32::MAX);
        if usize::try_from(scope.matcher).map_or(true, |m| m >= doc.spec.matchers.len())
            || !doc.spec.regions.contains(&scope.region)
        {
            continue;
        }
        let missing = sqlx::query(concat!(
            "SELECT ",
            cols!(),
            " FROM discovered_resources
              WHERE document = $1 AND matcher = $2 AND account = $3 AND region = $4
                AND NOT (key = ANY($5)) FOR UPDATE"
        ))
        .bind(&doc.metadata.name)
        .bind(matcher)
        .bind(&scope.account)
        .bind(&scope.region)
        .bind(&seen_keys)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| internal("finding missing resources", e))?;
        for row in missing
            .iter()
            .map(row_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| internal("reading rows", e))?
        {
            let missed = row.missed_cycles + 1;
            // A rejection is the admin's decision about this instance: it
            // stays rejected whether or not the instance is still there.
            let becomes_stale = !matches!(row.state.as_str(), "stale" | "rejected")
                && u32::try_from(missed).unwrap_or(u32::MAX) >= doc.spec.stale_after_cycles();
            sqlx::query(
                "UPDATE discovered_resources SET missed_cycles = $2,
                   state = CASE WHEN $3 THEN 'stale' ELSE state END,
                   stale_since = CASE WHEN $3 THEN now() ELSE stale_since END
                 WHERE key = $1",
            )
            .bind(&row.key)
            .bind(missed)
            .bind(becomes_stale)
            .execute(&mut *tx)
            .await
            .map_err(|e| internal("updating a missing resource", e))?;
            if becomes_stale {
                let name = display_name(&row);
                audit(
                    state,
                    EventKind::ResourceStale,
                    None,
                    json!({ "key": row.key, "resource": name, "document": doc.metadata.name, "missed_cycles": missed, "was": row.state }),
                )
                .await?;
            }
        }
    }
    tx.commit()
        .await
        .map_err(|e| internal("committing a discovery report", e))?;
    metrics::counter!("limen_discovery_reports_total").increment(1);
    refresh_overlay(state)
        .await
        .map_err(|e| internal("refreshing discovered resources", e))?;
    Ok(ReportDiscoveryResponse {
        accepted: kept,
        dropped,
    })
}

fn display_name(row: &Row) -> String {
    row.accepted
        .as_ref()
        .and_then(|a| a["name"].as_str().map(str::to_owned))
        .or_else(|| proposal_of(row).map(|p| p.name))
        .unwrap_or_else(|| row.provider_id.clone())
}

/// A name no other discovered resource, and no static resource, has.
async fn unique_name(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    key: &str,
    wanted: &str,
    provider_id: &str,
) -> Result<String, Status> {
    let tail: String = provider_id
        .chars()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_lowercase();
    let base = state.policy.base();
    let mut candidate = wanted.to_owned();
    for attempt in 0..20 {
        let taken_static = base.policy.resource(&candidate).is_some();
        let taken_discovered: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM discovered_resources
               WHERE key <> $1 AND state <> 'rejected'
                 AND (accepted->>'name' = $2 OR proposal->>'name' = $2))",
        )
        .bind(key)
        .bind(&candidate)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| internal("checking names", e))?;
        if !taken_static && !taken_discovered {
            return Ok(candidate);
        }
        candidate = if attempt == 0 {
            format!("{wanted}-{tail}")
        } else {
            format!("{wanted}-{tail}-{attempt}")
        };
        candidate.truncate(120);
    }
    Err(Status::failed_precondition("couldn't find a free name"))
}

#[allow(clippy::too_many_arguments)] // one row's worth of context
async fn upsert(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    doc: &DiscoveryDoc,
    worker_id: &str,
    key: &str,
    matcher: usize,
    found: &Found,
    mut proposal: Proposal,
) -> Result<(), Status> {
    let existing = sqlx::query(concat!(
        "SELECT ",
        cols!(),
        " FROM discovered_resources WHERE key = $1 FOR UPDATE"
    ))
    .bind(key)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| internal("reading a discovered resource", e))?
    .as_ref()
    .map(row_from)
    .transpose()
    .map_err(|e| internal("reading a discovered resource", e))?;
    let found_json = serde_json::to_value(found).map_err(|e| internal("encoding", e))?;
    let matcher_i = i32::try_from(matcher).unwrap_or(i32::MAX);

    let Some(row) = existing else {
        proposal.name = unique_name(state, tx, key, &proposal.name, &found.provider_id).await?;
        sqlx::query(
            "INSERT INTO discovered_resources (key, document, matcher, source, account, region, provider_id, found, proposal, state, reported_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10)",
        )
        .bind(key)
        .bind(&doc.metadata.name)
        .bind(matcher_i)
        .bind(found.source.as_str())
        .bind(&found.account)
        .bind(&found.region)
        .bind(&found.provider_id)
        .bind(&found_json)
        .bind(serde_json::to_value(&proposal).map_err(|e| internal("encoding", e))?)
        .bind(worker_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| internal("storing a discovered resource", e))?;
        metrics::counter!("limen_discovered_resources_new_total", "source" => found.source.as_str()).increment(1);
        return audit(
            state,
            EventKind::ResourceDiscovered,
            None,
            json!({
                "key": key, "resource": proposal.name, "document": doc.metadata.name,
                "source": found.source.as_str(), "kind": proposal.kind.as_str(),
                "labels": proposal.labels, "worker_id": worker_id,
                "blockers": proposal.blockers,
            }),
        )
        .await;
    };

    // Known. The name is kept unique like a new one's; a change to it is a
    // change like any other.
    proposal.name = unique_name(state, tx, key, &proposal.name, &found.provider_id).await?;
    let proposal_json = serde_json::to_value(&proposal).map_err(|e| internal("encoding", e))?;

    // Which state it is in after this sighting.
    let (state_now, change_pending, announced, auto_apply) =
        match (row.state.as_str(), &row.accepted) {
            ("rejected", _) => ("rejected", false, row.announced.clone(), None),
            ("pending", _) | ("stale", None) => ("pending", false, row.announced.clone(), None),
            (_, Some(accepted)) => {
                let diff = changes(accepted, &proposal);
                if diff.is_empty() {
                    ("accepted", false, None, None)
                } else if auto_acceptable(doc, accepted, &proposal) {
                    ("accepted", false, None, Some(accepted_view(&proposal)))
                } else {
                    let d = digest(&proposal_json);
                    if row.announced.as_deref() != Some(d.as_str()) {
                        audit(
                        state,
                        EventKind::ResourceRelabel,
                        None,
                        json!({
                            "key": key, "resource": accepted["name"], "document": doc.metadata.name,
                            "changes": diff, "auto": false, "worker_id": worker_id,
                        }),
                    )
                    .await?;
                        metrics::counter!("limen_discovered_resources_changes_total").increment(1);
                    }
                    ("accepted", true, Some(d), None)
                }
            }
            _ => ("pending", false, row.announced.clone(), None),
        };
    if let (Some(_), Some(old)) = (&auto_apply, &row.accepted) {
        audit(
            state,
            EventKind::ResourceRelabel,
            None,
            json!({
                "key": key, "resource": old["name"], "document": doc.metadata.name,
                "changes": changes(old, &proposal), "auto": true, "worker_id": worker_id,
            }),
        )
        .await?;
    }
    sqlx::query(
        "UPDATE discovered_resources SET found = $2, proposal = $3, state = $4, change_pending = $5,
           announced = $6, accepted = COALESCE($7, accepted), last_seen_at = now(), missed_cycles = 0,
           stale_since = NULL, reported_by = $8, matcher = $9
         WHERE key = $1",
    )
    .bind(key)
    .bind(&found_json)
    .bind(&proposal_json)
    .bind(state_now)
    .bind(change_pending)
    .bind(announced)
    .bind(auto_apply)
    .bind(worker_id)
    .bind(matcher_i)
    .execute(&mut **tx)
    .await
    .map_err(|e| internal("updating a discovered resource", e))?;
    Ok(())
}

// ---- reviewing --------------------------------------------------------------------------

fn info(row: &Row) -> DiscoveredInfo {
    let p = proposal_of(row);
    let accepted_name = row
        .accepted
        .as_ref()
        .and_then(|a| a["name"].as_str())
        .unwrap_or_default()
        .to_owned();
    let diff = match (&row.accepted, &p) {
        (Some(a), Some(p)) if row.change_pending => changes(a, p),
        _ => Vec::new(),
    };
    DiscoveredInfo {
        key: row.key.clone(),
        document: row.document.clone(),
        source: row.source.clone(),
        kind: p
            .as_ref()
            .map(|p| p.kind.as_str().to_owned())
            .unwrap_or_default(),
        name: p.as_ref().map(|p| p.name.clone()).unwrap_or_default(),
        labels: p
            .as_ref()
            .map(|p| {
                p.labels
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default(),
        target: p.as_ref().map(|p| p.target.clone()).unwrap_or_default(),
        account: row.account.clone(),
        region: row.region.clone(),
        provider_id: row.provider_id.clone(),
        state: row.state.clone(),
        change_pending: row.change_pending,
        blockers: p.map(|p| p.blockers).unwrap_or_default(),
        changes: diff,
        first_seen_unix: unix(row.first_seen_at),
        last_seen_unix: unix(row.last_seen_at),
        missed_cycles: u32::try_from(row.missed_cycles).unwrap_or(0),
        accepted_name,
        accepted_by: row.accepted_by.clone().unwrap_or_default(),
        reported_by: row.reported_by.clone(),
    }
}

pub async fn list(db: &Db, filter: &str) -> Result<Vec<DiscoveredInfo>, Status> {
    let rows = sqlx::query(concat!(
        "SELECT ",
        cols!(),
        " FROM discovered_resources WHERE ($1 = '' OR state = $1 OR ($1 = 'changed' AND change_pending))
          ORDER BY (state = 'pending' OR change_pending) DESC, last_seen_at DESC LIMIT 1000"
    ))
    .bind(filter)
    .fetch_all(db)
    .await
    .map_err(|e| internal("listing discovered resources", e))?;
    rows.iter()
        .map(|r| row_from(r).map(|r| info(&r)))
        .collect::<Result<_, _>>()
        .map_err(|e| internal("reading discovered resources", e))
}

/// Accept or reject a discovered resource, or the change waiting on one.
pub async fn review(
    state: &AppState,
    admin: &str,
    via: &'static str,
    key: &str,
    accept: bool,
    note: &str,
) -> Result<DiscoveredInfo, Status> {
    let note = note.trim();
    if note.len() > 500 || note.chars().any(char::is_control) {
        return Err(Status::invalid_argument(
            "note must be at most 500 characters, without control characters",
        ));
    }
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal("starting transaction", e))?;
    let row = sqlx::query(concat!(
        "SELECT ",
        cols!(),
        " FROM discovered_resources WHERE key = $1 FOR UPDATE"
    ))
    .bind(key)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| internal("reading a discovered resource", e))?
    .as_ref()
    .map(row_from)
    .transpose()
    .map_err(|e| internal("reading a discovered resource", e))?
    .ok_or_else(|| Status::not_found("no such discovered resource"))?;
    let proposal = proposal_of(&row).ok_or_else(|| Status::internal("unreadable proposal"))?;
    let doc = state
        .policy
        .base()
        .policy
        .discovery()
        .find(|d| d.metadata.name == row.document)
        .cloned();

    if accept {
        if !proposal.blockers.is_empty() {
            return Err(Status::failed_precondition(format!(
                "it can't be accepted yet: {}",
                proposal.blockers.join("; ")
            )));
        }
        let doc = doc.ok_or_else(|| {
            Status::failed_precondition("the discovery document it came from is gone")
        })?;
        // It has to be a resource policy accepts, under a name nothing else has.
        let resource = limen_policy::discovery::resource_doc(
            &proposal.name,
            &proposal.labels,
            &proposal.spec,
            &doc.spec.worker_selector,
        )
        .map_err(Status::failed_precondition)?;
        let (_, skipped) = state.policy.base().policy.with_discovered([resource]);
        if let Some((_, why)) = skipped.first() {
            return Err(Status::failed_precondition(format!(
                "it isn't a valid resource: {why}"
            )));
        }
        let clash: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM discovered_resources WHERE key <> $1 AND state = 'accepted' AND accepted->>'name' = $2)",
        )
        .bind(key)
        .bind(&proposal.name)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| internal("checking names", e))?;
        if clash {
            return Err(Status::failed_precondition(format!(
                "the name {} is taken",
                proposal.name
            )));
        }
        sqlx::query(
            "UPDATE discovered_resources SET state = 'accepted', accepted = $2, change_pending = false,
               announced = NULL, accepted_by = $3, accepted_at = now(), reviewed_by = $3, reviewed_at = now(), review_note = $4
             WHERE key = $1",
        )
        .bind(key)
        .bind(accepted_view(&proposal))
        .bind(admin)
        .bind(note)
        .execute(&mut *tx)
        .await
        .map_err(|e| internal("accepting", e))?;
    } else {
        // Rejecting a pending change to a resource already accepted refuses
        // the change only: the accepted version stays in force.
        sqlx::query(
            "UPDATE discovered_resources SET
               state = CASE WHEN change_pending AND accepted IS NOT NULL THEN state ELSE 'rejected' END,
               change_pending = false,
               reviewed_by = $2, reviewed_at = now(), review_note = $3 WHERE key = $1",
        )
        .bind(key)
        .bind(admin)
        .bind(note)
        .execute(&mut *tx)
        .await
        .map_err(|e| internal("rejecting", e))?;
    }
    audit(
        state,
        EventKind::ResourceReview,
        Some(admin),
        json!({
            "key": key, "resource": proposal.name, "document": row.document,
            "action": if accept { "accept" } else { "reject" },
            "was": row.state, "change": row.change_pending, "note": note, "via": via,
        }),
    )
    .await?;
    let updated = sqlx::query(concat!(
        "SELECT ",
        cols!(),
        " FROM discovered_resources WHERE key = $1"
    ))
    .bind(key)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| internal("reading", e))?;
    tx.commit()
        .await
        .map_err(|e| internal("committing a review", e))?;
    refresh_overlay(state)
        .await
        .map_err(|e| internal("refreshing discovered resources", e))?;
    row_from(&updated)
        .map(|r| info(&r))
        .map_err(|e| internal("reading", e))
}

// ---- policy overlay ---------------------------------------------------------------------------

/// The accepted resources, as policy documents. A resource whose discovery
/// document has gone from policy is left out (fail closed), as is one that no
/// longer builds a valid resource.
pub async fn overlay_docs(
    state: &AppState,
) -> Result<Vec<limen_policy::model::ResourceDoc>, sqlx::Error> {
    let rows = sqlx::query(concat!(
        "SELECT ",
        cols!(),
        " FROM discovered_resources WHERE state = 'accepted' ORDER BY key"
    ))
    .fetch_all(&state.db)
    .await?;
    let base = state.policy.base();
    let mut out = Vec::new();
    for r in &rows {
        let row = row_from(r)?;
        let Some(accepted) = &row.accepted else {
            continue;
        };
        let Some(doc) = base
            .policy
            .discovery()
            .find(|d| d.metadata.name == row.document)
        else {
            continue;
        };
        let labels: BTreeMap<String, String> =
            serde_json::from_value(accepted["labels"].clone()).unwrap_or_default();
        if let Ok(res) = limen_policy::discovery::resource_doc(
            accepted["name"].as_str().unwrap_or_default(),
            &labels,
            &accepted["spec"],
            &doc.spec.worker_selector,
        ) {
            out.push(res);
        }
    }
    Ok(out)
}

/// Recompute the accepted resources and, if they changed, put them in the
/// effective policy that snapshots carry.
pub async fn refresh_overlay(state: &AppState) -> Result<(), sqlx::Error> {
    let docs = overlay_docs(state).await?;
    state.policy.set_overlay(docs);
    Ok(())
}

/// Count by state, remove what has been stale for long enough, and keep the
/// gauge honest. A resource with an open session is never removed from under it.
pub async fn sweep(state: &AppState) -> Result<(), Status> {
    let base = state.policy.base();
    let stale_rows = sqlx::query(concat!(
        "SELECT ",
        cols!(),
        " FROM discovered_resources WHERE state = 'stale'"
    ))
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal("reading stale resources", e))?;
    for r in &stale_rows {
        let row = row_from(r).map_err(|e| internal("reading", e))?;
        let remove_after = base
            .policy
            .discovery()
            .find(|d| d.metadata.name == row.document)
            .map_or(limen_policy::discovery::DEFAULT_REMOVE_AFTER, |d| {
                d.spec.remove_after()
            });
        let since = row.stale_since.unwrap_or(row.last_seen_at);
        if OffsetDateTime::now_utc() - since < remove_after {
            continue;
        }
        let name = display_name(&row);
        let in_use: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM sessions WHERE resource = $1 AND ended_at IS NULL AND started_at > now() - interval '24 hours')",
        )
        .bind(&name)
        .fetch_one(&state.db)
        .await
        .map_err(|e| internal("checking sessions", e))?;
        if in_use {
            continue;
        }
        audit(
            state,
            EventKind::ResourceStale,
            None,
            json!({ "key": row.key, "resource": name, "document": row.document, "removed": true }),
        )
        .await?;
        sqlx::query("DELETE FROM discovered_resources WHERE key = $1 AND state = 'stale'")
            .bind(&row.key)
            .execute(&state.db)
            .await
            .map_err(|e| internal("removing a stale resource", e))?;
    }
    let counts =
        sqlx::query("SELECT state, count(*) AS n FROM discovered_resources GROUP BY state")
            .fetch_all(&state.db)
            .await
            .map_err(|e| internal("counting discovered resources", e))?;
    for s in ["pending", "accepted", "rejected", "stale"] {
        let n = counts
            .iter()
            .find(|r| r.try_get::<String, _>("state").is_ok_and(|x| x == s))
            .and_then(|r| r.try_get::<i64, _>("n").ok())
            .unwrap_or(0);
        #[allow(clippy::cast_precision_loss)]
        metrics::gauge!("limen_discovered_resources", "state" => s).set(n as f64);
    }
    Ok(())
}

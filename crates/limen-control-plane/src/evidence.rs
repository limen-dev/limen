//! Compliance evidence packs (ADR-0029). A pack gathers, for a period, what
//! an auditor asks for every year: who had access to what, who approved it,
//! whether anyone checked, and what changed. It is a single JSON file with a
//! **manifest of SHA-256 hashes signed by the control plane**, and its export
//! is itself an `evidence.export` audit event carrying the manifest hash, so a
//! pack that was edited, or never produced, shows. `limen-audit-verify
//! --evidence` checks one offline with only the internal CA certificate.
//!
//! The mapping to SOC 2 and ISO 27001 controls in the docs is guidance, not
//! certification.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use base64::Engine as _;
use limen_audit::{Context, EventKind};
use limen_proto::v1::Signed;
use limen_session::envelope::{Purpose, verify};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row as _;
use time::OffsetDateTime;
use tonic::Status;

use crate::state::{AppState, internal};

pub const FORMAT: &str = "limen-evidence/1";
/// Most rows of any section.
const MAX_ROWS: i64 = 50_000;
/// The longest period one pack covers.
const MAX_PERIOD_DAYS: i64 = 400;

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub format: String,
    pub generated_at: i64,
    pub from: i64,
    pub to: i64,
    pub requested_by: String,
    pub control_plane: String,
    /// Section name to the SHA-256 of its canonical JSON and its size.
    pub files: BTreeMap<String, FileEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub sha256: String,
    pub bytes: usize,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// One CSV cell. Cells that a spreadsheet would read as a formula are
/// prefixed so opening the file can't run anything.
fn csv_cell(v: &str) -> String {
    let v = if v.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{v}")
    } else {
        v.to_owned()
    };
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v
    }
}

fn csv(header: &[&str], rows: &[Value]) -> String {
    let mut out = header.join(",");
    out.push('\n');
    for r in rows {
        let cells: Vec<String> = header
            .iter()
            .map(|h| match &r[*h] {
                Value::Null => String::new(),
                Value::String(s) => csv_cell(s),
                Value::Array(a) => csv_cell(
                    &a.iter()
                        .map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_owned))
                        .collect::<Vec<_>>()
                        .join(";"),
                ),
                other => csv_cell(&other.to_string()),
            })
            .collect();
        out.push_str(&cells.join(","));
        out.push('\n');
    }
    out
}

fn rfc(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// Rows of a query as JSON objects, by column name.
async fn rows(
    state: &AppState,
    sql: &'static str,
    from: OffsetDateTime,
    to: OffsetDateTime,
) -> Result<Vec<sqlx::postgres::PgRow>, Status> {
    sqlx::query(sql)
        .bind(from)
        .bind(to)
        .bind(MAX_ROWS)
        .fetch_all(&state.db)
        .await
        .map_err(|e| internal("gathering evidence", e))
}

fn ts(r: &sqlx::postgres::PgRow, c: &str) -> Value {
    r.try_get::<Option<OffsetDateTime>, _>(c)
        .ok()
        .flatten()
        .map_or(Value::Null, |t| json!(rfc(t)))
}

fn text(r: &sqlx::postgres::PgRow, c: &str) -> Value {
    r.try_get::<Option<String>, _>(c)
        .ok()
        .flatten()
        .map_or(Value::Null, Value::String)
}

/// Gather, sign, audit, and return a pack for `[from, to)`.
#[allow(clippy::too_many_lines)] // one section per question an auditor asks
pub async fn export(
    state: &AppState,
    requested_by: &str,
    from_unix: i64,
    to_unix: i64,
) -> Result<(Vec<u8>, String), Status> {
    let from = OffsetDateTime::from_unix_timestamp(from_unix)
        .map_err(|_| Status::invalid_argument("bad from"))?;
    let to = OffsetDateTime::from_unix_timestamp(to_unix)
        .map_err(|_| Status::invalid_argument("bad to"))?;
    if from >= to {
        return Err(Status::invalid_argument("from must be before to"));
    }
    if (to - from).whole_days() > MAX_PERIOD_DAYS {
        return Err(Status::invalid_argument(format!(
            "a pack covers at most {MAX_PERIOD_DAYS} days"
        )));
    }
    let mut sections: BTreeMap<String, Value> = BTreeMap::new();
    let mut notes: Vec<String> = Vec::new();

    // Requests, with who approved.
    let reqs = rows(state, "SELECT r.id, r.requester, r.role, r.resource, r.reason, r.duration_secs, r.status, r.break_glass, r.approvals_required, r.created_at, r.decided_at,
            COALESCE((SELECT jsonb_agg(jsonb_build_object('approver', a.approver, 'decision', a.decision, 'comment', a.comment, 'at', a.decided_at) ORDER BY a.decided_at)
                      FROM access_approvals a WHERE a.request_id = r.id), '[]'::jsonb) AS approvals
         FROM access_requests r WHERE r.created_at >= $1 AND r.created_at < $2 ORDER BY r.created_at LIMIT $3", from, to).await?;
    let requests: Vec<Value> = reqs
        .iter()
        .map(|r| {
            json!({
                "id": r.try_get::<uuid::Uuid, _>("id").map(|u| u.to_string()).unwrap_or_default(),
                "requester": text(r, "requester"), "role": text(r, "role"), "resource": text(r, "resource"),
                "reason": text(r, "reason"), "duration_secs": r.try_get::<i32, _>("duration_secs").unwrap_or(0),
                "status": text(r, "status"), "break_glass": r.try_get::<bool, _>("break_glass").unwrap_or(false),
                "approvals_required": r.try_get::<i32, _>("approvals_required").unwrap_or(1),
                "created_at": ts(r, "created_at"), "decided_at": ts(r, "decided_at"),
                "approvals": r.try_get::<Value, _>("approvals").unwrap_or(Value::Null),
            })
        })
        .collect();
    sections.insert("access_requests".into(), Value::Array(requests.clone()));

    let grants = rows(state, "SELECT request_id, username, role, resource, reason, break_glass, approvers, granted_at, expires_at, revoked_at, revoked_by, revoke_reason
         FROM access_grants WHERE granted_at >= $1 AND granted_at < $2 ORDER BY granted_at LIMIT $3", from, to).await?;
    let grants: Vec<Value> = grants
        .iter()
        .map(|r| {
            json!({
                "request_id": r.try_get::<uuid::Uuid, _>("request_id").map(|u| u.to_string()).unwrap_or_default(),
                "user": text(r, "username"), "role": text(r, "role"), "resource": text(r, "resource"),
                "reason": text(r, "reason"), "break_glass": r.try_get::<bool, _>("break_glass").unwrap_or(false),
                "approvers": r.try_get::<Vec<String>, _>("approvers").unwrap_or_default(),
                "granted_at": ts(r, "granted_at"), "expires_at": ts(r, "expires_at"),
                "revoked_at": ts(r, "revoked_at"), "revoked_by": text(r, "revoked_by"), "revoke_reason": text(r, "revoke_reason"),
            })
        })
        .collect();
    sections.insert("access_grants".into(), Value::Array(grants.clone()));

    // Reviews and what they decided.
    let rev = rows(state, "SELECT i.review_id, r.name AS review, r.started_at, r.status, i.subject, i.subject_type, i.role, i.via, i.sessions_90d, i.last_used_at, i.reviewer, i.decision, i.comment, i.decided_by, i.decided_at
         FROM review_items i JOIN access_reviews r ON r.id = i.review_id WHERE r.started_at >= $1 AND r.started_at < $2 ORDER BY r.started_at, i.subject, i.role LIMIT $3", from, to).await?;
    let reviews: Vec<Value> = rev
        .iter()
        .map(|r| {
            json!({
                "review_id": r.try_get::<uuid::Uuid, _>("review_id").map(|u| u.to_string()).unwrap_or_default(),
                "review": text(r, "review"), "started_at": ts(r, "started_at"), "status": text(r, "status"),
                "subject": text(r, "subject"), "type": text(r, "subject_type"), "role": text(r, "role"), "via": text(r, "via"),
                "sessions_90d": r.try_get::<i32, _>("sessions_90d").unwrap_or(0), "last_used_at": ts(r, "last_used_at"),
                "reviewer": text(r, "reviewer"), "decision": text(r, "decision"), "comment": text(r, "comment"),
                "decided_by": text(r, "decided_by"), "decided_at": ts(r, "decided_at"),
            })
        })
        .collect();
    sections.insert("reviews".into(), Value::Array(reviews.clone()));

    let den = rows(state, "SELECT username, role, reason, created_by, created_at, expires_at, lifted_at, lifted_by, lift_reason
         FROM access_denies WHERE created_at >= $1 AND created_at < $2 ORDER BY created_at LIMIT $3", from, to).await?;
    sections.insert(
        "deny_overrides".into(),
        Value::Array(den.iter().map(|r| json!({
            "user": text(r, "username"), "role": text(r, "role"), "reason": text(r, "reason"), "created_by": text(r, "created_by"),
            "created_at": ts(r, "created_at"), "expires_at": ts(r, "expires_at"), "lifted_at": ts(r, "lifted_at"),
            "lifted_by": text(r, "lifted_by"), "lift_reason": text(r, "lift_reason"),
        })).collect()),
    );

    let locks = rows(
        state,
        "SELECT username, reason, locked_by, locked_at, released_by, released_at
         FROM user_locks WHERE locked_at >= $1 AND locked_at < $2 ORDER BY locked_at LIMIT $3",
        from,
        to,
    )
    .await?;
    sections.insert(
        "locks".into(),
        Value::Array(locks.iter().map(|r| json!({
            "user": text(r, "username"), "reason": text(r, "reason"), "locked_by": text(r, "locked_by"),
            "locked_at": ts(r, "locked_at"), "released_by": text(r, "released_by"), "released_at": ts(r, "released_at"),
        })).collect()),
    );

    let pol = rows(
        state,
        "SELECT version, digest, author, source_ref, created_at
         FROM policy_versions WHERE created_at >= $1 AND created_at < $2 ORDER BY version LIMIT $3",
        from,
        to,
    )
    .await?;
    sections.insert(
        "policy_changes".into(),
        Value::Array(pol.iter().map(|r| json!({
            "version": r.try_get::<i64, _>("version").unwrap_or(0), "digest": text(r, "digest"),
            "author": text(r, "author"), "source_ref": text(r, "source_ref"), "at": ts(r, "created_at"),
        })).collect()),
    );

    let ses = rows(state, "SELECT session_id, username, kind, resource, login, started_at, ended_at, end_reason, request_ids, recording_sha256
         FROM sessions WHERE started_at >= $1 AND started_at < $2 ORDER BY started_at LIMIT $3", from, to).await?;
    let sessions: Vec<Value> = ses
        .iter()
        .map(|r| {
            json!({
                "session_id": r.try_get::<uuid::Uuid, _>("session_id").map(|u| u.to_string()).unwrap_or_default(),
                "user": text(r, "username"), "kind": text(r, "kind"), "resource": text(r, "resource"), "as": text(r, "login"),
                "started_at": ts(r, "started_at"), "ended_at": ts(r, "ended_at"), "end_reason": text(r, "end_reason"),
                "request_ids": r.try_get::<Vec<String>, _>("request_ids").unwrap_or_default(),
                "recording_sha256": text(r, "recording_sha256"),
            })
        })
        .collect();
    sections.insert("sessions".into(), Value::Array(sessions.clone()));

    for (name, v) in &sections {
        if i64::try_from(v.as_array().map_or(0, Vec::len)).unwrap_or(0) >= MAX_ROWS {
            notes.push(format!(
                "{name} was cut at {MAX_ROWS} rows; narrow the period"
            ));
        }
    }
    notes.push("Session kills and component revocations are kept in the console for two days and in the audit sinks for good; use the audit trail for those.".into());
    notes.push("Roles come from the IdP groups at each person's latest login.".into());
    let policy = state.policy.base();
    sections.insert(
        "meta".into(),
        json!({
            "generated_at": rfc(OffsetDateTime::now_utc()), "from": rfc(from), "to": rfc(to),
            "requested_by": requested_by, "policy_version": policy.version, "policy_digest": policy.policy.digest(),
            "notes": notes,
            "counts": sections.iter().map(|(k, v)| (k.clone(), v.as_array().map_or(0, Vec::len))).collect::<BTreeMap<_, _>>(),
        }),
    );
    // The same facts, for a spreadsheet.
    sections.insert(
        "sessions.csv".into(),
        Value::String(csv(
            &[
                "session_id",
                "user",
                "kind",
                "resource",
                "as",
                "started_at",
                "ended_at",
                "end_reason",
                "request_ids",
            ],
            &sessions,
        )),
    );
    sections.insert(
        "access_requests.csv".into(),
        Value::String(csv(
            &[
                "id",
                "requester",
                "role",
                "resource",
                "reason",
                "status",
                "break_glass",
                "created_at",
                "decided_at",
            ],
            &requests,
        )),
    );
    sections.insert(
        "access_grants.csv".into(),
        Value::String(csv(
            &[
                "request_id",
                "user",
                "role",
                "resource",
                "reason",
                "break_glass",
                "approvers",
                "granted_at",
                "expires_at",
                "revoked_at",
            ],
            &grants,
        )),
    );
    sections.insert(
        "reviews.csv".into(),
        Value::String(csv(
            &[
                "review",
                "subject",
                "type",
                "role",
                "via",
                "sessions_90d",
                "reviewer",
                "decision",
                "comment",
                "decided_by",
                "decided_at",
            ],
            &reviews,
        )),
    );

    let mut files = BTreeMap::new();
    for (name, v) in &sections {
        let bytes = serde_json::to_vec(v).map_err(|e| internal("encoding evidence", e))?;
        files.insert(
            name.clone(),
            FileEntry {
                sha256: sha(&bytes),
                bytes: bytes.len(),
            },
        );
    }
    let manifest = Manifest {
        format: FORMAT.to_owned(),
        generated_at: OffsetDateTime::now_utc().unix_timestamp(),
        from: from_unix,
        to: to_unix,
        requested_by: requested_by.to_owned(),
        control_plane: state.config.id.clone(),
        files,
    };
    let manifest_json =
        serde_json::to_string(&manifest).map_err(|e| internal("encoding the manifest", e))?;
    let manifest_sha256 = sha(manifest_json.as_bytes());
    let key = state
        .snapshot_signer
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .ok_or_else(|| Status::unavailable("signing key not ready"))?;
    let signed = key
        .sign(Purpose::EvidencePack, manifest_json.clone().into_bytes())
        .map_err(|e| internal("signing evidence", e))?;

    // Anchored in the audit chain before the pack leaves: no event, no pack.
    state
        .audit
        .emit(
            EventKind::EvidenceExport,
            Context { user: Some(requested_by.to_owned()), session_id: None },
            json!({ "manifest_sha256": manifest_sha256, "from": from_unix, "to": to_unix, "sections": manifest.files.len() }),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "audit unavailable; refusing an evidence export");
            Status::unavailable("audit unavailable")
        })?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let pack = json!({
        "format": FORMAT,
        "manifest_json": manifest_json,
        "manifest_sha256": manifest_sha256,
        "signature_b64": b64.encode(&signed.signature),
        "signer_cert_b64": b64.encode(&signed.signer_cert_der),
        "sections": sections,
    });
    Ok((
        serde_json::to_vec_pretty(&pack).map_err(|e| internal("encoding the pack", e))?,
        manifest_sha256,
    ))
}

/// What checking a pack found.
#[derive(Debug, Default)]
pub struct Verification {
    pub manifest: Option<Manifest>,
    pub manifest_sha256: String,
    pub problems: Vec<String>,
}

impl Verification {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.problems.is_empty() && self.manifest.is_some()
    }
}

/// Check a pack offline: the manifest is signed by a control plane the
/// internal CA issued, and every section is what the manifest says.
#[must_use]
pub fn verify_pack(
    pack: &[u8],
    internal_ca: &rustls_pki_types::CertificateDer<'_>,
) -> Verification {
    let mut out = Verification::default();
    let b64 = base64::engine::general_purpose::STANDARD;
    let Ok(v) = serde_json::from_slice::<Value>(pack) else {
        out.problems.push("not a JSON document".into());
        return out;
    };
    if v["format"] != FORMAT {
        out.problems.push(format!("not a {FORMAT} pack"));
        return out;
    }
    let (Some(manifest_json), Some(sig), Some(cert)) = (
        v["manifest_json"].as_str(),
        v["signature_b64"].as_str().and_then(|s| b64.decode(s).ok()),
        v["signer_cert_b64"]
            .as_str()
            .and_then(|s| b64.decode(s).ok()),
    ) else {
        out.problems
            .push("the manifest or its signature is missing".into());
        return out;
    };
    out.manifest_sha256 = sha(manifest_json.as_bytes());
    if v["manifest_sha256"] != json!(out.manifest_sha256) {
        out.problems
            .push("the manifest hash in the pack doesn't match the manifest".into());
    }
    let signed = Signed {
        payload: manifest_json.as_bytes().to_vec(),
        signature: sig,
        signer_cert_der: cert,
    };
    if let Err(e) = verify(&signed, Purpose::EvidencePack, internal_ca) {
        out.problems
            .push(format!("the manifest's signature is not valid: {e}"));
        return out;
    }
    let Ok(manifest) = serde_json::from_str::<Manifest>(manifest_json) else {
        out.problems.push("the manifest is unreadable".into());
        return out;
    };
    let empty = serde_json::Map::new();
    let sections = v["sections"].as_object().unwrap_or(&empty);
    for (name, entry) in &manifest.files {
        match sections.get(name) {
            None => out.problems.push(format!("section {name} is missing")),
            Some(s) => {
                let bytes = serde_json::to_vec(s).unwrap_or_default();
                if sha(&bytes) != entry.sha256 {
                    out.problems
                        .push(format!("section {name} was changed after it was signed"));
                }
            }
        }
    }
    for name in sections.keys().filter(|n| !manifest.files.contains_key(*n)) {
        out.problems
            .push(format!("section {name} is not in the signed manifest"));
    }
    out.manifest = Some(manifest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_cells_cannot_run_in_a_spreadsheet_and_quote_properly() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_cell("+1"), "'+1");
        assert_eq!(csv_cell("@sum"), "'@sum");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn csv_has_a_header_and_one_row_each() {
        let rows = vec![
            json!({ "a": "x", "b": ["p", "q"], "c": 3 }),
            json!({ "a": null }),
        ];
        assert_eq!(csv(&["a", "b", "c"], &rows), "a,b,c\nx,p;q,3\n,,\n");
    }

    #[test]
    fn junk_is_not_a_pack() {
        let ca = rustls_pki_types::CertificateDer::from(vec![0u8]);
        for junk in [
            &b"not json"[..],
            b"{}",
            b"{\"format\":\"limen-evidence/1\"}",
        ] {
            assert!(!verify_pack(junk, &ca).ok());
        }
    }
}

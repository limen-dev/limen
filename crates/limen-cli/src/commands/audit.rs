//! `limen audit search` (ADR-0026) and `limen audit verify` (ADR-0009, ADR-0029).

use clap::Subcommand;
use limen_proto::v1::SearchRequest;
use limen_proto::v1::audit_search_client::AuditSearchClient;
use time::OffsetDateTime;

use crate::{api, ui};

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Find audit events and, if the operator indexes them, text from recordings.
    ///
    /// Words must all appear. "Quoted phrases" match as written. Filters:
    /// user:  resource:  kind:  session:  after:  before:  outcome:
    /// Dates are 2026-10-01 or an age such as 24h or 7d. Every search is
    /// itself recorded in the audit trail.
    Search {
        query: String,
        /// The most hits to return (up to 200).
        #[arg(long, default_value_t = 50)]
        limit: u32,
        /// Output JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Check the audit trail in S3, or an evidence pack, without trusting Limen.
    ///
    /// For auditors and operators. It does not sign in to Limen and asks it
    /// nothing. By default it reads the audit bucket directly with your AWS
    /// credentials, so it needs the read-only verifier policy from the audit
    /// Terraform module (`verifier_policy_json`); without that, S3 refuses.
    /// With --evidence it checks a pack from `limen admin evidence` offline,
    /// with only the internal CA certificate. Exits 2 if anything fails.
    Verify {
        /// Check a pack from `limen admin evidence` instead of the S3 trail.
        #[arg(long, value_name = "FILE")]
        evidence: Option<std::path::PathBuf>,
        /// With --evidence: an audit JSONL file; the pack's export event must be in it.
        #[arg(long, value_name = "FILE", requires = "evidence")]
        audit_events: Option<std::path::PathBuf>,
        /// The audit bucket.
        #[arg(
            long,
            env = "LIMEN_AUDIT_S3_BUCKET",
            required_unless_present = "evidence"
        )]
        bucket: Option<String>,
        #[arg(long, env = "LIMEN_AUDIT_S3_PREFIX", default_value = "")]
        prefix: String,
        #[arg(long, env = "LIMEN_AUDIT_S3_ENDPOINT")]
        endpoint: Option<String>,
        #[arg(long, env = "LIMEN_AUDIT_S3_PATH_STYLE")]
        path_style: bool,
        /// The Limen internal CA certificate (PEM): manifests must be signed by
        /// a control plane certificate it issued.
        #[arg(long)]
        ca_file: std::path::PathBuf,
    },
}

pub async fn run(proxy: Option<&str>, command: AuditCommand) -> anyhow::Result<()> {
    match command {
        AuditCommand::Search { query, limit, json } => search(proxy, &query, limit, json).await,
        AuditCommand::Verify {
            evidence,
            audit_events,
            bucket,
            prefix,
            endpoint,
            path_style,
            ca_file,
        } => {
            let pem = std::fs::read_to_string(&ca_file)?;
            let ca = limen_tunnel::tls::certs_from_pem(&pem)?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("no certificate in {}", ca_file.display()))?;
            if let Some(path) = &evidence {
                return verify_evidence(path, audit_events.as_deref(), &ca);
            }
            verify_bucket(
                &bucket.unwrap_or_default(),
                &prefix,
                endpoint.as_deref(),
                path_style,
                &ca,
            )
            .await
        }
    }
}

fn when(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

async fn search(proxy: Option<&str>, query: &str, limit: u32, json: bool) -> anyhow::Result<()> {
    let (_, channel) = api::authenticated(proxy)?;
    let resp = AuditSearchClient::new(channel)
        .search(SearchRequest {
            query: query.to_owned(),
            limit,
        })
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    if json {
        let hits: Vec<_> = resp
            .hits
            .iter()
            .map(|h| {
                serde_json::json!({
                    "at": when(h.at_unix), "kind": h.kind, "user": h.user, "resource": h.resource,
                    "session_id": h.session_id, "outcome": h.outcome,
                    "text": format!("{}{}{}", h.before, h.matched, h.after),
                    "match": h.matched,
                    "recording_offset_secs": (h.recording_offset_secs >= 0).then_some(h.recording_offset_secs),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "hits": hits, "truncated": resp.truncated,
                "history_url": (!resp.history_url.is_empty()).then_some(&resp.history_url),
            }))?
        );
        return Ok(());
    }
    if resp.hits.is_empty() {
        ui::info("Nothing matches.");
        ui::hint(
            "Search covers recent events only (30 days unless the operator changed it); older history is in the audit sinks.",
        );
        return Ok(());
    }
    for h in &resp.hits {
        let outcome = if h.outcome == "denied" {
            ui::red(" denied")
        } else {
            String::new()
        };
        anstream::println!(
            "{}  {}  {}{}",
            ui::dim(&when(h.at_unix)),
            ui::bold(&h.kind),
            [h.user.as_str(), h.resource.as_str()]
                .iter()
                .filter(|s| !s.is_empty())
                .copied()
                .collect::<Vec<_>>()
                .join(" on "),
            outcome
        );
        anstream::println!(
            "    {}{}{}",
            one_line(&h.before),
            ui::yellow(&one_line(&h.matched)),
            one_line(&h.after)
        );
        if !h.session_id.is_empty() {
            let at = if h.recording_offset_secs >= 0 {
                format!(" · recording at +{}s", h.recording_offset_secs)
            } else {
                String::new()
            };
            anstream::println!("    {}", ui::dim(&format!("session {}{at}", h.session_id)));
        }
    }
    if resp.truncated {
        ui::hint("More matched than shown. Narrow it with user:, resource:, kind:, or after:.");
    }
    if !resp.history_url.is_empty() {
        ui::hint(&format!("Full history: {}", resp.history_url));
    }
    Ok(())
}

/// Newlines in a snippet would break the layout.
fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

/// Walk every writer's chain in the audit bucket (ADR-0009).
async fn verify_bucket(
    bucket: &str,
    prefix: &str,
    endpoint: Option<&str>,
    path_style: bool,
    ca: &rustls_pki_types::CertificateDer<'_>,
) -> anyhow::Result<()> {
    let client = limen_verify::s3_client(endpoint, path_style).await;
    let report = limen_verify::bucket::verify_bucket(&client, bucket, prefix, ca)
        .await
        .map_err(|e| {
            let text = format!("{e:#}");
            let refused = ["AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "credentials"];
            if refused.iter().any(|r| text.contains(r)) {
                anyhow::anyhow!(
                    "{text}\nReading the audit bucket needs the read-only verifier policy from the audit Terraform module (verifier_policy_json). Ask whoever runs your audit bucket."
                )
            } else {
                e
            }
        })?;
    eprintln!(
        "writers: {}, batches: {}, records: {}, distinct events: {}",
        report.writers, report.batches, report.records, report.events
    );
    if report.chain_ok() {
        eprintln!("OK: every batch is present, unmodified, signed, and chained");
    } else {
        for p in &report.problems {
            eprintln!("PROBLEM: {p}");
        }
    }
    if report.seq_gaps.is_empty() {
        eprintln!("OK: no producer has a sequence gap");
    } else {
        for g in &report.seq_gaps {
            eprintln!("GAP: {g}");
        }
        eprintln!(
            "  (a gap is an event that was not recorded or not shipped; under fail_closed a refused action's failed emit also leaves one)"
        );
    }
    if report.seq_conflicts.is_empty() {
        eprintln!("OK: no sequence number is used by two events");
    } else {
        for c in &report.seq_conflicts {
            eprintln!("CONFLICT: {c}");
        }
    }
    if report.ok() {
        Ok(())
    } else {
        std::process::exit(2);
    }
}

/// Check an evidence pack offline (ADR-0029).
fn verify_evidence(
    path: &std::path::Path,
    audit_events: Option<&std::path::Path>,
    ca: &rustls_pki_types::CertificateDer<'_>,
) -> anyhow::Result<()> {
    let pack = std::fs::read(path)?;
    let v = limen_verify::pack::verify_pack(&pack, ca);
    let mut problems = v.problems.clone();
    if let (Some(events), Some(_)) = (audit_events, &v.manifest) {
        let text = std::fs::read_to_string(events)?;
        let anchored = text.lines().any(|l| {
            serde_json::from_str::<serde_json::Value>(l).is_ok_and(|e| {
                e["kind"] == "evidence.export" && e["data"]["manifest_sha256"] == v.manifest_sha256
            })
        });
        if anchored {
            eprintln!("OK: the export is recorded in the audit trail");
        } else {
            problems.push(format!(
                "no evidence.export event with manifest {} is in {}",
                v.manifest_sha256,
                events.display()
            ));
        }
    }
    if let Some(m) = &v.manifest {
        eprintln!(
            "pack for {} to {}, {} sections, exported by {} from {}",
            m.from,
            m.to,
            m.files.len(),
            m.requested_by,
            m.control_plane
        );
    }
    if problems.is_empty() {
        eprintln!("OK: the manifest is signed by the control plane and every section matches it");
        Ok(())
    } else {
        for p in &problems {
            eprintln!("PROBLEM: {p}");
        }
        std::process::exit(2);
    }
}

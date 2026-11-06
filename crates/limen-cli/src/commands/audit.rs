//! `limen audit search` (ADR-0026) and `limen audit verify` (ADR-0009, ADR-0029).

use clap::Subcommand;
use limen_proto::v1::audit_search_client::AuditSearchClient;
use limen_proto::v1::{SearchRequest, VerifierAccessRequest};
use time::OffsetDateTime;

use crate::{api, profile, ui};

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
    /// Check that the audit trail is intact: signed, chained, with nothing
    /// missing or altered.
    ///
    /// For auditors and admins (`limen:auditor` or `limen:admin`). Limen
    /// decides who may, records that you did, and gives your session
    /// short-lived read-only access to the audit bucket. The check itself runs
    /// on your machine, against the CA you pinned at login, so it does not
    /// rest on Limen's word. Exits 2 if anything fails.
    ///
    /// With --evidence it checks a pack from `limen admin evidence` offline
    /// instead, with no login: give it the pack and the CA certificate.
    Verify {
        /// Check a pack from `limen admin evidence`, offline.
        #[arg(long, value_name = "FILE")]
        evidence: Option<std::path::PathBuf>,
        /// With --evidence: an audit JSONL file; the pack's export event must be in it.
        #[arg(long, value_name = "FILE", requires = "evidence")]
        audit_events: Option<std::path::PathBuf>,
        /// The Limen internal CA certificate (PEM). Defaults to the CA pinned
        /// when you logged in. Needed with --evidence if you are not logged in.
        #[arg(long)]
        ca_file: Option<std::path::PathBuf>,
    },
}

pub async fn run(proxy: Option<&str>, command: AuditCommand) -> anyhow::Result<()> {
    match command {
        AuditCommand::Search { query, limit, json } => search(proxy, &query, limit, json).await,
        AuditCommand::Verify {
            evidence,
            audit_events,
            ca_file,
        } => {
            let ca = trusted_ca(proxy, ca_file.as_deref(), evidence.is_some())?;
            match evidence {
                Some(path) => verify_evidence(&path, audit_events.as_deref(), &ca),
                None => verify_bucket(proxy, &ca).await,
            }
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
/// One printable line: any control character (line breaks, and the escape
/// that starts a terminal sequence) becomes a space. The text comes from
/// events other people caused, and an auditor's terminal is not theirs to
/// rewrite.
fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::one_line;

    #[test]
    fn terminal_escapes_are_not_printed() {
        let out = one_line("a\u{1b}[2Kb\u{1b}]0;title\u{7}c\nd\r");
        assert!(!out.chars().any(char::is_control), "{out:?}");
        assert!(out.starts_with('a') && out.contains('d'));
    }
}

/// The CA manifests and packs must be signed under: `--ca-file`, else the one
/// pinned at login. Never anything Limen sends along with the data.
fn trusted_ca(
    proxy: Option<&str>,
    ca_file: Option<&std::path::Path>,
    offline: bool,
) -> anyhow::Result<rustls_pki_types::CertificateDer<'static>> {
    let pem = if let Some(path) = ca_file {
        std::fs::read_to_string(path)?
    } else {
        let pinned = match api::resolve_proxy(proxy) {
            Ok(p) => profile::trusted_ca(&p)?,
            Err(_) => None,
        };
        pinned.ok_or_else(|| {
            if offline {
                anyhow::anyhow!("give the Limen internal CA certificate with --ca-file")
            } else {
                anyhow::anyhow!("not logged in; run `limen login`")
            }
        })?
    };
    limen_tunnel::tls::certs_from_pem(&pem)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no certificate in the CA file"))
}

/// Ask Limen for read-only access to the audit bucket, then walk every
/// writer's chain from here (ADR-0009).
async fn verify_bucket(
    proxy: Option<&str>,
    ca: &rustls_pki_types::CertificateDer<'_>,
) -> anyhow::Result<()> {
    let (_, channel) = api::authenticated(proxy)?;
    let grant = AuditSearchClient::new(channel)
        .verifier_access(VerifierAccessRequest {})
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    let access = limen_verify::Access {
        endpoint: Some(grant.endpoint).filter(|e| !e.is_empty()),
        path_style: grant.path_style,
        region: grant.region,
        access_key_id: grant.access_key_id,
        secret_access_key: grant.secret_access_key,
        session_token: Some(grant.session_token).filter(|t| !t.is_empty()),
        expires_unix: u64::try_from(grant.expires_unix).ok().filter(|e| *e > 0),
    };
    let client = limen_verify::s3_client_with(&access);
    let report = limen_verify::bucket::verify_bucket(&client, &grant.bucket, &grant.prefix, ca)
        .await
        .map_err(|e| {
            let text = format!("{e:#}");
            let refused = ["AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch"];
            if refused.iter().any(|r| text.contains(r)) {
                anyhow::anyhow!(
                    "{text}\nLimen's verifier role could not read the audit bucket. Whoever runs your audit bucket needs to give that role the verifier_policy_json permissions."
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

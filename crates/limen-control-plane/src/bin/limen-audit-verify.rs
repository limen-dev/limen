//! Verify the integrity of the S3 audit trail.
//!
//!   limen-audit-verify --bucket limen-audit --ca-file internal-ca.pem
//!
//! Exits non-zero if any batch is missing, modified, reordered, or unsigned,
//! if any producer has a gap in its event sequence numbers, or if one
//! sequence number is carried by two different events.
//!
//! A gap means an event was not recorded or not shipped. "Not recorded"
//! includes an emit that failed in the `fail_closed` audit mode: it used up
//! its number and the action it audited was refused.

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "limen-audit-verify", version = limen_core::VERSION, about)]
struct Args {
    /// Check a compliance evidence pack instead of the S3 trail: the file
    /// from `limen admin evidence`. Needs only `--ca-file`.
    #[arg(long, value_name = "FILE")]
    evidence: Option<std::path::PathBuf>,
    /// With `--evidence`: an audit JSONL file; the pack's export event must be in it.
    #[arg(long, value_name = "FILE", requires = "evidence")]
    audit_events: Option<std::path::PathBuf>,
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let pem = std::fs::read_to_string(&args.ca_file)?;
    let ca = limen_tunnel::tls::certs_from_pem(&pem)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no certificate in {}", args.ca_file.display()))?;
    if let Some(path) = &args.evidence {
        return verify_evidence(path, args.audit_events.as_deref(), &ca);
    }
    let bucket = args.bucket.clone().unwrap_or_default();
    let client =
        limen_control_plane::sinks::s3_client(args.endpoint.as_deref(), args.path_style).await;
    let report =
        limen_control_plane::verify::verify_bucket(&client, &bucket, &args.prefix, &ca).await?;
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
    let v = limen_control_plane::evidence::verify_pack(&pack, ca);
    let mut problems = v.problems.clone();
    if let (Some(events), Some(m)) = (audit_events, &v.manifest) {
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
        let _ = m;
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

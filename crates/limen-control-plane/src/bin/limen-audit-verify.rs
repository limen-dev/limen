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
    #[arg(long, env = "LIMEN_AUDIT_S3_BUCKET")]
    bucket: String,
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
    let client =
        limen_control_plane::sinks::s3_client(args.endpoint.as_deref(), args.path_style).await;
    let report =
        limen_control_plane::verify::verify_bucket(&client, &args.bucket, &args.prefix, &ca)
            .await?;
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

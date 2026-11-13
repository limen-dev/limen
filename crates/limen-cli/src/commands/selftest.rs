//! `limen admin selftest ...` (ADR-0053): run the scheduled self-test of the
//! controls, read its runs, and fetch a signed report. `limen audit verify
//! --controls` checks a report offline.

use anyhow::Context as _;
use clap::Subcommand;
use limen_proto::v1::controls_client::ControlsClient;
use limen_proto::v1::{
    GetControlsReportRequest, ListSelfTestRunsRequest, RunSelfTestRequest, SelfTestRunInfo,
};
use time::OffsetDateTime;

use crate::{api, ui};

#[derive(Debug, Subcommand)]
pub enum SelftestCommand {
    /// Test the controls now and wait for the result (`limen:admin`).
    ///
    /// The control plane checks its own controls with a test principal that
    /// can never gain access: a denied path is denied, an expired certificate
    /// is refused, a lock is seen, the audit trail is shipping. It runs
    /// itself every day as well. A run is at most once a minute; if one is
    /// already running, you wait for that one. Exits 2 if a control failed.
    Run {
        /// Start it and return without waiting.
        #[arg(long)]
        no_wait: bool,
    },
    /// The latest runs (`limen:admin` or `limen:auditor`).
    Ls {
        #[arg(long, default_value_t = 10)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// Save the signed report of a run (`limen:admin` or `limen:auditor`).
    Report {
        /// The run's id, from `limen admin selftest ls`. Default: the latest with a report.
        id: Option<String>,
        /// Where to save it. Default: `limen-controls-report-<when the run started, UTC>.json`
        /// in the current directory.
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
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

fn verdict(status: &str) -> String {
    match status {
        "passed" => ui::green(status),
        "failed" | "error" => ui::red(status),
        other => ui::yellow(other),
    }
}

fn describe(r: &SelfTestRunInfo) -> String {
    format!(
        "{} passed, {} failed, {} skipped",
        r.passed, r.failed, r.skipped
    )
}

/// The runs as a table (colour included; tests strip it).
fn runs_table(runs: &[SelfTestRunInfo]) -> String {
    let rows: Vec<[String; 5]> = runs
        .iter()
        .map(|r| {
            [
                r.id.clone(),
                when(r.started_at_unix),
                r.trigger.clone(),
                verdict(&r.status),
                describe(r),
            ]
        })
        .collect();
    ui::table(["RUN", "STARTED", "BY", "RESULT", "CHECKS"], &rows)
}

pub async fn run(proxy: Option<&str>, command: SelftestCommand) -> anyhow::Result<()> {
    let (_, channel) = api::authenticated(proxy)?;
    let mut client = ControlsClient::new(channel);
    match command {
        SelftestCommand::Run { no_wait } => {
            let started = client
                .run_self_test(RunSelfTestRequest {})
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner();
            if started.already_running {
                ui::info("A self-test is already running; waiting for it.");
            }
            if no_wait {
                ui::success(&format!("Started self-test {}.", started.id));
                return Ok(());
            }
            let spinner = ui::spinner("Testing the controls");
            let mut finished = None;
            for _ in 0..180 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let runs = client
                    .list_self_test_runs(ListSelfTestRunsRequest { limit: 20 })
                    .await
                    .map_err(|s| api::status_error(&s))?
                    .into_inner()
                    .runs;
                if let Some(r) = runs
                    .into_iter()
                    .find(|r| r.id == started.id && r.status != "running")
                {
                    finished = Some(r);
                    break;
                }
            }
            drop(spinner);
            let r = finished.context("the self-test did not finish within three minutes")?;
            anstream::println!("{}  {}", verdict(&r.status), describe(&r));
            if !r.error.is_empty() {
                ui::warn(&r.error);
            }
            if r.status == "passed" {
                ui::hint(&format!(
                    "Save the signed report with `limen admin selftest report {}`.",
                    r.id
                ));
                if r.skipped > 0 {
                    ui::hint(
                        "Skipped checks did not run; the report says why. A skipped check is not a pass.",
                    );
                }
                Ok(())
            } else {
                std::process::exit(2);
            }
        }
        SelftestCommand::Ls { limit, json } => {
            let runs = client
                .list_self_test_runs(ListSelfTestRunsRequest { limit })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner()
                .runs;
            if json {
                let rows: Vec<_> = runs
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "id": r.id, "trigger": r.trigger, "requested_by": r.requested_by,
                            "status": r.status, "started_at": when(r.started_at_unix),
                            "finished_at": (r.finished_at_unix > 0).then(|| when(r.finished_at_unix)),
                            "passed": r.passed, "failed": r.failed, "skipped": r.skipped,
                            "manifest_sha256": r.manifest_sha256, "error": r.error,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
                return Ok(());
            }
            if runs.is_empty() {
                ui::info("No self-test has run yet.");
                ui::hint(
                    "`limen admin selftest run` starts one. They run by themselves every day.",
                );
                return Ok(());
            }
            anstream::print!("{}", runs_table(&runs));
            Ok(())
        }
        SelftestCommand::Report { id, out } => {
            let id = match id {
                Some(id) => id,
                None => client
                    .list_self_test_runs(ListSelfTestRunsRequest { limit: 50 })
                    .await
                    .map_err(|s| api::status_error(&s))?
                    .into_inner()
                    .runs
                    .into_iter()
                    .find(|r| !r.manifest_sha256.is_empty())
                    .map(|r| r.id)
                    .context("no run has a report yet")?,
            };
            let r = client
                .get_controls_report(GetControlsReportRequest { id })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner();
            let out = out.unwrap_or_else(|| {
                std::path::PathBuf::from(limen_verify::controls::report_file_name(
                    r.run.as_ref().map_or(0, |run| run.started_at_unix),
                ))
            });
            crate::profile::atomic_write(&out, &r.report, 0o600)
                .with_context(|| format!("writing {}", out.display()))?;
            ui::success(&format!(
                "Wrote {} ({} bytes), signed.",
                out.display(),
                r.report.len()
            ));
            ui::hint(
                "The control plane signs its own report. Check it anywhere with `limen audit verify --controls <file> --ca-file internal-ca.pem`, and verify the audit trail itself with `limen audit verify`.",
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(id: &str, status: &str, failed: u32, skipped: u32) -> SelfTestRunInfo {
        SelfTestRunInfo {
            id: id.into(),
            trigger: "schedule".into(),
            status: status.into(),
            started_at_unix: 1_794_000_000,
            passed: 6,
            failed,
            skipped,
            ..SelfTestRunInfo::default()
        }
    }

    #[test]
    fn the_table_shows_the_verdict_and_every_count_in_plain_text() {
        let out = ui::plain(&runs_table(&[
            run("r-1", "passed", 0, 2),
            run("r-2", "failed", 1, 0),
        ]));
        assert!(out.contains("RUN") && out.contains("RESULT"), "{out}");
        assert!(out.contains("6 passed, 0 failed, 2 skipped"), "{out}");
        assert!(out.contains("failed") && out.contains("1 failed"), "{out}");
        assert!(!out.contains('\u{1b}'), "colour must be stripped: {out:?}");
    }
}

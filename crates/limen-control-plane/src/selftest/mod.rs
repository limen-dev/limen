//! The scheduled self-test and controls report (ADR-0051).
//!
//! A run is claimed with one row in `selftest_runs` (a partial unique index
//! lets only one run be `running` across every replica), runs the checks in
//! [`checks`], anchors the report's manifest hash in the audit trail, signs
//! it, checks the signature it just made, and keeps the exact bytes.
//!
//! The report is the control plane attesting to itself; it says so inside
//! the signature.

pub mod checks;

use std::time::Duration;

use limen_audit::{Context, EventKind};
use limen_verify::controls::{ATTESTATION, Counts, Meta, Prepared, Run, Status, verify_report};
use serde_json::json;
use sqlx::Row as _;
use time::OffsetDateTime;
use tokio::sync::watch;
use tonic::Status as GrpcStatus;
use uuid::Uuid;

use crate::state::{AppState, internal};

/// Who a scheduled run is attributed to. The reserved prefix keeps it from
/// ever being a person (ADR-0051).
pub const SCHEDULER: &str = "selftest:scheduler";
/// A manual run may start at most this often.
const MANUAL_GAP_SECS: f64 = 60.0;
/// A run still `running` after this long belonged to a replica that died.
const ABANDON_AFTER_MINS: i64 = 15;
/// Runs are kept as long as the longest evidence-pack period.
const RETENTION_DAYS: i64 = 400;
/// The most a run waits after startup before the first scheduled run.
const STARTUP_GRACE: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    Schedule,
    Manual,
}

impl Trigger {
    fn as_str(self) -> &'static str {
        match self {
            Trigger::Schedule => "schedule",
            Trigger::Manual => "manual",
        }
    }
}

/// One row of `selftest_runs`, without the report.
#[derive(Debug, Clone)]
pub struct RunRow {
    pub id: Uuid,
    pub trigger: String,
    pub requested_by: String,
    pub status: String,
    pub started_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
    pub passed: i32,
    pub failed: i32,
    pub skipped: i32,
    pub manifest_sha256: Option<String>,
    pub error: Option<String>,
}

macro_rules! cols {
    () => {
        "id, trigger, requested_by, status, started_at, finished_at, passed, failed, skipped, manifest_sha256, error"
    };
}

fn row(r: &sqlx::postgres::PgRow) -> Result<RunRow, sqlx::Error> {
    Ok(RunRow {
        id: r.try_get("id")?,
        trigger: r.try_get("trigger")?,
        requested_by: r.try_get("requested_by")?,
        status: r.try_get("status")?,
        started_at: r.try_get("started_at")?,
        finished_at: r.try_get("finished_at")?,
        passed: r.try_get("passed")?,
        failed: r.try_get("failed")?,
        skipped: r.try_get("skipped")?,
        manifest_sha256: r.try_get("manifest_sha256")?,
        error: r.try_get("error")?,
    })
}

/// What asking for a run produced.
#[derive(Debug, Clone)]
pub enum Started {
    /// This call started a run; it finishes in the background.
    New(RunRow),
    /// A run is already in progress; this is it.
    AlreadyRunning(RunRow),
}

/// Claim a run: at most one `running` row exists across replicas, and a
/// scheduled claim needs that no scheduled run started within the interval.
///
/// # Errors
/// `resource_exhausted` for a second manual run within a minute; `internal`
/// for a database failure.
pub async fn claim(
    state: &AppState,
    trigger: Trigger,
    requested_by: &str,
) -> Result<Option<Started>, GrpcStatus> {
    let db = &state.db;
    // A replica that died mid-run left a row nobody will finish.
    sqlx::query(
        "UPDATE selftest_runs SET status = 'abandoned', finished_at = now(),
                error = 'the control plane running it stopped before it finished'
         WHERE status = 'running' AND started_at < now() - make_interval(mins => $1)",
    )
    .bind(i32::try_from(ABANDON_AFTER_MINS).unwrap_or(15))
    .execute(db)
    .await
    .map_err(|e| internal("abandoning stale self-test runs", e))?;

    if trigger == Trigger::Manual {
        let recent: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM selftest_runs WHERE trigger = 'manual' AND status <> 'running'
                            AND started_at > now() - make_interval(secs => $1))",
        )
        .bind(MANUAL_GAP_SECS)
        .fetch_one(db)
        .await
        .map_err(|e| internal("checking recent manual runs", e))?;
        if recent {
            return Err(GrpcStatus::resource_exhausted(
                "a self-test was run by hand a moment ago; wait a minute",
            ));
        }
    }
    let interval_secs = state.config.selftest_interval.as_secs_f64();
    let id = Uuid::now_v7();
    // `NOT EXISTS (scheduled run in the interval)` makes the replicas agree on
    // who runs; the unique index makes a tie impossible.
    let inserted = sqlx::query(concat!(
        "INSERT INTO selftest_runs (id, trigger, requested_by, control_plane, status)
         SELECT $1::uuid, $2::text, $3::text, $4::text, 'running'
         WHERE $2::text = 'manual' OR NOT EXISTS (
             SELECT 1 FROM selftest_runs
             WHERE trigger = 'schedule' AND status <> 'abandoned'
               AND started_at > now() - make_interval(secs => CASE WHEN status = 'error' THEN $6::float8 ELSE $5::float8 END))
         ON CONFLICT DO NOTHING
         RETURNING ", cols!(), ""
    ))
    .bind(id)
    .bind(trigger.as_str())
    .bind(requested_by)
    .bind(&state.config.id)
    .bind(interval_secs)
    // A run that ended in an error is tried again sooner (a quarter of the
    // interval, at most an hour) so a passing audit outage doesn't cost a day.
    .bind(interval_secs.div_euclid(4.0).clamp(1.0, 3600.0))
    .fetch_optional(db)
    .await
    .map_err(|e| internal("claiming a self-test run", e))?;
    if let Some(r) = inserted {
        return Ok(Some(Started::New(
            row(&r).map_err(|e| internal("reading a run", e))?,
        )));
    }
    // Either one is running, or (scheduled) another replica already ran it.
    let running = sqlx::query(concat!(
        "SELECT ",
        cols!(),
        " FROM selftest_runs WHERE status = 'running' LIMIT 1"
    ))
    .fetch_optional(db)
    .await
    .map_err(|e| internal("reading the running self-test", e))?;
    match running {
        Some(r) => Ok(Some(Started::AlreadyRunning(
            row(&r).map_err(|e| internal("reading a run", e))?,
        ))),
        None => Ok(None),
    }
}

/// Start a run in the background and return at once. The caller polls
/// [`list`] for the end.
///
/// # Errors
/// As [`claim`].
pub async fn start(
    state: &AppState,
    trigger: Trigger,
    requested_by: &str,
) -> Result<Option<Started>, GrpcStatus> {
    let claimed = claim(state, trigger, requested_by).await?;
    if let Some(Started::New(r)) = &claimed {
        let state = state.clone();
        let (id, started_at, who) = (r.id, r.started_at, requested_by.to_owned());
        tokio::spawn(async move {
            if let Err(e) = execute(&state, id, started_at, trigger, &who).await {
                tracing::error!(run = %id, error = %e, "the self-test could not finish");
            }
        });
    }
    Ok(claimed)
}

/// Run the checks and write the outcome. Whatever happens, the row leaves
/// `running`.
async fn execute(
    state: &AppState,
    id: Uuid,
    started_at: OffsetDateTime,
    trigger: Trigger,
    requested_by: &str,
) -> Result<(), String> {
    let outcome = build_and_store(state, id, started_at, trigger, requested_by).await;
    if let Err(why) = &outcome {
        // No report, no verdict: an `error` run alerts like a failed one.
        let _ = sqlx::query(
            "UPDATE selftest_runs SET status = 'error', finished_at = now(), error = $2
             WHERE id = $1 AND status = 'running'",
        )
        .bind(id)
        .bind(why.chars().take(500).collect::<String>())
        .execute(&state.db)
        .await;
        let _ = state
            .audit
            .emit(
                EventKind::SelftestRun,
                Context {
                    user: Some(requested_by.to_owned()),
                    session_id: None,
                },
                json!({ "run_id": id, "trigger": trigger.as_str(), "status": "error", "error": why.chars().take(200).collect::<String>() }),
            )
            .await;
    }
    publish_metrics(state).await;
    outcome
}

async fn build_and_store(
    state: &AppState,
    id: Uuid,
    started_at: OffsetDateTime,
    trigger: Trigger,
    requested_by: &str,
) -> Result<(), String> {
    let results = checks::run_all(state).await;
    let counts = Counts::of(&results);
    let policy = state.policy.base();
    let run = Run {
        meta: Meta {
            run_id: id.to_string(),
            trigger: trigger.as_str().to_owned(),
            started_at: started_at.unix_timestamp(),
            finished_at: OffsetDateTime::now_utc().unix_timestamp(),
            control_plane: state.config.id.clone(),
            policy_version: policy.version,
            policy_digest: policy.policy.digest(),
            build: env!("CARGO_PKG_VERSION").to_owned(),
            interval_secs: state.config.selftest_interval.as_secs(),
            expected_checks: checks::CHECKS
                .iter()
                .map(|(id, _)| (*id).to_owned())
                .collect(),
            attestation: ATTESTATION.to_owned(),
        },
        checks: results,
    };
    let prepared = Prepared::new(&run, requested_by).map_err(|e| format!("encoding: {e}"))?;
    let manifest_sha256 = prepared.manifest_sha256.clone();
    let failing: Vec<&str> = run
        .checks
        .iter()
        .filter(|c| c.status == Status::Failed)
        .map(|c| c.id.as_str())
        .collect();

    // Anchored in the audit trail before the report exists: no event, no report.
    state
        .audit
        .emit(
            EventKind::SelftestRun,
            Context {
                user: Some(requested_by.to_owned()),
                session_id: None,
            },
            json!({
                "run_id": id, "trigger": trigger.as_str(), "status": counts.verdict(),
                "passed": counts.passed, "failed": counts.failed, "skipped": counts.skipped,
                "failed_checks": failing, "manifest_sha256": manifest_sha256,
            }),
        )
        .await
        .map_err(|e| format!("audit unavailable: {e}"))?;

    let signer = state
        .snapshot_signer
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .ok_or("the signing key is not ready")?;
    let report = prepared
        .sign(&signer)
        .map_err(|e| format!("signing: {e}"))?;
    // Check what was just made, as an auditor would.
    let checked = verify_report(&report, state.cas.internal.cert_der());
    if !checked.ok() {
        return Err(format!(
            "the report did not verify: {}",
            checked.problems().join("; ")
        ));
    }
    sqlx::query(
        "UPDATE selftest_runs SET status = $2, finished_at = now(), passed = $3, failed = $4, skipped = $5,
                manifest_sha256 = $6, report = $7
         WHERE id = $1 AND status = 'running'",
    )
    .bind(id)
    .bind(counts.verdict())
    .bind(i32::try_from(counts.passed).unwrap_or(i32::MAX))
    .bind(i32::try_from(counts.failed).unwrap_or(i32::MAX))
    .bind(i32::try_from(counts.skipped).unwrap_or(i32::MAX))
    .bind(&manifest_sha256)
    .bind(&report)
    .execute(&state.db)
    .await
    .map_err(|e| format!("saving: {e}"))?;
    if counts.failed > 0 {
        tracing::error!(run = %id, failed = ?failing, "the self-test found a control that is not working");
    } else {
        tracing::info!(run = %id, passed = counts.passed, skipped = counts.skipped, "the self-test passed");
    }
    Ok(())
}

/// The newest runs, newest first.
///
/// # Errors
/// `internal` for a database failure.
pub async fn list(state: &AppState, limit: i64) -> Result<Vec<RunRow>, GrpcStatus> {
    let rows = sqlx::query(concat!(
        "SELECT ",
        cols!(),
        " FROM selftest_runs ORDER BY started_at DESC LIMIT $1"
    ))
    .bind(limit.clamp(1, 200))
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal("listing self-test runs", e))?;
    rows.iter()
        .map(|r| row(r).map_err(|e| internal("reading a run", e)))
        .collect()
}

/// The signed report of a run, if it has one.
///
/// # Errors
/// `not_found` when there is no such run or it produced no report.
pub async fn report(state: &AppState, id: Uuid) -> Result<(RunRow, Vec<u8>), GrpcStatus> {
    let r = sqlx::query(concat!(
        "SELECT ",
        cols!(),
        ", report FROM selftest_runs WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal("reading a self-test report", e))?
    .ok_or_else(|| GrpcStatus::not_found("no such self-test run"))?;
    let bytes: Option<Vec<u8>> = r
        .try_get("report")
        .map_err(|e| internal("reading a self-test report", e))?;
    let run = row(&r).map_err(|e| internal("reading a run", e))?;
    match bytes {
        Some(b) => Ok((run, b)),
        None => Err(GrpcStatus::not_found(
            "this run produced no report (it is still running, or it ended in an error)",
        )),
    }
}

/// Publish the last run's outcome as metrics from the database, so any
/// replica serves the same numbers, and a stalled schedule shows as a stale
/// timestamp.
pub async fn publish_metrics(state: &AppState) {
    let Ok(rows) = sqlx::query(
        "SELECT status, extract(epoch FROM finished_at)::float8 AS at, passed, failed, skipped, report
         FROM selftest_runs WHERE status IN ('passed', 'failed', 'error') ORDER BY started_at DESC LIMIT 1",
    )
    .fetch_all(&state.db)
    .await
    else {
        return;
    };
    let Some(r) = rows.first() else {
        return;
    };
    let status: String = r.try_get("status").unwrap_or_default();
    let at: f64 = r.try_get("at").unwrap_or(0.0);
    metrics::gauge!("limen_selftest_last_run_timestamp_seconds").set(at);
    metrics::gauge!("limen_selftest_last_run_ok").set(if status == "passed" { 1.0 } else { 0.0 });
    for (name, column) in [
        ("passed", "passed"),
        ("failed", "failed"),
        ("skipped", "skipped"),
    ] {
        let n: i32 = r.try_get(column).unwrap_or(0);
        metrics::gauge!("limen_selftest_checks", "status" => name).set(f64::from(n));
    }
    // Per check: 1 passed, 0 failed, NaN when skipped or when this run has no
    // report (so a series never keeps an older run's value).
    let report: Option<Vec<u8>> = r.try_get("report").ok().flatten();
    let doc = report.and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    for (known, _) in checks::CHECKS {
        let status = doc
            .as_ref()
            .and_then(|v| v["sections"]["checks"].as_array())
            .and_then(|list| list.iter().find(|c| c["id"] == *known))
            .and_then(|c| c["status"].as_str());
        let value = match status {
            Some("passed") => 1.0,
            Some("failed") => 0.0,
            _ => f64::NAN,
        };
        metrics::gauge!("limen_selftest_check_ok", "check" => *known).set(value);
    }
}

/// Delete runs older than the longest evidence period.
pub async fn prune(state: &AppState) {
    if let Err(e) = sqlx::query(
        "DELETE FROM selftest_runs WHERE started_at < now() - make_interval(days => $1) AND status <> 'running'",
    )
    .bind(i32::try_from(RETENTION_DAYS).unwrap_or(400))
    .execute(&state.db)
    .await
    {
        tracing::warn!(error = %e, "pruning old self-test runs failed");
    }
}

/// Run the checks on the schedule, and keep the metrics fresh. Does nothing
/// to the schedule when the interval is zero; the metrics still publish.
pub async fn job(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let interval = state.config.selftest_interval;
    // Let a fresh process settle before it judges itself, but never wait
    // longer than half an interval.
    let grace = STARTUP_GRACE.min(interval / 2);
    tokio::select! {
        () = tokio::time::sleep(grace) => {}
        _ = shutdown.changed() => return,
    }
    // Check often enough to start within a minute of being due, rarely enough
    // to cost nothing.
    let mut tick = tokio::time::interval(if interval.is_zero() {
        Duration::from_secs(60)
    } else {
        (interval / 4).clamp(Duration::from_millis(250), Duration::from_secs(60))
    });
    let mut n: u32 = 0;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        if !interval.is_zero() && !state.draining.load(std::sync::atomic::Ordering::SeqCst) {
            match start(&state, Trigger::Schedule, SCHEDULER).await {
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "starting the scheduled self-test failed"),
            }
        }
        n = n.wrapping_add(1);
        if n.is_multiple_of(4) {
            publish_metrics(&state).await;
        }
        if n.is_multiple_of(240) {
            prune(&state).await;
        }
    }
}

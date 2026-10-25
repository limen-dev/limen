//! `limen request`, `requests`, `approve`, `deny`, `cancel`, `explain`, and
//! the admin views of grants (ADR-0025, ADR-0028).

use std::time::Duration;

use anyhow::{Context as _, bail};
use limen_proto::v1::access_client::AccessClient;
use limen_proto::v1::{
    AccessRequestInfo, CancelAccessRequestRequest, DecideAccessRequestRequest, ExplainRequest,
    ListAccessGrantsRequest, ListAccessRequestsRequest, RequestAccessRequest,
    RevokeAccessGrantRequest,
};
use time::OffsetDateTime;

use crate::{api, ui};

fn client(proxy: Option<&str>) -> anyhow::Result<AccessClient<tonic::transport::Channel>> {
    let (_, channel) = api::authenticated(proxy)?;
    Ok(AccessClient::new(channel))
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

/// "in 12m" / "5m ago", for a time in the past or future.
fn relative(unix: i64) -> String {
    let secs = unix - OffsetDateTime::now_utc().unix_timestamp();
    let (n, past) = (secs.unsigned_abs(), secs < 0);
    let text = if n >= 86_400 {
        format!("{}d", n / 86_400)
    } else if n >= 3600 {
        format!("{}h {}m", n / 3600, n % 3600 / 60)
    } else if n >= 60 {
        format!("{}m", n / 60)
    } else {
        format!("{n}s")
    };
    if past {
        format!("{text} ago")
    } else {
        format!("in {text}")
    }
}

fn colored_status(status: &str) -> String {
    match status {
        "approved" => ui::green(status),
        "pending" => ui::yellow(status),
        "denied" | "revoked" => ui::red(status),
        _ => ui::dim(status),
    }
}

fn show(r: &AccessRequestInfo) {
    let mut rows = vec![
        ("Request", ui::bold(&r.id)),
        ("Status", colored_status(&r.status)),
        ("Who", r.requester.clone()),
        ("Resource", ui::bold(&r.resource)),
        ("Role", ui::role(&r.role)),
        ("For", format_secs(u64::from(r.duration_seconds))),
        (
            "Reason",
            if r.reason.is_empty() {
                ui::dim("-")
            } else {
                r.reason.clone()
            },
        ),
    ];
    if r.break_glass {
        rows.push(("Kind", ui::red("break-glass")));
    }
    if r.status == "pending" {
        rows.push((
            "Approvals",
            format!(
                "{} of {} needed · lapses {}",
                r.approvals
                    .iter()
                    .filter(|a| a.decision == "approve")
                    .count(),
                r.approvals_required,
                relative(r.expires_at_unix)
            ),
        ));
    }
    if r.grant_expires_at_unix > 0 {
        rows.push((
            "Access ends",
            format!(
                "{} ({})",
                when(r.grant_expires_at_unix),
                relative(r.grant_expires_at_unix)
            ),
        ));
    }
    if r.can_decide || r.requester_sessions_30d > 0 {
        rows.push((
            "Past 30 days",
            format!(
                "{} session(s) on this resource{}",
                r.requester_sessions_30d,
                if r.requester_last_session_unix > 0 {
                    format!(", the latest {}", relative(r.requester_last_session_unix))
                } else {
                    String::new()
                }
            ),
        ));
    }
    anstream::println!("{}", ui::key_values(&rows));
    for a in &r.approvals {
        anstream::println!(
            "  {} {}{}",
            if a.decision == "approve" {
                ui::green("✓")
            } else {
                ui::red("✗")
            },
            a.approver,
            if a.comment.is_empty() {
                String::new()
            } else {
                format!(": {}", a.comment)
            }
        );
    }
}

fn format_secs(secs: u64) -> String {
    limen_policy::duration::DurationStr(Duration::from_secs(secs)).to_string()
}

/// How long to wait for a decision when asked to.
const WAIT_LIMIT: Duration = Duration::from_hours(1);

pub struct RequestArgs<'a> {
    pub resource: &'a str,
    pub role: Option<&'a str>,
    pub duration: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub break_glass: bool,
    pub wait: bool,
    pub json: bool,
}

pub async fn request(proxy: Option<&str>, a: RequestArgs<'_>) -> anyhow::Result<()> {
    let duration_seconds = match a.duration {
        Some(d) => u32::try_from(
            limen_policy::duration::DurationStr::parse(d)
                .map_err(anyhow::Error::msg)
                .context("--for")?
                .0
                .as_secs(),
        )
        .context("--for is too long")?,
        None => 0,
    };
    let mut access = client(proxy)?;
    let info = access
        .request_access(RequestAccessRequest {
            resource: a.resource.to_owned(),
            role: a.role.unwrap_or_default().to_owned(),
            duration_seconds,
            reason: a.reason.unwrap_or_default().to_owned(),
            break_glass: a.break_glass,
        })
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    if a.json {
        println!("{}", serde_json::to_string_pretty(&request_json(&info))?);
        if !a.wait || info.status != "pending" {
            return Ok(());
        }
    } else {
        show(&info);
    }
    if info.status == "approved" {
        granted_hint(&info);
        return Ok(());
    }
    if !a.wait {
        ui::hint(
            "Waiting for an approver. Check with `limen requests`, or ask with --wait next time.",
        );
        return Ok(());
    }
    let id = info.id.clone();
    let spinner =
        ui::spinner("Waiting for an approver (Ctrl-C to stop waiting; the request stays open)");
    let started = std::time::Instant::now();
    let result = loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let current = access
            .list_access_requests(ListAccessRequestsRequest {
                scope: "mine".into(),
                status: String::new(),
                limit: 50,
            })
            .await
            .map_err(|s| api::status_error(&s))?
            .into_inner()
            .requests
            .into_iter()
            .find(|r| r.id == id);
        match current {
            Some(r) if r.status != "pending" => break Some(r),
            _ if started.elapsed() > WAIT_LIMIT => break None,
            _ => {}
        }
    };
    spinner.finish();
    match result {
        Some(r) if r.status == "approved" => {
            ui::success("Approved.");
            granted_hint(&r);
            Ok(())
        }
        Some(r) => bail!("the request was {}", r.status),
        None => bail!("gave up waiting; the request is still open (`limen requests`)"),
    }
}

fn granted_hint(r: &AccessRequestInfo) {
    ui::success(&format!(
        "You have {} on {} until {}.",
        ui::role(&r.role),
        ui::bold(&r.resource),
        when(r.grant_expires_at_unix)
    ));
    ui::hint(&format!(
        "Proxies and workers pick the grant up within about 20 seconds. Then: `limen show {}`.",
        r.resource
    ));
}

fn request_json(r: &AccessRequestInfo) -> serde_json::Value {
    serde_json::json!({
        "id": r.id, "requester": r.requester, "role": r.role, "resource": r.resource,
        "reason": r.reason, "duration_seconds": r.duration_seconds, "status": r.status,
        "break_glass": r.break_glass, "approvals_required": r.approvals_required,
        "approvals": r.approvals.iter().map(|a| serde_json::json!({
            "approver": a.approver, "decision": a.decision, "comment": a.comment, "at": a.decided_at_unix,
        })).collect::<Vec<_>>(),
        "created_at": r.created_at_unix, "expires_at": r.expires_at_unix,
        "grant_expires_at": r.grant_expires_at_unix, "can_decide": r.can_decide,
        "requester_sessions_30d": r.requester_sessions_30d,
    })
}

pub async fn requests(
    proxy: Option<&str>,
    scope: &str,
    status: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    let mut access = client(proxy)?;
    let list = access
        .list_access_requests(ListAccessRequestsRequest {
            scope: scope.to_owned(),
            status: status.unwrap_or_default().to_owned(),
            limit: 100,
        })
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner()
        .requests;
    if json {
        let items: Vec<_> = list.iter().map(request_json).collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }
    if list.is_empty() {
        ui::info(match scope {
            "approvable" => "Nothing is waiting for you to approve.",
            "all" => "There are no access requests.",
            _ => "You have no access requests.",
        });
        if scope != "approvable" && scope != "all" {
            ui::hint("Ask for access with `limen request <resource> --for 30m --reason \"...\"`.");
        }
        return Ok(());
    }
    let rows: Vec<[String; 6]> = list
        .iter()
        .map(|r| {
            [
                ui::bold(&r.id),
                colored_status(&r.status),
                r.requester.clone(),
                format!(
                    "{} {}",
                    ui::bold(&r.resource),
                    ui::dim(&format!("({})", r.role))
                ),
                format_secs(u64::from(r.duration_seconds)),
                if r.status == "approved" && r.grant_expires_at_unix > 0 {
                    format!("ends {}", relative(r.grant_expires_at_unix))
                } else if r.status == "pending" {
                    format!(
                        "{}/{} approvals",
                        r.approvals
                            .iter()
                            .filter(|a| a.decision == "approve")
                            .count(),
                        r.approvals_required
                    )
                } else {
                    ui::dim(&relative(r.created_at_unix))
                },
            ]
        })
        .collect();
    ui::print_table(
        ["request", "status", "who", "resource", "for", "state"],
        &rows,
    );
    if scope == "approvable" {
        ui::hint(
            "Decide with `limen approve <id>` or `limen deny <id>`; the id above, with --comment to say why.",
        );
    }
    Ok(())
}

pub async fn decide(
    proxy: Option<&str>,
    id: &str,
    approve: bool,
    comment: Option<&str>,
) -> anyhow::Result<()> {
    let mut access = client(proxy)?;
    let info = access
        .decide_access_request(DecideAccessRequestRequest {
            id: id.to_owned(),
            approve,
            comment: comment.unwrap_or_default().to_owned(),
        })
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    show(&info);
    match (approve, info.status.as_str()) {
        (true, "approved") => ui::success("Approved. The access is granted until the time above."),
        (true, _) => ui::info(&format!(
            "Your approval is recorded; {} of {} needed.",
            info.approvals
                .iter()
                .filter(|a| a.decision == "approve")
                .count(),
            info.approvals_required
        )),
        (false, _) => ui::success("Denied."),
    }
    Ok(())
}

pub async fn cancel(proxy: Option<&str>, id: &str) -> anyhow::Result<()> {
    let mut access = client(proxy)?;
    let info = access
        .cancel_access_request(CancelAccessRequestRequest { id: id.to_owned() })
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    ui::success(&format!(
        "Request {} is {}.",
        ui::bold(&info.id),
        info.status
    ));
    Ok(())
}

pub async fn grants(proxy: Option<&str>, all: bool, json: bool) -> anyhow::Result<()> {
    let mut access = client(proxy)?;
    let list = access
        .list_access_grants(ListAccessGrantsRequest { include_ended: all })
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner()
        .grants;
    if json {
        let items: Vec<_> = list
            .iter()
            .map(|g| serde_json::json!({
                "request_id": g.request_id, "user": g.username, "role": g.role, "resource": g.resource,
                "reason": g.reason, "break_glass": g.break_glass, "granted_at": g.granted_at_unix,
                "expires_at": g.expires_at_unix, "approvers": g.approvers,
            }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }
    if list.is_empty() {
        ui::info("No access is granted by request right now.");
        return Ok(());
    }
    let rows: Vec<[String; 5]> = list
        .iter()
        .map(|g| {
            [
                ui::bold(&g.request_id),
                if g.break_glass {
                    format!("{} {}", g.username, ui::red("break-glass"))
                } else {
                    g.username.clone()
                },
                format!(
                    "{} {}",
                    ui::bold(&g.resource),
                    ui::dim(&format!("({})", g.role))
                ),
                relative(g.expires_at_unix),
                ui::dim(&g.reason),
            ]
        })
        .collect();
    ui::print_table(["request", "user", "resource", "ends", "reason"], &rows);
    Ok(())
}

pub async fn revoke_grant(proxy: Option<&str>, id: &str, reason: &str) -> anyhow::Result<()> {
    let mut access = client(proxy)?;
    let resp = access
        .revoke_access_grant(RevokeAccessGrantRequest {
            request_id: id.to_owned(),
            reason: reason.to_owned(),
        })
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    if resp.revoked {
        ui::success(&format!(
            "Revoked {}. {} open session(s) end within about 10 seconds.",
            ui::bold(id),
            resp.sessions_ended
        ));
    } else {
        ui::info(&format!("{id} had already ended."));
    }
    Ok(())
}

pub async fn explain(
    proxy: Option<&str>,
    resource: &str,
    principal: Option<&str>,
    database: Option<&str>,
    user: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    let mut access = client(proxy)?;
    let resp = access
        .explain(ExplainRequest {
            resource: resource.to_owned(),
            principal: principal.unwrap_or_default().to_owned(),
            database: database.unwrap_or_default().to_owned(),
            user: user.unwrap_or_default().to_owned(),
        })
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({ "lines": resp.lines, "full_trace": resp.full_trace })
            )?
        );
        return Ok(());
    }
    for line in &resp.lines {
        println!("{line}");
    }
    Ok(())
}

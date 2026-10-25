//! `limen admin review ...`, `limen review ...` and `limen admin evidence`
//! (ADR-0029).

use std::path::PathBuf;

use clap::Subcommand;
use limen_proto::v1::reviews_client::ReviewsClient;
use limen_proto::v1::{
    DecideReviewItemRequest, ExportEvidenceRequest, LiftDenyRequest, ListDeniesRequest,
    ListReviewItemsRequest, ListReviewsRequest, StartReviewRequest,
};
use time::OffsetDateTime;

use crate::{api, ui};

#[derive(Debug, Subcommand)]
pub enum ReviewCommand {
    /// Start an access review: a snapshot of who holds which role, sent to its owners.
    Start {
        #[arg(long)]
        name: Option<String>,
        /// Days the reviewers have (default 14).
        #[arg(long, default_value_t = 14)]
        due_days: u32,
        /// Days a flagged role stays withheld (default 30).
        #[arg(long, default_value_t = 30)]
        override_days: u32,
    },
    /// Reviews. By default those with items for you.
    Ls {
        /// Every review (limen:admin or limen:auditor).
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// The items of a review: yours, or all of them for admins and auditors.
    Items {
        review: String,
        #[arg(long)]
        mine: bool,
        #[arg(long)]
        open: bool,
        #[arg(long)]
        json: bool,
    },
    /// Certify an item: the person should keep the role.
    Certify {
        item: String,
        #[arg(long, short = 'm', default_value = "")]
        comment: String,
    },
    /// Flag an item for removal. The role is withheld from them at once.
    Flag {
        item: String,
        #[arg(long, short = 'm')]
        comment: String,
    },
    /// Roles withheld by a review.
    Overrides {
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Give a withheld role back.
    Lift {
        id: String,
        #[arg(long)]
        reason: String,
    },
}

fn day(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .map(|t| t.date().to_string())
        .unwrap_or_default()
}

#[allow(clippy::too_many_lines)] // one arm per command
pub async fn run(proxy: Option<&str>, command: ReviewCommand) -> anyhow::Result<()> {
    let (_, channel) = api::authenticated(proxy)?;
    let mut c = ReviewsClient::new(channel);
    match command {
        ReviewCommand::Start {
            name,
            due_days,
            override_days,
        } => {
            let r = c
                .start_review(StartReviewRequest {
                    name: name.unwrap_or_default(),
                    due_days,
                    override_days,
                })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner();
            ui::success(&format!(
                "Started {} with {} items, due {}.",
                ui::bold(&r.name),
                r.items,
                day(r.due_at_unix)
            ));
            ui::hint(&format!(
                "Reviewers decide in the console or with `limen admin review items {}`.",
                r.id
            ));
        }
        ReviewCommand::Ls { all, json } => {
            let reviews = c
                .list_reviews(ListReviewsRequest {
                    scope: if all { "all".into() } else { "mine".into() },
                })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner()
                .reviews;
            if json {
                let v: Vec<_> = reviews.iter().map(|r| serde_json::json!({
                    "id": r.id, "name": r.name, "status": r.status, "items": r.items, "decided": r.decided,
                    "flagged": r.flagged, "certified_without_comment": r.certified_silently, "overdue": r.overdue,
                    "due": day(r.due_at_unix),
                })).collect();
                println!("{}", serde_json::to_string_pretty(&v)?);
                return Ok(());
            }
            if reviews.is_empty() {
                ui::info("No reviews.");
                return Ok(());
            }
            let rows: Vec<[String; 5]> = reviews
                .iter()
                .map(|r| {
                    [
                        ui::bold(&r.id),
                        r.name.clone(),
                        if r.overdue {
                            ui::red("overdue")
                        } else {
                            r.status.clone()
                        },
                        format!("{}/{} decided, {} flagged", r.decided, r.items, r.flagged),
                        day(r.due_at_unix),
                    ]
                })
                .collect();
            ui::print_table(["review", "name", "status", "progress", "due"], &rows);
        }
        ReviewCommand::Items {
            review,
            mine,
            open,
            json,
        } => {
            let items = c
                .list_review_items(ListReviewItemsRequest {
                    review_id: review,
                    mine,
                    open_only: open,
                })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner()
                .items;
            if json {
                let v: Vec<_> = items.iter().map(|i| serde_json::json!({
                    "id": i.id, "subject": i.subject, "type": i.subject_type, "role": i.role, "via": i.via,
                    "reaches": i.reaches.iter().map(|r| &r.name).collect::<Vec<_>>(), "sessions_90d": i.sessions_90d,
                    "reviewer": i.reviewer, "decision": i.decision, "comment": i.comment, "can_decide": i.can_decide,
                })).collect();
                println!("{}", serde_json::to_string_pretty(&v)?);
                return Ok(());
            }
            let rows: Vec<[String; 6]> = items
                .iter()
                .map(|i| {
                    [
                        ui::bold(&i.id),
                        i.subject.clone(),
                        ui::role(&i.role),
                        format!("{} resource(s)", i.reaches.len()),
                        if i.unused {
                            ui::yellow("unused 90d")
                        } else {
                            format!("{} sessions", i.sessions_90d)
                        },
                        match i.decision.as_str() {
                            "certify" => ui::green("certified"),
                            "flag" => ui::red("flagged"),
                            _ if i.can_decide => ui::yellow("yours to decide"),
                            _ => ui::dim(&i.reviewer),
                        },
                    ]
                })
                .collect();
            ui::print_table(["item", "who", "role", "reaches", "use", "state"], &rows);
        }
        ReviewCommand::Certify { item, comment } => {
            c.decide_review_item(DecideReviewItemRequest {
                item_id: item,
                certify: true,
                comment,
            })
            .await
            .map_err(|s| api::status_error(&s))?;
            ui::success("Certified.");
        }
        ReviewCommand::Flag { item, comment } => {
            let i = c
                .decide_review_item(DecideReviewItemRequest {
                    item_id: item,
                    certify: false,
                    comment,
                })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner();
            ui::success(&format!(
                "Flagged. {} no longer has {} (withheld until the IdP group is fixed).",
                ui::bold(&i.subject),
                ui::role(&i.role)
            ));
            ui::hint(
                "Ask whoever owns the IdP group to remove them; the override lifts itself when it shows at their next login.",
            );
        }
        ReviewCommand::Overrides { all, json } => {
            let d = c
                .list_denies(ListDeniesRequest { include_ended: all })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner()
                .denies;
            if json {
                let v: Vec<_> = d.iter().map(|x| serde_json::json!({ "id": x.id, "user": x.username, "role": x.role, "reason": x.reason, "active": x.active, "expires": day(x.expires_at_unix) })).collect();
                println!("{}", serde_json::to_string_pretty(&v)?);
                return Ok(());
            }
            if d.is_empty() {
                ui::info("No roles are withheld.");
                return Ok(());
            }
            let rows: Vec<[String; 5]> = d
                .iter()
                .map(|x| {
                    [
                        ui::bold(&x.id),
                        x.username.clone(),
                        ui::role(&x.role),
                        if x.active {
                            day(x.expires_at_unix)
                        } else {
                            ui::dim("ended")
                        },
                        ui::dim(&x.reason),
                    ]
                })
                .collect();
            ui::print_table(["override", "who", "role", "until", "why"], &rows);
        }
        ReviewCommand::Lift { id, reason } => {
            let r = c
                .lift_deny(LiftDenyRequest { id, reason })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner();
            if r.lifted {
                ui::success("Lifted.");
            } else {
                ui::info("It had already ended.");
            }
        }
    }
    Ok(())
}

/// `limen admin evidence --from --to [--out file]`.
pub async fn evidence(
    proxy: Option<&str>,
    from: &str,
    to: &str,
    out: &PathBuf,
) -> anyhow::Result<()> {
    let parse = |s: &str| -> anyhow::Result<i64> {
        let d = time::Date::parse(
            s,
            &time::macros::format_description!("[year]-[month]-[day]"),
        )
        .map_err(|_| anyhow::anyhow!("{s:?} is not a date like 2026-01-31"))?;
        Ok(d.midnight().assume_utc().unix_timestamp())
    };
    let (_, channel) = api::authenticated(proxy)?;
    let r = ReviewsClient::new(channel)
        .export_evidence(ExportEvidenceRequest {
            from_unix: parse(from)?,
            to_unix: parse(to)?,
        })
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    std::fs::write(out, &r.pack)?;
    ui::success(&format!(
        "Wrote {} ({} bytes), signed. Manifest {}.",
        out.display(),
        r.pack.len(),
        ui::dim(&r.manifest_sha256)
    ));
    ui::hint(
        "Check it anywhere with `limen-audit-verify --evidence <file> --ca-file internal-ca.pem`.",
    );
    Ok(())
}

//! `limen audit search` (ADR-0026).

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
}

pub async fn run(proxy: Option<&str>, command: AuditCommand) -> anyhow::Result<()> {
    match command {
        AuditCommand::Search { query, limit, json } => search(proxy, &query, limit, json).await,
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

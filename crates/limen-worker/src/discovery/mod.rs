//! Cloud discovery on the worker (ADR-0027). The worker runs the matchers of
//! the `discovery` documents that name it, with a **describe-only** role, and
//! reports facts to the control plane. It never decides a name, a label, or
//! whether anything is reachable: a report can only add a *pending* resource.
//! The control plane never calls the customer's account.

pub mod aws;
pub mod sources;
pub mod xml;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use limen_policy::discovery::DiscoveryDoc;
use limen_proto::v1::discovery_client::DiscoveryClient;
use limen_proto::v1::{DiscoveredItem, ReportDiscoveryRequest, ScanScope};
use tokio::sync::watch;

use crate::Worker;
use crate::db::sigv4::Credentials;

/// Most items one report may hold (the control plane's limit too).
const MAX_ITEMS: usize = 5_000;

/// Run the discovery documents that name this worker, each at its interval,
/// until shutdown.
pub async fn run(worker: Worker, mut shutdown: watch::Receiver<bool>) {
    let aws = match aws::Aws::new(worker.config.discovery_endpoint_url.clone()) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "discovery can't start");
            return;
        }
    };
    let mut last: BTreeMap<String, Instant> = BTreeMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        let Some(snapshot) = worker.policy.latest() else {
            continue;
        };
        let labels = worker.credentials().labels.clone();
        for doc in snapshot.policy.discovery() {
            if !doc.spec.worker_runs(&labels) {
                continue;
            }
            let due = last
                .get(&doc.metadata.name)
                .is_none_or(|t| t.elapsed() >= doc.spec.interval());
            if !due {
                continue;
            }
            last.insert(doc.metadata.name.clone(), Instant::now());
            match scan_document(&worker, &aws, doc).await {
                Ok((items, complete)) => {
                    metrics::counter!("limen_discovery_scans_total", "outcome" => "ok")
                        .increment(1);
                    if let Err(e) = report(&worker, doc, items, complete).await {
                        tracing::warn!(document = %doc.metadata.name, error = %e, "reporting discovered resources failed");
                    }
                }
                Err(e) => {
                    metrics::counter!("limen_discovery_scans_total", "outcome" => "failed")
                        .increment(1);
                    tracing::warn!(document = %doc.metadata.name, error = %e, "discovery scan failed");
                }
            }
        }
    }
}

async fn report(
    worker: &Worker,
    doc: &DiscoveryDoc,
    items: Vec<DiscoveredItem>,
    complete: Vec<ScanScope>,
) -> anyhow::Result<()> {
    let channel = worker.control_plane()?;
    let resp = DiscoveryClient::new(channel)
        .report(ReportDiscoveryRequest {
            document: doc.metadata.name.clone(),
            items,
            complete,
        })
        .await?
        .into_inner();
    tracing::info!(document = %doc.metadata.name, kept = resp.accepted, dropped = resp.dropped, "reported discovered resources");
    Ok(())
}

/// One entry per account to scan: its id and the credentials to scan with.
async fn accounts(
    aws: &aws::Aws,
    doc: &DiscoveryDoc,
    base: &Credentials,
) -> Vec<(String, Result<Credentials, String>)> {
    let region = doc.spec.regions.first().map_or("us-east-1", String::as_str);
    if doc.spec.accounts.is_empty() {
        let id = aws.account_of(base, region).await;
        return vec![match id {
            Ok(id) => (id, Ok(base.clone())),
            Err(e) => (String::new(), Err(e)),
        }];
    }
    let mut out = Vec::new();
    for a in &doc.spec.accounts {
        let id = a.role_arn.split(':').nth(4).unwrap_or_default().to_owned();
        let creds = aws
            .assume_role(base, &a.role_arn, region)
            .await
            .map(|(c, _)| c);
        out.push((id, creds));
    }
    out
}

/// Scan every account, region, and matcher. Returns the items, and the scopes
/// that were scanned to the end (only those can show something is missing).
async fn scan_document(
    worker: &Worker,
    aws: &aws::Aws,
    doc: &DiscoveryDoc,
) -> Result<(Vec<DiscoveredItem>, Vec<ScanScope>), String> {
    let base = worker.aws_credentials().await?;
    let mut items: Vec<DiscoveredItem> = Vec::new();
    let mut complete = Vec::new();
    for (account, creds) in accounts(aws, doc, &base).await {
        let creds = match creds {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(document = %doc.metadata.name, %account, error = %e, "can't use the account's role");
                continue;
            }
        };
        for region in &doc.spec.regions {
            for (idx, m) in doc.spec.matchers.iter().enumerate() {
                match sources::scan(aws, &creds, m, &account, region).await {
                    Ok(found) => {
                        let room = MAX_ITEMS.saturating_sub(items.len());
                        let whole = found.len() <= room;
                        items.extend(found.into_iter().take(room).map(|f| to_item(idx, &f)));
                        if whole {
                            complete.push(ScanScope {
                                matcher: u32::try_from(idx).unwrap_or(u32::MAX),
                                account: account.clone(),
                                region: region.clone(),
                            });
                        }
                    }
                    Err(e) => {
                        tracing::warn!(document = %doc.metadata.name, %account, %region, source = m.source.as_str(), error = %e, "scan failed; its resources are not counted as missing");
                    }
                }
            }
        }
    }
    Ok((items, complete))
}

fn to_item(matcher: usize, f: &limen_policy::discovery::Found) -> DiscoveredItem {
    DiscoveredItem {
        matcher: u32::try_from(matcher).unwrap_or(u32::MAX),
        source: f.source.as_str().to_owned(),
        account: f.account.clone(),
        region: f.region.clone(),
        provider_id: f.provider_id.clone(),
        target: f.target.clone(),
        tags: f.tags.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        facts: f
            .facts
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    }
}

#[cfg(test)]
mod tests;

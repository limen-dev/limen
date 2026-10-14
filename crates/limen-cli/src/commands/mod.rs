//! Command implementations.

pub mod admin;
pub mod login;

use limen_proto::v1::ListResourcesRequest;
use limen_proto::v1::resources_client::ResourcesClient;

use crate::api;
use crate::profile::Profile;

pub fn logout(proxy: Option<&str>) -> anyhow::Result<()> {
    let proxy = api::resolve_proxy(proxy)?;
    if Profile::delete(&proxy)? {
        println!("Logged out of {proxy}. Local credentials deleted.");
    } else {
        println!("Not logged in to {proxy}.");
    }
    Ok(())
}

pub fn status(proxy: Option<&str>) -> anyhow::Result<()> {
    let proxy = api::resolve_proxy(proxy)?;
    let Some(profile) = Profile::load(&proxy)? else {
        println!("Not logged in to {proxy}. Run `limen login`.");
        return Ok(());
    };
    let remaining = profile.expires_at() - time::OffsetDateTime::now_utc();
    println!("Proxy:    {}", profile.meta.proxy);
    println!("User:     {}", profile.meta.username);
    println!("Roles:    {}", profile.meta.roles.join(", "));
    if remaining.is_positive() {
        println!(
            "Expires:  in {}m {}s",
            remaining.whole_minutes(),
            remaining.whole_seconds() % 60
        );
    } else {
        println!("Expires:  EXPIRED. Run `limen login`.");
    }
    Ok(())
}

pub async fn ls(proxy: Option<&str>, json: bool) -> anyhow::Result<()> {
    let (_, channel) = api::authenticated(proxy)?;
    let resp = ResourcesClient::new(channel)
        .list_resources(ListResourcesRequest {})
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    if json {
        let items: Vec<_> = resp
            .resources
            .iter()
            .map(|r| serde_json::json!({ "name": r.name, "kind": r.kind, "labels": r.labels, "principals": r.principals }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }
    if resp.resources.is_empty() {
        println!("No resources available to you.");
        return Ok(());
    }
    let rows: Vec<[String; 4]> = resp
        .resources
        .iter()
        .map(|r| {
            let mut labels: Vec<_> = r.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
            labels.sort();
            [
                r.name.clone(),
                r.kind.clone(),
                r.principals.join(","),
                labels.join(","),
            ]
        })
        .collect();
    print_table(["NAME", "KIND", "PRINCIPALS", "LABELS"], &rows);
    Ok(())
}

/// Print rows as an aligned table.
pub fn print_table<const N: usize>(header: [&str; N], rows: &[[String; N]]) {
    let mut widths = header.map(str::len);
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.len());
        }
    }
    let line = |cells: Vec<&str>| {
        let parts: Vec<String> = cells
            .iter()
            .zip(widths)
            .map(|(c, w)| format!("{c:<w$}"))
            .collect();
        println!("{}", parts.join("  ").trim_end());
    };
    line(header.to_vec());
    for row in rows {
        line(row.iter().map(String::as_str).collect());
    }
}

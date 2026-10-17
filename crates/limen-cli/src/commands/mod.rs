//! Command implementations.

pub mod admin;
pub mod bot;
pub mod kube;
pub mod login;
pub mod ssh;

use limen_proto::v1::ListResourcesRequest;
use limen_proto::v1::resources_client::ResourcesClient;

use crate::profile::Profile;
use crate::{api, ui};

pub fn logout(proxy: Option<&str>) -> anyhow::Result<()> {
    let proxy = api::resolve_proxy(proxy)?;
    if Profile::delete(&proxy)? {
        ui::success(&format!(
            "Logged out of {}. Local credentials deleted.",
            ui::bold(&proxy)
        ));
    } else {
        ui::info(&format!("Not logged in to {proxy}."));
    }
    Ok(())
}

pub fn status(proxy: Option<&str>) -> anyhow::Result<()> {
    let proxy = api::resolve_proxy(proxy)?;
    let Some(profile) = Profile::load(&proxy)? else {
        ui::info(&format!("Not logged in to {proxy}."));
        ui::hint("Run `limen login` to sign in.");
        return Ok(());
    };
    let remaining = profile.expires_at() - time::OffsetDateTime::now_utc();
    let roles: Vec<String> = profile.meta.roles.iter().map(|r| ui::role(r)).collect();
    anstream::println!(
        "{}",
        ui::key_values(&[
            ("Proxy", profile.meta.proxy.clone()),
            ("User", ui::bold(&profile.meta.username)),
            ("Roles", roles.join(", ")),
            ("Expires", ui::expiry(remaining)),
        ])
    );
    if remaining.is_positive() {
        ui::hint("Next: `limen ls` to see what you can reach.");
    } else {
        ui::hint("Your credentials expired. Run `limen login`.");
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
        ui::info("No resources are available to you.");
        ui::hint("Your roles don't grant access to anything yet. Ask an admin.");
        return Ok(());
    }
    let rows: Vec<[String; 4]> = resp
        .resources
        .iter()
        .map(|r| {
            let mut labels: Vec<_> = r.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
            labels.sort();
            [
                ui::bold(&r.name),
                ui::kind_label(&r.kind),
                r.principals.join(", "),
                ui::dim(&labels.join(" ")),
            ]
        })
        .collect();
    ui::print_table(["name", "kind", "access as", "labels"], &rows);
    let n = resp.resources.len();
    ui::hint(&format!(
        "{n} resource{} · connect with `limen ssh <name>`",
        if n == 1 { "" } else { "s" }
    ));
    Ok(())
}

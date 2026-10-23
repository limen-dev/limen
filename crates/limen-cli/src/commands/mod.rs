//! Command implementations.

pub mod admin;
pub mod bot;
pub mod db;
pub mod kafka;
pub mod kube;
pub mod login;
pub mod mongo;
pub mod mq;
pub mod redis;
pub mod search;
pub mod ssh;
pub mod tcp;
pub mod web;

use limen_proto::v1::ListResourcesRequest;
use limen_proto::v1::resources_client::ResourcesClient;

use crate::profile::Profile;
use crate::{api, ui};

/// End the login at the proxy, then delete the local credentials. The proxy
/// and workers refuse the certificate from then on, wherever a copy of it is.
/// If the proxy can't be reached the local credentials still go, and the
/// message says the certificate stays valid until it expires.
pub async fn logout(proxy: Option<&str>) -> anyhow::Result<()> {
    let proxy = api::resolve_proxy(proxy)?;
    let Some(profile) = Profile::load(&proxy)? else {
        ui::info(&format!("Not logged in to {proxy}."));
        return Ok(());
    };
    let ended = if profile.is_expired() {
        // Nothing left to end: an expired certificate is refused anyway.
        Ok(())
    } else {
        end_login(&proxy, &profile).await
    };
    Profile::delete(&proxy)?;
    match ended {
        Ok(()) => ui::success(&format!(
            "Logged out of {}. The login is ended and local credentials are deleted.",
            ui::bold(&proxy)
        )),
        Err(e) => {
            ui::warn(&format!(
                "Local credentials for {} are deleted, but the login could not be ended at the proxy ({e:#}).",
                ui::bold(&proxy)
            ));
            ui::hint(&format!(
                "The certificate stays valid until {}. An admin can lock the user to cut it off sooner.",
                profile.expires_at()
            ));
        }
    }
    Ok(())
}

async fn end_login(proxy: &str, profile: &Profile) -> anyhow::Result<()> {
    let channel = api::connect(proxy, Some(profile.identity()?))?;
    limen_proto::v1::auth_client::AuthClient::new(channel)
        .logout(limen_proto::v1::LogoutRequest {})
        .await
        .map_err(|s| api::status_error(&s))?;
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

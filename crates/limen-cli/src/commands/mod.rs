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

use limen_proto::v1::resources_client::ResourcesClient;
use limen_proto::v1::{ListResourcesRequest, Resource};

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

/// Parse a `key=value` label filter.
pub fn parse_label(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_owned(), v.to_owned())),
        _ => Err("expected KEY=VALUE".to_owned()),
    }
}

/// Whether a resource passes the `--type` and `--label` filters of `limen ls`.
fn matches_filters(r: &Resource, kinds: &[&str], labels: &[(String, String)]) -> bool {
    (kinds.is_empty() || kinds.contains(&r.kind.as_str()))
        && labels
            .iter()
            .all(|(k, v)| r.labels.get(k).is_some_and(|actual| actual == v))
}

pub async fn ls(
    proxy: Option<&str>,
    json: bool,
    kinds: &[&str],
    labels: &[(String, String)],
) -> anyhow::Result<()> {
    let (_, channel) = api::authenticated(proxy)?;
    let resp = ResourcesClient::new(channel)
        .list_resources(ListResourcesRequest {})
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    let filtered = !kinds.is_empty() || !labels.is_empty();
    let resources: Vec<_> = resp
        .resources
        .into_iter()
        .filter(|r| matches_filters(r, kinds, labels))
        .collect();
    if json {
        let items: Vec<_> = resources
            .iter()
            .map(|r| serde_json::json!({ "name": r.name, "kind": r.kind, "labels": r.labels, "principals": r.principals }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }
    if resources.is_empty() {
        if filtered {
            ui::info("No resources match those filters.");
            ui::hint("Run `limen ls` without --type or --label to see everything you can reach.");
        } else {
            ui::info("No resources are available to you.");
            ui::hint("Your roles don't grant access to anything yet. Ask an admin.");
        }
        return Ok(());
    }
    let rows: Vec<[String; 4]> = resources
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
    let n = resources.len();
    ui::hint(&format!(
        "{n} resource{} · connect with `limen ssh <name>`",
        if n == 1 { "" } else { "s" }
    ));
    Ok(())
}

#[cfg(test)]
mod ls_filter_tests {
    use super::*;

    fn resource(kind: &str, labels: &[(&str, &str)]) -> Resource {
        Resource {
            name: "r".into(),
            kind: kind.into(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn filters_by_type_and_every_label() {
        let r = resource("postgres", &[("env", "staging"), ("team", "payments")]);
        assert!(matches_filters(&r, &[], &[]));
        assert!(matches_filters(&r, &["postgres"], &[]));
        assert!(!matches_filters(&r, &["ssh", "mysql"], &[]));
        let env = ("env".to_owned(), "staging".to_owned());
        let team = ("team".to_owned(), "other".to_owned());
        assert!(matches_filters(&r, &[], std::slice::from_ref(&env)));
        assert!(!matches_filters(&r, &[], &[env, team]));
    }

    #[test]
    fn parses_label_flags() {
        assert_eq!(parse_label("env=prod"), Ok(("env".into(), "prod".into())));
        assert_eq!(parse_label("a=b=c"), Ok(("a".into(), "b=c".into())));
        assert!(parse_label("env").is_err());
        assert!(parse_label("=x").is_err());
    }
}

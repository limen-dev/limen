//! Command implementations.

pub mod access;
pub mod admin;
pub mod audit;
pub mod bot;
pub mod conns;
pub mod db;
pub mod kafka;
pub mod kube;
pub mod login;
pub mod mongo;
pub mod mq;
pub mod policy;
pub mod redis;
pub mod search;
pub mod ssh;
pub mod tcp;
pub mod web;

use limen_proto::v1::resources_client::ResourcesClient;
use limen_proto::v1::{ListResourcesRequest, Resource};

use crate::profile::Profile;
use crate::{api, ui};
use anyhow::Context as _;

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
    let stopped = conns::stop_all(&proxy);
    if stopped > 0 {
        ui::info(&format!("Closed {stopped} detached connection(s)."));
    }
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

pub fn status(proxy: Option<&str>, json: bool) -> anyhow::Result<()> {
    let proxy = api::resolve_proxy(proxy)?;
    let Some(profile) = Profile::load(&proxy)? else {
        if json {
            println!(
                "{}",
                serde_json::json!({ "proxy": proxy, "logged_in": false })
            );
            return Ok(());
        }
        ui::info(&format!("Not logged in to {proxy}."));
        ui::hint("Run `limen login` to sign in.");
        return Ok(());
    };
    let remaining = profile.expires_at() - time::OffsetDateTime::now_utc();
    if json {
        let expires = profile
            .expires_at()
            .format(&time::format_description::well_known::Rfc3339)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "proxy": profile.meta.proxy,
                "logged_in": remaining.is_positive(),
                "user": profile.meta.username,
                "roles": profile.meta.roles,
                "expires_at": expires,
                "seconds_left": remaining.whole_seconds().max(0),
            }))?
        );
        return Ok(());
    }
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

/// What `limen ls` and the per-protocol `ls` views narrow the list by.
#[derive(Debug, Default)]
pub struct ListFilter {
    pub query: Option<String>,
    pub json: bool,
    pub quiet: bool,
    pub watch: Option<u64>,
    pub labels: Vec<(String, String)>,
}

/// Whether a resource passes the type, label and text filters of `limen ls`.
fn matches_filters(r: &Resource, kinds: &[&str], f: &ListFilter) -> bool {
    let text = |needle: &str| {
        let needle = needle.to_lowercase();
        r.name.to_lowercase().contains(&needle)
            || r.labels
                .iter()
                .any(|(k, v)| format!("{k}={v}").to_lowercase().contains(&needle))
    };
    (kinds.is_empty() || kinds.contains(&r.kind.as_str()))
        && f.labels
            .iter()
            .all(|(k, v)| r.labels.get(k).is_some_and(|actual| actual == v))
        && f.query.as_deref().is_none_or(text)
}

/// The words of the command that opens a resource of this kind, after `limen`.
pub fn connect_words(kind: &str, name: &str) -> Vec<String> {
    let (group, verb): (&str, &str) = match kind {
        "postgres" | "mysql" | "redshift" => ("db", "connect"),
        "redis" => ("redis", "connect"),
        "kubernetes" => ("kube", "login"),
        "mongodb" => ("mongo", "connect"),
        "opensearch" | "elasticsearch" => ("search", "connect"),
        "rabbitmq" => ("mq", "connect"),
        "kafka" => ("kafka", "connect"),
        "web" => ("web", "open"),
        "tcp" => ("tcp", ""),
        _ => ("ssh", ""),
    };
    let mut words = vec![group.to_owned()];
    if !verb.is_empty() {
        words.push(verb.to_owned());
    }
    words.push(name.to_owned());
    words
}

/// The command that opens a resource of this kind, for hints.
fn connect_command(kind: &str, name: &str) -> String {
    format!("limen {}", connect_words(kind, name).join(" "))
}

/// The type of a resource the caller can access.
pub async fn kind_of(proxy: Option<&str>, name: &str) -> anyhow::Result<String> {
    fetch_resources(proxy)
        .await?
        .into_iter()
        .find(|r| r.name == name)
        .map(|r| r.kind)
        .with_context(|| format!("no resource named `{name}` is available to you; see `limen ls`"))
}

async fn fetch_resources(proxy: Option<&str>) -> anyhow::Result<Vec<Resource>> {
    Ok(fetch_all(proxy).await?.resources)
}

async fn fetch_all(proxy: Option<&str>) -> anyhow::Result<limen_proto::v1::ListResourcesResponse> {
    let (_, channel) = api::authenticated(proxy)?;
    Ok(ResourcesClient::new(channel)
        .list_resources(ListResourcesRequest {})
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner())
}

fn sorted_labels(r: &Resource) -> Vec<String> {
    let mut labels: Vec<_> = r.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
    labels.sort();
    labels
}

pub async fn ls(proxy: Option<&str>, f: &ListFilter, kinds: &[&str]) -> anyhow::Result<()> {
    let Some(secs) = f.watch else {
        return ls_once(proxy, f, kinds).await;
    };
    let tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    loop {
        if tty {
            print!("\x1b[2J\x1b[H");
        }
        // A blip (proxy restart, expired login) shouldn't end a watch; show it and retry.
        if let Err(e) = ls_once(proxy, f, kinds).await {
            ui::error(&e);
        }
        tokio::time::sleep(std::time::Duration::from_secs(secs.max(1))).await;
    }
}

async fn ls_once(proxy: Option<&str>, f: &ListFilter, kinds: &[&str]) -> anyhow::Result<()> {
    let filtered = !kinds.is_empty() || !f.labels.is_empty() || f.query.is_some();
    let all = fetch_all(proxy).await?;
    let resources: Vec<_> = all
        .resources
        .into_iter()
        .filter(|r| matches_filters(r, kinds, f))
        .collect();
    // What the user could get by asking (ADR-0025): names and kinds only.
    let requestable: Vec<_> = all
        .requestable
        .into_iter()
        .filter(|r| {
            (kinds.is_empty() || kinds.contains(&r.kind.as_str()))
                && f.query
                    .as_deref()
                    .is_none_or(|q| r.name.to_lowercase().contains(&q.to_lowercase()))
        })
        .collect();
    if f.json {
        let items: Vec<_> = resources
            .iter()
            .map(|r| serde_json::json!({ "name": r.name, "kind": r.kind, "labels": r.labels, "principals": r.principals, "grant_expires_at": (r.grant_expires_at_unix > 0).then_some(r.grant_expires_at_unix) }))
            .collect();
        if requestable.is_empty() {
            println!("{}", serde_json::to_string_pretty(&items)?);
        } else {
            let ask: Vec<_> = requestable
                .iter()
                .map(|r| serde_json::json!({ "name": r.name, "kind": r.kind, "roles": r.roles }))
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({ "resources": items, "requestable": ask })
                )?
            );
        }
        return Ok(());
    }
    if f.quiet {
        for r in &resources {
            println!("{}", r.name);
        }
        return Ok(());
    }
    if resources.is_empty() {
        if filtered {
            ui::info("No resources match those filters.");
            ui::hint("Run `limen ls` without filters to see everything you can reach.");
        } else if requestable.is_empty() {
            ui::info("No resources are available to you.");
            ui::hint("Your roles don't grant access to anything yet. Ask an admin.");
        } else {
            ui::info("You don't have standing access to anything yet.");
        }
        print_requestable(&requestable);
        return Ok(());
    }
    let rows: Vec<[String; 4]> = resources
        .iter()
        .map(|r| {
            let until = if r.grant_expires_at_unix > 0 {
                let left = time::OffsetDateTime::from_unix_timestamp(r.grant_expires_at_unix)
                    .map_or(time::Duration::ZERO, |t| {
                        t - time::OffsetDateTime::now_utc()
                    });
                format!("  {}", ui::expiry(left))
            } else {
                String::new()
            };
            [
                ui::bold(&r.name),
                ui::kind_label(&r.kind),
                format!("{}{until}", r.principals.join(", ")),
                ui::dim(&sorted_labels(r).join(" ")),
            ]
        })
        .collect();
    ui::print_table(["name", "kind", "access as", "labels"], &rows);
    print_requestable(&requestable);
    let n = resources.len();
    let hint = if n == 1 {
        format!(
            "1 resource · connect with `{}`",
            connect_command(&resources[0].kind, &resources[0].name)
        )
    } else {
        format!("{n} resources · `limen show <name>` tells you how to connect to one")
    };
    ui::hint(&hint);
    Ok(())
}

/// "You can ask for" lines after the table.
fn print_requestable(requestable: &[limen_proto::v1::RequestableResource]) {
    if requestable.is_empty() {
        return;
    }
    anstream::println!("\n{}", ui::bold("You can ask for"));
    let rows: Vec<[String; 3]> = requestable
        .iter()
        .map(|r| {
            [
                ui::bold(&r.name),
                ui::kind_label(&r.kind),
                ui::dim(&r.roles.join(", ")),
            ]
        })
        .collect();
    ui::print_table(["name", "kind", "through"], &rows);
    ui::hint("Ask with `limen request <name> --for 30m --reason \"...\"`.");
}

/// `limen show <resource>`: everything the control plane tells this user about one resource.
pub async fn show(proxy: Option<&str>, name: &str, json: bool) -> anyhow::Result<()> {
    let resources = fetch_resources(proxy).await?;
    let Some(r) = resources.iter().find(|r| r.name == name) else {
        let near: Vec<_> = resources
            .iter()
            .filter(|r| r.name.contains(name))
            .map(|r| r.name.as_str())
            .collect();
        let tip = if near.is_empty() {
            String::new()
        } else {
            format!(" Did you mean: {}?", near.join(", "))
        };
        anyhow::bail!("no resource named `{name}` is available to you.{tip}");
    };
    let connect = connect_command(&r.kind, &r.name);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "name": r.name,
                "kind": r.kind,
                "labels": r.labels,
                "principals": r.principals,
                "default_database": r.default_database,
                "web_url": r.web_url,
                "connect": connect,
            }))?
        );
        return Ok(());
    }
    let mut rows = vec![
        ("Name", ui::bold(&r.name)),
        ("Kind", ui::kind_label(&r.kind)),
        ("Access as", r.principals.join(", ")),
        ("Labels", sorted_labels(r).join(" ")),
    ];
    if !r.default_database.is_empty() {
        rows.push(("Default database", r.default_database.clone()));
    }
    if !r.web_url.is_empty() {
        rows.push(("Address", r.web_url.clone()));
    }
    rows.push(("Connect", format!("`{connect}`")));
    anstream::println!("{}", ui::key_values(&rows));
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
        let none = ListFilter::default();
        assert!(matches_filters(&r, &[], &none));
        assert!(matches_filters(&r, &["postgres"], &none));
        assert!(!matches_filters(&r, &["ssh", "mysql"], &none));
        let q = |t: &str| ListFilter {
            query: Some(t.into()),
            ..ListFilter::default()
        };
        assert!(matches_filters(&r, &[], &q("PAYM")));
        assert!(matches_filters(&r, &[], &q("env=stag")));
        assert!(!matches_filters(&r, &[], &q("nope")));
        let env = ("env".to_owned(), "staging".to_owned());
        let team = ("team".to_owned(), "other".to_owned());
        let with = |labels| ListFilter {
            labels,
            ..ListFilter::default()
        };
        assert!(matches_filters(&r, &[], &with(vec![env.clone()])));
        assert!(!matches_filters(&r, &[], &with(vec![env, team])));
    }

    #[test]
    fn connect_commands_follow_the_kind() {
        assert_eq!(connect_command("mysql", "a"), "limen db connect a");
        assert_eq!(connect_command("rabbitmq", "a"), "limen mq connect a");
        assert_eq!(connect_command("ssh", "a"), "limen ssh a");
    }

    #[test]
    fn parses_label_flags() {
        assert_eq!(parse_label("env=prod"), Ok(("env".into(), "prod".into())));
        assert_eq!(parse_label("a=b=c"), Ok(("a".into(), "b=c".into())));
        assert!(parse_label("env").is_err());
        assert!(parse_label("=x").is_err());
    }
}

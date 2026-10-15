//! `limen admin ...`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::Subcommand;
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{
    ApplyPolicyRequest, CreateJoinTokenRequest, GetPolicyRequest, KillSessionRequest,
    ListComponentsRequest, ListLocksRequest, LockUserRequest, PolicySource, RevokeComponentRequest,
    UnlockUserRequest,
};

use crate::api;
use crate::ui;

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Validate and apply role, mapping, and resource YAML. Files or directories.
    Apply {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Show what would change without applying it.
        #[arg(long)]
        dry_run: bool,
        /// Where the policy came from, recorded in the audit trail (for example a Git SHA).
        #[arg(long)]
        source_ref: Option<String>,
    },
    /// Show the active policy version.
    Policy,
    /// Join tokens for proxies and workers.
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// List enrolled proxies and workers, with their tunnels.
    Components,
    /// Refuse a user's logins and sessions, and end their open sessions.
    Lock {
        /// The user's name, as in the audit trail.
        username: String,
        /// Why. Recorded in the audit trail.
        #[arg(long)]
        reason: String,
    },
    /// Lift a lock. The user can log in again.
    Unlock { username: String },
    /// List locked users.
    Locks,
    /// Stop honouring a proxy's or worker's certificate. Its tunnels drop within about 10 seconds.
    Revoke {
        /// The component ID, from `limen admin components`.
        component_id: String,
        /// Why. Recorded in the audit trail.
        #[arg(long)]
        reason: String,
    },
    /// End one live session.
    KillSession {
        /// The session ID, from `session.start` in the audit trail.
        session_id: String,
        /// Why. Recorded in the audit trail.
        #[arg(long)]
        reason: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Create a single-use join token.
    Create {
        /// proxy or worker.
        #[arg(long, default_value = "worker")]
        kind: String,
        /// Labels for the enrolled component, as key=value. Repeatable.
        #[arg(long = "label")]
        labels: Vec<String>,
        /// How long the token stays valid, for example 15m.
        #[arg(long, default_value = "15m")]
        ttl: String,
        /// DNS names a proxy may put in its certificate. Repeatable.
        #[arg(long = "dns-name")]
        dns_names: Vec<String>,
    },
}

pub async fn run(proxy: Option<&str>, command: AdminCommand) -> anyhow::Result<()> {
    let (_, channel) = api::authenticated(proxy)?;
    let mut admin = AdminClient::new(channel);
    match command {
        AdminCommand::Apply {
            paths,
            dry_run,
            source_ref,
        } => {
            let sources = collect_sources(&paths)?;
            let resp = admin
                .apply_policy(ApplyPolicyRequest {
                    sources,
                    dry_run,
                    source_ref: source_ref.unwrap_or_default(),
                })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner();
            let diff = resp.diff.unwrap_or_default();
            for name in &diff.added {
                anstream::println!("{}", ui::green(&format!("+ {name}")));
            }
            for name in &diff.changed {
                anstream::println!("{}", ui::yellow(&format!("~ {name}")));
            }
            for name in &diff.removed {
                anstream::println!("{}", ui::red(&format!("- {name}")));
            }
            if diff.added.is_empty() && diff.changed.is_empty() && diff.removed.is_empty() {
                ui::success(&format!(
                    "No changes. Policy version {} is current.",
                    resp.version
                ));
            } else if resp.applied {
                ui::success(&format!(
                    "Applied policy version {} ({})",
                    ui::bold(&resp.version.to_string()),
                    ui::dim(&resp.digest[..12.min(resp.digest.len())])
                ));
            } else {
                ui::info("Dry run: nothing was applied.");
            }
        }
        AdminCommand::Policy => {
            let p = admin
                .get_policy(GetPolicyRequest {})
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner();
            anstream::println!(
                "{}",
                ui::key_values(&[
                    ("Version", ui::bold(&p.version.to_string())),
                    ("Digest", p.digest.clone()),
                    (
                        "Author",
                        if p.author.is_empty() {
                            "-".into()
                        } else {
                            p.author.clone()
                        }
                    ),
                    ("Resources", p.resource_count.to_string()),
                ])
            );
        }
        AdminCommand::Token {
            command:
                TokenCommand::Create {
                    kind,
                    labels,
                    ttl,
                    dns_names,
                },
        } => {
            let labels = labels
                .iter()
                .map(|l| {
                    l.split_once('=')
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .with_context(|| format!("label {l:?} must be key=value"))
                })
                .collect::<anyhow::Result<HashMap<_, _>>>()?;
            let ttl = parse_ttl(&ttl)?;
            let resp = admin
                .create_join_token(CreateJoinTokenRequest {
                    kind,
                    ttl_seconds: u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX),
                    labels,
                    dns_names,
                })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner();
            println!("{}", resp.token);
            ui::warn(&format!(
                "Single use. Expires at {}.",
                time::OffsetDateTime::from_unix_timestamp(resp.expires_at_unix)
                    .map(|t| t.to_string())
                    .unwrap_or_default()
            ));
        }
        AdminCommand::Components => {
            let resp = admin
                .list_components(ListComponentsRequest {})
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner();
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let rows: Vec<[String; 5]> = resp
                .components
                .iter()
                .map(|c| {
                    let mut labels: Vec<_> =
                        c.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
                    labels.sort();
                    [
                        ui::bold(&c.id),
                        c.kind.clone(),
                        ui::dim(&labels.join(" ")),
                        format!("{}s ago", now - c.last_seen_at_unix),
                        c.tunnels.len().to_string(),
                    ]
                })
                .collect();
            ui::print_table(["id", "kind", "labels", "last seen", "tunnels"], &rows);
        }
        lock_command @ (AdminCommand::Lock { .. }
        | AdminCommand::Unlock { .. }
        | AdminCommand::Locks
        | AdminCommand::Revoke { .. }
        | AdminCommand::KillSession { .. }) => run_locks(&mut admin, lock_command).await?,
    }
    Ok(())
}

/// Locks and session kills (ADR-0017).
async fn run_locks(
    admin: &mut AdminClient<tonic::transport::Channel>,
    command: AdminCommand,
) -> anyhow::Result<()> {
    match command {
        AdminCommand::Lock { username, reason } => {
            let resp = admin
                .lock_user(LockUserRequest {
                    username: username.clone(),
                    reason,
                })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner();
            if resp.locked {
                ui::success(&format!("Locked {}", ui::bold(&username)));
                ui::hint(
                    "New logins and sessions are refused now; open sessions end within about 10 seconds.",
                );
            } else {
                ui::info(&format!("{username} was already locked."));
            }
        }
        AdminCommand::Unlock { username } => {
            let resp = admin
                .unlock_user(UnlockUserRequest {
                    username: username.clone(),
                })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner();
            if resp.unlocked {
                ui::success(&format!("Unlocked {}", ui::bold(&username)));
            } else {
                ui::info(&format!("{username} wasn't locked."));
            }
        }
        AdminCommand::Locks => {
            let resp = admin
                .list_locks(ListLocksRequest {})
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner();
            let rows: Vec<[String; 4]> = resp
                .locks
                .iter()
                .map(|l| {
                    [
                        l.username.clone(),
                        l.locked_by.clone(),
                        time::OffsetDateTime::from_unix_timestamp(l.locked_at_unix)
                            .map(|t| t.to_string())
                            .unwrap_or_default(),
                        l.reason.clone(),
                    ]
                })
                .collect();
            if rows.is_empty() {
                ui::info("Nobody is locked.");
            } else {
                ui::print_table(["user", "locked by", "locked at", "reason"], &rows);
            }
        }
        AdminCommand::Revoke {
            component_id,
            reason,
        } => {
            let resp = admin
                .revoke_component(RevokeComponentRequest {
                    component_id: component_id.clone(),
                    reason,
                })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner();
            if resp.revoked {
                ui::success(&format!("Revoked {}", ui::bold(&component_id)));
                ui::hint(
                    "Renewal is refused, and proxies drop its tunnels within about 10 seconds.",
                );
            } else {
                ui::info(&format!("{component_id} was already revoked."));
            }
        }
        AdminCommand::KillSession { session_id, reason } => {
            let resp = admin
                .kill_session(KillSessionRequest {
                    session_id: session_id.clone(),
                    reason,
                })
                .await
                .map_err(|s| api::status_error(&s))?
                .into_inner();
            if resp.killed {
                ui::success(&format!(
                    "Session {} will end within about 10 seconds",
                    ui::bold(&session_id)
                ));
            } else {
                ui::info(&format!("Session {session_id} was already marked to end."));
            }
        }
        _ => unreachable!("only lock commands are routed here"),
    }
    Ok(())
}

fn parse_ttl(s: &str) -> anyhow::Result<Duration> {
    let split = s
        .find(|c: char| !c.is_ascii_digit())
        .context("ttl needs a unit (s, m, h)")?;
    let (n, unit) = s.split_at(split);
    let n: u64 = n.parse().context("invalid ttl")?;
    Ok(match unit {
        "s" => Duration::from_secs(n),
        "m" => Duration::from_mins(n),
        "h" => Duration::from_hours(n),
        _ => bail!("ttl unit must be s, m, or h"),
    })
}

/// Read YAML files, recursing into directories. Sorted for stable output.
fn collect_sources(paths: &[PathBuf]) -> anyhow::Result<Vec<PolicySource>> {
    let mut files = Vec::new();
    for path in paths {
        collect(path, &mut files)?;
    }
    files.sort();
    if files.is_empty() {
        bail!("no .yaml or .yml files found");
    }
    files
        .into_iter()
        .map(|f| {
            Ok(PolicySource {
                content: std::fs::read_to_string(&f)
                    .with_context(|| format!("reading {}", f.display()))?,
                name: f.display().to_string(),
            })
        })
        .collect()
}

fn collect(path: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            collect(&entry?.path(), out)?;
        }
    } else if matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yaml" | "yml")
    ) {
        out.push(path.to_owned());
    } else if !path.exists() {
        bail!("{} does not exist", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn collects_yaml_from_directories() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/policy");
        let sources = super::collect_sources(&[dir]).expect("collect");
        assert_eq!(sources.len(), 5);
        assert!(sources.iter().all(|s| {
            std::path::Path::new(&s.name)
                .extension()
                .is_some_and(|e| e == "yaml")
        }));
    }

    #[test]
    fn parses_ttl() {
        assert_eq!(super::parse_ttl("15m").expect("ok").as_secs(), 900);
        assert!(super::parse_ttl("15").is_err());
        assert!(super::parse_ttl("15d").is_err());
    }
}

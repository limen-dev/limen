//! `limen policy ...`: ask questions of a policy (ADR-0028). Everything runs
//! the same decision code as enforcement (`limen-policy`), offline on a
//! directory of YAML, or against the active policy with `--active`.

use std::path::PathBuf;

use anyhow::{Context as _, bail};
use clap::Subcommand;
use limen_policy::tooling::{ChangeKind, Via};
use limen_policy::{Document, Policy};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, GetPolicyDocumentsRequest, SuggestPolicyRequest};

use super::admin::collect_sources;
use crate::{api, ui};

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Run the `policy_test` cases in a policy. Exits non-zero if any fails, for CI.
    Test {
        /// Policy files or directories (roles, mappings, resources, and tests).
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Also list the resources and roles that no case touches.
        #[arg(long)]
        coverage: bool,
        /// Fail if there are no test cases at all.
        #[arg(long)]
        require_cases: bool,
        /// Output JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Who can reach a resource: the roles, groups, bots, and requestable roles.
    WhoCan {
        resource: String,
        #[command(flatten)]
        source: Source,
        #[arg(long)]
        json: bool,
    },
    /// What a group, or a bot, can reach and could ask for.
    WhatCan {
        /// IdP groups. Repeat for a person in several.
        #[arg(long = "group")]
        groups: Vec<String>,
        /// A bot instead of groups.
        #[arg(long, conflicts_with = "groups")]
        bot: Option<String>,
        #[command(flatten)]
        source: Source,
        #[arg(long)]
        json: bool,
    },
    /// What changes in who can reach what between two policies, not between two YAML files.
    Diff {
        /// The old policy: files or directories, or `active` for the running one.
        old: Vec<String>,
        /// The new policy: files or directories (after `--new`).
        #[arg(long = "new", required = true)]
        new: Vec<PathBuf>,
        /// text, json, or markdown (for a pull request comment).
        #[arg(long, default_value = "text", value_parser = ["text", "json", "markdown"])]
        format: String,
        /// Exit non-zero if anyone gains standing access, so CI can ask for a closer look.
        #[arg(long)]
        fail_on_widening: bool,
        /// Also replay the last DAYS (1 to 30, default 30) of recorded sessions through
        /// the active and the new policy and say who would have been refused (needs
        /// limen:admin; the old side must be `active`; the new files are read as
        /// `limen admin apply` reads them).
        #[arg(
            long,
            value_name = "DAYS",
            num_args = 0..=1,
            default_missing_value = "30",
            value_parser = clap::value_parser!(u32).range(1..=30)
        )]
        replay: Option<u32>,
        /// With --replay: exit non-zero if any recorded session would have been refused.
        #[arg(long, requires = "replay")]
        fail_on_affected: bool,
    },
    /// Propose a tighter policy from what people used: access a role grants that nobody used.
    ///
    /// Needs limen:admin. It only proposes removals and never applies them. The
    /// history must be at least as long as the window.
    Suggest {
        /// Days of sessions to judge by (7 to 365). A quarterly job needs 120 or more.
        #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(u32).range(7..=365))]
        window_days: u32,
        /// Write the changed roles, as policy YAML, to this new file.
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Print only the YAML, for a pipe.
        #[arg(long, conflicts_with_all = ["json", "output"])]
        yaml: bool,
        /// Print the full result as JSON.
        #[arg(long, conflicts_with = "yaml")]
        json: bool,
    },
}

/// Where the policy to ask about comes from.
#[derive(Debug, clap::Args)]
pub struct Source {
    /// Read the policy from these files or directories (offline).
    #[arg(long = "from", value_name = "PATH", conflicts_with = "active")]
    from: Vec<PathBuf>,
    /// Ask the running control plane for its active policy (needs limen:admin).
    #[arg(long)]
    active: bool,
}

async fn load(proxy: Option<&str>, source: &Source) -> anyhow::Result<Policy> {
    if source.active || source.from.is_empty() {
        return active(proxy).await;
    }
    from_paths(&source.from)
}

fn from_paths(paths: &[PathBuf]) -> anyhow::Result<Policy> {
    let sources = collect_sources(paths)?;
    Policy::parse_yaml(
        sources
            .iter()
            .map(|s| (s.name.as_str(), s.content.as_str())),
    )
    .context("the policy is not valid")
}

async fn active(proxy: Option<&str>) -> anyhow::Result<Policy> {
    let (_, channel) = api::authenticated(proxy)?;
    let resp = AdminClient::new(channel)
        .get_policy_documents(GetPolicyDocumentsRequest {})
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    let docs: Vec<Document> = serde_json::from_str(&resp.documents_json)?;
    Policy::from_documents(docs).context("the active policy did not load")
}

pub async fn run(proxy: Option<&str>, command: PolicyCommand) -> anyhow::Result<()> {
    match command {
        PolicyCommand::Test {
            paths,
            coverage,
            require_cases,
            json,
        } => test(&paths, coverage, require_cases, json),
        PolicyCommand::WhoCan {
            resource,
            source,
            json,
        } => who_can(&load(proxy, &source).await?, &resource, json),
        PolicyCommand::WhatCan {
            groups,
            bot,
            source,
            json,
        } => what_can(&load(proxy, &source).await?, &groups, bot.as_deref(), json),
        PolicyCommand::Diff {
            old,
            new,
            format,
            fail_on_widening,
            replay,
            fail_on_affected,
        } => {
            diff(
                proxy,
                &old,
                &new,
                &format,
                fail_on_widening,
                replay.map(|days| (days, fail_on_affected)),
            )
            .await
        }
        PolicyCommand::Suggest {
            window_days,
            output,
            yaml,
            json,
        } => suggest(proxy, window_days, output.as_deref(), yaml, json).await,
    }
}

fn test(paths: &[PathBuf], coverage: bool, require_cases: bool, json: bool) -> anyhow::Result<()> {
    let policy = from_paths(paths)?;
    let report = policy.run_tests();
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for r in &report.results {
            let mark = if r.passed {
                ui::green("✓")
            } else {
                ui::red("✗")
            };
            anstream::println!(
                "{mark} {}  {}",
                ui::dim(&format!("{} #{}", r.test, r.case)),
                r.name
            );
            if !r.passed {
                anstream::println!(
                    "    expected {}, got {}{}",
                    ui::bold(&r.expected),
                    ui::bold(&r.got),
                    if r.detail.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", r.detail)
                    }
                );
            }
        }
        let c = &report.coverage;
        if coverage || report.results.is_empty() {
            anstream::println!(
                "\n{} resources and {} roles; {} must-deny case(s).",
                c.resources,
                c.roles,
                c.deny_cases
            );
            if !c.untested_resources.is_empty() {
                anstream::println!(
                    "Resources no case touches: {}",
                    c.untested_resources.join(", ")
                );
            }
            if !c.untested_roles.is_empty() {
                anstream::println!("Roles no case touches: {}", c.untested_roles.join(", "));
            }
        }
        if report.results.is_empty() {
            ui::warn("No policy_test documents found.");
        } else if report.ok() {
            ui::success(&format!("{} case(s) pass.", report.results.len()));
        }
    }
    if !report.ok() {
        bail!(
            "{} of {} policy test case(s) failed",
            report.failed(),
            report.results.len()
        );
    }
    if require_cases && report.results.is_empty() {
        bail!("no policy test cases found (--require-cases)");
    }
    Ok(())
}

fn via_text(via: Via) -> String {
    match via {
        Via::Standing => "standing".to_owned(),
        Via::Request => ui::yellow("by request"),
        Via::BreakGlass => ui::red("break-glass"),
    }
}

fn who_can(policy: &Policy, resource: &str, json: bool) -> anyhow::Result<()> {
    if policy.resource(resource).is_none() {
        bail!("the policy has no resource named `{resource}`");
    }
    let entries = policy.who_can(resource);
    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }
    if entries.is_empty() {
        ui::info(&format!(
            "Nobody can reach `{resource}`: no role that selects it is held by a group or bot, or can be requested."
        ));
        return Ok(());
    }
    let rows: Vec<[String; 5]> = entries
        .iter()
        .map(|e| {
            let mut who = Vec::new();
            who.extend(e.groups.iter().map(|g| format!("group {g}")));
            who.extend(e.bots.iter().map(|b| format!("bot {b}")));
            [
                ui::role(&e.role),
                via_text(e.via),
                e.principals.join(", "),
                who.join(", "),
                if e.approvers.is_empty() {
                    ui::dim("-")
                } else {
                    e.approvers.join(", ")
                },
            ]
        })
        .collect();
    ui::print_table(["role", "how", "as", "who", "approved by"], &rows);
    Ok(())
}

fn what_can(
    policy: &Policy,
    groups: &[String],
    bot: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    if groups.is_empty() && bot.is_none() {
        bail!("name a group with --group, or a bot with --bot");
    }
    let can = policy.what_can(groups, bot).map_err(anyhow::Error::msg)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&can)?);
        return Ok(());
    }
    if can.standing.is_empty() {
        ui::info("Nothing, with standing access.");
    } else {
        let rows: Vec<[String; 3]> = can
            .standing
            .iter()
            .map(|r| {
                [
                    ui::bold(&r.name),
                    ui::kind_label(r.kind.as_str()),
                    r.principals.join(", "),
                ]
            })
            .collect();
        ui::print_table(["resource", "kind", "as"], &rows);
    }
    if !can.requestable.is_empty() {
        anstream::println!("\n{}", ui::bold("Could ask for"));
        let rows: Vec<[String; 3]> = can
            .requestable
            .iter()
            .map(|r| {
                [
                    ui::bold(&r.name),
                    ui::kind_label(r.kind.as_str()),
                    r.roles.join(", "),
                ]
            })
            .collect();
        ui::print_table(["resource", "kind", "through"], &rows);
    }
    Ok(())
}

async fn diff(
    proxy: Option<&str>,
    old: &[String],
    new: &[PathBuf],
    format: &str,
    fail_on_widening: bool,
    replay: Option<(u32, bool)>,
) -> anyhow::Result<()> {
    if replay.is_some() && !(old.is_empty() || old == ["active"]) {
        bail!("--replay compares against the running policy: use `active` as the old policy");
    }
    let old_policy = if old.is_empty() || old == ["active"] {
        active(proxy).await?
    } else {
        from_paths(&old.iter().map(PathBuf::from).collect::<Vec<_>>())?
    };
    let new_policy = from_paths(new)?;
    let result = old_policy.access_diff(&new_policy);
    let replayed = match replay {
        Some((days, _)) => Some(replay_report(proxy, new, days).await?),
        None => None,
    };
    match (format, &replayed) {
        ("json", None) => println!("{}", serde_json::to_string_pretty(&result)?),
        ("json", Some(r)) => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "access": result, "replay": r }))?
        ),
        ("markdown", _) => {
            print!("{}", result.render_markdown());
            if let Some(r) = &replayed {
                print!("\n{}", r.render_markdown());
            }
        }
        _ => {
            for c in &result.changes {
                let line = match c.change {
                    ChangeKind::Gain => ui::yellow(&format!("+ {}", c.text())),
                    ChangeKind::Loss => ui::green(&format!("- {}", c.text())),
                };
                anstream::println!("{line}");
            }
            if result.changes.is_empty() {
                ui::success("No change in effective access.");
            }
            if let Some(r) = &replayed {
                println!("\n{}", r.render_text());
            }
        }
    }
    for w in new_policy.warnings() {
        ui::warn(&w);
    }
    if fail_on_widening && result.widens_standing() {
        bail!("standing access widens (--fail-on-widening)");
    }
    if let (Some((_, true)), Some(r)) = (replay, &replayed)
        && r.affected_sessions > 0
    {
        bail!(
            "{} recorded sessions would have been refused (--fail-on-affected)",
            r.affected_sessions
        );
    }
    Ok(())
}

async fn suggest(
    proxy: Option<&str>,
    window_days: u32,
    output: Option<&std::path::Path>,
    yaml: bool,
    json: bool,
) -> anyhow::Result<()> {
    // Before the question is asked (and audited): a new file, or nothing.
    if let Some(path) = output
        && path.exists()
    {
        bail!(
            "{} already exists; --output writes a new file only",
            path.display()
        );
    }
    let (_, channel) = api::authenticated(proxy)?;
    let resp = AdminClient::new(channel)
        .suggest_policy(SuggestPolicyRequest { window_days })
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    if yaml {
        print!("{}", resp.yaml);
        return Ok(());
    }
    if let Some(path) = output {
        use std::io::Write as _;
        // A new file only: a suggestion must not replace a policy by accident.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("{} must be a new file", path.display()))?;
        file.write_all(resp.yaml.as_bytes())?;
    }
    if json {
        println!("{}", resp.report_json);
        return Ok(());
    }
    print!("{}", resp.text);
    if !resp.diff.is_empty() {
        anstream::println!("\n{}", ui::bold("Effective access after the changes"));
        for line in resp.diff.lines() {
            anstream::println!("{}", ui::green(line));
        }
    }
    if let Some(path) = output {
        ui::success(&format!(
            "Wrote the changed roles to {} (from policy version {}). Nothing was applied: \
             put them in your policy repository, then run `limen policy diff active --new <policy>` and `limen policy test`.",
            path.display(),
            resp.policy_version
        ));
    }
    Ok(())
}

/// Ask the control plane to replay recorded sessions through the running
/// policy and the one these files would make (a dry-run apply).
async fn replay_report(
    proxy: Option<&str>,
    new: &[PathBuf],
    days: u32,
) -> anyhow::Result<limen_policy::replay::ReplayReport> {
    let sources = collect_sources(new)?;
    let (_, channel) = api::authenticated(proxy)?;
    let resp = AdminClient::new(channel)
        .apply_policy(ApplyPolicyRequest {
            sources,
            dry_run: true,
            replay_days: days,
            ..Default::default()
        })
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    serde_json::from_str(&resp.replay_json)
        .context("the control plane did not return a replay (is it an older version?)")
}

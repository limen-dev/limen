//! `limen`: log in through your identity provider and get short-lived access
//! to SSH hosts today, and (planned) databases, Redis, Kubernetes, MongoDB,
//! search, message brokers, web apps, and TCP services.

// A CLI's job is printing to stdout.
#![allow(clippy::print_stdout)]
// Doc comments on commands become `--help` text, where product names read better without backticks.
#![allow(clippy::doc_markdown)]

mod api;
mod commands;
mod oidc;
mod profile;
mod ui;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use limen_core::telemetry::{self, LogFormat};

/// Help colours: the Limen teal for headings, plain text elsewhere.
const STYLES: clap::builder::Styles = clap::builder::Styles::styled()
    .header(
        anstyle::Style::new()
            .fg_color(Some(anstyle::Color::Rgb(anstyle::RgbColor(20, 184, 166))))
            .effects(anstyle::Effects::BOLD),
    )
    .usage(
        anstyle::Style::new()
            .fg_color(Some(anstyle::Color::Rgb(anstyle::RgbColor(20, 184, 166))))
            .effects(anstyle::Effects::BOLD),
    )
    .literal(anstyle::Style::new().effects(anstyle::Effects::BOLD))
    .placeholder(anstyle::Style::new().effects(anstyle::Effects::DIMMED));

#[derive(Debug, Parser)]
#[command(
    name = "limen",
    version = limen_core::VERSION,
    about,
    styles = STYLES,
    after_help = "Start with `limen login`, then `limen ls`. Output is plain when piped or when NO_COLOR is set."
)]
struct Cli {
    /// When to use colour: auto, always, or never.
    #[arg(
        long,
        global = true,
        value_enum,
        default_value = "auto",
        value_name = "WHEN"
    )]
    color: ColorWhen,

    /// Proxy address, for example `limen.example.com:443`. Defaults to the last one used.
    #[arg(long, global = true, env = "LIMEN_PROXY")]
    proxy: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ColorWhen {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Log in through the identity provider and get short-lived credentials.
    Login {
        /// Use the device code flow, for machines without a browser.
        #[arg(long)]
        device: bool,
        /// Print the login URL instead of opening a browser.
        #[arg(long)]
        no_browser: bool,
        /// CA certificate to trust for the proxy. Pinned for later commands.
        #[arg(long)]
        ca_file: Option<PathBuf>,
    },
    /// Delete local credentials.
    Logout,
    /// Show the current identity, roles, and when the credentials expire.
    Status,
    /// List resources you are allowed to access.
    Ls {
        /// Output JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Open an SSH session: `limen ssh [login@]resource [command...]`.
    Ssh {
        target: String,
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// OpenSSH ProxyCommand used by `limen ssh` and `limen config ssh`.
    #[command(hide = true)]
    SshProxy { login: String, host: String },
    /// Print configuration snippets for other tools.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    // The commands below are planned integrations (ADR-0018, ADR-0022). Their
    // arguments are settled so scripts and docs can be written now; each one
    // says plainly that it isn't available yet.
    /// PostgreSQL, MySQL, Aurora, and Redshift (planned, Phase 6).
    Db {
        #[command(subcommand)]
        command: DbCommand,
    },
    /// Redis and Valkey (planned, Phase 7).
    Redis {
        #[command(subcommand)]
        command: RedisCommand,
    },
    /// Kubernetes and EKS (planned, Phase 8).
    Kube {
        #[command(subcommand)]
        command: KubeCommand,
    },
    /// MongoDB, Atlas, and DocumentDB (planned, Phase 9).
    Mongo {
        #[command(subcommand)]
        command: MongoCommand,
    },
    /// OpenSearch and Elasticsearch (planned, Phase 10).
    Search {
        #[command(subcommand)]
        command: SearchCommand,
    },
    /// RabbitMQ and Amazon MQ (planned, Phase 11).
    Mq {
        #[command(subcommand)]
        command: MqCommand,
    },
    /// Kafka and MSK (planned, Phase 11).
    Kafka {
        #[command(subcommand)]
        command: KafkaCommand,
    },
    /// Internal web apps (planned, Phase 12).
    Web {
        #[command(subcommand)]
        command: WebCommand,
    },
    /// Raw TCP services (planned, Phase 12): `limen tcp <resource>`.
    Tcp {
        resource: String,
        /// Local address to listen on. Defaults to a free port on 127.0.0.1.
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
    },
    /// Administrative commands. These require the limen:admin role.
    Admin {
        #[command(subcommand)]
        command: commands::admin::AdminCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// An ~/.ssh/config block so `ssh <login>@<resource>.limen` works directly.
    Ssh,
}

#[derive(Debug, Subcommand)]
enum DbCommand {
    /// Open a local listener for psql or mysql to connect to without a password.
    Connect {
        resource: String,
        #[arg(long)]
        db_role: Option<String>,
        #[arg(long)]
        database: Option<String>,
        /// Local address to listen on. Defaults to a free port on 127.0.0.1.
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum RedisCommand {
    /// Open a local listener for redis-cli.
    Connect {
        resource: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum KubeCommand {
    /// Write a kubeconfig context that uses the limen exec credential plugin.
    Login { cluster: String },
}

#[derive(Debug, Subcommand)]
enum MongoCommand {
    /// Open a local listener for mongosh and drivers.
    Connect {
        resource: String,
        #[arg(long)]
        role: Option<String>,
        #[arg(long)]
        database: Option<String>,
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum SearchCommand {
    /// Open a local listener for curl and the OpenSearch or Elasticsearch clients.
    Connect {
        resource: String,
        #[arg(long)]
        role: Option<String>,
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum MqCommand {
    /// Open a local AMQP listener.
    Connect {
        resource: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum KafkaCommand {
    /// Open local listeners for Kafka clients.
    Connect {
        resource: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum WebCommand {
    /// Open an internal web app in your browser after single sign-on.
    Open {
        app: String,
        /// Print the address instead of opening a browser.
        #[arg(long)]
        no_browser: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    anstream::ColorChoice::write_global(match cli.color {
        ColorWhen::Auto => anstream::ColorChoice::Auto,
        ColorWhen::Always => anstream::ColorChoice::Always,
        ColorWhen::Never => anstream::ColorChoice::Never,
    });
    // Logs go to stderr and default to warnings, so command output stays clean.
    telemetry::init_with_default(LogFormat::Text, "warn");
    if let Err(e) = run(cli).await {
        ui::error(&e);
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let proxy = cli.proxy.as_deref();
    match cli.command {
        Command::Login {
            device,
            no_browser,
            ca_file,
        } => commands::login::run(proxy, device, !no_browser, ca_file.as_deref()).await,
        Command::Logout => commands::logout(proxy),
        Command::Status => commands::status(proxy),
        Command::Ls { json } => commands::ls(proxy, json).await,
        Command::Admin { command } => commands::admin::run(proxy, command).await,
        Command::Ssh { target, command } => commands::ssh::ssh(proxy, &target, &command).await,
        Command::SshProxy { login, host } => commands::ssh::ssh_proxy(proxy, &login, &host).await,
        Command::Config {
            command: ConfigCommand::Ssh,
        } => commands::ssh::config(proxy),
        Command::Db { .. } => not_yet("limen db connect", "database access", "Phase 6"),
        Command::Redis { .. } => not_yet("limen redis connect", "Redis access", "Phase 7"),
        Command::Kube { .. } => not_yet("limen kube login", "Kubernetes access", "Phase 8"),
        Command::Mongo { .. } => not_yet("limen mongo connect", "MongoDB access", "Phase 9"),
        Command::Search { .. } => not_yet("limen search connect", "search access", "Phase 10"),
        Command::Mq { .. } => not_yet("limen mq connect", "RabbitMQ access", "Phase 11"),
        Command::Kafka { .. } => not_yet("limen kafka connect", "Kafka access", "Phase 11"),
        Command::Web { .. } => not_yet("limen web open", "web app access", "Phase 12"),
        Command::Tcp { .. } => not_yet("limen tcp", "TCP service access", "Phase 12"),
    }
}

/// The planned integrations are in policy and in the console already, but no
/// worker serves them. Say so, and say when.
fn not_yet(command: &str, what: &str, phase: &str) -> anyhow::Result<()> {
    anyhow::bail!(
        "`{command}` isn't available yet: {what} is planned for {phase}. \
         You can already see these resources with `limen ls`. Roadmap: https://github.com/jfcmartins/limen/milestones"
    )
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::{Cli, Command, DbCommand};

    /// Every planned integration has a command whose arguments parse, and that
    /// fails with the phase and no side effects.
    #[test]
    fn planned_commands_parse() {
        for args in [
            &[
                "db",
                "connect",
                "r",
                "--db-role",
                "x",
                "--database",
                "d",
                "--listen",
                "127.0.0.1:5433",
            ][..],
            &["redis", "connect", "r", "--user", "u"],
            &["kube", "login", "c"],
            &["mongo", "connect", "r", "--role", "x", "--database", "d"],
            &["search", "connect", "r", "--role", "x"],
            &["mq", "connect", "r", "--user", "u"],
            &["kafka", "connect", "r", "--user", "u"],
            &["web", "open", "app", "--no-browser"],
            &["tcp", "r", "--listen", "127.0.0.1:2121"],
        ] {
            let mut full = vec!["limen"];
            full.extend_from_slice(args);
            Cli::try_parse_from(full).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
    }

    #[test]
    fn planned_commands_say_when() {
        let message = super::not_yet("limen mongo connect", "MongoDB access", "Phase 9")
            .expect_err("not available")
            .to_string();
        assert!(message.contains("limen mongo connect") && message.contains("Phase 9"));
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_db_connect() {
        let cli = Cli::try_parse_from([
            "limen",
            "db",
            "connect",
            "orders-prod",
            "--db-role",
            "readonly",
        ])
        .expect("parse");
        assert!(matches!(
            cli.command,
            Command::Db { command: DbCommand::Connect { ref resource, .. } } if resource == "orders-prod"
        ));
    }
}

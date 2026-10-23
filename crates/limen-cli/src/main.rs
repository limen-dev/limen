//! `limen`: log in through your identity provider and get short-lived access
//! to SSH hosts, SQL databases, Redis or Valkey, Kubernetes clusters, and search
//! (`OpenSearch` and Elasticsearch), and (planned) MongoDB, message brokers, web
//! apps, and TCP services.

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

/// Where a bot's identity token comes from (ADR-0019).
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
#[value(rename_all = "snake_case")]
enum BotMethod {
    GithubActions,
    Gitlab,
    Oidc,
}

impl BotMethod {
    fn as_str(self) -> &'static str {
        match self {
            BotMethod::GithubActions => "github_actions",
            BotMethod::Gitlab => "gitlab",
            BotMethod::Oidc => "oidc",
        }
    }
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
        /// Log in as a bot with this CI platform's identity token, instead of
        /// as a person. In GitHub Actions the token is requested for you.
        #[arg(long, value_enum, value_name = "METHOD", conflicts_with_all = ["device", "no_browser"])]
        bot: Option<BotMethod>,
        /// Which bot, if more than one could match the token.
        #[arg(long, requires = "bot", value_name = "NAME")]
        bot_name: Option<String>,
        /// Read the token from this environment variable (default for gitlab and oidc: LIMEN_ID_TOKEN).
        #[arg(long, requires = "bot", value_name = "VAR")]
        token_env: Option<String>,
        /// Read the token from this file, or `-` for standard input.
        #[arg(
            long,
            requires = "bot",
            value_name = "FILE",
            conflicts_with = "token_env"
        )]
        token_file: Option<PathBuf>,
        /// The audience to ask GitHub for. Defaults to the one the control plane expects.
        #[arg(long, requires = "bot", value_name = "AUD")]
        audience: Option<String>,
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
    /// PostgreSQL, MySQL, Aurora, and Redshift.
    Db {
        #[command(subcommand)]
        command: DbCommand,
    },
    /// Redis and Valkey: `limen redis connect <resource>`.
    Redis {
        #[command(subcommand)]
        command: RedisCommand,
    },
    /// Kubernetes and EKS.
    Kube {
        #[command(subcommand)]
        command: KubeCommand,
    },
    /// MongoDB, Atlas, and DocumentDB: `limen mongo connect <resource>`.
    Mongo {
        #[command(subcommand)]
        command: MongoCommand,
    },
    /// `OpenSearch` and Elasticsearch: `limen search connect <resource>`.
    Search {
        #[command(subcommand)]
        command: SearchCommand,
    },
    /// RabbitMQ and Amazon MQ: `limen mq connect <resource>`.
    Mq {
        #[command(subcommand)]
        command: MqCommand,
    },
    /// Kafka and MSK: `limen kafka connect <resource>`.
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
        #[arg(long, value_name = "ADDR", conflicts_with = "socket")]
        listen: Option<String>,
        /// Listen on a Unix socket (mode 0600) instead of TCP.
        #[arg(long, value_name = "PATH")]
        socket: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum RedisCommand {
    /// Open a local listener that redis-cli (or any Redis or Valkey client) connects to without a password.
    Connect {
        resource: String,
        /// The Redis ACL user to act as (Valkey has the same). Optional when policy allows only one.
        #[arg(long)]
        user: Option<String>,
        /// Local address to listen on. Defaults to a free port on 127.0.0.1.
        #[arg(long, value_name = "ADDR", conflicts_with = "socket")]
        listen: Option<String>,
        /// Listen on a unix socket (mode 0600, in a directory only you can enter) instead of TCP.
        #[arg(long, value_name = "PATH")]
        socket: Option<std::path::PathBuf>,
        /// Stop after this long with no connection, e.g. 30m. 0 never stops.
        #[arg(long, value_name = "DURATION", default_value = "1h", value_parser = commands::redis::parse_idle)]
        idle_timeout: std::time::Duration,
    },
}

#[derive(Debug, Subcommand)]
enum KubeCommand {
    /// Write a kubeconfig for a cluster; kubectl then asks `limen kube credentials`.
    Login {
        cluster: String,
        /// Write the kubeconfig here instead of in the profile directory.
        #[arg(long, value_name = "FILE")]
        kubeconfig: Option<PathBuf>,
        /// Print the kubeconfig instead of writing it.
        #[arg(long, conflicts_with = "kubeconfig")]
        print: bool,
    },
    /// The kubectl exec credential plugin: prints your short-lived certificate.
    Credentials,
}

#[derive(Debug, Subcommand)]
enum MongoCommand {
    /// Open a local listener that mongosh (or any MongoDB driver) connects to without a password.
    Connect {
        resource: String,
        /// The MongoDB role to act as. Optional when policy allows only one.
        #[arg(long)]
        role: Option<String>,
        /// The database to open. Defaults to the resource's default_database.
        #[arg(long)]
        database: Option<String>,
        /// Local address to listen on. Defaults to a free port on 127.0.0.1.
        #[arg(long, value_name = "ADDR", conflicts_with = "socket")]
        listen: Option<String>,
        /// Listen on a unix socket (mode 0600, in a directory only you can enter) instead of TCP.
        #[arg(long, value_name = "PATH")]
        socket: Option<std::path::PathBuf>,
        /// Stop after this long with no connection, e.g. 30m. 0 never stops.
        #[arg(long, value_name = "DURATION", default_value = "1h", value_parser = commands::redis::parse_idle)]
        idle_timeout: std::time::Duration,
    },
}

#[derive(Debug, Subcommand)]
enum SearchCommand {
    /// Open a local listener that curl and the Elasticsearch and `OpenSearch` clients use without a credential.
    Connect {
        resource: String,
        /// The engine role to act as. Optional when policy allows only one.
        #[arg(long)]
        role: Option<String>,
        /// Local address to listen on (loopback only). Defaults to a free port on 127.0.0.1.
        #[arg(long, value_name = "ADDR", conflicts_with = "socket")]
        listen: Option<String>,
        /// Listen on a unix socket (mode 0600, in a directory only you can enter) instead of TCP.
        #[arg(long, value_name = "PATH")]
        socket: Option<std::path::PathBuf>,
        /// Stop after this long with no connection, e.g. 30m. 0 never stops.
        #[arg(long, value_name = "DURATION", default_value = "1h", value_parser = commands::search::parse_idle)]
        idle_timeout: std::time::Duration,
    },
}

#[derive(Debug, Subcommand)]
enum MqCommand {
    /// Open a local listener that AMQP 0-9-1 clients (pika, amqplib, Bunny, ...) connect to without a password.
    Connect {
        resource: String,
        /// The broker user to act as. Optional when policy allows only one.
        #[arg(long)]
        user: Option<String>,
        /// The vhost the printed URL names. The client chooses the real one; policy limits it.
        #[arg(long, default_value = "/")]
        vhost: String,
        /// Local address to listen on. Defaults to a free port on 127.0.0.1.
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
        /// Stop after this long with no connection, e.g. 30m. 0 never stops.
        #[arg(long, value_name = "DURATION", default_value = "1h", value_parser = commands::redis::parse_idle)]
        idle_timeout: std::time::Duration,
    },
}

#[derive(Debug, Subcommand)]
enum KafkaCommand {
    /// Open local listeners that Kafka clients (kcat, the Java client, librdkafka, ...) bootstrap from without a password.
    Connect {
        resource: String,
        /// The broker user to act as. Optional when policy allows only one.
        #[arg(long)]
        user: Option<String>,
        /// Local address of the bootstrap listener. Defaults to a free port on 127.0.0.1.
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
        /// Broker slots to open (one local listener per broker of the cluster).
        #[arg(long, default_value_t = commands::kafka::DEFAULT_BROKERS, value_parser = commands::kafka::brokers_parser)]
        brokers: usize,
        /// Stop after this long with no connection, e.g. 30m. 0 never stops.
        #[arg(long, value_name = "DURATION", default_value = "1h", value_parser = commands::redis::parse_idle)]
        idle_timeout: std::time::Duration,
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

#[allow(clippy::too_many_lines)] // one arm per command
async fn run(cli: Cli) -> anyhow::Result<()> {
    let proxy = cli.proxy.as_deref();
    match cli.command {
        Command::Login {
            bot: Some(method),
            bot_name,
            token_env,
            token_file,
            audience,
            ca_file,
            ..
        } => {
            commands::bot::run(commands::bot::BotLogin {
                proxy,
                method: method.as_str(),
                bot: bot_name.as_deref(),
                token_env: token_env.as_deref(),
                token_file: token_file.as_deref(),
                audience: audience.as_deref(),
                ca_file: ca_file.as_deref(),
            })
            .await
        }
        Command::Login {
            device,
            no_browser,
            ca_file,
            ..
        } => commands::login::run(proxy, device, !no_browser, ca_file.as_deref()).await,
        Command::Logout => commands::logout(proxy).await,
        Command::Status => commands::status(proxy),
        Command::Ls { json } => commands::ls(proxy, json).await,
        Command::Admin { command } => commands::admin::run(proxy, command).await,
        Command::Ssh { target, command } => commands::ssh::ssh(proxy, &target, &command).await,
        Command::SshProxy { login, host } => commands::ssh::ssh_proxy(proxy, &login, &host).await,
        Command::Config {
            command: ConfigCommand::Ssh,
        } => commands::ssh::config(proxy),
        Command::Db {
            command:
                DbCommand::Connect {
                    resource,
                    db_role,
                    database,
                    listen,
                    socket,
                },
        } => {
            commands::db::connect(
                proxy,
                &resource,
                db_role.as_deref(),
                database.as_deref(),
                listen.as_deref(),
                socket.as_deref(),
            )
            .await
        }
        Command::Redis {
            command:
                RedisCommand::Connect {
                    resource,
                    user,
                    listen,
                    socket,
                    idle_timeout,
                },
        } => {
            commands::redis::connect(
                proxy,
                &resource,
                user.as_deref(),
                listen.as_deref(),
                socket.as_deref(),
                idle_timeout,
            )
            .await
        }
        Command::Kube { command } => match command {
            KubeCommand::Login {
                cluster,
                kubeconfig,
                print,
            } => commands::kube::login(proxy, &cluster, kubeconfig.as_deref(), print).await,
            KubeCommand::Credentials => commands::kube::credentials(proxy),
        },
        Command::Mongo {
            command:
                MongoCommand::Connect {
                    resource,
                    role,
                    database,
                    listen,
                    socket,
                    idle_timeout,
                },
        } => {
            commands::mongo::connect(
                proxy,
                &resource,
                role.as_deref(),
                database.as_deref(),
                listen.as_deref(),
                socket.as_deref(),
                idle_timeout,
            )
            .await
        }
        Command::Search {
            command:
                SearchCommand::Connect {
                    resource,
                    role,
                    listen,
                    socket,
                    idle_timeout,
                },
        } => {
            commands::search::connect(
                proxy,
                &resource,
                role.as_deref(),
                listen.as_deref(),
                socket.as_deref(),
                idle_timeout,
            )
            .await
        }
        Command::Mq {
            command:
                MqCommand::Connect {
                    resource,
                    user,
                    vhost,
                    listen,
                    idle_timeout,
                },
        } => {
            commands::mq::connect(
                proxy,
                &resource,
                user.as_deref(),
                &vhost,
                listen.as_deref(),
                idle_timeout,
            )
            .await
        }
        Command::Kafka {
            command:
                KafkaCommand::Connect {
                    resource,
                    user,
                    listen,
                    brokers,
                    idle_timeout,
                },
        } => {
            commands::kafka::connect(
                proxy,
                &resource,
                user.as_deref(),
                listen.as_deref(),
                brokers,
                idle_timeout,
            )
            .await
        }
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
    fn kube_commands_parse() {
        for args in [
            &["kube", "login", "c"][..],
            &["kube", "login", "c", "--kubeconfig", "/tmp/k"],
            &["kube", "login", "c", "--print"],
            &["--proxy", "p:1", "kube", "credentials"],
        ] {
            let mut full = vec!["limen"];
            full.extend_from_slice(args);
            Cli::try_parse_from(full).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
        assert!(
            Cli::try_parse_from([
                "limen",
                "kube",
                "login",
                "c",
                "--print",
                "--kubeconfig",
                "x"
            ])
            .is_err()
        );
    }

    #[test]
    fn mq_and_kafka_connect_options_parse() {
        let ok = |args: &[&str]| {
            let mut full = vec!["limen"];
            full.extend_from_slice(args);
            Cli::try_parse_from(full)
        };
        assert!(
            ok(&[
                "mq",
                "connect",
                "r",
                "--user",
                "u",
                "--vhost",
                "orders",
                "--listen",
                "127.0.0.1:5673"
            ])
            .is_ok()
        );
        assert!(ok(&["mq", "connect", "r", "--idle-timeout", "30m"]).is_ok());
        assert!(
            ok(&[
                "kafka",
                "connect",
                "r",
                "--user",
                "u",
                "--brokers",
                "3",
                "--listen",
                "127.0.0.1:9192"
            ])
            .is_ok()
        );
        assert!(ok(&["kafka", "connect", "r", "--brokers", "0"]).is_err());
        assert!(ok(&["kafka", "connect", "r", "--brokers", "65"]).is_err());
        assert!(ok(&["kafka", "connect", "r", "--idle-timeout", "soon"]).is_err());
    }

    #[test]
    fn redis_connect_options_parse() {
        let ok = |args: &[&str]| {
            let mut full = vec!["limen", "redis", "connect"];
            full.extend_from_slice(args);
            Cli::try_parse_from(full)
        };
        assert!(ok(&["cache", "--user", "read", "--listen", "127.0.0.1:6380"]).is_ok());
        assert!(
            ok(&[
                "cache",
                "--socket",
                "/tmp/limen/r.sock",
                "--idle-timeout",
                "30m"
            ])
            .is_ok()
        );
        assert!(ok(&["cache", "--socket", "/tmp/s", "--listen", "127.0.0.1:1"]).is_err());
        assert!(ok(&["cache", "--idle-timeout", "soon"]).is_err());
    }

    #[test]
    fn search_connect_options_parse() {
        let ok = |args: &[&str]| {
            let mut full = vec!["limen", "search", "connect"];
            full.extend_from_slice(args);
            Cli::try_parse_from(full)
        };
        assert!(ok(&["logs", "--role", "read", "--listen", "127.0.0.1:9200"]).is_ok());
        assert!(
            ok(&[
                "logs",
                "--socket",
                "/tmp/limen/s.sock",
                "--idle-timeout",
                "30m"
            ])
            .is_ok()
        );
        assert!(ok(&["logs", "--socket", "/tmp/s", "--listen", "127.0.0.1:1"]).is_err());
        assert!(ok(&["logs", "--idle-timeout", "soon"]).is_err());
    }

    #[test]
    fn bot_login_options_parse_and_conflict_where_they_should() {
        let ok = |args: &[&str]| {
            let mut full = vec!["limen"];
            full.extend_from_slice(args);
            Cli::try_parse_from(full)
        };
        assert!(ok(&["login", "--bot", "github_actions"]).is_ok());
        assert!(
            ok(&[
                "login",
                "--bot",
                "gitlab",
                "--token-env",
                "CI_TOKEN",
                "--bot-name",
                "nightly"
            ])
            .is_ok()
        );
        assert!(ok(&["login", "--bot", "oidc", "--token-file", "-"]).is_ok());
        // A bot has no browser or device flow, and bot options mean nothing without --bot.
        assert!(ok(&["login", "--bot", "gitlab", "--device"]).is_err());
        assert!(ok(&["login", "--token-env", "X"]).is_err());
        assert!(
            ok(&[
                "login",
                "--bot",
                "oidc",
                "--token-env",
                "X",
                "--token-file",
                "f"
            ])
            .is_err()
        );
        assert!(
            ok(&["login", "--bot", "circleci"]).is_err(),
            "unknown methods are refused"
        );
    }

    #[test]
    fn mongo_connect_options_parse() {
        let ok = |args: &[&str]| {
            let mut full = vec!["limen", "mongo", "connect"];
            full.extend_from_slice(args);
            Cli::try_parse_from(full)
        };
        assert!(ok(&["catalog", "--role", "read", "--database", "orders"]).is_ok());
        assert!(
            ok(&[
                "catalog",
                "--listen",
                "127.0.0.1:27018",
                "--idle-timeout",
                "30m"
            ])
            .is_ok()
        );
        assert!(ok(&["catalog", "--socket", "/tmp/limen/m.sock"]).is_ok());
        assert!(ok(&["catalog", "--socket", "/tmp/s", "--listen", "127.0.0.1:1"]).is_err());
        assert!(ok(&["catalog", "--idle-timeout", "soon"]).is_err());
    }

    #[test]
    fn planned_commands_say_when() {
        let message = super::not_yet("limen search connect", "search access", "Phase 10")
            .expect_err("not available")
            .to_string();
        assert!(message.contains("limen search connect") && message.contains("Phase 10"));
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

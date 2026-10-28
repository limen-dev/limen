//! `limen`: log in through your identity provider and get short-lived access
//! to SSH hosts, SQL databases, Redis or Valkey, Kubernetes clusters, search
//! (`OpenSearch` and Elasticsearch), MongoDB, message brokers, and TCP services;
//! internal web apps open in a browser after single sign-on.

// A CLI's job is printing to stdout.
#![allow(clippy::print_stdout)]
// Doc comments on commands become `--help` text, where product names read better without backticks.
#![allow(clippy::doc_markdown)]

mod api;
mod commands;
mod oidc;
mod profile;
mod reference;
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

    /// Run a `connect` command in the background and return once it is listening.
    #[arg(short = 'd', long, global = true)]
    detach: bool,

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
    /// Find out why access doesn't work: proxy, CA, network, clock, login, and (with a name) one resource.
    Doctor {
        /// Also check access to this resource.
        resource: Option<String>,
        /// Output JSON, for a support ticket. It holds no secrets.
        #[arg(long)]
        json: bool,
    },
    /// Show the current identity, roles, and when the credentials expire.
    Status {
        /// Output JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// List resources you are allowed to access.
    Ls {
        #[command(flatten)]
        args: ListArgs,
        /// Only resources of this type, such as `postgres` or `ssh`.
        #[arg(long = "type", value_name = "KIND")]
        kind: Option<String>,
    },
    /// Ask for access to a resource for a limited time, with a reason.
    Request {
        resource: String,
        /// Which requestable role, when more than one reaches the resource.
        #[arg(long)]
        role: Option<String>,
        /// How long you need it, such as 30m or 2h. The role sets the limit.
        #[arg(long = "for", value_name = "DURATION")]
        duration: Option<String>,
        /// Why. Approvers and auditors read it; some roles want a ticket id in it.
        #[arg(long, short = 'm')]
        reason: Option<String>,
        /// Use a break-glass role: granted at once, and reviewed afterwards.
        #[arg(long)]
        break_glass: bool,
        /// Wait for an approver instead of returning.
        #[arg(long)]
        wait: bool,
        #[arg(long)]
        json: bool,
    },
    /// Your access requests. `--approvals` shows the ones waiting for you.
    Requests {
        /// Requests you may approve or deny.
        #[arg(long, conflicts_with = "all")]
        approvals: bool,
        /// Every request (limen:admin or limen:auditor).
        #[arg(long)]
        all: bool,
        /// pending, approved, denied, expired, cancelled, or revoked.
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Approve an access request. Never your own.
    Approve {
        id: String,
        #[arg(long, short = 'm')]
        comment: Option<String>,
    },
    /// Deny an access request.
    Deny {
        id: String,
        #[arg(long, short = 'm')]
        comment: Option<String>,
    },
    /// Withdraw an access request of yours that is still waiting.
    Cancel { id: String },
    /// Say why you can or cannot reach a resource.
    Explain {
        resource: String,
        /// What you would use on it, such as login=ubuntu or db_role=limen_read.
        #[arg(long = "as", value_name = "KIND=NAME")]
        principal: Option<String>,
        /// With db_role or mongo_role: the database.
        #[arg(long)]
        database: Option<String>,
        /// Explain for this user, with the full trace (limen:admin).
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Access reviews waiting for you: `limen review ls`, `certify`, `flag`.
    Review {
        #[command(subcommand)]
        command: commands::review::ReviewCommand,
    },
    /// Search the audit trail (limen:admin or limen:auditor).
    Audit {
        #[command(subcommand)]
        command: commands::audit::AuditCommand,
    },
    /// Ask a policy questions: test it, who can reach what, what changes.
    Policy {
        #[command(subcommand)]
        command: commands::policy::PolicyCommand,
    },
    /// Open any resource by name: picks `ssh`, `db connect`, `redis connect`, ... from its type.
    Connect {
        resource: String,
        /// Options passed to the command it picks, e.g. `--listen 127.0.0.1:6380` or `--role readonly`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// List and stop connections started with `--detach`.
    Conns {
        #[command(subcommand)]
        command: ConnsCommand,
    },
    /// Print a shell completion script: `limen completions zsh > ~/.zfunc/_limen`.
    Completions { shell: clap_complete::Shell },
    /// Print the CLI reference as Markdown, generated from the command tree.
    #[command(hide = true)]
    MarkdownHelp,
    /// Show one resource: type, labels, how you may access it, and the command to connect.
    Show {
        resource: String,
        /// Output JSON instead of text.
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
    // Integration command groups.
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
    /// Internal web apps behind browser SSO.
    Web {
        #[command(subcommand)]
        command: WebCommand,
    },
    /// Open a local TCP forward to an authorized resource.
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

/// Options shared by every `ls` view.
#[derive(Debug, clap::Args)]
struct ListArgs {
    /// Only resources whose name or a label contains this text (case-insensitive).
    query: Option<String>,
    /// Output JSON instead of a table.
    #[arg(long, conflicts_with_all = ["quiet", "watch"])]
    json: bool,
    /// Redraw the list every SECS seconds (default 2) until interrupted.
    #[arg(long, value_name = "SECS", num_args = 0..=1, default_missing_value = "2")]
    watch: Option<u64>,
    /// Print only the resource names, one per line, for scripts and shell loops.
    #[arg(short, long)]
    quiet: bool,
    /// Only resources with this label (`key=value`). Repeat to require several.
    #[arg(long, value_name = "KEY=VALUE", value_parser = commands::parse_label)]
    label: Vec<(String, String)>,
}

impl From<ListArgs> for commands::ListFilter {
    fn from(a: ListArgs) -> Self {
        Self {
            query: a.query,
            json: a.json,
            quiet: a.quiet,
            watch: a.watch,
            labels: a.label,
        }
    }
}

#[derive(Debug, Subcommand)]
enum ConnsCommand {
    /// List detached connections.
    Ls {
        /// Output JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// End detached connections.
    Stop {
        /// Connection ids from `limen conns ls`.
        ids: Vec<String>,
        /// End all of them.
        #[arg(long, conflicts_with = "ids")]
        all: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Print an ~/.ssh/config block for `ssh <login>@<resource>.limen`, or
    /// `--install` one that makes plain `ssh <resource>`, scp, rsync and git work.
    Ssh {
        /// Include Limen's generated ssh_config from ~/.ssh/config, kept up to date on every login.
        #[arg(long, conflicts_with = "uninstall")]
        install: bool,
        /// Remove the Include from ~/.ssh/config and delete the generated ssh_config.
        #[arg(long)]
        uninstall: bool,
        /// The OpenSSH config to change, instead of ~/.ssh/config.
        #[arg(long, value_name = "FILE")]
        file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum DbCommand {
    /// List the postgres/mysql/redshift resources you can access.
    Ls(ListArgs),
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
    /// List the redis resources you can access.
    Ls(ListArgs),
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
    /// List the kubernetes resources you can access.
    Ls(ListArgs),
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
    /// Write one kubeconfig with a context for every cluster you can reach, refreshed on every login.
    Config {
        /// Print it instead of writing it.
        #[arg(long, conflicts_with = "uninstall")]
        print: bool,
        /// Delete the generated kubeconfig.
        #[arg(long)]
        uninstall: bool,
    },
    /// The kubectl exec credential plugin: prints your short-lived certificate.
    Credentials,
}

#[derive(Debug, Subcommand)]
enum MongoCommand {
    /// List the mongodb resources you can access.
    Ls(ListArgs),
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
    /// List the opensearch/elasticsearch resources you can access.
    Ls(ListArgs),
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
    /// List the rabbitmq resources you can access.
    Ls(ListArgs),
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
    /// List the kafka resources you can access.
    Ls(ListArgs),
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
    /// List the web resources you can access.
    Ls(ListArgs),
    /// Open an internal web app in your browser after single sign-on.
    Open {
        app: String,
        /// Print the address instead of opening a browser.
        #[arg(long)]
        no_browser: bool,
    },
}

/// The argument list for the command that opens `resource`, chosen by its type.
async fn connect_argv(
    proxy: Option<&str>,
    resource: &str,
    extra: &[String],
) -> anyhow::Result<Vec<String>> {
    let kind = commands::kind_of(proxy, resource).await?;
    let mut argv = vec!["limen".to_owned()];
    if let Some(p) = proxy {
        argv.extend(["--proxy".to_owned(), p.to_owned()]);
    }
    argv.extend(commands::connect_words(&kind, resource));
    argv.extend(extra.iter().cloned());
    Ok(argv)
}

#[tokio::main]
async fn main() {
    let cli = Cli::try_parse().unwrap_or_else(|e| {
        use clap::error::ErrorKind;
        let shows_overview = matches!(
            e.kind(),
            // Not on --version: the banner would repeat the version line.
            ErrorKind::DisplayHelp | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
        let args: Vec<String> = std::env::args().skip(1).collect();
        if shows_overview && is_top_level(args.iter().cloned()) {
            // Parsing stopped before `--color` was applied; honour it here.
            if args.iter().any(|a| a == "--color=never") {
                anstream::ColorChoice::Never.write_global();
            } else if args.iter().any(|a| a == "--color=always") {
                anstream::ColorChoice::Always.write_global();
            }
            ui::banner();
        }
        e.exit()
    });
    anstream::ColorChoice::write_global(match cli.color {
        ColorWhen::Auto => anstream::ColorChoice::Auto,
        ColorWhen::Always => anstream::ColorChoice::Always,
        ColorWhen::Never => anstream::ColorChoice::Never,
    });
    // Logs go to stderr and default to warnings, so command output stays clean.
    telemetry::init_with_default(LogFormat::Text, "warn");
    if let Ok(id) = std::env::var(commands::conns::ENV_ID) {
        tokio::spawn(commands::conns::watch_expiry(id, cli.proxy.clone()));
    }
    let result = run(cli).await;
    if let Ok(id) = std::env::var(commands::conns::ENV_ID) {
        commands::conns::forget(&id);
    }
    if let Err(e) = result {
        ui::error(&e);
        std::process::exit(1);
    }
}

/// Whether the arguments ask about `limen` itself (`--help`, `help`, none)
/// rather than about a subcommand, where a banner would only be noise.
fn is_top_level(args: impl IntoIterator<Item = String>) -> bool {
    let args: Vec<String> = args.into_iter().collect();
    args.iter().all(|a| a.starts_with('-')) || args == ["help"]
}

/// Commands that open a local listener, the only ones `--detach` applies to.
fn opens_listener(command: &Command) -> bool {
    matches!(
        command,
        Command::Db {
            command: DbCommand::Connect { .. }
        } | Command::Redis {
            command: RedisCommand::Connect { .. }
        } | Command::Mongo {
            command: MongoCommand::Connect { .. }
        } | Command::Search {
            command: SearchCommand::Connect { .. }
        } | Command::Mq {
            command: MqCommand::Connect { .. }
        } | Command::Kafka {
            command: KafkaCommand::Connect { .. }
        } | Command::Tcp { .. }
            | Command::Connect { .. }
    )
}

#[allow(clippy::too_many_lines)] // one arm per command
async fn run(cli: Cli) -> anyhow::Result<()> {
    let proxy = cli.proxy.as_deref();
    if cli.detach {
        anyhow::ensure!(
            opens_listener(&cli.command),
            "--detach applies to commands that open a local listener, such as `limen redis connect`"
        );
        return commands::conns::detach(proxy).await;
    }
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
        } => {
            ui::banner();
            commands::login::run(proxy, device, !no_browser, ca_file.as_deref()).await
        }
        Command::Logout => commands::logout(proxy).await,
        Command::Doctor { resource, json } => {
            commands::doctor::run(proxy, resource.as_deref(), json).await
        }
        Command::Status { json } => commands::status(proxy, json),
        Command::Ls { args, kind } => {
            commands::ls(proxy, &args.into(), kind.as_deref().as_slice()).await
        }
        Command::Connect { resource, args } => {
            let argv = connect_argv(proxy, &resource, &args).await?;
            Box::pin(run(Cli::try_parse_from(argv)?)).await
        }
        Command::Conns { command } => match command {
            ConnsCommand::Ls { json } => commands::conns::ls(proxy, json),
            ConnsCommand::Stop { ids, all } => commands::conns::stop_command(proxy, &ids, all),
        },
        Command::Completions { shell } => {
            // Render first: writing straight to a closed pipe (`| head`) would panic.
            let mut script = Vec::new();
            clap_complete::generate(
                shell,
                &mut <Cli as clap::CommandFactory>::command(),
                "limen",
                &mut script,
            );
            let _ = std::io::Write::write_all(&mut std::io::stdout(), &script);
            Ok(())
        }
        Command::MarkdownHelp => {
            let text = reference::render(&<Cli as clap::CommandFactory>::command());
            let _ = std::io::Write::write_all(&mut std::io::stdout(), text.as_bytes());
            Ok(())
        }
        Command::Show { resource, json } => commands::show(proxy, &resource, json).await,
        Command::Db {
            command: DbCommand::Ls(args),
        } => commands::ls(proxy, &args.into(), &["postgres", "mysql", "redshift"]).await,
        Command::Redis {
            command: RedisCommand::Ls(args),
        } => commands::ls(proxy, &args.into(), &["redis"]).await,
        Command::Mongo {
            command: MongoCommand::Ls(args),
        } => commands::ls(proxy, &args.into(), &["mongodb"]).await,
        Command::Search {
            command: SearchCommand::Ls(args),
        } => commands::ls(proxy, &args.into(), &["opensearch", "elasticsearch"]).await,
        Command::Mq {
            command: MqCommand::Ls(args),
        } => commands::ls(proxy, &args.into(), &["rabbitmq"]).await,
        Command::Kafka {
            command: KafkaCommand::Ls(args),
        } => commands::ls(proxy, &args.into(), &["kafka"]).await,
        Command::Web {
            command: WebCommand::Ls(args),
        } => commands::ls(proxy, &args.into(), &["web"]).await,
        Command::Request {
            resource,
            role,
            duration,
            reason,
            break_glass,
            wait,
            json,
        } => {
            commands::access::request(
                proxy,
                commands::access::RequestArgs {
                    resource: &resource,
                    role: role.as_deref(),
                    duration: duration.as_deref(),
                    reason: reason.as_deref(),
                    break_glass,
                    wait,
                    json,
                },
            )
            .await
        }
        Command::Requests {
            approvals,
            all,
            status,
            json,
        } => {
            let scope = if approvals {
                "approvable"
            } else if all {
                "all"
            } else {
                "mine"
            };
            commands::access::requests(proxy, scope, status.as_deref(), json).await
        }
        Command::Approve { id, comment } => {
            commands::access::decide(proxy, &id, true, comment.as_deref()).await
        }
        Command::Deny { id, comment } => {
            commands::access::decide(proxy, &id, false, comment.as_deref()).await
        }
        Command::Cancel { id } => commands::access::cancel(proxy, &id).await,
        Command::Explain {
            resource,
            principal,
            database,
            user,
            json,
        } => {
            commands::access::explain(
                proxy,
                &resource,
                principal.as_deref(),
                database.as_deref(),
                user.as_deref(),
                json,
            )
            .await
        }
        Command::Policy { command } => commands::policy::run(proxy, command).await,
        Command::Audit { command } => commands::audit::run(proxy, command).await,
        Command::Review { command } => commands::review::run(proxy, command).await,
        Command::Admin { command } => commands::admin::run(proxy, command).await,
        Command::Ssh { target, command } => commands::ssh::ssh(proxy, &target, &command).await,
        Command::SshProxy { login, host } => commands::ssh::ssh_proxy(proxy, &login, &host).await,
        Command::Config {
            command:
                ConfigCommand::Ssh {
                    install,
                    uninstall,
                    file,
                },
        } => {
            if install {
                commands::tools::install_ssh(proxy, file.as_deref()).await
            } else if uninstall {
                commands::tools::uninstall_ssh(file.as_deref())
            } else {
                anyhow::ensure!(file.is_none(), "--file goes with --install or --uninstall");
                commands::ssh::config(proxy)
            }
        }
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
            KubeCommand::Config { print, uninstall } => {
                if uninstall {
                    commands::tools::uninstall_kube()
                } else {
                    commands::tools::install_kube(proxy, print).await
                }
            }
            KubeCommand::Credentials => commands::kube::credentials(proxy),
            KubeCommand::Ls(args) => commands::ls(proxy, &args.into(), &["kubernetes"]).await,
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
        Command::Web {
            command: WebCommand::Open { app, no_browser },
        } => commands::web::open(proxy, &app, no_browser).await,
        Command::Tcp { resource, listen } => {
            commands::tcp::connect(proxy, &resource, listen.as_deref()).await
        }
    }
}

/// Planned integrations are in policy and in the console already, but no
/// worker serves them. Say so, and say when.
#[cfg(test)]
fn not_yet(command: &str, what: &str, phase: &str) -> anyhow::Result<()> {
    anyhow::bail!(
        "`{command}` isn't available yet: {what} is planned for {phase}. \
         You can already see these resources with `limen ls`. Roadmap: https://github.com/jfcmartins/limen/milestones"
    )
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::{Cli, Command, DbCommand, is_top_level};

    /// Resource commands have a stable, parseable CLI shape.
    #[test]
    fn resource_commands_parse() {
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
            &["kube", "config"],
            &["kube", "config", "--print"],
            &["kube", "config", "--uninstall"],
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
    fn doctor_and_tool_config_parse() {
        let ok = |args: &[&str]| {
            let mut full = vec!["limen"];
            full.extend_from_slice(args);
            Cli::try_parse_from(full)
        };
        assert!(ok(&["doctor"]).is_ok());
        assert!(ok(&["doctor", "web-1", "--json"]).is_ok());
        assert!(ok(&["config", "ssh"]).is_ok());
        assert!(ok(&["config", "ssh", "--install"]).is_ok());
        assert!(ok(&["config", "ssh", "--install", "--file", "/tmp/c"]).is_ok());
        assert!(ok(&["config", "ssh", "--uninstall"]).is_ok());
        assert!(ok(&["config", "ssh", "--install", "--uninstall"]).is_err());
        assert!(ok(&["kube", "config", "--print", "--uninstall"]).is_err());
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
    fn banner_only_for_top_level_help() {
        let args = |a: &[&str]| a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        assert!(is_top_level(args(&[])));
        assert!(is_top_level(args(&["--help"])));
        assert!(is_top_level(args(&["-V"])));
        assert!(is_top_level(args(&["help"])));
        assert!(!is_top_level(args(&["ls", "--help"])));
        assert!(!is_top_level(args(&["help", "ls"])));
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_per_protocol_ls() {
        for group in [
            "db", "redis", "kube", "mongo", "search", "mq", "kafka", "web",
        ] {
            let cli =
                Cli::try_parse_from(["limen", group, "ls", "stag", "-q", "--label", "env=prod"])
                    .unwrap_or_else(|e| panic!("{group} ls: {e}"));
            assert!(matches!(
                cli.command,
                Command::Db { .. }
                    | Command::Redis { .. }
                    | Command::Kube { .. }
                    | Command::Mongo { .. }
                    | Command::Search { .. }
                    | Command::Mq { .. }
                    | Command::Kafka { .. }
                    | Command::Web { .. }
            ));
        }
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

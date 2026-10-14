//! `limen`: log in through your identity provider and get short-lived access
//! to SSH hosts, databases, Redis, and Kubernetes.

// A CLI's job is printing to stdout.
#![allow(clippy::print_stdout)]

mod api;
mod commands;
mod oidc;
mod profile;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use limen_core::telemetry::{self, LogFormat};

#[derive(Debug, Parser)]
#[command(name = "limen", version = limen_core::VERSION, about)]
struct Cli {
    /// Proxy address, for example `limen.example.com:443`. Defaults to the last one used.
    #[arg(long, global = true, env = "LIMEN_PROXY")]
    proxy: Option<String>,

    #[command(subcommand)]
    command: Command,
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
    /// Database access.
    Db {
        #[command(subcommand)]
        command: DbCommand,
    },
    /// Redis access.
    Redis {
        #[command(subcommand)]
        command: RedisCommand,
    },
    /// Kubernetes access.
    Kube {
        #[command(subcommand)]
        command: KubeCommand,
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
    },
}

#[derive(Debug, Subcommand)]
enum RedisCommand {
    /// Open a local listener for redis-cli.
    Connect { resource: String },
}

#[derive(Debug, Subcommand)]
enum KubeCommand {
    /// Write a kubeconfig context that uses the limen exec credential plugin.
    Login { cluster: String },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    // Logs go to stderr and default to warnings, so command output stays clean.
    telemetry::init_with_default(LogFormat::Text, "warn");
    if let Err(e) = run(cli).await {
        eprintln!("error: {e:#}");
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
        Command::Db { .. } => not_yet(4),
        Command::Redis { .. } => not_yet(5),
        Command::Kube { .. } => not_yet(6),
    }
}

fn not_yet(phase: u8) -> anyhow::Result<()> {
    anyhow::bail!("not implemented yet: this command lands in Phase {phase}")
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::{Cli, Command, DbCommand};

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

//! `limen`: log in through your identity provider and get short-lived access
//! to SSH hosts, databases, Redis, and Kubernetes.

use clap::{Parser, Subcommand};
use limen_core::telemetry::{self, LogFormat};

#[derive(Debug, Parser)]
#[command(name = "limen", version = limen_core::VERSION, about)]
struct Cli {
    /// Proxy address, for example `limen.example.com:443`.
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
    },
    /// Delete local credentials.
    Logout,
    /// Show the current identity, roles, and when the credentials expire.
    Status,
    /// List resources you are allowed to access.
    Ls,
    /// Open an SSH session: `limen ssh user@host`.
    Ssh {
        target: String,
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
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
    /// Administrative commands. These require an admin role.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
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

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Validate and apply role and resource YAML to the control plane.
    Apply {
        paths: Vec<std::path::PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    telemetry::init(LogFormat::Text);
    let phase = match &cli.command {
        Command::Login { .. }
        | Command::Logout
        | Command::Status
        | Command::Ls
        | Command::Admin { .. } => 1,
        Command::Ssh { .. } => 2,
        Command::Db { .. } => 4,
        Command::Redis { .. } => 5,
        Command::Kube { .. } => 6,
    };
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

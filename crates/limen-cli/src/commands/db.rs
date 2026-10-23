//! `limen db connect` (design §5.2, ADR-0033): a local listener that turns
//! every connection from `psql`, `mysql`, or any driver into one Limen
//! session. The user's client never holds a password; the worker logs in to
//! the database as a `limen_*` role.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use limen_proto::v1::resources_client::ResourcesClient;
use limen_proto::v1::{ListResourcesRequest, SessionRequest, SessionResponse};
use limen_tunnel::framing::{read_message, write_message};
use limen_tunnel::tls::client_config;
use tokio::net::TcpListener;

use crate::api;
use crate::profile::{self, Profile};

/// Stop listening after this long with no connection (threat model).
const IDLE: Duration = Duration::from_hours(1);

struct Plan {
    kind: String,
    role: String,
    /// The resource's `default_database`, if it has one.
    default_database: Option<String>,
}

/// The resource's kind and the DB role to use: the one named, or the only one allowed.
async fn plan(proxy: Option<&str>, resource: &str, role: Option<&str>) -> anyhow::Result<Plan> {
    let (_, channel) = api::authenticated(proxy)?;
    let resources = ResourcesClient::new(channel)
        .list_resources(ListResourcesRequest {})
        .await
        .map_err(|s| api::status_error(&s).context("looking up your database access"))?
        .into_inner()
        .resources;
    let found = resources
        .into_iter()
        .find(|r| {
            r.name == resource && matches!(r.kind.as_str(), "postgres" | "mysql" | "redshift")
        })
        .with_context(|| format!("you have no database access to {resource:?}; see `limen ls`"))?;
    let role = match role {
        Some(r) => {
            if !found.principals.iter().any(|p| p == r) {
                bail!(
                    "you may not use the database role {r} on {resource}; allowed: {}",
                    found.principals.join(", ")
                );
            }
            r.to_owned()
        }
        None => match found.principals.as_slice() {
            [only] => only.clone(),
            many => bail!(
                "several database roles are allowed on {resource}; pick one with --db-role: {}",
                many.join(", ")
            ),
        },
    };
    Ok(Plan {
        kind: found.kind,
        role,
        default_database: Some(found.default_database).filter(|d| !d.is_empty()),
    })
}

/// The command to run in another terminal.
#[must_use]
pub fn client_command(
    kind: &str,
    host: &str,
    port: u16,
    role: &str,
    database: Option<&str>,
) -> String {
    match kind {
        "mysql" => {
            let db = database
                .map(|d| format!(" --database={d}"))
                .unwrap_or_default();
            format!("mysql --host={host} --port={port} --user={role} --ssl-mode=DISABLED{db}")
        }
        _ => {
            let db = database.map(|d| format!(" dbname={d}")).unwrap_or_default();
            format!("psql \"host={host} port={port} user={role}{db} sslmode=disable\"")
        }
    }
}

pub async fn connect(
    proxy: Option<&str>,
    resource: &str,
    db_role: Option<&str>,
    database: Option<&str>,
    listen: Option<&str>,
    socket: Option<&str>,
) -> anyhow::Result<()> {
    let proxy_addr = api::resolve_proxy(proxy)?;
    let profile = Profile::load(&proxy_addr)?
        .with_context(|| format!("not logged in to {proxy_addr}; run `limen login`"))?;
    profile.identity()?; // fail early on expired credentials
    let plan = plan(proxy, resource, db_role).await?;
    // Fail here, not on the first client connection, where the user would
    // only see the client's generic "lost connection".
    let database = database.or(plan.default_database.as_deref());
    if database.is_none() {
        bail!(
            "{resource} has no default database; name one: limen db connect {resource} --database <name>"
        );
    }
    let ca = profile::trusted_ca(&proxy_addr)?
        .with_context(|| format!("no CA pinned for {proxy_addr}"))?;
    let tls = Arc::new(client_config(
        &limen_tunnel::tls::certs_from_pem(&ca)?,
        Some(profile.identity()?),
        &[limen_tunnel::alpn::DB],
    )?);
    let session = Arc::new(Session {
        proxy_addr,
        tls,
        resource: resource.to_owned(),
        role: plan.role.clone(),
        database: database.unwrap_or_default().to_owned(),
    });

    #[cfg(unix)]
    if let Some(path) = socket {
        return serve_socket(session, path, &plan, database).await;
    }
    #[cfg(not(unix))]
    if socket.is_some() {
        bail!("--socket needs a Unix system");
    }

    let addr = listen.unwrap_or("127.0.0.1:0");
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("listening on {addr}"))?;
    let local = listener.local_addr()?;
    if !local.ip().is_loopback() {
        eprintln!(
            "warning: {local} is not a loopback address; anyone who can reach it can use your session"
        );
    }
    announce(
        &plan,
        &local.ip().to_string(),
        Some(local.port()),
        None,
        database,
        resource,
    );
    loop {
        let accepted = tokio::time::timeout(IDLE, listener.accept()).await;
        let Ok(accepted) = accepted else {
            eprintln!(
                "no connections for {} minutes; closing the listener.",
                IDLE.as_secs() / 60
            );
            return Ok(());
        };
        let (stream, _) = accepted?;
        let _ = stream.set_nodelay(true);
        let session = Arc::clone(&session);
        tokio::spawn(async move {
            if let Err(e) = session.run(stream).await {
                eprintln!("limen: {e:#}");
            }
        });
    }
}

fn announce(
    plan: &Plan,
    host: &str,
    port: Option<u16>,
    socket: Option<&str>,
    database: Option<&str>,
    resource: &str,
) {
    eprintln!(
        "Limen is ready for {resource} as {}. In another terminal:",
        plan.role
    );
    match (port, socket) {
        (Some(port), _) => eprintln!(
            "  {}",
            client_command(&plan.kind, host, port, &plan.role, database)
        ),
        (None, Some(path)) => {
            let line = if plan.kind == "mysql" {
                format!(
                    "mysql --socket={path} --user={} --ssl-mode=DISABLED",
                    plan.role
                )
            } else {
                let dir = std::path::Path::new(path)
                    .parent()
                    .map_or(".".into(), |p| p.display().to_string());
                format!(
                    "psql \"host={dir} user={} sslmode=disable\"  (socket file .s.PGSQL.5432)",
                    plan.role
                )
            };
            eprintln!("  {line}");
        }
        _ => {}
    }
    eprintln!("No password is needed. Press Ctrl-C to stop.");
}

#[cfg(unix)]
async fn serve_socket(
    session: Arc<Session>,
    path: &str,
    plan: &Plan,
    database: Option<&str>,
) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::remove_file(path);
    let listener =
        tokio::net::UnixListener::bind(path).with_context(|| format!("binding {path}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    announce(plan, "", None, Some(path), database, &session.resource);
    loop {
        let accepted = tokio::time::timeout(IDLE, listener.accept()).await;
        let Ok(accepted) = accepted else {
            let _ = std::fs::remove_file(path);
            return Ok(());
        };
        let (stream, _) = accepted?;
        let session = Arc::clone(&session);
        tokio::spawn(async move {
            if let Err(e) = session.run(stream).await {
                eprintln!("limen: {e:#}");
            }
        });
    }
}

struct Session {
    proxy_addr: String,
    tls: Arc<rustls::ClientConfig>,
    resource: String,
    role: String,
    database: String,
}

impl Session {
    /// One local connection becomes one session through the proxy.
    async fn run<S>(&self, local: S) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut tls = limen_tunnel::connect::dial(
            &self.proxy_addr,
            api::server_name(&self.proxy_addr)?,
            Arc::clone(&self.tls),
        )
        .await
        .with_context(|| format!("connecting to {}", self.proxy_addr))?;
        write_message(
            &mut tls,
            &SessionRequest {
                resource: self.resource.clone(),
                principal: self.role.clone(),
                database: self.database.clone(),
                group: String::new(),
            },
        )
        .await?;
        let response: SessionResponse = read_message(&mut tls)
            .await
            .context("reading the proxy's answer")?;
        if !response.ok {
            bail!("{}", response.error);
        }
        let mut local = local;
        let _ = tokio::io::copy_bidirectional(&mut local, &mut tls).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::client_command;

    #[test]
    fn prints_a_command_without_a_password() {
        let c = client_command("postgres", "127.0.0.1", 5433, "limen_read", Some("orders"));
        assert_eq!(
            c,
            "psql \"host=127.0.0.1 port=5433 user=limen_read dbname=orders sslmode=disable\""
        );
        assert!(!c.contains("password"));
        assert_eq!(
            client_command("mysql", "127.0.0.1", 3307, "limen_write", None),
            "mysql --host=127.0.0.1 --port=3307 --user=limen_write --ssl-mode=DISABLED"
        );
    }
}

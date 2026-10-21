//! `limen redis connect` (design §5.3, ADR-0034).
//!
//! Opens a listener on loopback (or a unix socket) for `redis-cli` and any
//! Redis client. Each connection it accepts becomes one Limen session: the
//! CLI opens a stream to the proxy with the user's certificate and then
//! copies bytes. The client sends no password, and the Redis server's
//! credential never leaves the worker.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context as _, bail};
use limen_proto::v1::ListResourcesRequest;
use limen_proto::v1::resources_client::ResourcesClient;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{api, ui};

pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub(crate) enum Listener {
    Tcp(tokio::net::TcpListener),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
}

impl Listener {
    pub(crate) async fn accept(&self) -> std::io::Result<Box<dyn Io>> {
        match self {
            Listener::Tcp(l) => {
                let (stream, _) = l.accept().await?;
                stream.set_nodelay(true)?;
                Ok(Box::new(stream))
            }
            #[cfg(unix)]
            Listener::Unix(l) => Ok(Box::new(l.accept().await?.0)),
        }
    }
}

/// `30m`, `1h`, `90s`, or `0` for never.
pub fn parse_idle(text: &str) -> Result<Duration, String> {
    if text == "0" {
        return Ok(Duration::ZERO);
    }
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .ok_or("add a unit: s, m, or h")?;
    let n: u64 = text[..split].parse().map_err(|_| "not a number")?;
    match &text[split..] {
        "s" => Ok(Duration::from_secs(n)),
        "m" => Ok(Duration::from_mins(n)),
        "h" => Ok(Duration::from_hours(n)),
        _ => Err("use s, m, or h".into()),
    }
}

/// The user to act as when the person didn't name one: the only one policy
/// allows. `kind` is the resource kind, `noun` what the principal is called
/// (for messages), and `command` the command that was run (`limen redis connect`).
pub(crate) async fn default_principal(
    proxy: Option<&str>,
    resource: &str,
    kind: &str,
    noun: &str,
    command: &str,
) -> anyhow::Result<String> {
    let (_, channel) = api::authenticated(proxy)?;
    let resources = ResourcesClient::new(channel)
        .list_resources(ListResourcesRequest {})
        .await
        .map_err(|s| api::status_error(&s).context(format!("couldn't look up your {noun}s for {resource}; name one: {command} {resource} --user <user>")))?
        .into_inner()
        .resources;
    let found = resources
        .into_iter()
        .find(|r| r.name == resource && r.kind == kind)
        .with_context(|| format!("you have no access to {resource:?}; see `limen ls`"))?;
    match found.principals.as_slice() {
        [only] => Ok(only.clone()),
        many => {
            let options: Vec<String> = many
                .iter()
                .map(|u| format!("  {command} {resource} --user {u}"))
                .collect();
            bail!(
                "several {noun}s are allowed on {resource}; pick one:\n{}",
                options.join("\n")
            )
        }
    }
}

/// A listener only the current user can reach: a socket file in a private directory.
#[cfg(unix)]
pub(crate) fn bind_socket(path: &Path) -> anyhow::Result<Listener> {
    use std::os::unix::fs::{
        DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _,
    };
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    let meta = std::fs::metadata(dir)?;
    if meta.mode() & 0o077 != 0 {
        bail!(
            "{} is open to other users (mode {:o}); put the socket in a directory only you can enter, e.g. chmod 700",
            dir.display(),
            meta.mode() & 0o777
        );
    }
    if let Ok(existing) = std::fs::symlink_metadata(path) {
        if existing.file_type().is_socket() {
            std::fs::remove_file(path)?;
        } else {
            bail!("{} exists and is not a socket", path.display());
        }
    }
    let listener = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("listening on {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(Listener::Unix(listener))
}

#[cfg(not(unix))]
pub(crate) fn bind_socket(_: &Path) -> anyhow::Result<Listener> {
    bail!("--socket needs a unix system; use --listen")
}

pub async fn connect(
    proxy: Option<&str>,
    resource: &str,
    user: Option<&str>,
    listen: Option<&str>,
    socket: Option<&Path>,
    idle_timeout: Duration,
) -> anyhow::Result<()> {
    let user = match user {
        Some(u) => u.to_owned(),
        None => {
            default_principal(
                proxy,
                resource,
                "redis",
                "Redis user",
                "limen redis connect",
            )
            .await?
        }
    };
    // Fail now, with a clear message, if the login is gone or the proxy is unreachable.
    drop(super::ssh::open_session(proxy, limen_tunnel::alpn::REDIS, resource, &user).await?);

    let (listener, how) = match socket {
        Some(path) => (
            bind_socket(path)?,
            format!("redis-cli -s {}", path.display()),
        ),
        None => {
            let addr = listen.unwrap_or("127.0.0.1:0");
            let tcp = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("listening on {addr}"))?;
            let local = tcp.local_addr()?;
            if !local.ip().is_loopback() {
                bail!(
                    "--listen must be a loopback address: anyone who can reach it would act as you"
                );
            }
            (
                Listener::Tcp(tcp),
                format!("redis-cli -h {} -p {}", local.ip(), local.port()),
            )
        }
    };
    ui::success(&format!(
        "Listening for {} as {}.",
        ui::bold(resource),
        ui::bold(&user)
    ));
    ui::info(&format!("Run: {how}"));
    ui::hint(
        "No password needed. Each connection is its own audited session. Press Ctrl-C to stop.",
    );

    let proxy: Option<Arc<str>> = proxy.map(Arc::from);
    let resource: Arc<str> = Arc::from(resource);
    let user: Arc<str> = Arc::from(user);
    let active = Arc::new(AtomicUsize::new(0));
    // When the last connection ended (or we started), for the idle timeout.
    let quiet_since = Arc::new(std::sync::Mutex::new(tokio::time::Instant::now()));
    let mut check_idle = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let local = accepted.context("accepting a connection")?;
                let (proxy, resource, user) =
                    (proxy.clone(), Arc::clone(&resource), Arc::clone(&user));
                let (active, quiet_since) = (Arc::clone(&active), Arc::clone(&quiet_since));
                active.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    session(local, proxy.as_deref(), &resource, &user).await;
                    *quiet_since.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                        tokio::time::Instant::now();
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
            _ = check_idle.tick() => {
                let quiet = quiet_since.lock().unwrap_or_else(std::sync::PoisonError::into_inner).elapsed();
                if !idle_timeout.is_zero() && active.load(Ordering::SeqCst) == 0 && quiet >= idle_timeout {
                    ui::info("No connections for a while; stopping.");
                    break;
                }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    if let Some(path) = socket {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

/// One local connection = one session. A refusal reaches the client as a
/// Redis error, so `redis-cli` shows why instead of "connection closed".
async fn session(mut local: Box<dyn Io>, proxy: Option<&str>, resource: &str, user: &str) {
    match super::ssh::open_session(proxy, limen_tunnel::alpn::REDIS, resource, user).await {
        Ok(mut upstream) => {
            let _ = tokio::io::copy_bidirectional(&mut local, &mut upstream).await;
        }
        Err(e) => {
            let _ = local.write_all(&refusal(&e)).await;
            let _ = local.shutdown().await;
        }
    }
}

/// The error a client sees when Limen refuses the session: one RESP line.
fn refusal(e: &anyhow::Error) -> Vec<u8> {
    let text: String = format!("{e:#}")
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    format!("-ERR Limen: {}\r\n", text.trim()).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_timeouts() {
        assert_eq!(parse_idle("30m"), Ok(Duration::from_mins(30)));
        assert_eq!(parse_idle("1h"), Ok(Duration::from_hours(1)));
        assert_eq!(parse_idle("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_idle("0"), Ok(Duration::ZERO));
        assert!(parse_idle("5").is_err());
        assert!(parse_idle("soon").is_err());
        assert!(parse_idle("5d").is_err());
    }

    #[test]
    fn refusals_are_one_resp_line() {
        let e =
            anyhow::anyhow!("several users:\r\n  limen redis connect x --user a").context("outer");
        let bytes = refusal(&e);
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.starts_with("-ERR Limen: outer: several users:"));
        assert_eq!(text.matches('\n').count(), 1, "{text:?}");
        assert!(text.ends_with("\r\n"));
    }

    #[cfg(unix)]
    #[test]
    fn sockets_need_a_private_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("dir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        let _guard = rt.enter();
        let open = bind_socket(&dir.path().join("r.sock"));
        assert!(open.is_err(), "world-readable directory");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let path = dir.path().join("r.sock");
        assert!(bind_socket(&path).is_ok());
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

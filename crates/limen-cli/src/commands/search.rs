//! `limen search connect` (design §5.5, ADR-0036).
//!
//! Opens a listener on loopback (or a unix socket) for `curl` and the
//! Elasticsearch and `OpenSearch` clients. Each connection it accepts becomes
//! one Limen session: the CLI opens a stream to the proxy with the user's
//! certificate and then copies bytes. The client sends no credential, and the
//! engine's credential never leaves the worker.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context as _, bail};
use limen_proto::v1::ListResourcesRequest;
use limen_proto::v1::resources_client::ResourcesClient;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{api, ui};

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

enum Listener {
    Tcp(tokio::net::TcpListener),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
}

impl Listener {
    async fn accept(&self) -> std::io::Result<Box<dyn Io>> {
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

/// The engine role to act as when the person didn't name one: the only one policy allows.
async fn default_role(proxy: Option<&str>, resource: &str) -> anyhow::Result<String> {
    let (_, channel) = api::authenticated(proxy)?;
    let resources = ResourcesClient::new(channel)
        .list_resources(ListResourcesRequest {})
        .await
        .map_err(|s| api::status_error(&s).context(format!("couldn't look up your search roles for {resource}; name one: limen search connect {resource} --role <role>")))?
        .into_inner()
        .resources;
    let found = resources
        .into_iter()
        .find(|r| r.name == resource && matches!(r.kind.as_str(), "opensearch" | "elasticsearch"))
        .with_context(|| format!("you have no search access to {resource:?}; see `limen ls`"))?;
    match found.principals.as_slice() {
        [only] => Ok(only.clone()),
        many => {
            let options: Vec<String> = many
                .iter()
                .map(|u| format!("  limen search connect {resource} --role {u}"))
                .collect();
            bail!(
                "several search roles are allowed on {resource}; pick one:\n{}",
                options.join("\n")
            )
        }
    }
}

/// A listener only the current user can reach: a socket file in a private directory.
#[cfg(unix)]
fn bind_socket(path: &Path) -> anyhow::Result<Listener> {
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
fn bind_socket(_: &Path) -> anyhow::Result<Listener> {
    bail!("--socket needs a unix system; use --listen")
}

pub async fn connect(
    proxy: Option<&str>,
    resource: &str,
    role: Option<&str>,
    listen: Option<&str>,
    socket: Option<&Path>,
    idle_timeout: Duration,
) -> anyhow::Result<()> {
    let role = match role {
        Some(r) => r.to_owned(),
        None => default_role(proxy, resource).await?,
    };
    // Every session of this run carries one group, so the console shows them as
    // one row.
    let group = uuid::Uuid::new_v4().simple().to_string();
    // Fail now, with a clear message, if the login is gone, the proxy is
    // unreachable, or policy refuses. The session stays open, idle, until this
    // command stops: it is what keeps the run active in the console while
    // clients come and go.
    let _anchor = super::ssh::open_session_in(
        proxy,
        limen_tunnel::alpn::SEARCH,
        resource,
        &role,
        "",
        &group,
    )
    .await?;

    let (listener, how) = match socket {
        Some(path) => (
            bind_socket(path)?,
            format!("curl --unix-socket {} http://localhost/", path.display()),
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
                format!("curl http://{}:{}/", local.ip(), local.port()),
            )
        }
    };
    ui::success(&format!(
        "Listening for {} as {}.",
        ui::bold(resource),
        ui::bold(&role)
    ));
    ui::info(&format!("Run: {how}"));
    ui::hint(
        "No credentials and no TLS settings needed; point the Elasticsearch or OpenSearch client at that URL. Each connection is its own audited session. Press Ctrl-C to stop.",
    );

    let proxy: Option<Arc<str>> = proxy.map(Arc::from);
    let resource: Arc<str> = Arc::from(resource);
    let role: Arc<str> = Arc::from(role);
    let group: Arc<str> = Arc::from(group);
    let active = Arc::new(AtomicUsize::new(0));
    // When the last connection ended (or we started), for the idle timeout.
    let quiet_since = Arc::new(std::sync::Mutex::new(tokio::time::Instant::now()));
    let mut check_idle = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let local = accepted.context("accepting a connection")?;
                let (proxy, resource, role, group) = (
                    proxy.clone(),
                    Arc::clone(&resource),
                    Arc::clone(&role),
                    Arc::clone(&group),
                );
                let (active, quiet_since) = (Arc::clone(&active), Arc::clone(&quiet_since));
                active.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    session(local, proxy.as_deref(), &resource, &role, &group).await;
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

/// One local connection = one session. A refusal reaches the client as an
/// HTTP error with an engine-shaped JSON body, so `curl` and the clients
/// show why instead of "connection closed".
async fn session(
    mut local: Box<dyn Io>,
    proxy: Option<&str>,
    resource: &str,
    role: &str,
    group: &str,
) {
    match super::ssh::open_session_in(proxy, limen_tunnel::alpn::SEARCH, resource, role, "", group)
        .await
    {
        Ok(mut upstream) => {
            let _ = tokio::io::copy_bidirectional(&mut local, &mut upstream).await;
        }
        Err(e) => {
            let _ = local.write_all(&refusal(&e)).await;
            let _ = local.shutdown().await;
        }
    }
}

/// Whether Limen refused the session, or couldn't open it. Clients retry the
/// second kind (502, 503) and not the first (403), which is what they should do.
fn status_of(text: &str) -> (u16, &'static str) {
    const UNAVAILABLE: [&str; 12] = [
        "no worker",
        "couldn't connect",
        "couldn't open",
        "can't be decided",
        "no capacity",
        "didn't answer",
        "tunnel closed",
        "shutting down",
        "couldn't reach",
        "unavailable",
        "connecting to",
        "timed out",
    ];
    if UNAVAILABLE.iter().any(|m| text.contains(m)) {
        (503, "Service Unavailable")
    } else {
        (403, "Forbidden")
    }
}

/// The reply a client sees when Limen refuses the session: an error with the
/// shape both engines use, so `curl` and the clients show why.
fn refusal(e: &anyhow::Error) -> Vec<u8> {
    let text: String = format!("{e:#}")
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let (status, reason_phrase) = status_of(&text);
    let body = serde_json::json!({
        "error": { "type": "limen_exception", "reason": format!("Limen: {}", text.trim()) },
        "status": status
    })
    .to_string();
    format!(
        "HTTP/1.1 {status} {reason_phrase}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_timeouts() {
        assert_eq!(parse_idle("30m"), Ok(Duration::from_mins(30)));
        assert_eq!(parse_idle("0"), Ok(Duration::ZERO));
        assert!(parse_idle("5").is_err());
        assert!(parse_idle("5d").is_err());
    }

    #[test]
    fn refusals_are_a_json_403_the_clients_can_show() {
        let e =
            anyhow::anyhow!("several roles:\r\n  limen search connect x --role a").context("outer");
        let text = String::from_utf8(refusal(&e)).expect("utf8");
        let (head, body) = text.split_once("\r\n\r\n").expect("header and body");
        assert!(head.starts_with("HTTP/1.1 403 Forbidden"), "{head}");
        assert!(head.contains(&format!("content-length: {}", body.len())));
        let json: serde_json::Value = serde_json::from_str(body).expect("json");
        assert_eq!(json["status"], 403);
        let reason = json["error"]["reason"].as_str().expect("reason");
        assert!(
            reason.starts_with("Limen: outer: several roles:"),
            "{reason}"
        );
        assert!(!reason.contains('\n'));
    }

    #[test]
    fn refusals_and_outages_get_different_statuses() {
        let status = |m: &str| {
            let text = String::from_utf8(refusal(&anyhow::anyhow!("{m}"))).expect("utf8");
            text.split_whitespace().nth(1).expect("status").to_owned()
        };
        assert_eq!(status("access denied to read@logs"), "403");
        assert_eq!(status("user is locked: left the company"), "403");
        assert_eq!(status("no worker is connected that can reach logs"), "503");
        assert_eq!(
            status("worker couldn't open the session: couldn't connect to the search server"),
            "503"
        );
        assert_eq!(
            status("no capacity: every worker is at its session limit"),
            "503"
        );
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
        assert!(
            bind_socket(&dir.path().join("s.sock")).is_err(),
            "world-readable directory"
        );
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let path = dir.path().join("s.sock");
        assert!(bind_socket(&path).is_ok());
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

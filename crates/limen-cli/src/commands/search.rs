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
    limen_core::duration::parse_short(text)
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

    let mut host_port = None;
    let (listener, how) = match socket {
        Some(path) => (
            bind_socket(path)?,
            format!("curl --unix-socket {} http://localhost/", path.display()),
        ),
        None => {
            let addr = listen.unwrap_or("127.0.0.1:0");
            let tcp = super::tcp::bind_loopback(addr).await?;
            let local = tcp.local_addr()?;
            host_port = Some(local.port());
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
                    session(local, host_port, proxy.as_deref(), &resource, &role, &group).await;
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
    local: Box<dyn Io>,
    host_port: Option<u16>,
    proxy: Option<&str>,
    resource: &str,
    role: &str,
    group: &str,
) {
    let Some(port) = host_port else {
        // A unix socket: a browser can't reach it, so there is nothing to check.
        match super::ssh::open_session_in(
            proxy,
            limen_tunnel::alpn::SEARCH,
            resource,
            role,
            "",
            group,
        )
        .await
        {
            Ok(mut upstream) => {
                let mut local = local;
                let _ = tokio::io::copy_bidirectional(&mut local, &mut upstream).await;
            }
            Err(e) => {
                let mut local = local;
                let _ = local.write_all(&refusal(&e)).await;
                let _ = local.shutdown().await;
            }
        }
        return;
    };
    // A TCP listener on loopback is reachable from any web page the user
    // opens (DNS rebinding, or a plain cross-site request). Every request is
    // checked before it is forwarded.
    let (mut local_r, mut local_w) = tokio::io::split(local);
    let mut buf = Vec::new();
    let first = match next_request(&mut local_r, &mut buf, port).await {
        Next::Request(req) => req,
        Next::Eof => return,
        Next::Rejected(why) => {
            let _ = local_w.write_all(&web_refusal(why)).await;
            let _ = local_w.shutdown().await;
            return;
        }
    };
    let mut upstream = match super::ssh::open_session_in(
        proxy,
        limen_tunnel::alpn::SEARCH,
        resource,
        role,
        "",
        group,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            let _ = local_w.write_all(&refusal(&e)).await;
            let _ = local_w.shutdown().await;
            return;
        }
    };
    let (mut up_r, mut up_w) = tokio::io::split(&mut upstream);
    let mut replies = Box::pin(tokio::io::copy(&mut up_r, &mut local_w));
    let mut requests = Box::pin(forward_requests(
        &mut local_r,
        &mut up_w,
        &mut buf,
        port,
        first,
    ));
    tokio::select! {
        _ = &mut replies => {}
        verdict = &mut requests => match verdict {
            // The client is done sending; let the replies finish.
            Next::Eof => {
                drop(requests);
                let _ = up_w.shutdown().await;
                let _ = replies.await;
            }
            Next::Rejected(why) => {
                drop(requests);
                drop(replies);
                let _ = local_w.write_all(&web_refusal(why)).await;
                let _ = local_w.shutdown().await;
            }
            Next::Request(_) => {}
        },
    }
}

/// The longest request head accepted from a local client.
const MAX_HEAD: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
struct Req {
    head: usize,
    body: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum Next {
    Eof,
    Request(Req),
    Rejected(&'static str),
}

/// Why a request head is not forwarded, or the length of its body.
///
/// The `Host` header must be this listener's own address (a rebinding page
/// carries its own domain there), and a request that carries `Origin` came
/// from a web page: `curl` and the client libraries send neither a foreign
/// `Host` nor an `Origin`.
fn check_head(head: &[u8], port: u16) -> Result<u64, &'static str> {
    let text = std::str::from_utf8(head).map_err(|_| "the request head is not valid text")?;
    let mut host = None;
    let mut length = None;
    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "host" if host.replace(value).is_some() => {
                return Err("more than one Host header");
            }
            "origin" => return Err("requests from web pages (with an Origin header) are refused"),
            "transfer-encoding" | "upgrade" => {
                return Err("chunked bodies and protocol upgrades are not supported");
            }
            "content-length" => {
                let n = value.parse::<u64>().map_err(|_| "bad Content-Length")?;
                if length.replace(n).is_some() {
                    return Err("more than one Content-Length header");
                }
            }
            _ => {}
        }
    }
    let host = host.ok_or("a Host header is required")?;
    let own = ["127.0.0.1", "localhost", "[::1]"]
        .iter()
        .any(|h| host.eq_ignore_ascii_case(&format!("{h}:{port}")));
    if !own {
        return Err("the Host header is not this listener's loopback address");
    }
    Ok(length.unwrap_or(0))
}

/// Reads the next request head from the client (keeping any bytes read past it in `buf`).
async fn next_request<R: AsyncRead + Unpin>(r: &mut R, buf: &mut Vec<u8>, port: u16) -> Next {
    use tokio::io::AsyncReadExt as _;
    let head = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if buf.len() > MAX_HEAD {
            return Next::Rejected("the request head is too long");
        }
        let mut chunk = [0u8; 4096];
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => return Next::Eof,
            Ok(n) => buf.extend_from_slice(chunk.get(..n).unwrap_or_default()),
        }
    };
    match check_head(buf.get(..head).unwrap_or_default(), port) {
        Ok(body) => Next::Request(Req { head, body }),
        Err(why) => Next::Rejected(why),
    }
}

/// Forwards the checked request `first`, then every following request on the
/// connection after checking it the same way.
async fn forward_requests<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    buf: &mut Vec<u8>,
    port: u16,
    first: Req,
) -> Next {
    use tokio::io::AsyncReadExt as _;
    let mut req = first;
    loop {
        // The head, and as much of the body as is already buffered.
        let body_buffered = u64::try_from(buf.len().saturating_sub(req.head)).unwrap_or(u64::MAX);
        let taken = req
            .head
            .saturating_add(usize::try_from(body_buffered.min(req.body)).unwrap_or(usize::MAX));
        if w.write_all(buf.get(..taken).unwrap_or_default())
            .await
            .is_err()
        {
            return Next::Eof;
        }
        buf.drain(..taken);
        let mut left = req.body.saturating_sub(body_buffered);
        while left > 0 {
            let mut chunk = [0u8; 8192];
            let want = usize::try_from(left).unwrap_or(usize::MAX).min(chunk.len());
            match r.read(chunk.get_mut(..want).unwrap_or_default()).await {
                Ok(0) | Err(_) => return Next::Eof,
                Ok(n) => {
                    if w.write_all(chunk.get(..n).unwrap_or_default())
                        .await
                        .is_err()
                    {
                        return Next::Eof;
                    }
                    left = left.saturating_sub(n as u64);
                }
            }
        }
        match next_request(r, buf, port).await {
            Next::Request(next) => req = next,
            other => return other,
        }
    }
}

fn web_refusal(why: &str) -> Vec<u8> {
    let body = serde_json::json!({
        "error": { "type": "limen_exception", "reason": format!("Limen: {why}") },
        "status": 403
    })
    .to_string();
    format!(
        "HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
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

    fn head(host: &str, extra: &str) -> Vec<u8> {
        format!("POST /x/_search HTTP/1.1\r\nHost: {host}\r\n{extra}\r\n").into_bytes()
    }

    #[test]
    fn only_the_listeners_own_address_is_a_valid_host() {
        for ok in [
            "127.0.0.1:9200",
            "localhost:9200",
            "LocalHost:9200",
            "[::1]:9200",
        ] {
            assert_eq!(
                check_head(&head(ok, "content-length: 7\r\n"), 9200),
                Ok(7),
                "{ok}"
            );
        }
        for bad in [
            "attacker.example:9200",
            "127.0.0.1.attacker.example:9200",
            "127.0.0.1:9201",
            "127.0.0.1",
            "10.0.0.1:9200",
        ] {
            assert!(check_head(&head(bad, ""), 9200).is_err(), "{bad}");
        }
        assert!(
            check_head(b"GET / HTTP/1.1\r\n\r\n", 9200).is_err(),
            "no Host"
        );
        assert!(
            check_head(
                &head("127.0.0.1:9200", "Origin: https://evil.example\r\n"),
                9200
            )
            .is_err()
        );
        assert!(
            check_head(
                &head("127.0.0.1:9200", "Transfer-Encoding: chunked\r\n"),
                9200
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn every_request_on_a_connection_is_checked() {
        use tokio::io::AsyncReadExt as _;
        let ok = head("127.0.0.1:9200", "content-length: 2\r\n");
        let mut wire = ok.clone();
        wire.extend_from_slice(b"{}");
        wire.extend_from_slice(&head(
            "127.0.0.1:9200",
            "Origin: https://evil.example\r\ncontent-length: 2\r\n",
        ));
        wire.extend_from_slice(b"{}");
        let (mut client, server) = tokio::io::duplex(65536);
        client.write_all(&wire).await.expect("write");
        let (mut sink_r, mut sink_w) = tokio::io::duplex(65536);
        let mut r = server;
        let mut buf = Vec::new();
        let Next::Request(first) = next_request(&mut r, &mut buf, 9200).await else {
            panic!("the first request is fine");
        };
        let verdict = forward_requests(&mut r, &mut sink_w, &mut buf, 9200, first).await;
        assert!(matches!(verdict, Next::Rejected(_)), "{verdict:?}");
        drop(sink_w);
        let mut forwarded = Vec::new();
        sink_r.read_to_end(&mut forwarded).await.expect("read");
        let mut want = ok;
        want.extend_from_slice(b"{}");
        assert_eq!(
            forwarded, want,
            "only the first request reaches the session"
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

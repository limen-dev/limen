//! `limen mongo connect` (design §5.4, ADR-0035).
//!
//! Opens a listener on loopback (or a unix socket) for `mongosh` and any
//! MongoDB driver. Each connection it accepts becomes one Limen session (all
//! of a run share a group, so the console shows them as one row): the
//! CLI opens a stream to the proxy with the user's certificate and then
//! copies bytes. The client sends no credentials, and the server's login
//! never leaves the worker. A driver opens a few connections (monitoring and
//! the pool), so one `mongosh` opens a few sessions.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context as _, bail};
use limen_proto::v1::ListResourcesRequest;
use limen_proto::v1::resources_client::ResourcesClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::redis::{Io, Listener, bind_socket};
use crate::{api, ui};

/// What a connection will act as.
struct Plan {
    role: String,
    database: String,
    /// Shared by every session of this run, so the console shows one row for
    /// the several connections a driver opens.
    group: String,
}

/// The role (the one named, or the only one policy allows) and the database
/// (the one named, or the resource's default).
async fn plan(
    proxy: Option<&str>,
    resource: &str,
    role: Option<&str>,
    database: Option<&str>,
) -> anyhow::Result<Plan> {
    let (_, channel) = api::authenticated(proxy)?;
    let resources = ResourcesClient::new(channel)
        .list_resources(ListResourcesRequest {})
        .await
        .map_err(|s| api::status_error(&s).context("looking up your MongoDB access"))?
        .into_inner()
        .resources;
    let found = resources
        .into_iter()
        .find(|r| r.name == resource && r.kind == "mongodb")
        .with_context(|| format!("you have no MongoDB access to {resource:?}; see `limen ls`"))?;
    let role = match role {
        Some(r) => {
            if !found.principals.iter().any(|p| p == r) {
                bail!(
                    "you may not use the MongoDB role {r} on {resource}; allowed: {}",
                    found.principals.join(", ")
                );
            }
            r.to_owned()
        }
        None => match found.principals.as_slice() {
            [only] => only.clone(),
            many => {
                let options: Vec<String> = many
                    .iter()
                    .map(|r| format!("  limen mongo connect {resource} --role {r}"))
                    .collect();
                bail!(
                    "several MongoDB roles are allowed on {resource}; pick one:\n{}",
                    options.join("\n")
                )
            }
        },
    };
    let database = match database {
        Some(d) => d.to_owned(),
        None if !found.default_database.is_empty() => found.default_database,
        None => bail!(
            "{resource} has no default database; name one: limen mongo connect {resource} --database <name>"
        ),
    };
    Ok(Plan {
        role,
        database,
        group: uuid::Uuid::new_v4().simple().to_string(),
    })
}

/// The connection string to give `mongosh`, without a password.
#[must_use]
pub fn connection_string(listener: &Address, database: &str) -> String {
    match listener {
        Address::Tcp(host, port) => {
            format!("mongodb://{host}:{port}/{database}?directConnection=true")
        }
        Address::Socket(path) => format!("mongodb://{}/{database}", percent_encode(path)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Tcp(String, u16),
    Socket(String),
}

/// Percent-encode a path for a MongoDB URI host (`/` must be `%2F`).
fn percent_encode(text: &str) -> String {
    use std::fmt::Write as _;
    text.bytes().fold(String::new(), |mut out, b| {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
        out
    })
}

pub async fn connect(
    proxy: Option<&str>,
    resource: &str,
    role: Option<&str>,
    database: Option<&str>,
    listen: Option<&str>,
    socket: Option<&Path>,
    idle_timeout: Duration,
) -> anyhow::Result<()> {
    let plan = plan(proxy, resource, role, database).await?;
    // Fail now, with a clear message, if the login is gone, the proxy is
    // unreachable, or policy refuses: the worker connects to the server here
    // too, so a bad credential on the worker shows up before the first client.
    drop(
        super::ssh::open_session_in(
            proxy,
            limen_tunnel::alpn::MONGO,
            resource,
            &plan.role,
            &plan.database,
            &plan.group,
        )
        .await?,
    );

    let (listener, address) = match socket {
        Some(path) => (
            bind_socket(path)?,
            Address::Socket(path.display().to_string()),
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
                Address::Tcp(local.ip().to_string(), local.port()),
            )
        }
    };
    ui::success(&format!(
        "Listening for {} as {} in {}.",
        ui::bold(resource),
        ui::bold(&plan.role),
        ui::bold(&plan.database)
    ));
    ui::info(&format!(
        "Run: mongosh \"{}\"",
        connection_string(&address, &plan.database)
    ));
    ui::hint(
        "No password needed. Each connection is its own audited session. Press Ctrl-C to stop.",
    );

    let proxy: Option<Arc<str>> = proxy.map(Arc::from);
    let resource: Arc<str> = Arc::from(resource);
    let plan = Arc::new(plan);
    let active = Arc::new(AtomicUsize::new(0));
    // When the last connection ended (or we started), for the idle timeout.
    let quiet_since = Arc::new(std::sync::Mutex::new(tokio::time::Instant::now()));
    let mut check_idle = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let local = accepted.context("accepting a connection")?;
                let (proxy, resource, plan) =
                    (proxy.clone(), Arc::clone(&resource), Arc::clone(&plan));
                let (active, quiet_since) = (Arc::clone(&active), Arc::clone(&quiet_since));
                active.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    session(local, proxy.as_deref(), &resource, &plan).await;
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
/// MongoDB error, so `mongosh` shows why instead of "connection closed".
async fn session(mut local: Box<dyn Io>, proxy: Option<&str>, resource: &str, plan: &Plan) {
    match super::ssh::open_session_in(
        proxy,
        limen_tunnel::alpn::MONGO,
        resource,
        &plan.role,
        &plan.database,
        &plan.group,
    )
    .await
    {
        Ok(mut upstream) => {
            let _ = tokio::io::copy_bidirectional(&mut local, &mut upstream).await;
        }
        Err(e) => refuse(&mut local, &e).await,
    }
}

/// Answer the client's first message with an error that carries the reason.
async fn refuse(local: &mut Box<dyn Io>, e: &anyhow::Error) {
    let text: String = format!("{e:#}")
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut head = [0u8; 16];
    let first = tokio::time::timeout(Duration::from_secs(5), local.read_exact(&mut head)).await;
    if let Ok(Ok(_)) = first {
        let request_id = i32::from_le_bytes([head[4], head[5], head[6], head[7]]);
        let opcode = i32::from_le_bytes([head[12], head[13], head[14], head[15]]);
        let _ = local
            .write_all(&error_message(
                request_id,
                opcode,
                &format!("Limen: {}", text.trim()),
            ))
            .await;
    }
    let _ = local.shutdown().await;
}

/// The reply to a request, as an error: `OP_REPLY` to a legacy `OP_QUERY`,
/// `OP_MSG` to anything else.
fn error_message(request_id: i32, request_opcode: i32, text: &str) -> Vec<u8> {
    let (body, opcode) = if request_opcode == 2004 {
        let doc = bson_error(text, true);
        let mut body = Vec::new();
        body.extend_from_slice(&2i32.to_le_bytes()); // QueryFailure
        body.extend_from_slice(&0i64.to_le_bytes());
        body.extend_from_slice(&0i32.to_le_bytes());
        body.extend_from_slice(&1i32.to_le_bytes());
        body.extend_from_slice(&doc);
        (body, 1i32)
    } else {
        let doc = bson_error(text, false);
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.push(0);
        body.extend_from_slice(&doc);
        (body, 2013i32)
    };
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(
        &i32::try_from(16 + body.len())
            .unwrap_or(i32::MAX)
            .to_le_bytes(),
    );
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&request_id.to_le_bytes());
    out.extend_from_slice(&opcode.to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// `{ok: 0, errmsg, code: 18, codeName}` (or `$err` for a legacy reply).
fn bson_error(text: &str, legacy: bool) -> Vec<u8> {
    let mut doc = vec![0u8; 4];
    let string = |doc: &mut Vec<u8>, key: &str, value: &str| {
        doc.push(0x02);
        doc.extend_from_slice(key.as_bytes());
        doc.push(0);
        doc.extend_from_slice(
            &i32::try_from(value.len() + 1)
                .unwrap_or(i32::MAX)
                .to_le_bytes(),
        );
        doc.extend_from_slice(value.as_bytes());
        doc.push(0);
    };
    if legacy {
        string(&mut doc, "$err", text);
    }
    doc.push(0x01);
    doc.extend_from_slice(b"ok\0");
    doc.extend_from_slice(&0f64.to_le_bytes());
    if !legacy {
        string(&mut doc, "errmsg", text);
    }
    doc.push(0x10);
    doc.extend_from_slice(b"code\0");
    doc.extend_from_slice(&18i32.to_le_bytes());
    string(&mut doc, "codeName", "AuthenticationFailed");
    doc.push(0);
    let len = i32::try_from(doc.len()).unwrap_or(i32::MAX);
    doc[..4].copy_from_slice(&len.to_le_bytes());
    doc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_strings_carry_no_password() {
        let tcp = connection_string(&Address::Tcp("127.0.0.1".into(), 27018), "orders");
        assert_eq!(
            tcp,
            "mongodb://127.0.0.1:27018/orders?directConnection=true"
        );
        let sock = connection_string(&Address::Socket("/run/me/m.sock".into()), "orders");
        assert_eq!(sock, "mongodb://%2Frun%2Fme%2Fm.sock/orders");
        assert!(!tcp.contains('@') && !sock.contains('@'));
    }

    #[test]
    fn a_refusal_is_a_well_formed_mongodb_error() {
        for (opcode, expect_opcode) in [(2013, 2013), (2004, 1)] {
            let msg = error_message(7, opcode, "Limen: access denied to write@orders");
            let len = i32::from_le_bytes(msg[0..4].try_into().expect("4"));
            assert_eq!(usize::try_from(len).expect("len"), msg.len());
            assert_eq!(i32::from_le_bytes(msg[8..12].try_into().expect("4")), 7);
            assert_eq!(
                i32::from_le_bytes(msg[12..16].try_into().expect("4")),
                expect_opcode
            );
            let text = String::from_utf8_lossy(&msg);
            assert!(text.contains("access denied to write@orders"));
            assert!(text.contains("AuthenticationFailed"));
        }
        // The BSON document inside is internally consistent.
        let doc = bson_error("x", false);
        let declared = i32::from_le_bytes(doc[0..4].try_into().expect("4"));
        assert_eq!(usize::try_from(declared).expect("len"), doc.len());
        assert_eq!(*doc.last().expect("nul"), 0);
    }
}

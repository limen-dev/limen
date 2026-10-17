//! MySQL wire protocol (also MariaDB and Aurora MySQL): a message-aware relay
//! (ADR-0033). It is half duplex, like the protocol: read one command from the
//! client, audit it, forward it, then relay the target's whole answer.
//!
//! Toward the client the worker plays the server. It offers no TLS (the hop
//! from the CLI is already mutual TLS), no compression, no `LOCAL INFILE`, no
//! `DEPRECATE_EOF`, and no query attributes, so the framing below stays simple
//! and the client can't ask the worker to read its files. Toward the target it
//! logs in as the `limen_*` user and, when the resource uses TLS, upgrades the
//! connection before sending any credential.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use aws_lc_rs::digest;
use limen_audit::Emitter;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use super::audit::{Auditor, Outcome, Phase};
use super::sqltext::{self, Statement};
use super::target::{BoxedIo, Target};
use super::{DbSessionConfig, KillEntry};

const LONG_PASSWORD: u32 = 0x1;
const FOUND_ROWS: u32 = 0x2;
const LONG_FLAG: u32 = 0x4;
const CONNECT_WITH_DB: u32 = 0x8;
const IGNORE_SPACE: u32 = 0x100;
const PROTOCOL_41: u32 = 0x200;
const INTERACTIVE: u32 = 0x400;
const SSL: u32 = 0x800;
const TRANSACTIONS: u32 = 0x2000;
const SECURE_CONNECTION: u32 = 0x8000;
const MULTI_STATEMENTS: u32 = 0x1_0000;
const MULTI_RESULTS: u32 = 0x2_0000;
const PS_MULTI_RESULTS: u32 = 0x4_0000;
const PLUGIN_AUTH: u32 = 0x8_0000;
const CONNECT_ATTRS: u32 = 0x10_0000;
const PLUGIN_AUTH_LENENC_DATA: u32 = 0x20_0000;

/// What the worker offers a client.
const OFFERED: u32 = LONG_PASSWORD
    | FOUND_ROWS
    | LONG_FLAG
    | CONNECT_WITH_DB
    | IGNORE_SPACE
    | PROTOCOL_41
    | INTERACTIVE
    | TRANSACTIONS
    | SECURE_CONNECTION
    | MULTI_STATEMENTS
    | MULTI_RESULTS
    | PS_MULTI_RESULTS
    | PLUGIN_AUTH
    | CONNECT_ATTRS
    | PLUGIN_AUTH_LENENC_DATA;

/// Client flags that change what the target does, so they are passed on.
const PASS_ON: u32 = FOUND_ROWS | IGNORE_SPACE | INTERACTIVE | MULTI_STATEMENTS;

const STATUS_AUTOCOMMIT: u16 = 0x0002;
const STATUS_MORE_RESULTS: u16 = 0x0008;
const MAX_PACKET: usize = 0x00ff_ffff;
/// Largest command (text of a statement) read in full.
const MAX_COMMAND: usize = 64 * 1024 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_hours(1);
const SERVER_VERSION: &str = "8.4.0-Limen";

const COM_QUIT: u8 = 0x01;
const COM_INIT_DB: u8 = 0x02;
const COM_QUERY: u8 = 0x03;
const COM_STATISTICS: u8 = 0x09;
const COM_PING: u8 = 0x0e;
const COM_STMT_PREPARE: u8 = 0x16;
const COM_STMT_EXECUTE: u8 = 0x17;
const COM_STMT_SEND_LONG_DATA: u8 = 0x18;
const COM_STMT_CLOSE: u8 = 0x19;
const COM_STMT_RESET: u8 = 0x1a;
const COM_SET_OPTION: u8 = 0x1b;
const COM_RESET_CONNECTION: u8 = 0x1f;

#[derive(Debug, thiserror::Error)]
pub(super) enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// Something to tell the client before closing.
    #[error("{0}")]
    Refused(String),
    #[error("audit unavailable: {0}")]
    Audit(#[from] limen_audit::AuditError),
    #[error("{0}")]
    Protocol(String),
}

pub(super) type Result<T, E = Error> = std::result::Result<T, E>;

// ---- packets ---------------------------------------------------------------

#[derive(Debug, Clone)]
pub(super) struct Packet {
    pub seq: u8,
    pub payload: Vec<u8>,
}

pub(super) async fn read_packet<R: AsyncRead + Unpin + ?Sized>(
    r: &mut R,
) -> std::io::Result<Packet> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head).await?;
    let len = usize::from(head[0]) | usize::from(head[1]) << 8 | usize::from(head[2]) << 16;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(Packet {
        seq: head[3],
        payload,
    })
}

/// One packet, as read. Payloads of 0xffffff bytes or more are the caller's
/// business (commands handle continuation; responses are forwarded as they come).
pub(super) async fn write_packet<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    p: &Packet,
) -> std::io::Result<()> {
    let len = p.payload.len();
    let l = u32::try_from(len).unwrap_or(u32::MAX).to_le_bytes();
    let head = [l[0], l[1], l[2], p.seq];
    w.write_all(&head).await?;
    w.write_all(&p.payload).await
}

/// A logical payload, split into packets of at most 0xffffff bytes.
fn packets_for(first_seq: u8, payload: &[u8]) -> Vec<Packet> {
    let mut out = Vec::new();
    let mut seq = first_seq;
    let mut chunks = payload.chunks(MAX_PACKET).peekable();
    while let Some(chunk) = chunks.next() {
        out.push(Packet {
            seq,
            payload: chunk.to_vec(),
        });
        seq = seq.wrapping_add(1);
        if chunks.peek().is_none() && chunk.len() == MAX_PACKET {
            out.push(Packet {
                seq,
                payload: Vec::new(),
            });
        }
    }
    if out.is_empty() {
        out.push(Packet {
            seq: first_seq,
            payload: Vec::new(),
        });
    }
    out
}

pub(super) fn lenenc(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    match first {
        0..=0xfa => Some((u64::from(first), 1)),
        0xfc => Some((
            u64::from(u16::from_le_bytes(buf.get(1..3)?.try_into().ok()?)),
            3,
        )),
        0xfd => {
            let b = buf.get(1..4)?;
            Some((
                u64::from(b[0]) | u64::from(b[1]) << 8 | u64::from(b[2]) << 16,
                4,
            ))
        }
        0xfe => Some((u64::from_le_bytes(buf.get(1..9)?.try_into().ok()?), 9)),
        _ => None,
    }
}

fn put_lenenc(out: &mut Vec<u8>, n: usize) {
    let n = u64::try_from(n).unwrap_or(u64::MAX);
    let bytes = n.to_le_bytes();
    if n < 0xfb {
        out.push(bytes[0]);
    } else if n <= 0xffff {
        out.push(0xfc);
        out.extend_from_slice(&bytes[..2]);
    } else if n <= 0x00ff_ffff {
        out.push(0xfd);
        out.extend_from_slice(&bytes[..3]);
    } else {
        out.push(0xfe);
        out.extend_from_slice(&bytes);
    }
}

fn put_lenenc_str(out: &mut Vec<u8>, s: &[u8]) {
    put_lenenc(out, s.len());
    out.extend_from_slice(s);
}

pub(super) fn cstr(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = buf.iter().position(|&b| b == 0)?;
    Some((&buf[..end], &buf[end + 1..]))
}

fn err_payload(code: u16, state: &str, message: &str) -> Vec<u8> {
    let mut p = vec![0xff];
    p.extend_from_slice(&code.to_le_bytes());
    p.push(b'#');
    p.extend_from_slice(state.as_bytes());
    p.extend_from_slice(message.as_bytes());
    p
}

fn ok_payload() -> Vec<u8> {
    let mut p = vec![0x00, 0, 0];
    p.extend_from_slice(&STATUS_AUTOCOMMIT.to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes());
    p
}

pub(super) fn is_eof(p: &Packet) -> bool {
    p.payload.first() == Some(&0xfe) && p.payload.len() < 9
}

/// `(sqlstate, number, message)` from an ERR packet.
pub(super) fn parse_err(payload: &[u8]) -> (String, u32, String) {
    let number = payload
        .get(1..3)
        .map_or(0, |b| u32::from(u16::from_le_bytes([b[0], b[1]])));
    if payload.get(3) == Some(&b'#') && payload.len() >= 9 {
        (
            String::from_utf8_lossy(&payload[4..9]).into_owned(),
            number,
            String::from_utf8_lossy(&payload[9..]).into_owned(),
        )
    } else {
        (
            "HY000".to_owned(),
            number,
            String::from_utf8_lossy(payload.get(3..).unwrap_or(&[])).into_owned(),
        )
    }
}

// ---- authentication toward the target -------------------------------------

fn sha1(parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    for p in parts {
        ctx.update(p);
    }
    ctx.finish().as_ref().to_vec()
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = digest::Context::new(&digest::SHA256);
    for p in parts {
        ctx.update(p);
    }
    ctx.finish().as_ref().to_vec()
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

/// `mysql_native_password`: SHA1(pw) XOR SHA1(nonce + SHA1(SHA1(pw))).
fn native_password(password: &str, nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let stage1 = sha1(&[password.as_bytes()]);
    let stage2 = sha1(&[&stage1]);
    xor(&stage1, &sha1(&[nonce, &stage2]))
}

/// `caching_sha2_password` fast path: SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) + nonce).
fn caching_sha2_password(password: &str, nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let stage1 = sha256(&[password.as_bytes()]);
    let stage2 = sha256(&[&stage1]);
    xor(&stage1, &sha256(&[&stage2, nonce]))
}

/// The response for `plugin`, or why it can't be given.
fn auth_response(plugin: &str, password: &str, nonce: &[u8], tls: bool) -> Result<Vec<u8>, String> {
    match plugin {
        "mysql_native_password" => Ok(native_password(password, nonce)),
        "caching_sha2_password" => Ok(caching_sha2_password(password, nonce)),
        "mysql_clear_password" if tls => {
            let mut v = password.as_bytes().to_vec();
            v.push(0);
            Ok(v)
        }
        "mysql_clear_password" => Err(
            "the database asks for a clear-text password, which Limen only sends over TLS".into(),
        ),
        other => Err(format!(
            "unsupported database authentication plugin {other}"
        )),
    }
}

struct ServerHello {
    thread_id: u32,
    caps: u32,
    nonce: Vec<u8>,
    plugin: String,
}

fn parse_server_hello(p: &[u8]) -> Result<ServerHello> {
    if p.first() == Some(&0xff) {
        let (_, _, message) = parse_err(p);
        return Err(Error::Refused(format!(
            "the database refused the connection: {message}"
        )));
    }
    let bad = || Error::Protocol("malformed database greeting".into());
    if p.first() != Some(&10) {
        return Err(Error::Refused(
            "the database speaks an unsupported protocol version".into(),
        ));
    }
    let (_, rest) = cstr(&p[1..]).ok_or_else(bad)?;
    let thread_id = u32::from_le_bytes(
        rest.get(0..4)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?,
    );
    let scramble1 = rest.get(4..12).ok_or_else(bad)?;
    let cap_low = u16::from_le_bytes(
        rest.get(13..15)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?,
    );
    let mut caps = u32::from(cap_low);
    let mut nonce = scramble1.to_vec();
    let mut plugin = String::from("mysql_native_password");
    if rest.len() > 15 {
        // charset(1) status(2) cap_high(2) auth_len(1) reserved(10)
        let cap_high = u16::from_le_bytes(
            rest.get(18..20)
                .ok_or_else(bad)?
                .try_into()
                .map_err(|_| bad())?,
        );
        caps |= u32::from(cap_high) << 16;
        let auth_len = usize::from(*rest.get(20).ok_or_else(bad)?);
        let tail = rest.get(31..).ok_or_else(bad)?;
        let second = auth_len.saturating_sub(9).max(12).min(tail.len());
        nonce.extend_from_slice(&tail[..second.min(12)]);
        let after = tail.get(13.min(tail.len())..).unwrap_or(&[]);
        if let Some((name, _)) = cstr(after) {
            plugin = String::from_utf8_lossy(name).into_owned();
        }
    }
    Ok(ServerHello {
        thread_id,
        caps,
        nonce,
        plugin,
    })
}

pub(super) struct Upstream {
    pub io: BoxedIo,
    pub thread_id: u32,
}

pub(super) struct Login<'a> {
    pub user: &'a str,
    pub password: &'a limen_core::secret::Secret<String>,
    pub database: &'a str,
    pub session: &'a str,
}

async fn finish_login(
    login: &Login<'_>,
    mut io: BoxedIo,
    hello: ServerHello,
    flags: u32,
    charset: u8,
    mut seq: u8,
    tls: bool,
) -> Result<Upstream> {
    let mut plugin = hello.plugin.clone();
    let mut nonce = hello.nonce.clone();
    let password = login.password.expose();
    let response = auth_response(&plugin, password, &nonce, tls).map_err(Error::Refused)?;
    let mut body = Vec::new();
    body.extend_from_slice(&flags.to_le_bytes());
    body.extend_from_slice(&0x0100_0000u32.to_le_bytes());
    body.push(charset);
    body.extend_from_slice(&[0u8; 23]);
    body.extend_from_slice(login.user.as_bytes());
    body.push(0);
    put_lenenc_str(&mut body, &response);
    body.extend_from_slice(login.database.as_bytes());
    body.push(0);
    body.extend_from_slice(plugin.as_bytes());
    body.push(0);
    let mut attrs = Vec::new();
    for (k, v) in [
        ("_client_name", "limen"),
        ("program_name", "limen"),
        ("limen_session", login.session),
    ] {
        put_lenenc_str(&mut attrs, k.as_bytes());
        put_lenenc_str(&mut attrs, v.as_bytes());
    }
    put_lenenc_str(&mut body, &attrs);
    write_packet(&mut io, &Packet { seq, payload: body }).await?;

    loop {
        let p = read_packet(&mut io).await?;
        seq = p.seq.wrapping_add(1);
        match p.payload.first() {
            Some(0x00) => {
                return Ok(Upstream {
                    io,
                    thread_id: hello.thread_id,
                });
            }
            Some(0xff) => {
                let (_, number, message) = parse_err(&p.payload);
                tracing::warn!(session = %login.session, number, %message, "the database refused the login");
                return Err(Error::Refused(
                    if number == 1045 && message.starts_with("Access denied") {
                        format!("could not authenticate to the database as {}", login.user)
                    } else {
                        message
                    },
                ));
            }
            Some(0xfe) => {
                // AuthSwitchRequest: plugin name, then its nonce.
                let (name, data) = cstr(&p.payload[1..])
                    .ok_or_else(|| Error::Protocol("malformed auth switch".into()))?;
                plugin = String::from_utf8_lossy(name).into_owned();
                nonce = data.iter().copied().take_while(|&b| b != 0).collect();
                let resp = auth_response(&plugin, password, &nonce, tls).map_err(Error::Refused)?;
                write_packet(&mut io, &Packet { seq, payload: resp }).await?;
            }
            Some(0x01) => match p.payload.get(1) {
                Some(0x03) => {} // fast authentication succeeded; OK follows
                Some(0x04) if tls => {
                    let mut pw = password.as_bytes().to_vec();
                    pw.push(0);
                    write_packet(&mut io, &Packet { seq, payload: pw }).await?;
                }
                Some(0x04) => {
                    return Err(Error::Refused(
                        "the database needs the full caching_sha2_password exchange, which Limen only does over TLS".into(),
                    ));
                }
                _ => return Err(Error::Protocol("unexpected authentication data".into())),
            },
            _ => {
                return Err(Error::Protocol(
                    "unexpected packet during database login".into(),
                ));
            }
        }
    }
}

// ---- the client's greeting -------------------------------------------------

struct ClientHello {
    flags: u32,
    charset: u8,
    user: String,
    database: Option<String>,
}

fn greeting(connection_id: u32, nonce: &[u8; 20]) -> Vec<u8> {
    let mut p = vec![10];
    p.extend_from_slice(SERVER_VERSION.as_bytes());
    p.push(0);
    p.extend_from_slice(&connection_id.to_le_bytes());
    p.extend_from_slice(&nonce[..8]);
    p.push(0);
    let caps = OFFERED.to_le_bytes();
    p.extend_from_slice(&caps[..2]);
    p.push(45); // utf8mb4_general_ci
    p.extend_from_slice(&STATUS_AUTOCOMMIT.to_le_bytes());
    p.extend_from_slice(&caps[2..]);
    p.push(21);
    p.extend_from_slice(&[0u8; 10]);
    p.extend_from_slice(&nonce[8..]);
    p.push(0);
    p.extend_from_slice(b"mysql_native_password\0");
    p
}

fn parse_client_hello(p: &[u8]) -> Result<ClientHello> {
    let bad = || Error::Protocol("malformed handshake response".into());
    if p.len() < 32 {
        return Err(bad());
    }
    let flags = u32::from_le_bytes(p[0..4].try_into().map_err(|_| bad())?);
    if flags & SSL != 0 && p.len() == 32 {
        return Err(Error::Refused(
            "TLS isn't offered here: the connection is already encrypted".into(),
        ));
    }
    if flags & PROTOCOL_41 == 0 {
        return Err(Error::Refused(
            "clients older than protocol 4.1 aren't supported".into(),
        ));
    }
    let charset = p[8];
    let (user, mut rest) = cstr(&p[32..]).ok_or_else(bad)?;
    if flags & PLUGIN_AUTH_LENENC_DATA != 0 {
        let (size, header) = lenenc(rest).ok_or_else(bad)?;
        rest = rest
            .get(header + usize::try_from(size).map_err(|_| bad())?..)
            .ok_or_else(bad)?;
    } else if flags & SECURE_CONNECTION != 0 {
        let size = usize::from(*rest.first().ok_or_else(bad)?);
        rest = rest.get(1 + size..).ok_or_else(bad)?;
    } else {
        rest = cstr(rest).ok_or_else(bad)?.1;
    }
    let database = if flags & CONNECT_WITH_DB != 0 {
        let (db, tail) = cstr(rest).ok_or_else(bad)?;
        rest = tail;
        Some(String::from_utf8_lossy(db).into_owned()).filter(|d| !d.is_empty())
    } else {
        None
    };
    let _ = rest;
    Ok(ClientHello {
        flags,
        charset,
        user: String::from_utf8_lossy(user).into_owned(),
        database,
    })
}

// ---- the session -----------------------------------------------------------

pub(super) async fn serve<S>(
    client: S,
    cfg: DbSessionConfig,
    emitter: Emitter,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let audit = Auditor::new(
        emitter,
        cfg.session_id,
        &cfg.username,
        &cfg.resource,
        cfg.engine,
        &cfg.role,
        &cfg.database,
        cfg.normalize_literals,
    );
    let mut client = client;
    let mut seq = 2u8;
    let result = session(&mut client, &cfg, &audit, &mut seq).await;
    match result {
        Ok(()) => Ok(()),
        Err(Error::Refused(why)) => {
            tracing::info!(session = %cfg.session_id, user = %cfg.username, reason = %why, "database session refused");
            let _ = write_packet(
                &mut client,
                &Packet {
                    seq,
                    payload: err_payload(1045, "28000", &why),
                },
            )
            .await;
            let _ = client.shutdown().await;
            Ok(())
        }
        Err(Error::Audit(e)) => {
            tracing::error!(session = %cfg.session_id, error = %e, "audit unavailable; closing the database session");
            let _ = write_packet(
                &mut client,
                &Packet {
                    seq,
                    payload: err_payload(
                        1105,
                        "HY000",
                        "Limen can't record this session right now, so it is closed",
                    ),
                },
            )
            .await;
            let _ = client.shutdown().await;
            Ok(())
        }
        Err(Error::Io(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

async fn session<S>(
    client: &mut S,
    cfg: &DbSessionConfig,
    audit: &Auditor,
    seq: &mut u8,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Greet. The connection id is ours; a KILL naming it is translated below.
    let connection_id = cfg.registry.next_connection_id();
    let nonce: [u8; 20] = std::array::from_fn(|_| rand::random::<u8>() | 1);
    write_packet(
        client,
        &Packet {
            seq: 0,
            payload: greeting(connection_id, &nonce),
        },
    )
    .await?;
    let response = tokio::time::timeout(Duration::from_secs(30), read_packet(client))
        .await
        .map_err(|_| Error::Protocol("no handshake response".into()))??;
    *seq = response.seq.wrapping_add(1);
    let hello = parse_client_hello(&response.payload)?;
    if hello.user != cfg.role {
        return Err(Error::Refused(format!(
            "this session is for the database role {}, not {}",
            cfg.role, hello.user
        )));
    }
    if let Some(db) = &hello.database
        && *db != cfg.database
        && *db != cfg.role
    {
        return Err(Error::Refused(format!(
            "this session is for the database {}, not {db}",
            cfg.database
        )));
    }
    let upstream = connect_upstream_checked(cfg, &hello).await?;
    cfg.registry.insert_mysql(
        connection_id,
        KillEntry {
            username: cfg.username.clone(),
            resource: cfg.resource.clone(),
            real_id: upstream.thread_id,
        },
    );
    write_packet(
        client,
        &Packet {
            seq: *seq,
            payload: ok_payload(),
        },
    )
    .await?;
    let result = commands(client, upstream.io, cfg, audit).await;
    cfg.registry.remove_mysql(connection_id);
    result
}

async fn connect_upstream_checked(cfg: &DbSessionConfig, hello: &ClientHello) -> Result<Upstream> {
    let session = cfg.session_id.to_string();
    let login = Login {
        user: &cfg.login_user,
        password: &cfg.password,
        database: &cfg.database,
        session: &session,
    };
    match connect_upstream(&cfg.target, &login, hello.flags, hello.charset).await {
        Ok(u) => Ok(u),
        Err(Error::Io(e)) => {
            tracing::warn!(session = %cfg.session_id, resource = %cfg.resource, error = %e, "can't reach the database");
            Err(Error::Refused(
                "Limen couldn't connect to the database (is it reachable, and does its certificate match?)".into(),
            ))
        }
        Err(e) => Err(e),
    }
}

pub(super) async fn connect_upstream(
    target: &Target,
    login: &Login<'_>,
    client_flags: u32,
    charset: u8,
) -> Result<Upstream> {
    // The TLS upgrade needs the raw TCP stream, so the greeting is read here.
    let mut tcp = target.dial().await?;
    let greeting = read_packet(&mut tcp).await?;
    let hello = parse_server_hello(&greeting.payload)?;
    let tls = target.uses_tls();
    let mut flags = LONG_PASSWORD
        | LONG_FLAG
        | PROTOCOL_41
        | TRANSACTIONS
        | SECURE_CONNECTION
        | MULTI_RESULTS
        | PS_MULTI_RESULTS
        | PLUGIN_AUTH
        | CONNECT_ATTRS
        | PLUGIN_AUTH_LENENC_DATA
        | CONNECT_WITH_DB
        | (client_flags & PASS_ON);
    flags &= hello.caps | SSL;
    let mut seq = greeting.seq.wrapping_add(1);
    if !tls {
        return finish_login(login, Box::new(tcp), hello, flags, charset, seq, false).await;
    }
    if hello.caps & SSL == 0 {
        return Err(Error::Refused(
            "the database doesn't offer TLS, and Limen won't connect without it".into(),
        ));
    }
    flags |= SSL;
    let mut req = Vec::with_capacity(32);
    req.extend_from_slice(&flags.to_le_bytes());
    req.extend_from_slice(&0x0100_0000u32.to_le_bytes());
    req.push(charset);
    req.extend_from_slice(&[0u8; 23]);
    write_packet(&mut tcp, &Packet { seq, payload: req }).await?;
    seq = seq.wrapping_add(1);
    let io = target.start_tls(tcp).await?;
    finish_login(login, io, hello, flags, charset, seq, true).await
}

// ---- the command phase -----------------------------------------------------

#[derive(Debug)]
struct Pending {
    id: Uuid,
    started: Instant,
    outcome: Outcome,
    done: bool,
}

#[derive(Default)]
struct State {
    pending: VecDeque<Pending>,
    statements: HashMap<u32, (Uuid, Statement)>,
    /// The prepare in flight: its event and statement.
    preparing: Option<(Uuid, Statement)>,
}

impl State {
    fn push(&mut self, id: Uuid) {
        self.pending.push_back(Pending {
            id,
            started: Instant::now(),
            outcome: Outcome::default(),
            done: false,
        });
    }

    fn settle(&mut self, f: impl FnOnce(&mut Outcome)) {
        if let Some(p) = self.pending.iter_mut().find(|p| !p.done) {
            f(&mut p.outcome);
            p.outcome.finished = Some(Instant::now());
            p.done = true;
        }
    }

    fn settle_error(&mut self, payload: &[u8]) {
        let (state, number, message) = parse_err(payload);
        self.settle(|o| {
            o.error_code = Some(state);
            o.error_number = Some(number);
            o.error_message = Some(message);
        });
    }

    async fn finish(&mut self, audit: &Auditor) -> Result<()> {
        for p in self.pending.drain(..) {
            audit.finished(p.id, p.started, &p.outcome).await?;
        }
        Ok(())
    }
}

async fn reply<S: AsyncWrite + Unpin>(
    client: &mut S,
    seq: u8,
    code: u16,
    state: &str,
    message: &str,
) -> Result<()> {
    write_packet(
        client,
        &Packet {
            seq,
            payload: err_payload(code, state, message),
        },
    )
    .await?;
    Ok(())
}

/// What a command's answer looks like.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// One OK or ERR packet.
    Single,
    /// OK, ERR, or result sets (possibly several).
    Statement,
    Prepare,
    /// One packet of text.
    Text,
    /// Nothing comes back.
    None,
}

#[allow(clippy::too_many_lines)]
async fn commands<S>(
    client: &mut S,
    mut up: BoxedIo,
    cfg: &DbSessionConfig,
    audit: &Auditor,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut st = State::default();
    loop {
        let first = match tokio::time::timeout(IDLE_TIMEOUT, read_packet(client)).await {
            Err(_) => return Err(Error::Protocol("idle timeout".into())),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(r) => r?,
        };
        let mut packets = vec![first];
        while packets
            .last()
            .is_some_and(|p| p.payload.len() == MAX_PACKET)
        {
            if packets.iter().map(|p| p.payload.len()).sum::<usize>() > MAX_COMMAND {
                return Err(Error::Refused("message too large".into()));
            }
            packets.push(read_packet(client).await?);
        }
        let seq = packets[0].seq;
        let payload: Vec<u8> = packets.iter().flat_map(|p| p.payload.clone()).collect();
        let Some(&command) = payload.first() else {
            return Err(Error::Protocol("empty command".into()));
        };
        let body = &payload[1..];
        let mut forward = packets;
        let answer = match command {
            COM_QUIT => {
                for p in &forward {
                    write_packet(&mut up, p).await?;
                }
                return Ok(());
            }
            COM_PING | COM_SET_OPTION | COM_STMT_RESET => Answer::Single,
            COM_STATISTICS => Answer::Text,
            COM_RESET_CONNECTION => {
                st.statements.clear();
                let id = audit.action(Phase::Simple, "reset_connection").await?;
                st.push(id);
                Answer::Single
            }
            COM_INIT_DB => {
                let db = String::from_utf8_lossy(body).into_owned();
                if db != cfg.database {
                    audit.action(Phase::Refused, "use").await?;
                    reply(
                        client,
                        seq.wrapping_add(1),
                        1044,
                        "42000",
                        &format!("Access denied for database {db}"),
                    )
                    .await?;
                    continue;
                }
                let id = audit.action(Phase::Simple, "use").await?;
                st.push(id);
                Answer::Single
            }
            COM_QUERY => {
                let text = String::from_utf8_lossy(body).into_owned();
                let statements = sqltext::split(&text, audit.flavor());
                if statements.iter().any(|s| s.kind == "use") {
                    audit.action(Phase::Refused, "use").await?;
                    reply(
                        client,
                        seq.wrapping_add(1),
                        1044,
                        "42000",
                        "USE is not allowed through Limen: this session is for one database",
                    )
                    .await?;
                    continue;
                }
                if let Some(rewritten) = kill_target(&statements, cfg, client, seq, audit).await? {
                    match rewritten {
                        Kill::Refused => continue,
                        Kill::Forward(real_text) => {
                            let mut p = vec![COM_QUERY];
                            p.extend_from_slice(real_text.as_bytes());
                            forward = packets_for(seq, &p);
                        }
                    }
                }
                for s in &statements {
                    let id = audit.statement(Phase::Simple, s, None, None).await?;
                    st.push(id);
                }
                Answer::Statement
            }
            COM_STMT_PREPARE => {
                let text = String::from_utf8_lossy(body).into_owned();
                let statement = sqltext::split(&text, audit.flavor())
                    .into_iter()
                    .next()
                    .unwrap_or(Statement {
                        kind: "empty",
                        text: String::new(),
                    });
                if statement.kind == "use" {
                    audit.action(Phase::Refused, "use").await?;
                    reply(
                        client,
                        seq.wrapping_add(1),
                        1044,
                        "42000",
                        "USE is not allowed through Limen",
                    )
                    .await?;
                    continue;
                }
                let id = audit
                    .statement(Phase::Parse, &statement, None, None)
                    .await?;
                st.push(id);
                st.preparing = Some((id, statement));
                Answer::Prepare
            }
            COM_STMT_EXECUTE => {
                let Some(stmt_id) = body
                    .get(0..4)
                    .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                else {
                    return Err(Error::Protocol("short COM_STMT_EXECUTE".into()));
                };
                if body.get(4).copied().unwrap_or(0) != 0 {
                    audit.action(Phase::Refused, "cursor").await?;
                    reply(
                        client,
                        seq.wrapping_add(1),
                        1235,
                        "42000",
                        "cursors are not supported through Limen",
                    )
                    .await?;
                    continue;
                }
                let known = st.statements.get(&stmt_id).cloned();
                let id = match known {
                    Some((parse_id, statement)) => {
                        audit
                            .statement(
                                Phase::Execute,
                                &statement,
                                Some(&stmt_id.to_string()),
                                Some(parse_id),
                            )
                            .await?
                    }
                    None => {
                        audit
                            .statement(
                                Phase::Execute,
                                &Statement {
                                    kind: "unknown",
                                    text: String::new(),
                                },
                                Some(&stmt_id.to_string()),
                                None,
                            )
                            .await?
                    }
                };
                st.push(id);
                Answer::Statement
            }
            COM_STMT_CLOSE => {
                if let Some(b) = body.get(0..4) {
                    st.statements
                        .remove(&u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
                }
                Answer::None
            }
            COM_STMT_SEND_LONG_DATA => Answer::None,
            other => {
                // COM_CHANGE_USER, replication, COM_FIELD_LIST, COM_PROCESS_KILL,
                // COM_SHUTDOWN, COM_DEBUG, ... (ADR-0033 section 4).
                audit
                    .action(Phase::Refused, &format!("command_{other:#04x}"))
                    .await?;
                reply(
                    client,
                    seq.wrapping_add(1),
                    1235,
                    "42000",
                    "this command is not allowed through Limen",
                )
                .await?;
                continue;
            }
        };
        for p in &forward {
            write_packet(&mut up, p).await?;
        }
        up.flush().await?;
        match answer {
            Answer::None => {}
            Answer::Single => {
                let p = read_packet(&mut up).await?;
                match p.payload.first() {
                    Some(0xff) => st.settle_error(&p.payload),
                    _ => st.settle(|o| o.rows = None),
                }
                st.finish(audit).await?;
                write_packet(client, &p).await?;
            }
            Answer::Text => {
                let p = read_packet(&mut up).await?;
                write_packet(client, &p).await?;
            }
            Answer::Prepare => relay_prepare(client, &mut up, &mut st, audit).await?,
            Answer::Statement => relay_statement(client, &mut up, &mut st, audit).await?,
        }
        client.flush().await?;
    }
}

enum Kill {
    Refused,
    Forward(String),
}

/// `KILL [QUERY|CONNECTION] <id>`: the id is the one Limen gave the client,
/// so it is translated to the target's thread id, and only for the same user.
/// Every other `KILL` is refused.
async fn kill_target<S: AsyncWrite + Unpin>(
    statements: &[Statement],
    cfg: &DbSessionConfig,
    client: &mut S,
    seq: u8,
    audit: &Auditor,
) -> Result<Option<Kill>> {
    if !statements.iter().any(|s| s.kind == "kill") {
        return Ok(None);
    }
    let parsed = match statements {
        [only] => parse_kill(&only.text),
        _ => None,
    };
    let Some((scope, id)) = parsed else {
        audit.action(Phase::Refused, "kill").await?;
        reply(
            client,
            seq.wrapping_add(1),
            1235,
            "42000",
            "only KILL [QUERY|CONNECTION] <id> is allowed through Limen",
        )
        .await?;
        return Ok(Some(Kill::Refused));
    };
    let entry = cfg
        .registry
        .get_mysql(id)
        .filter(|e| e.username == cfg.username && e.resource == cfg.resource);
    let Some(entry) = entry else {
        audit.action(Phase::Refused, "kill").await?;
        reply(
            client,
            seq.wrapping_add(1),
            1094,
            "HY000",
            &format!("Unknown thread id: {id}"),
        )
        .await?;
        return Ok(Some(Kill::Refused));
    };
    Ok(Some(Kill::Forward(format!(
        "KILL {scope} {}",
        entry.real_id
    ))))
}

/// `("QUERY" | "CONNECTION", id)` from `KILL ...`, or `None` for any other shape.
fn parse_kill(text: &str) -> Option<(&'static str, u32)> {
    use sqlparser::dialect::MySqlDialect;
    use sqlparser::tokenizer::{Token, Tokenizer};
    let tokens: Vec<Token> = Tokenizer::new(&MySqlDialect {}, text)
        .tokenize()
        .ok()?
        .into_iter()
        .filter(|t| !matches!(t, Token::Whitespace(_) | Token::SemiColon))
        .collect();
    let word = |t: &Token| match t {
        Token::Word(w) if w.quote_style.is_none() => Some(w.value.to_ascii_uppercase()),
        _ => None,
    };
    let number = |t: &Token| match t {
        Token::Number(n, false) => n.parse::<u32>().ok(),
        _ => None,
    };
    match tokens.as_slice() {
        [k, id] if word(k)? == "KILL" => Some(("CONNECTION", number(id)?)),
        [k, s, id] if word(k)? == "KILL" => match word(s)?.as_str() {
            "QUERY" => Some(("QUERY", number(id)?)),
            "CONNECTION" => Some(("CONNECTION", number(id)?)),
            _ => None,
        },
        _ => None,
    }
}

async fn relay_prepare<S>(
    client: &mut S,
    up: &mut BoxedIo,
    st: &mut State,
    audit: &Auditor,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let first = read_packet(up).await?;
    if first.payload.first() == Some(&0xff) {
        st.settle_error(&first.payload);
        st.finish(audit).await?;
        write_packet(client, &first).await?;
        return Ok(());
    }
    let p = &first.payload;
    let bad = || Error::Protocol("malformed prepare response".into());
    let stmt_id = u32::from_le_bytes(p.get(1..5).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
    let columns = u16::from_le_bytes(p.get(5..7).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
    let params = u16::from_le_bytes(p.get(7..9).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
    if let Some(entry) = st.preparing.take() {
        st.statements.insert(stmt_id, entry);
    }
    st.settle(|_| {});
    st.finish(audit).await?;
    write_packet(client, &first).await?;
    for count in [params, columns] {
        if count > 0 {
            for _ in 0..count {
                let d = read_packet(up).await?;
                write_packet(client, &d).await?;
            }
            let eof = read_packet(up).await?;
            write_packet(client, &eof).await?;
        }
    }
    Ok(())
}

async fn relay_statement<S>(
    client: &mut S,
    up: &mut BoxedIo,
    st: &mut State,
    audit: &Auditor,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    loop {
        let first = read_packet(up).await?;
        match first.payload.first() {
            Some(0x00) => {
                let p = &first.payload;
                let (affected, used) = lenenc(&p[1..]).unwrap_or((0, 1));
                let (_, used2) = lenenc(p.get(1 + used..).unwrap_or(&[])).unwrap_or((0, 1));
                let status = p
                    .get(1 + used + used2..1 + used + used2 + 2)
                    .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]));
                st.settle(|o| o.rows = Some(affected));
                let more = status & STATUS_MORE_RESULTS != 0;
                if !more {
                    st.finish(audit).await?;
                }
                write_packet(client, &first).await?;
                if !more {
                    return Ok(());
                }
            }
            Some(0xff) => {
                st.settle_error(&first.payload);
                st.finish(audit).await?;
                write_packet(client, &first).await?;
                return Ok(());
            }
            Some(0xfb) => {
                return Err(Error::Protocol(
                    "the database asked for a local file".into(),
                ));
            }
            Some(_) => {
                let (columns, _) = lenenc(&first.payload)
                    .ok_or_else(|| Error::Protocol("bad column count".into()))?;
                write_packet(client, &first).await?;
                for _ in 0..columns {
                    let d = read_packet(up).await?;
                    write_packet(client, &d).await?;
                }
                let eof = read_packet(up).await?;
                write_packet(client, &eof).await?;
                let mut rows = 0u64;
                loop {
                    let p = read_packet(up).await?;
                    if is_eof(&p) {
                        let status = p
                            .payload
                            .get(3..5)
                            .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]));
                        st.settle(|o| o.rows = Some(rows));
                        let more = status & STATUS_MORE_RESULTS != 0;
                        if !more {
                            st.finish(audit).await?;
                        }
                        write_packet(client, &p).await?;
                        if more {
                            break;
                        }
                        return Ok(());
                    }
                    if p.payload.first() == Some(&0xff) {
                        st.settle_error(&p.payload);
                        st.finish(audit).await?;
                        write_packet(client, &p).await?;
                        return Ok(());
                    }
                    rows += 1;
                    write_packet(client, &p).await?;
                }
            }
            None => return Err(Error::Protocol("empty response".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lenenc_round_trips() {
        for n in [0usize, 250, 251, 65_535, 65_536, 16_000_000] {
            let mut out = Vec::new();
            put_lenenc(&mut out, n);
            assert_eq!(lenenc(&out), Some((n as u64, out.len())));
        }
        assert_eq!(lenenc(&[0xfb]), None);
        assert_eq!(lenenc(&[]), None);
    }

    #[test]
    fn long_payloads_are_split_with_a_terminating_empty_packet() {
        let p = packets_for(3, &vec![1u8; MAX_PACKET]);
        assert_eq!(p.len(), 2);
        assert_eq!((p[0].seq, p[1].seq, p[1].payload.len()), (3, 4, 0));
        let p = packets_for(0, &vec![1u8; MAX_PACKET + 5]);
        assert_eq!((p.len(), p[1].payload.len()), (2, 5));
        assert_eq!(packets_for(9, b"").len(), 1);
    }

    #[test]
    fn native_password_matches_the_server_side_check() {
        // The server stores SHA1(SHA1(pw)). It recovers SHA1(pw) from the token.
        let nonce = b"abcdefghijklmnopqrst";
        let token = native_password("pencil", nonce);
        let stage2 = sha1(&[&sha1(&[b"pencil"])]);
        let stage1 = xor(&token, &sha1(&[nonce, &stage2]));
        assert_eq!(sha1(&[&stage1]), stage2);
        assert_eq!(native_password("", nonce), Vec::<u8>::new());
    }

    #[test]
    fn clear_password_needs_tls() {
        assert!(auth_response("mysql_clear_password", "t", b"", false).is_err());
        assert_eq!(
            auth_response("mysql_clear_password", "t", b"", true).expect("tls"),
            b"t\0"
        );
        assert!(auth_response("sha256_password", "t", b"", true).is_err());
    }

    #[test]
    fn kill_is_parsed_strictly() {
        assert_eq!(parse_kill("KILL QUERY 42"), Some(("QUERY", 42)));
        assert_eq!(parse_kill("kill  connection 7 ;"), Some(("CONNECTION", 7)));
        assert_eq!(parse_kill("KILL 9"), Some(("CONNECTION", 9)));
        assert_eq!(parse_kill("KILL QUERY 1 + 1"), None);
        assert_eq!(parse_kill("KILL QUERY (select 1)"), None);
        assert_eq!(parse_kill("KILL USER x"), None);
        assert_eq!(parse_kill("select 1"), None);
    }

    #[test]
    fn err_packets_parse() {
        let p = err_payload(1146, "42S02", "Table 'x' doesn't exist");
        assert_eq!(
            parse_err(&p),
            ("42S02".into(), 1146, "Table 'x' doesn't exist".into())
        );
        assert_eq!(parse_err(&[0xff, 1, 0, b'o', b'k']).0, "HY000");
    }

    #[test]
    fn client_hello_is_parsed_with_and_without_a_database() {
        let mut p = Vec::new();
        let flags = PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH | CONNECT_WITH_DB;
        p.extend_from_slice(&flags.to_le_bytes());
        p.extend_from_slice(&[0, 0, 0, 1]);
        p.push(45);
        p.extend_from_slice(&[0u8; 23]);
        p.extend_from_slice(b"limen_ro\0");
        p.push(3);
        p.extend_from_slice(b"xyz");
        p.extend_from_slice(b"orders\0mysql_native_password\0");
        let h = parse_client_hello(&p).expect("hello");
        assert_eq!(
            (h.user.as_str(), h.database.as_deref(), h.charset),
            ("limen_ro", Some("orders"), 45)
        );
        // An SSL request (32 bytes with the flag) is refused.
        let mut ssl = (flags | SSL).to_le_bytes().to_vec();
        ssl.extend_from_slice(&[0u8; 28]);
        assert!(matches!(parse_client_hello(&ssl), Err(Error::Refused(_))));
        assert!(parse_client_hello(&p[..10]).is_err());
    }

    #[test]
    fn the_greeting_has_the_right_shape() {
        let g = greeting(0x4000_0001, &[7u8; 20]);
        assert_eq!(g[0], 10);
        let hello = parse_server_hello(&g).expect("parses as a server greeting");
        assert_eq!(hello.thread_id, 0x4000_0001);
        assert_eq!(hello.nonce, vec![7u8; 20]);
        assert_eq!(hello.plugin, "mysql_native_password");
        assert_eq!(hello.caps & SSL, 0, "no TLS is offered");
        assert_eq!(hello.caps & 0x80, 0, "no LOCAL INFILE");
        assert_eq!(hello.caps & 0x100_0000, 0, "no DEPRECATE_EOF");
    }
}

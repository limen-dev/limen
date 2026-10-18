//! PostgreSQL wire protocol v3 (also Redshift): a message-aware relay.
//!
//! Toward the client the worker plays the server: it accepts the startup
//! message without a password (the stream is already authenticated and
//! authorized), checks the role and database against the grant, and hands the
//! client a random cancel key. Toward the target it logs in as the `limen_*`
//! role. After that, frames are relayed; only the ones needed for audit
//! (`Q`, `P`, `B`, `E`, `C`, `F` from the client; `C`, `E`, `Z` from the
//! server) are read in full.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use limen_audit::Emitter;
use limen_core::secret::Secret;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use uuid::Uuid;

use super::audit::{Auditor, Outcome, Phase};
use super::scram;
use super::sqltext::{self, Statement};
use super::target::{BoxedIo, Target};
use super::{CancelEntry, DbSessionConfig};

const PROTOCOL_3_0: u32 = 196_608;
const CANCEL_REQUEST: u32 = 80_877_102;
const SSL_REQUEST: u32 = 80_877_103;
const GSSENC_REQUEST: u32 = 80_877_104;

/// Largest startup packet a client may send.
const MAX_STARTUP: usize = 10_000;
/// Largest handshake frame read from the target.
pub(super) const MAX_HANDSHAKE_FRAME: usize = 1024 * 1024;
/// Frames the worker reads in full to audit them. A bigger one ends the session.
const MAX_BUFFERED: usize = 64 * 1024 * 1024;
/// Longest silence from the client before the session is closed.
const IDLE_TIMEOUT: Duration = Duration::from_hours(1);
const CHUNK: usize = 32 * 1024;

/// Startup parameters passed on to the target. `application_name` is ours;
/// `options` and `replication` are refused; anything else is dropped.
const PASS_THROUGH: &[&str] = &[
    "client_encoding",
    "datestyle",
    "timezone",
    "extra_float_digits",
    "search_path",
];

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

// ---- message helpers -------------------------------------------------------

/// A frame length as it goes on the wire.
fn be32(n: usize) -> [u8; 4] {
    u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes()
}

pub(super) fn put_cstr(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}

/// An `ErrorResponse` frame.
fn error_frame(severity: &str, code: &str, message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (tag, value) in [
        (b'S', severity),
        (b'V', severity),
        (b'C', code),
        (b'M', message),
    ] {
        body.push(tag);
        put_cstr(&mut body, value);
    }
    body.push(0);
    frame(b'E', &body)
}

pub(super) fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    out.push(kind);
    out.extend_from_slice(
        &u32::try_from(body.len() + 4)
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    out.extend_from_slice(body);
    out
}

/// The NUL-terminated string at the start of `buf`, and the rest after it.
pub(super) fn take_cstr(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = buf.iter().position(|&b| b == 0)?;
    Some((&buf[..end], &buf[end + 1..]))
}

pub(super) fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Fields of an `ErrorResponse` or `NoticeResponse` body: `(tag, value)`.
pub(super) fn error_fields(body: &[u8]) -> Vec<(u8, String)> {
    let mut fields = Vec::new();
    let mut rest = body;
    while let Some((&tag, tail)) = rest.split_first() {
        if tag == 0 {
            break;
        }
        let Some((value, tail)) = take_cstr(tail) else {
            break;
        };
        fields.push((tag, lossy(value)));
        rest = tail;
    }
    fields
}

pub(super) fn field(fields: &[(u8, String)], tag: u8) -> Option<&str> {
    fields
        .iter()
        .find(|(t, _)| *t == tag)
        .map(|(_, v)| v.as_str())
}

pub(super) async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<(u8, Vec<u8>)> {
    let kind = r.read_u8().await?;
    let len = r.read_u32().await? as usize;
    if len < 4 || len - 4 > max {
        return Err(Error::Protocol(format!(
            "frame {:?} has length {len}",
            kind as char
        )));
    }
    let mut body = vec![0u8; len - 4];
    r.read_exact(&mut body).await?;
    Ok((kind, body))
}

// ---- startup toward the client --------------------------------------------

struct Startup {
    params: HashMap<String, String>,
}

enum FirstPacket {
    Startup(Startup),
    Cancel { pid: u32, secret: u32 },
}

async fn read_first_packet<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
) -> Result<FirstPacket> {
    loop {
        let len = client.read_u32().await? as usize;
        if !(8..=MAX_STARTUP).contains(&len) {
            return Err(Error::Protocol(format!("startup packet of {len} bytes")));
        }
        let mut payload = vec![0u8; len - 4];
        client.read_exact(&mut payload).await?;
        let code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        match code {
            SSL_REQUEST | GSSENC_REQUEST => {
                // The hop from the CLI is already mutual TLS.
                client.write_all(b"N").await?;
            }
            CANCEL_REQUEST => {
                if payload.len() != 12 {
                    return Err(Error::Protocol("malformed cancel request".into()));
                }
                return Ok(FirstPacket::Cancel {
                    pid: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
                    secret: u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]),
                });
            }
            c if c >> 16 == 3 => {
                if c != PROTOCOL_3_0 {
                    // NegotiateProtocolVersion: we speak 3.0, no options rejected.
                    let mut body = Vec::new();
                    body.extend_from_slice(&0u32.to_be_bytes());
                    body.extend_from_slice(&0u32.to_be_bytes());
                    client.write_all(&frame(b'v', &body)).await?;
                }
                let mut params = HashMap::new();
                let mut rest = &payload[4..];
                while let Some((key, tail)) = take_cstr(rest) {
                    if key.is_empty() {
                        break;
                    }
                    let (value, tail) = take_cstr(tail)
                        .ok_or_else(|| Error::Protocol("malformed startup packet".into()))?;
                    params.insert(lossy(key), lossy(value));
                    rest = tail;
                }
                return Ok(FirstPacket::Startup(Startup { params }));
            }
            _ => {
                return Err(Error::Refused("unsupported frontend protocol".into()));
            }
        }
    }
}

/// The startup parameters to send the target, after the guards of
/// ADR-0033 section 4.
fn target_params(cfg: &DbSessionConfig, startup: &Startup) -> Result<Vec<(String, String)>> {
    let p = &startup.params;
    if p.contains_key("replication") {
        return Err(Error::Refused(
            "replication connections are not allowed through Limen".into(),
        ));
    }
    if p.contains_key("options") {
        return Err(Error::Refused(
            "startup options are not allowed through Limen; use SET after connecting".into(),
        ));
    }
    match p.get("user") {
        Some(user) if *user == cfg.role => {}
        Some(user) => {
            return Err(Error::Refused(format!(
                "this session is for the database role {}, not {user}",
                cfg.role
            )));
        }
        None => return Err(Error::Refused("no user in the startup message".into())),
    }
    // libpq sends the user name as the database when none is given: that
    // means "the database this session was granted".
    if let Some(db) = p.get("database")
        && *db != cfg.database
        && *db != cfg.role
    {
        return Err(Error::Refused(format!(
            "this session is for the database {}, not {db}",
            cfg.database
        )));
    }
    let mut out = vec![
        ("user".to_owned(), cfg.login_user.clone()),
        ("database".to_owned(), cfg.database.clone()),
        (
            "application_name".to_owned(),
            format!("limen:{}", cfg.session_id),
        ),
    ];
    for key in PASS_THROUGH {
        if let Some(v) = p.get(*key) {
            out.push(((*key).to_owned(), v.clone()));
        }
    }
    Ok(out)
}

// ---- the target ------------------------------------------------------------

pub(super) struct Backend {
    pub reader: ReadHalf<BoxedIo>,
    pub writer: WriteHalf<BoxedIo>,
    pub pid: u32,
    pub secret: u32,
    /// `ParameterStatus` frames, to pass to the client.
    pub status: Vec<Vec<u8>>,
    /// The `ReadyForQuery` frame that ended the startup.
    pub ready: Vec<u8>,
}

/// TCP, then the PostgreSQL TLS negotiation when the target uses TLS.
async fn open(target: &Target) -> Result<BoxedIo> {
    let mut tcp = target.dial().await?;
    if !target.uses_tls() {
        return Ok(Box::new(tcp));
    }
    tcp.write_all(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]).await?;
    let answer = tcp.read_u8().await?;
    if answer != b'S' {
        return Err(Error::Refused(
            "the database doesn't accept TLS, and Limen won't connect without it".into(),
        ));
    }
    Ok(target.start_tls(tcp).await?)
}

pub(super) async fn connect_backend(
    target: &Target,
    role: &str,
    password: &Secret<String>,
    session: &str,
    params: &[(String, String)],
) -> Result<Backend> {
    let io = open(target).await?;
    let (mut reader, mut writer) = split(io);

    let mut body = Vec::new();
    body.extend_from_slice(&PROTOCOL_3_0.to_be_bytes());
    for (k, v) in params {
        put_cstr(&mut body, k);
        put_cstr(&mut body, v);
    }
    body.push(0);
    let mut startup = u32::try_from(body.len() + 4)
        .unwrap_or(u32::MAX)
        .to_be_bytes()
        .to_vec();
    startup.extend_from_slice(&body);
    writer.write_all(&startup).await?;

    let mut scram_state: Option<String> = None; // client-first-bare
    let mut proof: Option<scram::Proof> = None;
    loop {
        let (kind, body) = read_frame(&mut reader, MAX_HANDSHAKE_FRAME).await?;
        match kind {
            b'R' => {
                let code = body
                    .get(..4)
                    .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                    .ok_or_else(|| Error::Protocol("short authentication frame".into()))?;
                match code {
                    0 => break,
                    3 => {
                        let mut pw = password.expose().clone().into_bytes();
                        pw.push(0);
                        writer.write_all(&frame(b'p', &pw)).await?;
                        zero(&mut pw);
                    }
                    10 => {
                        let offered = lossy(&body[4..]);
                        if !offered.split('\0').any(|m| m == "SCRAM-SHA-256") {
                            return Err(Error::Refused(
                                "the database offers no SCRAM-SHA-256 authentication".into(),
                            ));
                        }
                        let bare = scram::client_first_bare(&scram::new_nonce());
                        let first = scram::client_first(&bare);
                        let mut msg = Vec::new();
                        put_cstr(&mut msg, "SCRAM-SHA-256");
                        msg.extend_from_slice(
                            &i32::try_from(first.len()).unwrap_or(0).to_be_bytes(),
                        );
                        msg.extend_from_slice(first.as_bytes());
                        writer.write_all(&frame(b'p', &msg)).await?;
                        scram_state = Some(bare);
                    }
                    11 => {
                        let bare = scram_state
                            .take()
                            .ok_or_else(|| Error::Protocol("unexpected SASL continue".into()))?;
                        let server_first = lossy(&body[4..]);
                        let p = scram::client_final(password.expose(), &bare, &server_first)
                            .map_err(|e| Error::Refused(format!("SCRAM: {e}")))?;
                        writer
                            .write_all(&frame(b'p', p.client_final.as_bytes()))
                            .await?;
                        proof = Some(p);
                    }
                    12 => {
                        let ok = proof
                            .take()
                            .is_some_and(|p| p.verify_server_final(&lossy(&body[4..])));
                        if !ok {
                            return Err(Error::Refused(
                                "the database failed to prove it knows the password".into(),
                            ));
                        }
                    }
                    5 => {
                        // MD5 password login: Redshift, and PostgreSQL set up
                        // with `md5` in pg_hba.conf. Never offered over a clear
                        // channel: the connection is TLS unless `insecure_dev`.
                        let salt: [u8; 4] = body
                            .get(4..8)
                            .and_then(|b| b.try_into().ok())
                            .ok_or_else(|| {
                                Error::Protocol("short MD5 authentication frame".into())
                            })?;
                        let mut pw = md5_password(role, password.expose(), salt).into_bytes();
                        pw.push(0);
                        writer.write_all(&frame(b'p', &pw)).await?;
                        zero(&mut pw);
                    }
                    other => {
                        return Err(Error::Refused(format!(
                            "unsupported database authentication method ({other})"
                        )));
                    }
                }
            }
            b'E' => {
                let fields = error_fields(&body);
                let code = field(&fields, b'C').unwrap_or("");
                let message = field(&fields, b'M').unwrap_or("error");
                tracing::warn!(session = %session, %code, %message, "the database refused the login");
                return Err(Error::Refused(if code.starts_with("28") {
                    format!("could not authenticate to the database as {role}")
                } else {
                    message.to_owned()
                }));
            }
            b'N' => {}
            other => {
                return Err(Error::Protocol(format!(
                    "unexpected {:?} during database login",
                    other as char
                )));
            }
        }
    }

    // Authenticated. Collect what the client needs until ReadyForQuery.
    let (mut status, mut pid, mut secret) = (Vec::new(), 0, 0);
    loop {
        let (kind, body) = read_frame(&mut reader, MAX_HANDSHAKE_FRAME).await?;
        match kind {
            b'S' => status.push(frame(b'S', &body)),
            b'K' if body.len() >= 8 => {
                pid = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                secret = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
            }
            b'Z' => {
                return Ok(Backend {
                    reader,
                    writer,
                    pid,
                    secret,
                    status,
                    ready: frame(b'Z', &body),
                });
            }
            b'N' => {}
            b'E' => {
                let fields = error_fields(&body);
                return Err(Error::Refused(
                    field(&fields, b'M')
                        .unwrap_or("the database refused the session")
                        .to_owned(),
                ));
            }
            other => {
                return Err(Error::Protocol(format!(
                    "unexpected {:?} during database startup",
                    other as char
                )));
            }
        }
    }
}

/// `md5` + hex(md5(hex(md5(password + user)) + salt)): the legacy PostgreSQL
/// password message. Redshift still uses it.
fn md5_password(user: &str, password: &str, salt: [u8; 4]) -> String {
    use md5::{Digest, Md5};
    let hex = |bytes: &[u8]| {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    };
    let inner = Md5::new()
        .chain_update(password.as_bytes())
        .chain_update(user.as_bytes())
        .finalize();
    let outer = Md5::new()
        .chain_update(hex(&inner).as_bytes())
        .chain_update(salt)
        .finalize();
    format!("md5{}", hex(&outer))
}

/// Overwrite a buffer that held a secret.
fn zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
}

// ---- cancel ----------------------------------------------------------------

async fn forward_cancel(
    cfg: &DbSessionConfig,
    audit: &Auditor,
    pid: u32,
    secret: u32,
) -> Result<()> {
    let entry = cfg
        .registry
        .get((pid, secret))
        .filter(|e| e.username == cfg.username && e.resource == cfg.resource);
    // Same answer whether the key is unknown or someone else's.
    let Some(entry) = entry else {
        return Ok(());
    };
    audit.action(Phase::Cancel, "cancel").await?;
    let mut io = open(&entry.target).await?;
    let mut packet = vec![0, 0, 0, 16];
    packet.extend_from_slice(&CANCEL_REQUEST.to_be_bytes());
    packet.extend_from_slice(&entry.pid.to_be_bytes());
    packet.extend_from_slice(&entry.secret.to_be_bytes());
    io.write_all(&packet).await?;
    io.shutdown().await.ok();
    Ok(())
}

// ---- the session -----------------------------------------------------------

type ClientWriter<S> = Arc<tokio::sync::Mutex<WriteHalf<S>>>;

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
    match session(&mut client, &cfg, &audit).await {
        Ok(()) => Ok(()),
        Err(Error::Refused(why)) => {
            tracing::info!(session = %cfg.session_id, user = %cfg.username, reason = %why, "database session refused");
            let _ = client.write_all(&error_frame("FATAL", "28000", &why)).await;
            let _ = client.shutdown().await;
            Ok(())
        }
        Err(Error::Audit(e)) => {
            tracing::error!(session = %cfg.session_id, error = %e, "audit unavailable; closing the database session");
            let _ = client
                .write_all(&error_frame(
                    "FATAL",
                    "58000",
                    "Limen can't record this session right now, so it is closed",
                ))
                .await;
            let _ = client.shutdown().await;
            Ok(())
        }
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
        Err(e) => Err(e.into()),
    }
}

async fn session<S>(client: &mut S, cfg: &DbSessionConfig, audit: &Auditor) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let startup = match tokio::time::timeout(Duration::from_secs(30), read_first_packet(client))
        .await
        .map_err(|_| Error::Protocol("no startup message".into()))??
    {
        FirstPacket::Cancel { pid, secret } => {
            return forward_cancel(cfg, audit, pid, secret).await;
        }
        FirstPacket::Startup(s) => s,
    };
    let params = target_params(cfg, &startup)?;
    let backend = match connect_backend(
        &cfg.target,
        &cfg.login_user,
        &cfg.password,
        &cfg.session_id.to_string(),
        &params,
    )
    .await
    {
        Ok(b) => b,
        Err(Error::Io(e)) => {
            tracing::warn!(session = %cfg.session_id, resource = %cfg.resource, error = %e, "can't reach the database");
            return Err(Error::Refused(
                "Limen couldn't connect to the database (is it reachable, and does its certificate match?)".into(),
            ));
        }
        Err(e) => return Err(e),
    };

    // The client gets its own cancel key; the real one stays here.
    let key = (rand::random::<u32>(), rand::random::<u32>());
    cfg.registry.insert(
        key,
        CancelEntry {
            username: cfg.username.clone(),
            resource: cfg.resource.clone(),
            pid: backend.pid,
            secret: backend.secret,
            target: cfg.target.clone(),
        },
    );
    let result = relay(client, backend, cfg, audit, key).await;
    cfg.registry.remove(key);
    result
}

/// What the client sent that is waiting for the target's answer.
#[derive(Debug)]
struct Pending {
    id: Uuid,
    started: Instant,
    outcome: Outcome,
    done: bool,
}

#[derive(Debug, Default)]
struct Shared {
    pending: VecDeque<Pending>,
    /// Prepared statements by name: the `Parse` event and the statement.
    statements: HashMap<Vec<u8>, (Uuid, Statement)>,
    /// Portals by name: the statement name they were bound to.
    portals: HashMap<Vec<u8>, Vec<u8>>,
}

async fn relay<S>(
    client: &mut S,
    backend: Backend,
    cfg: &DbSessionConfig,
    audit: &Auditor,
    key: (u32, u32),
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let Backend {
        reader: mut target_read,
        writer: mut target_write,
        status,
        ready,
        ..
    } = backend;
    // Hand over the session: AuthenticationOk, parameters, our key, ReadyForQuery.
    let mut hello = frame(b'R', &0u32.to_be_bytes());
    for s in status {
        hello.extend_from_slice(&s);
    }
    let mut k = Vec::new();
    k.extend_from_slice(&key.0.to_be_bytes());
    k.extend_from_slice(&key.1.to_be_bytes());
    hello.extend_from_slice(&frame(b'K', &k));
    hello.extend_from_slice(&ready);
    client.write_all(&hello).await?;

    let (mut client_read, client_write) = split(client);
    let client_write: ClientWriter<_> = Arc::new(tokio::sync::Mutex::new(client_write));
    let shared = Arc::new(Mutex::new(Shared::default()));

    let result = {
        let up = client_to_target(&mut client_read, &mut target_write, &shared, audit);
        let down = target_to_client(&mut target_read, &client_write, &shared, audit);
        tokio::pin!(up);
        tokio::pin!(down);
        tokio::select! {
            r = &mut up => r,
            r = &mut down => r,
        }
    };

    // Whatever was still waiting for an answer never got one.
    let leftover: Vec<Pending> = lock(&shared).pending.drain(..).collect();
    for p in leftover {
        if let Err(e) = audit.finished(p.id, p.started, &p.outcome).await {
            tracing::error!(session = %cfg.session_id, error = %e, "couldn't audit an unfinished statement");
        }
    }
    let _ = target_write.shutdown().await;
    if let Err(Error::Audit(_)) = &result {
        let mut w = client_write.lock().await;
        let _ = w
            .write_all(&error_frame(
                "FATAL",
                "58000",
                "Limen can't record this session right now, so it is closed",
            ))
            .await;
    }
    result
}

fn lock(shared: &Mutex<Shared>) -> std::sync::MutexGuard<'_, Shared> {
    shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn copy_exact<R, W>(from: &mut R, to: &mut W, mut remaining: usize) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; CHUNK.min(remaining.max(1))];
    while remaining > 0 {
        let n = remaining.min(buf.len());
        from.read_exact(&mut buf[..n]).await?;
        to.write_all(&buf[..n]).await?;
        remaining -= n;
    }
    Ok(())
}

/// Client → target. Statements are audited before they are forwarded.
async fn client_to_target<S>(
    client: &mut ReadHalf<S>,
    target: &mut WriteHalf<BoxedIo>,
    shared: &Mutex<Shared>,
    audit: &Auditor,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    loop {
        let kind = match tokio::time::timeout(IDLE_TIMEOUT, client.read_u8()).await {
            Err(_) => return Err(Error::Protocol("idle timeout".into())),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(r) => r?,
        };
        let len = client.read_u32().await? as usize;
        if len < 4 {
            return Err(Error::Protocol(format!(
                "frame {:?} has length {len}",
                kind as char
            )));
        }
        let body_len = len - 4;
        match kind {
            b'Q' | b'P' | b'B' | b'E' | b'C' | b'D' | b'S' | b'H' | b'X' | b'p' => {
                if body_len > MAX_BUFFERED {
                    return Err(Error::Refused("message too large".into()));
                }
                let mut body = vec![0u8; body_len];
                client.read_exact(&mut body).await?;
                inspect(kind, &body, shared, audit).await?;
                target.write_all(&frame(kind, &body)).await?;
                if kind == b'X' {
                    return Ok(());
                }
            }
            b'F' => {
                // Fast-path function call (large objects).
                let id = audit.action(Phase::FunctionCall, "function_call").await?;
                lock(shared).pending.push_back(Pending {
                    id,
                    started: Instant::now(),
                    outcome: Outcome::default(),
                    done: false,
                });
                target.write_all(&[kind]).await?;
                target.write_all(&be32(len)).await?;
                copy_exact(client, target, body_len).await?;
            }
            _ => {
                // CopyData, CopyDone, CopyFail and anything else: stream.
                target.write_all(&[kind]).await?;
                target.write_all(&be32(len)).await?;
                copy_exact(client, target, body_len).await?;
            }
        }
        target.flush().await?;
    }
}

async fn inspect(kind: u8, body: &[u8], shared: &Mutex<Shared>, audit: &Auditor) -> Result<()> {
    match kind {
        b'Q' => {
            let (text, _) = take_cstr(body).unwrap_or((body, &[]));
            let text = lossy(text);
            for statement in sqltext::split(&text, audit.flavor()) {
                let id = audit
                    .statement(Phase::Simple, &statement, None, None)
                    .await?;
                lock(shared).pending.push_back(Pending {
                    id,
                    started: Instant::now(),
                    outcome: Outcome::default(),
                    done: false,
                });
            }
        }
        b'P' => {
            let Some((name, rest)) = take_cstr(body) else {
                return Ok(());
            };
            let (text, _) = take_cstr(rest).unwrap_or((rest, &[]));
            let text = lossy(text);
            let statement = sqltext::split(&text, audit.flavor())
                .into_iter()
                .next()
                .unwrap_or(Statement {
                    kind: "empty",
                    text: String::new(),
                });
            let id = audit
                .statement(Phase::Parse, &statement, Some(&lossy(name)), None)
                .await?;
            lock(shared)
                .statements
                .insert(name.to_vec(), (id, statement));
        }
        b'B' => {
            if let Some((portal, rest)) = take_cstr(body)
                && let Some((statement, _)) = take_cstr(rest)
            {
                lock(shared)
                    .portals
                    .insert(portal.to_vec(), statement.to_vec());
            }
        }
        b'E' => {
            let (portal, _) = take_cstr(body).unwrap_or((body, &[]));
            let known = {
                let g = lock(shared);
                g.portals.get(portal).and_then(|name| {
                    g.statements
                        .get(name)
                        .map(|(id, s)| (name.clone(), *id, s.clone()))
                })
            };
            let id = if let Some((name, parse_id, statement)) = known {
                audit
                    .statement(
                        Phase::Execute,
                        &statement,
                        Some(&lossy(&name)),
                        Some(parse_id),
                    )
                    .await?
            } else {
                audit
                    .statement(
                        Phase::Execute,
                        &Statement {
                            kind: "unknown",
                            text: String::new(),
                        },
                        None,
                        None,
                    )
                    .await?
            };
            lock(shared).pending.push_back(Pending {
                id,
                started: Instant::now(),
                outcome: Outcome::default(),
                done: false,
            });
        }
        b'C' => {
            // Close a statement ('S') or portal ('P').
            if let Some((&which, rest)) = body.split_first()
                && let Some((name, _)) = take_cstr(rest)
            {
                let mut g = lock(shared);
                if which == b'S' {
                    g.statements.remove(name);
                } else {
                    g.portals.remove(name);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Target → client. `CommandComplete` and `ErrorResponse` settle the oldest
/// open statement; `ReadyForQuery` writes the end events before it reaches
/// the client.
async fn target_to_client<S>(
    target: &mut ReadHalf<BoxedIo>,
    client_write: &ClientWriter<S>,
    shared: &Mutex<Shared>,
    audit: &Auditor,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    loop {
        let kind = match target.read_u8().await {
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            r => r?,
        };
        let len = target.read_u32().await? as usize;
        if len < 4 {
            return Err(Error::Protocol(format!(
                "frame {:?} has length {len}",
                kind as char
            )));
        }
        let body_len = len - 4;
        match kind {
            b'C' | b'E' | b'Z' | b'I' | b's' if body_len <= MAX_HANDSHAKE_FRAME => {
                let mut body = vec![0u8; body_len];
                target.read_exact(&mut body).await?;
                let now = Instant::now();
                match kind {
                    b'C' => {
                        let tag = take_cstr(&body).map_or_else(String::new, |(t, _)| lossy(t));
                        settle(shared, |o| {
                            o.rows = sqltext::rows_from_tag(&tag);
                            o.finished = Some(now);
                        });
                    }
                    b'I' | b's' => settle(shared, |o| o.finished = Some(now)),
                    b'E' => {
                        let fields = error_fields(&body);
                        settle(shared, |o| {
                            o.error_code = Some(field(&fields, b'C').unwrap_or("").to_owned());
                            o.error_message = field(&fields, b'M').map(str::to_owned);
                            o.finished = Some(now);
                        });
                    }
                    b'Z' => {
                        let done: Vec<Pending> = lock(shared).pending.drain(..).collect();
                        for p in done {
                            audit.finished(p.id, p.started, &p.outcome).await?;
                        }
                    }
                    _ => {}
                }
                let mut w = client_write.lock().await;
                w.write_all(&frame(kind, &body)).await?;
                w.flush().await?;
            }
            _ => {
                let mut w = client_write.lock().await;
                w.write_all(&[kind]).await?;
                w.write_all(&be32(len)).await?;
                copy_exact(target, &mut *w, body_len).await?;
                w.flush().await?;
            }
        }
    }
}

/// Apply `f` to the oldest statement that has no answer yet.
fn settle(shared: &Mutex<Shared>, f: impl FnOnce(&mut Outcome)) {
    let mut g = lock(shared);
    if let Some(p) = g.pending.iter_mut().find(|p| !p.done) {
        f(&mut p.outcome);
        p.done = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_frames_parse_back() {
        let f = error_frame("FATAL", "28000", "nope");
        assert_eq!(f[0], b'E');
        let len = u32::from_be_bytes([f[1], f[2], f[3], f[4]]) as usize;
        assert_eq!(len, f.len() - 1);
        let fields = error_fields(&f[5..]);
        assert_eq!(field(&fields, b'C'), Some("28000"));
        assert_eq!(field(&fields, b'M'), Some("nope"));
        assert_eq!(field(&fields, b'S'), Some("FATAL"));
    }

    #[test]
    fn cstr_splitting() {
        assert_eq!(take_cstr(b"abc\0def"), Some((&b"abc"[..], &b"def"[..])));
        assert_eq!(take_cstr(b"abc"), None);
        assert_eq!(take_cstr(b"\0x"), Some((&b""[..], &b"x"[..])));
    }

    #[test]
    fn md5_login_matches_the_postgresql_algorithm() {
        // Computed independently: md5(md5("passwordpostgres") + 01020304).
        assert_eq!(
            md5_password("postgres", "password", [1, 2, 3, 4]),
            "md598511ceaec347a656f032c7f2a16ef17"
        );
    }

    #[test]
    fn frames_have_inclusive_length() {
        assert_eq!(frame(b'Z', b"I"), [b'Z', 0, 0, 0, 5, b'I']);
    }
}

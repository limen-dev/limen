//! `RabbitMQ` and Amazon MQ sessions (design §5.5, ADR-0037). The worker is an
//! AMQP 0-9-1 server toward the user's client and a client toward the broker:
//!
//! pika ──(TLS to proxy, tunnel)── worker ── (TLS, broker user) ── `RabbitMQ`
//!
//! The client authenticates below AMQP (mTLS and the proxy's grant), so what
//! it sends as credentials is accepted and dropped. The worker logs in to the
//! broker itself, to the vhost the client opened if the grant allows it.
//!
//! After that the worker relays frames. Method frames from the client are
//! decoded far enough to check the role's grant and to write the audit event
//! first; content headers and bodies pass through unread (the body size in
//! the header goes into the event). A refused method closes its channel with
//! `403 access-refused`, the broker's own answer to a permission error, and
//! the worker closes the broker's side of that channel itself.

pub mod codec;
pub mod rules;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context as _, bail};
use limen_audit::{Context, Emitter, EventKind};
use limen_policy::{BrokerTarget, MqGrant};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use uuid::Uuid;

use self::codec::{
    Args, BODY, Frame, HEADER, HEARTBEAT, METHOD, PROTOCOL_HEADER, channel_close, channel_close_ok,
    connection_close, connection_open, connection_open_ok, connection_start, connection_start_ok,
    connection_tune, connection_tune_ok, ids, parse_frame,
};
use self::rules::{InspectError, Inspected, Rules};
use crate::broker::{BoxedStream, Credential, Settings};
use crate::ssh::SessionOutcome;

/// The frame size the worker offers the client: `RabbitMQ`'s default.
const FRAME_MAX: u32 = 131_072;
const CHANNEL_MAX: u16 = 2047;
/// The heartbeat the worker proposes, in seconds.
const HEARTBEAT_SECS: u16 = 60;
/// The most a client may take to finish the AMQP handshake.
const HANDSHAKE: Duration = Duration::from_secs(15);
/// How long what is queued for the client gets to go out when the session ends.
const FLUSH_WAIT: Duration = Duration::from_secs(2);
/// A refused channel's number is reusable once the broker has closed it too.
const REUSE_WAIT: Duration = Duration::from_secs(5);
/// More than this waiting for a client that isn't reading ends the session.
const MAX_CLIENT_BACKLOG: usize = 64 * 1024 * 1024;

const ACCESS_REFUSED: u16 = 403;
const NOT_ALLOWED: u16 = 530;
const COMMAND_INVALID: u16 = 503;
const NOT_IMPLEMENTED: u16 = 540;
const INTERNAL_ERROR: u16 = 541;
const UNEXPECTED_FRAME: u16 = 505;
const FRAME_ERROR: u16 = 501;

/// Everything about a session that is known before the first byte.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub session_id: String,
    pub username: String,
    pub mq_user: String,
    pub resource: String,
    pub target: BrokerTarget,
}

/// A session whose grants are loaded and whose broker credential exists.
pub struct Prepared {
    config: SessionConfig,
    rules: Rules,
    credential: Credential,
    settings: Arc<Settings>,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Prepared {
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.config.session_id
    }
}

/// Check that the worker can log in as the broker user. The connection itself
/// is made after the client's `Connection.Open`, which names the vhost.
///
/// # Errors
/// If the worker holds no credential for the broker user.
pub fn prepare(
    settings: &Arc<Settings>,
    grants: Vec<MqGrant>,
    config: SessionConfig,
) -> anyhow::Result<Prepared> {
    let credential = settings
        .credential(&config.resource, &config.mq_user)
        .with_context(|| {
            format!(
                "the worker has no credential for {:?} on {:?} (--broker-credentials-file)",
                config.mq_user, config.resource
            )
        })?
        .clone();
    if credential.password.is_none() {
        bail!(
            "the credential for {:?} on {:?} has no password (RabbitMQ logs in with PLAIN)",
            config.mq_user,
            config.resource
        );
    }
    Ok(Prepared {
        rules: Rules::new(grants),
        config,
        credential,
        settings: Arc::clone(settings),
    })
}

/// Reads frames off a byte stream.
struct FrameReader<R> {
    reader: R,
    buf: Vec<u8>,
    max_payload: usize,
    /// Where reads land; on the heap so futures that hold a reader stay small.
    chunk: Vec<u8>,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    fn new(reader: R, max_payload: usize) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            max_payload,
            chunk: vec![0u8; 16 * 1024],
        }
    }

    /// The next frame, or `None` on a clean end of stream.
    async fn next(&mut self) -> anyhow::Result<Option<Frame>> {
        loop {
            if let Some((frame, used)) = parse_frame(&self.buf, self.max_payload)? {
                self.buf.drain(..used);
                return Ok(Some(frame));
            }
            let n = self.reader.read(&mut self.chunk).await?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                bail!("the connection closed in the middle of a frame");
            }
            self.buf.extend_from_slice(&self.chunk[..n]);
        }
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> anyhow::Result<()> {
    w.write_all(&frame.encode()).await?;
    w.flush().await?;
    Ok(())
}

/// What the client asked for in its handshake.
struct ClientHello {
    /// Bytes read past `Connection.Open`.
    leftover: Vec<u8>,
    vhost: String,
    heartbeat: u16,
    frame_max: u32,
    channel_max: u16,
}

/// Why a client's handshake ended without a session.
enum HandshakeEnd {
    /// The client spoke something else; it has been told what we speak.
    WrongProtocol,
}

async fn expect_method<R: AsyncRead + Unpin>(
    reader: &mut FrameReader<R>,
    class: u16,
    method: u16,
) -> anyhow::Result<Frame> {
    let frame = reader
        .next()
        .await?
        .context("the client closed the connection during the handshake")?;
    match frame.as_method() {
        Some((c, m, _)) if (c, m) == (class, method) && frame.channel == 0 => Ok(frame),
        _ => bail!("unexpected frame during the handshake (wanted {class}.{method})"),
    }
}

/// Play the server's side of the handshake up to `Connection.Open`.
async fn client_handshake<S>(client: &mut S) -> anyhow::Result<Result<ClientHello, HandshakeEnd>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 8];
    client.read_exact(&mut header).await?;
    if header != PROTOCOL_HEADER {
        // The spec: say which protocol we do speak, then close.
        client.write_all(&PROTOCOL_HEADER).await?;
        client.flush().await?;
        return Ok(Err(HandshakeEnd::WrongProtocol));
    }
    write_frame(client, &connection_start()).await?;
    let (mut read, mut write) = tokio::io::split(client);
    let mut frames = FrameReader::new(&mut read, FRAME_MAX as usize);
    // Credentials are discarded: the client is already authenticated below AMQP.
    expect_method(&mut frames, ids::CONNECTION, ids::START_OK).await?;
    write_frame(
        &mut write,
        &connection_tune(CHANNEL_MAX, FRAME_MAX, HEARTBEAT_SECS),
    )
    .await?;
    let tune_ok = expect_method(&mut frames, ids::CONNECTION, ids::TUNE_OK).await?;
    let (_, _, args) = tune_ok.as_method().context("tune-ok")?;
    let mut a = Args::new(args);
    let channel_max = a.u16()?;
    let frame_max = a.u32()?;
    let heartbeat = a.u16()?;
    if frame_max > FRAME_MAX {
        write_frame(
            &mut write,
            &connection_close(
                NOT_ALLOWED,
                "NOT_ALLOWED - frame-max is above what was offered",
                10,
                31,
            ),
        )
        .await?;
        bail!("the client asked for a frame-max above the offer");
    }
    let open = expect_method(&mut frames, ids::CONNECTION, ids::OPEN).await?;
    let (_, _, args) = open.as_method().context("open")?;
    let vhost = Args::new(args).shortstr()?;
    let leftover = std::mem::take(&mut frames.buf);
    Ok(Ok(ClientHello {
        leftover,
        vhost,
        heartbeat: heartbeat.min(3600),
        frame_max: if frame_max == 0 { FRAME_MAX } else { frame_max },
        channel_max: if channel_max == 0 {
            CHANNEL_MAX
        } else {
            channel_max.min(CHANNEL_MAX)
        },
    }))
}

/// A connection to the broker, logged in and opened on a vhost.
struct Upstream {
    reader: FrameReader<tokio::io::ReadHalf<BoxedStream>>,
    writer: tokio::io::WriteHalf<BoxedStream>,
}

#[allow(clippy::too_many_arguments)]
async fn connect_broker(prepared: &Prepared, hello: &ClientHello) -> anyhow::Result<Upstream> {
    let config = &prepared.config;
    let stream = prepared
        .settings
        .dial(
            &config.target.endpoint,
            config.target.tls,
            Some(&prepared.credential),
        )
        .await?;
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = FrameReader::new(read, FRAME_MAX as usize + 1024);
    write.write_all(&PROTOCOL_HEADER).await?;
    write.flush().await?;

    let start = reader
        .next()
        .await?
        .context("the broker closed the connection")?;
    let (class, method, args) = start.as_method().context("expected Connection.Start")?;
    if (class, method) != (ids::CONNECTION, ids::START) {
        bail!("expected Connection.Start, got {class}.{method}");
    }
    let mut a = Args::new(args);
    a.u8()?;
    a.u8()?;
    a.skip_long()?;
    let mechanisms = String::from_utf8_lossy(a.longstr()?).into_owned();
    if !mechanisms.split(' ').any(|m| m == "PLAIN") {
        bail!("the broker offers {mechanisms:?}, not PLAIN");
    }
    let password = prepared
        .credential
        .password
        .as_ref()
        .context("no password")?;
    write_frame(
        &mut write,
        &connection_start_ok(
            &format!("limen:{}", config.session_id),
            &config.mq_user,
            password.expose(),
        ),
    )
    .await?;

    let tune = reader
        .next()
        .await?
        .context("the broker closed the connection after the login")?;
    let Some((class, method, args)) = tune.as_method() else {
        bail!("expected Connection.Tune");
    };
    if (class, method) == (ids::CONNECTION, ids::CLOSE) {
        bail!("the broker refused the login: {}", close_text(args));
    }
    if (class, method) != (ids::CONNECTION, ids::TUNE) {
        bail!("expected Connection.Tune, got {class}.{method}");
    }
    let mut a = Args::new(args);
    let broker_channel_max = a.u16()?;
    let broker_frame_max = a.u32()?;
    if broker_frame_max != 0 && broker_frame_max < hello.frame_max {
        bail!(
            "the broker's frame-max ({broker_frame_max}) is below what the client was offered ({})",
            hello.frame_max
        );
    }
    if broker_channel_max != 0 && broker_channel_max < hello.channel_max {
        bail!(
            "the broker allows fewer channels ({broker_channel_max}) than the client was offered"
        );
    }
    write_frame(
        &mut write,
        &connection_tune_ok(hello.channel_max, hello.frame_max, hello.heartbeat),
    )
    .await?;
    write_frame(&mut write, &connection_open(&hello.vhost)).await?;
    let ok = reader
        .next()
        .await?
        .context("the broker closed the connection while opening the vhost")?;
    match ok.as_method() {
        Some((c, m, _)) if (c, m) == (ids::CONNECTION, ids::OPEN_OK) => {}
        Some((c, m, args)) if (c, m) == (ids::CONNECTION, ids::CLOSE) => {
            bail!("the broker refused the vhost: {}", close_text(args));
        }
        _ => bail!("expected Connection.OpenOk"),
    }
    reader.max_payload = hello.frame_max as usize;
    Ok(Upstream {
        reader,
        writer: write,
    })
}

/// The reply text of a `Connection.Close`.
fn close_text(args: &[u8]) -> String {
    let mut a = Args::new(args);
    match (a.u16(), a.shortstr()) {
        (Ok(code), Ok(text)) => format!("{code} {text}"),
        _ => "unreadable close".to_owned(),
    }
}

/// A channel the worker closed on the client's behalf.
#[derive(Debug, Default, Clone, Copy)]
struct Refused {
    client_closed: bool,
    upstream_closed: bool,
}

struct Shared {
    /// Bytes for the client, written by a task of their own.
    to_client: mpsc::UnboundedSender<Vec<u8>>,
    client_backlog: Arc<AtomicUsize>,
    to_broker: mpsc::Sender<Vec<u8>>,
    refused: std::sync::Mutex<HashMap<u16, Refused>>,
    /// Server-named queues this session created.
    owned: std::sync::Mutex<HashSet<String>>,
    // Totals for `mq.summary` and `session.end`.
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    published: AtomicU64,
    published_bytes: AtomicU64,
    delivered: AtomicU64,
    delivered_bytes: AtomicU64,
    refusals: AtomicU64,
}

impl Shared {
    fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn to_client(&self, bytes: Vec<u8>) -> anyhow::Result<()> {
        let backlog = self.client_backlog.fetch_add(bytes.len(), Ordering::SeqCst) + bytes.len();
        if backlog > MAX_CLIENT_BACKLOG {
            bail!("the client isn't reading");
        }
        self.bytes_out
            .fetch_add(bytes.len() as u64, Ordering::SeqCst);
        self.to_client
            .send(bytes)
            .map_err(|_| anyhow::anyhow!("the client connection closed"))
    }

    async fn to_broker(&self, bytes: Vec<u8>) -> anyhow::Result<()> {
        self.to_broker
            .send(bytes)
            .await
            .map_err(|_| anyhow::anyhow!("the broker connection closed"))
    }

    /// Close `channel` toward the client and, on its own, toward the broker.
    async fn refuse_channel(
        &self,
        channel: u16,
        code: u16,
        text: &str,
        class: u16,
        method: u16,
    ) -> anyhow::Result<()> {
        self.refusals.fetch_add(1, Ordering::SeqCst);
        Self::lock(&self.refused).insert(channel, Refused::default());
        self.to_client(channel_close(channel, code, text, class, method).encode())?;
        self.to_broker(channel_close(channel, 200, "", 0, 0).encode())
            .await
    }

    /// Note that one side finished closing a refused channel; forget the
    /// channel when both have.
    fn mark_closed(&self, channel: u16, from_client: bool) {
        let mut refused = Self::lock(&self.refused);
        if let Some(r) = refused.get_mut(&channel) {
            if from_client {
                r.client_closed = true;
            } else {
                r.upstream_closed = true;
            }
            if r.client_closed && r.upstream_closed {
                refused.remove(&channel);
            }
        }
    }

    fn refused_state(&self, channel: u16) -> Option<Refused> {
        Self::lock(&self.refused).get(&channel).copied()
    }
}

/// Serve `client` until it or the broker goes away.
pub async fn serve<S>(
    mut client: S,
    prepared: Prepared,
    audit: Emitter,
) -> anyhow::Result<SessionOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ctx = Context {
        user: Some(prepared.config.username.clone()),
        session_id: Uuid::parse_str(&prepared.config.session_id).ok(),
    };
    let hello = match tokio::time::timeout(HANDSHAKE, client_handshake(&mut client)).await {
        Err(_) => bail!("the client didn't finish the AMQP handshake in time"),
        Ok(r) => match r? {
            Ok(hello) => hello,
            Err(HandshakeEnd::WrongProtocol) => {
                return Ok(SessionOutcome::default());
            }
        },
    };
    let config = &prepared.config;

    // The vhost is the client's choice; policy decides.
    if !prepared.rules.vhost_allowed(&hello.vhost) {
        let reason = format!("vhost {:?} is not allowed for your role", hello.vhost);
        let _ = audit
            .emit(
                EventKind::AuthDenied,
                ctx.clone(),
                json!({ "action": "mq", "operation": "connect", "resource": config.resource, "mq_user": config.mq_user, "vhost": hello.vhost, "reason": reason }),
            )
            .await;
        write_frame(
            &mut client,
            &connection_close(
                ACCESS_REFUSED,
                &format!("ACCESS_REFUSED - {reason}"),
                10,
                40,
            ),
        )
        .await?;
        return Ok(SessionOutcome::default());
    }
    let connect_event = json!({ "action": "connect", "resource": config.resource, "mq_user": config.mq_user, "vhost": hello.vhost });
    if let Err(e) = audit
        .emit(EventKind::MqOperation, ctx.clone(), connect_event)
        .await
    {
        tracing::error!(error = %e, "audit unavailable; refusing an AMQP connection");
        write_frame(
            &mut client,
            &connection_close(
                INTERNAL_ERROR,
                "INTERNAL_ERROR - audit is unavailable; connection refused",
                10,
                40,
            ),
        )
        .await?;
        return Ok(SessionOutcome::default());
    }
    let upstream = match tokio::time::timeout(HANDSHAKE, connect_broker(&prepared, &hello)).await {
        Ok(Ok(u)) => u,
        Ok(Err(e)) => {
            // The detail names the broker and the account: it stays in the log.
            tracing::warn!(error = %e, resource = %config.resource, "couldn't open the AMQP connection");
            write_frame(
                &mut client,
                &connection_close(INTERNAL_ERROR, "INTERNAL_ERROR - couldn't connect to the broker; ask an admin to check the worker's log", 10, 40),
            )
            .await?;
            return Ok(SessionOutcome::default());
        }
        Err(_) => {
            tracing::warn!(resource = %config.resource, "timed out opening the AMQP connection");
            write_frame(
                &mut client,
                &connection_close(
                    INTERNAL_ERROR,
                    "INTERNAL_ERROR - timed out connecting to the broker",
                    10,
                    40,
                ),
            )
            .await?;
            return Ok(SessionOutcome::default());
        }
    };
    write_frame(&mut client, &connection_open_ok()).await?;
    relay(client, upstream, &prepared, hello, audit, ctx).await
}

#[allow(clippy::too_many_lines)]
async fn relay<S>(
    client: S,
    upstream: Upstream,
    prepared: &Prepared,
    hello: ClientHello,
    audit: Emitter,
    ctx: Context,
) -> anyhow::Result<SessionOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (client_read, mut client_write) = tokio::io::split(client);
    let Upstream {
        reader: broker_reader,
        writer: mut broker_write,
    } = upstream;
    let (to_client, mut for_client) = mpsc::unbounded_channel::<Vec<u8>>();
    let (to_broker, mut for_broker) = mpsc::channel::<Vec<u8>>(256);
    let backlog = Arc::new(AtomicUsize::new(0));
    let shared = Arc::new(Shared {
        to_client,
        client_backlog: Arc::clone(&backlog),
        to_broker,
        refused: std::sync::Mutex::default(),
        owned: std::sync::Mutex::default(),
        bytes_in: AtomicU64::new(0),
        bytes_out: AtomicU64::new(0),
        published: AtomicU64::new(0),
        published_bytes: AtomicU64::new(0),
        delivered: AtomicU64::new(0),
        delivered_bytes: AtomicU64::new(0),
        refusals: AtomicU64::new(0),
    });

    // Each side is written by a task of its own, so a slow client never
    // stops us reading the broker, nor the reverse.
    let client_writer = tokio::spawn(async move {
        while let Some(mut bytes) = for_client.recv().await {
            while bytes.len() < 64 * 1024 {
                match for_client.try_recv() {
                    Ok(more) => bytes.extend_from_slice(&more),
                    Err(_) => break,
                }
            }
            client_write.write_all(&bytes).await?;
            client_write.flush().await?;
            backlog.fetch_sub(bytes.len(), Ordering::SeqCst);
        }
        let _ = client_write.shutdown().await;
        anyhow::Ok(())
    });
    let broker_writer = tokio::spawn(async move {
        while let Some(mut bytes) = for_broker.recv().await {
            while bytes.len() < 64 * 1024 {
                match for_broker.try_recv() {
                    Ok(more) => bytes.extend_from_slice(&more),
                    Err(_) => break,
                }
            }
            broker_write.write_all(&bytes).await?;
            broker_write.flush().await?;
        }
        let _ = broker_write.shutdown().await;
        anyhow::Ok(())
    });
    let idle = (hello.heartbeat > 0).then(|| Duration::from_secs(u64::from(hello.heartbeat) * 3));
    let mut client_frames = FrameReader::new(client_read, hello.frame_max as usize);
    client_frames.buf = hello.leftover;
    let from_client = client_to_broker(
        client_frames,
        Arc::clone(&shared),
        prepared,
        hello.vhost.clone(),
        audit.clone(),
        ctx.clone(),
        idle,
    );
    let from_broker = broker_to_client(broker_reader, Arc::clone(&shared), idle);
    let heartbeats = heartbeat_loop(Arc::clone(&shared), hello.heartbeat);

    tokio::pin!(from_client, from_broker, heartbeats);
    let mut result: anyhow::Result<()> = tokio::select! {
        r = &mut from_client => r,
        r = &mut from_broker => r,
        r = &mut heartbeats => r,
    };
    // Tell the broker the connection is over (it logs an abrupt close
    // otherwise), then let what is queued go out before dropping the sockets.
    let _ = shared
        .to_broker(connection_close(200, "Limen: the session ended", 0, 0).encode())
        .await;
    let config = &prepared.config;
    let summary = json!({
        "resource": config.resource,
        "mq_user": config.mq_user,
        "vhost": hello.vhost,
        "published": shared.published.load(Ordering::SeqCst),
        "published_bytes": shared.published_bytes.load(Ordering::SeqCst),
        "delivered": shared.delivered.load(Ordering::SeqCst),
        "delivered_bytes": shared.delivered_bytes.load(Ordering::SeqCst),
        "refused": shared.refusals.load(Ordering::SeqCst),
        "bytes_in": shared.bytes_in.load(Ordering::SeqCst),
        "bytes_out": shared.bytes_out.load(Ordering::SeqCst),
    });
    let output_bytes = shared.bytes_out.load(Ordering::SeqCst);
    drop(shared);
    let _ = tokio::time::timeout(FLUSH_WAIT, async {
        let _ = client_writer.await;
        let _ = broker_writer.await;
    })
    .await;
    if let Err(e) = audit.emit(EventKind::MqSummary, ctx, summary).await {
        tracing::error!(error = %e, "couldn't write the AMQP session summary");
    }
    // A client or broker that hung up is an ordinary end.
    if let Err(e) = &result {
        tracing::debug!(error = %e, "AMQP session ended");
        if is_hangup(e) {
            result = Ok(());
        }
    }
    result?;
    Ok(SessionOutcome {
        output_bytes,
        ..SessionOutcome::default()
    })
}

fn is_hangup(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>().is_some_and(|io| {
        matches!(
            io.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionAborted
        )
    })
}

/// Both sides get a heartbeat at half the interval; the broker and the client
/// each see a peer that is alive, and each read has its own timeout.
async fn heartbeat_loop(shared: Arc<Shared>, secs: u16) -> anyhow::Result<()> {
    if secs == 0 {
        std::future::pending::<()>().await;
    }
    let mut tick = tokio::time::interval(Duration::from_secs(u64::from(secs.max(2)) / 2));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tick.tick().await;
        let beat = Frame::heartbeat().encode();
        shared.to_client(beat.clone())?;
        shared.to_broker(beat).await?;
    }
}

async fn read_with_idle<R: AsyncRead + Unpin>(
    reader: &mut FrameReader<R>,
    idle: Option<Duration>,
) -> anyhow::Result<Option<Frame>> {
    match idle {
        Some(limit) => tokio::time::timeout(limit, reader.next())
            .await
            .map_err(|_| anyhow::anyhow!("no heartbeat or traffic for {}s", limit.as_secs()))?,
        None => reader.next().await,
    }
}

/// A publish waits for its content header, which tells the size.
struct HeldPublish {
    method: Frame,
    inspected: Inspected,
}

/// One client frame, decided but not yet acted on.
struct Planned {
    /// The event to write before anything is forwarded.
    event: Option<(EventKind, serde_json::Value)>,
    /// What to do once the event is written (or at once, if there is none).
    action: Action,
}

enum Action {
    /// Send these frames to the broker.
    Forward(Vec<Frame>),
    /// Send this frame to the client only.
    ReplyToClient(Frame),
    /// Refuse the channel (a denial, or an event that couldn't be written).
    Refuse {
        channel: u16,
        code: u16,
        text: String,
        class: u16,
        method: u16,
    },
    /// The client has closed a channel the worker refused.
    MarkClientClosed(u16),
    /// A client reopens a channel whose broker side is still closing.
    ForwardWhenFree(u16, Frame),
    /// End the session after telling the client why.
    Fail(u16, String),
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn client_to_broker<R>(
    mut reader: FrameReader<R>,
    shared: Arc<Shared>,
    prepared: &Prepared,
    vhost: String,
    audit: Emitter,
    ctx: Context,
    idle: Option<Duration>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let config = &prepared.config;
    let mut held: HashMap<u16, HeldPublish> = HashMap::new();
    loop {
        let first = match read_with_idle(&mut reader, idle).await {
            Ok(Some(f)) => f,
            Ok(None) => return Ok(()),
            Err(e) => {
                if let Some(fe) = e.downcast_ref::<codec::FrameError>() {
                    let _ = shared.to_client(
                        connection_close(FRAME_ERROR, &format!("FRAME_ERROR - {fe}"), 0, 0)
                            .encode(),
                    );
                }
                return Err(e);
            }
        };
        // Everything already buffered is planned together, so one group
        // commit covers a burst of publishes.
        let mut frames = vec![first];
        while let Some((f, used)) = codec::parse_frame(&reader.buf, reader.max_payload)? {
            reader.buf.drain(..used);
            frames.push(f);
        }
        let mut plan: Vec<Planned> = Vec::with_capacity(frames.len());
        // Channels refused earlier in this batch: their effect is applied
        // after planning, but the frames that follow them are already here.
        let mut local: HashMap<u16, Refused> = HashMap::new();
        for frame in frames {
            shared
                .bytes_in
                .fetch_add(frame.payload.len() as u64 + 8, Ordering::SeqCst);
            plan_frame(
                frame, &shared, prepared, &vhost, &mut held, &mut local, &mut plan,
            );
        }
        let written = futures::future::join_all(plan.iter().map(|p| async {
            match &p.event {
                Some((kind, data)) => audit
                    .emit(*kind, ctx.clone(), data.clone())
                    .await
                    .map(|_| ()),
                None => Ok(()),
            }
        }))
        .await;
        for (planned, written) in plan.into_iter().zip(written) {
            apply(&shared, config, planned, written.is_ok()).await?;
        }
    }
}

/// The state of a channel the worker closed, counting refusals planned in the
/// same batch and not yet applied.
fn effective(shared: &Shared, local: &HashMap<u16, Refused>, channel: u16) -> Option<Refused> {
    local
        .get(&channel)
        .copied()
        .or_else(|| shared.refused_state(channel))
}

/// Decide what one client frame means.
/// Channel 0 and the content frames are
/// handled here; method frames go to the rules.
#[allow(clippy::too_many_lines)]
fn plan_frame(
    frame: Frame,
    shared: &Shared,
    prepared: &Prepared,
    vhost: &str,
    held: &mut HashMap<u16, HeldPublish>,
    local: &mut HashMap<u16, Refused>,
    plan: &mut Vec<Planned>,
) {
    let config = &prepared.config;
    let channel = frame.channel;
    let push = |plan: &mut Vec<Planned>, action: Action| {
        plan.push(Planned {
            event: None,
            action,
        });
    };
    match frame.kind {
        METHOD if channel == 0 => match frame.as_method() {
            Some((ids::CONNECTION, ids::CLOSE | ids::CLOSE_OK, _)) => {
                push(plan, Action::Forward(vec![frame]));
            }
            _ => push(
                plan,
                Action::Fail(
                    COMMAND_INVALID,
                    "COMMAND_INVALID - not allowed on this connection".into(),
                ),
            ),
        },
        METHOD => {
            // A channel the worker closed: answer its close, drop the rest.
            if let Some(state) = effective(shared, local, channel) {
                match frame.as_method() {
                    Some((ids::CHANNEL, ids::CHANNEL_CLOSE, _)) => {
                        push(plan, Action::ReplyToClient(channel_close_ok(channel)));
                        push(plan, Action::MarkClientClosed(channel));
                        local.entry(channel).or_insert(state).client_closed = true;
                    }
                    Some((ids::CHANNEL, ids::CHANNEL_CLOSE_OK, _)) => {
                        push(plan, Action::MarkClientClosed(channel));
                        local.entry(channel).or_insert(state).client_closed = true;
                    }
                    Some((ids::CHANNEL, ids::CHANNEL_OPEN, _)) if state.client_closed => {
                        push(plan, Action::ForwardWhenFree(channel, frame));
                    }
                    _ => {}
                }
                held.remove(&channel);
                return;
            }
            if held.contains_key(&channel) {
                push(
                    plan,
                    Action::Fail(
                        UNEXPECTED_FRAME,
                        "UNEXPECTED_FRAME - expected a content header".into(),
                    ),
                );
                return;
            }
            let Some((class, method, args)) = frame.as_method() else {
                push(
                    plan,
                    Action::Fail(FRAME_ERROR, "FRAME_ERROR - short method frame".into()),
                );
                return;
            };
            let inspected = match rules::inspect(class, method, args) {
                Ok(i) => i,
                Err(InspectError::Malformed) => {
                    push(
                        plan,
                        Action::Fail(FRAME_ERROR, "FRAME_ERROR - malformed method".into()),
                    );
                    return;
                }
                Err(InspectError::Unsupported) => {
                    local.insert(channel, Refused::default());
                    let reason = format!("method {class}.{method} is not supported through Limen");
                    let insp = Inspected {
                        action: "unsupported",
                        ..Inspected::default()
                    };
                    plan.push(Planned {
                        event: Some((
                            EventKind::AuthDenied,
                            rules::denied_data(
                                &insp,
                                &config.resource,
                                &config.mq_user,
                                vhost,
                                channel,
                                &reason,
                            ),
                        )),
                        action: Action::Refuse {
                            channel,
                            code: NOT_IMPLEMENTED,
                            text: format!("NOT_IMPLEMENTED - {reason}"),
                            class,
                            method,
                        },
                    });
                    return;
                }
            };
            let owned = Shared::lock(&shared.owned).clone();
            match prepared.rules.check(vhost, &inspected, &owned) {
                Err(reason) => {
                    local.insert(channel, Refused::default());
                    plan.push(Planned {
                        event: Some((
                            EventKind::AuthDenied,
                            rules::denied_data(
                                &inspected,
                                &config.resource,
                                &config.mq_user,
                                vhost,
                                channel,
                                &reason,
                            ),
                        )),
                        action: Action::Refuse {
                            channel,
                            code: ACCESS_REFUSED,
                            text: format!("ACCESS_REFUSED - {reason}"),
                            class,
                            method,
                        },
                    });
                }
                Ok(()) if inspected.publish => {
                    held.insert(
                        channel,
                        HeldPublish {
                            method: frame,
                            inspected,
                        },
                    );
                }
                Ok(()) => plan.push(Planned {
                    event: inspected.audited.then(|| {
                        (
                            EventKind::MqOperation,
                            rules::audit_data(
                                &inspected,
                                &config.resource,
                                &config.mq_user,
                                vhost,
                                channel,
                                None,
                            ),
                        )
                    }),
                    action: Action::Forward(vec![frame]),
                }),
            }
        }
        HEADER => {
            if effective(shared, local, channel).is_some() {
                held.remove(&channel);
                return;
            }
            match held.remove(&channel) {
                Some(HeldPublish { method, inspected }) => {
                    let size = frame.body_size().unwrap_or(0);
                    shared.published.fetch_add(1, Ordering::SeqCst);
                    shared.published_bytes.fetch_add(size, Ordering::SeqCst);
                    plan.push(Planned {
                        event: Some((
                            EventKind::MqOperation,
                            rules::audit_data(
                                &inspected,
                                &config.resource,
                                &config.mq_user,
                                vhost,
                                channel,
                                Some(size),
                            ),
                        )),
                        action: Action::Forward(vec![method, frame]),
                    });
                }
                None => push(
                    plan,
                    Action::Fail(
                        UNEXPECTED_FRAME,
                        "UNEXPECTED_FRAME - content header without a publish".into(),
                    ),
                ),
            }
        }
        BODY if effective(shared, local, channel).is_none() => {
            push(plan, Action::Forward(vec![frame]));
        }
        // Heartbeats, and body frames of a channel the worker closed.
        _ => {}
    }
}

async fn apply(
    shared: &Shared,
    config: &SessionConfig,
    planned: Planned,
    audited: bool,
) -> anyhow::Result<()> {
    let Planned { event, action } = planned;
    let audit_failed = event.is_some() && !audited;
    match action {
        Action::Forward(frames) => {
            // A channel closed since this was planned (an audit failure
            // earlier in the batch) takes no more traffic.
            let channel = frames.first().map_or(0, |f| f.channel);
            if channel != 0 && shared.refused_state(channel).is_some() {
                return Ok(());
            }
            if audit_failed {
                // Fail closed: what can't be audited doesn't run.
                tracing::error!(resource = %config.resource, session = %config.session_id, "audit unavailable; refusing an AMQP operation");
                metrics::counter!("limen_broker_audit_failures_total", "protocol" => "amqp")
                    .increment(1);
                let (class, method) = frames
                    .first()
                    .and_then(Frame::as_method)
                    .map_or((0, 0), |(c, m, _)| (c, m));
                return shared
                    .refuse_channel(
                        channel,
                        INTERNAL_ERROR,
                        "INTERNAL_ERROR - audit is unavailable; operation refused",
                        class,
                        method,
                    )
                    .await;
            }
            for frame in frames {
                shared.to_broker(frame.encode()).await?;
            }
            Ok(())
        }
        Action::ReplyToClient(frame) => shared.to_client(frame.encode()),
        Action::MarkClientClosed(channel) => {
            shared.mark_closed(channel, true);
            Ok(())
        }
        Action::Refuse {
            channel,
            code,
            text,
            class,
            method,
        } => {
            metrics::counter!("limen_broker_refused_total", "protocol" => "amqp").increment(1);
            if audit_failed {
                // A denial that can't be audited is still a denial.
                tracing::error!(resource = %config.resource, session = %config.session_id, "failed to audit a denied AMQP operation");
            }
            shared
                .refuse_channel(channel, code, &text, class, method)
                .await
        }
        Action::ForwardWhenFree(channel, frame) => {
            let deadline = tokio::time::Instant::now() + REUSE_WAIT;
            while shared.refused_state(channel).is_some() {
                if tokio::time::Instant::now() >= deadline {
                    let _ = shared.to_client(
                        connection_close(
                            INTERNAL_ERROR,
                            "INTERNAL_ERROR - the channel is still closing",
                            20,
                            10,
                        )
                        .encode(),
                    );
                    bail!("a refused channel was not released by the broker in time");
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            shared.to_broker(frame.encode()).await
        }
        Action::Fail(code, text) => {
            let _ = shared.to_client(connection_close(code, &text, 0, 0).encode());
            bail!("{text}")
        }
    }
}

async fn broker_to_client<R>(
    mut reader: FrameReader<R>,
    shared: Arc<Shared>,
    idle: Option<Duration>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let Some(frame) = read_with_idle(&mut reader, idle).await? else {
            return Ok(());
        };
        let channel = frame.channel;
        if frame.kind == HEARTBEAT {
            continue;
        }
        if channel != 0 && shared.refused_state(channel).is_some() {
            // The channel is closed toward the client; finish closing it with the broker.
            match frame.as_method() {
                Some((ids::CHANNEL, ids::CHANNEL_CLOSE_OK, _)) => {
                    shared.mark_closed(channel, false);
                }
                Some((ids::CHANNEL, ids::CHANNEL_CLOSE, _)) => {
                    shared.to_broker(channel_close_ok(channel).encode()).await?;
                    shared.mark_closed(channel, false);
                }
                _ => {}
            }
            continue;
        }
        match frame.kind {
            METHOD => match frame.as_method() {
                Some((ids::BASIC, ids::BASIC_DELIVER | ids::BASIC_GET_OK, _)) => {
                    shared.delivered.fetch_add(1, Ordering::SeqCst);
                }
                Some((ids::QUEUE, ids::QUEUE_DECLARE_OK, args)) => {
                    // A queue the broker named for this session is the session's.
                    if let Ok(name) = Args::new(args).shortstr()
                        && name.starts_with("amq.gen-")
                    {
                        Shared::lock(&shared.owned).insert(name);
                    }
                }
                Some((ids::CONNECTION, ids::CLOSE, _)) => {
                    // The broker is closing the connection; the client's
                    // CloseOk goes back to it, and the session ends with it.
                    shared.to_client(frame.encode())?;
                    return Ok(());
                }
                _ => {}
            },
            BODY => {
                shared
                    .delivered_bytes
                    .fetch_add(frame.payload.len() as u64, Ordering::SeqCst);
            }
            _ => {}
        }
        shared.to_client(frame.encode())?;
    }
}

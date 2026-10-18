//! Redis and Valkey sessions (design §5.3, ADR-0034). The worker is a Redis
//! server toward the user's client and a Redis client toward the target:
//!
//! redis-cli ──(TLS to proxy, tunnel)── worker ── (TLS, ACL user) ── Redis
//!
//! The client authenticates below Redis (mTLS and the proxy's grant), so its
//! own `AUTH` is accepted and dropped. The worker logs in to the target
//! itself. Every command is checked against the role's grant and audited
//! before it is forwarded; bytes of allowed commands and of every reply go
//! through untouched.
//!
//! Replies must stay in order with the commands that earned them, and the
//! worker answers some commands itself (a denial, `AUTH`). So a queue of
//! what was sent records, per command, whether the target will reply or the
//! worker already has.

pub mod codec;
pub mod rules;
pub mod target;

#[cfg(test)]
mod tests;

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::bail;
use limen_audit::{Context, Emitter, EventKind};
use limen_policy::{RedisGrant, RedisTarget};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

use self::codec::{
    Command, FrameKind, FrameScanner, RequestScanner, encode_command, error_reply, frame_kind,
    is_error, parse_command,
};
use self::rules::{KeySpecs, Rules};
use self::target::{BoxedStream, Settings};
use crate::ssh::SessionOutcome;

/// The most a single request or reply may take in memory.
const MAX_FRAME: usize = 256 * 1024 * 1024;
/// Queued commands are joined into one write up to about this size.
const COALESCE: usize = 64 * 1024;
/// How long a client that closed its writing side waits for outstanding replies.
/// How long what is already queued for a client gets to go out after an error.
const ERROR_FLUSH_WAIT: Duration = Duration::from_secs(2);
const HALF_CLOSE_WAIT: Duration = Duration::from_secs(10);
/// ElastiCache drops an IAM connection after 12 hours unless it is re-authenticated.
const REAUTH_AFTER: Duration = Duration::from_hours(11);
/// Past this, a connection that couldn't re-authenticate ends.
const REAUTH_DEADLINE: Duration = Duration::from_mins(11 * 60 + 55);
const REAUTH_RETRY: Duration = Duration::from_secs(5);

/// After one of these the connection is a Pub/Sub stream: the server's
/// frames are no longer one reply per command, so they are passed through.
const SUBSCRIBE: &[&str] = &[
    "SUBSCRIBE",
    "PSUBSCRIBE",
    "SSUBSCRIBE",
    "UNSUBSCRIBE",
    "PUNSUBSCRIBE",
    "SUNSUBSCRIBE",
];

/// Everything about a session that is known before the first command.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub session_id: String,
    pub username: String,
    pub redis_user: String,
    pub resource: String,
    pub target: RedisTarget,
    /// When to log in to the target again (IAM only). A field so tests can shorten it.
    pub reauth_after: Duration,
    pub reauth_deadline: Duration,
}

/// A session whose target connection is open and logged in.
pub struct Prepared {
    config: SessionConfig,
    stream: BoxedStream,
    rules: Rules,
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

/// Connect to the target and learn its command table. Failing here means the
/// proxy gets a clean refusal instead of a session that dies at once.
pub async fn prepare(
    settings: &Settings,
    grants: Vec<RedisGrant>,
    config: SessionConfig,
) -> anyhow::Result<Prepared> {
    let connected = target::connect(
        settings,
        &config.resource,
        &config.target,
        &config.redis_user,
        &config.session_id,
    )
    .await?;
    let specs = KeySpecs::from_command_info(&connected.command_info)
        .map_err(|e| anyhow::anyhow!("reading the target's command table: {e}"))?;
    Ok(Prepared {
        config,
        stream: connected.stream,
        rules: Rules::new(grants, specs),
    })
}

/// What the worker has to do when the target replies.
#[derive(Debug)]
enum Pending {
    /// A command the target will answer; pass its reply on.
    Forwarded,
    /// The worker's own reply, to send once everything before it has answered.
    Local(Vec<u8>),
    /// The worker's own request to the target (re-login): swallow the reply.
    /// An error reply means the login failed, and ends the session.
    Internal,
    /// The worker's own request whose reply, error or not, is dropped.
    Swallow,
}

/// The order replies must go to the client in.
struct Out {
    queue: VecDeque<Pending>,
}

/// More than this waiting for a client that isn't reading ends the session
/// (the server's own output-buffer limit plays the same part).
const MAX_CLIENT_BACKLOG: usize = 512 * 1024 * 1024;

struct Shared {
    /// Only ever held briefly, never across an await.
    out: std::sync::Mutex<Out>,
    /// Bytes for the client, written by a task of their own: a client that
    /// sends a long pipeline before reading must not stop us reading it.
    to_client: mpsc::UnboundedSender<Vec<u8>>,
    /// Bytes handed to `to_client` and not yet written.
    client_backlog: AtomicUsize,
    /// Held while queueing a request and handing it to the target writer, so
    /// the queue and the wire never disagree about order.
    order: Mutex<()>,
    to_target: mpsc::Sender<Vec<u8>>,
    subscribed: AtomicBool,
    in_multi: AtomicBool,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl Shared {
    fn out(&self) -> std::sync::MutexGuard<'_, Out> {
        self.out
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn send_to_client(&self, bytes: Vec<u8>) -> anyhow::Result<()> {
        let backlog = self.client_backlog.fetch_add(bytes.len(), Ordering::SeqCst) + bytes.len();
        if backlog > MAX_CLIENT_BACKLOG {
            bail!("the client isn't reading its replies");
        }
        self.to_client
            .send(bytes)
            .map_err(|_| anyhow::anyhow!("the client connection closed"))
    }

    /// Send every worker-made reply that is next in line.
    fn flush_local(&self, out: &mut Out) -> anyhow::Result<()> {
        while let Some(Pending::Local(_)) = out.queue.front() {
            if let Some(Pending::Local(bytes)) = out.queue.pop_front() {
                self.send_to_client(bytes)?;
            }
        }
        Ok(())
    }
}

impl Shared {
    async fn forward(&self, bytes: Vec<u8>) -> anyhow::Result<()> {
        let _order = self.order.lock().await;
        if !self.subscribed.load(Ordering::SeqCst) {
            self.out().queue.push_back(Pending::Forwarded);
        }
        self.to_target
            .send(bytes)
            .await
            .map_err(|_| anyhow::anyhow!("the Redis connection closed"))
    }

    /// Hand a `SUBSCRIBE` to the target. First every reply owed for earlier
    /// commands is delivered, so none is left waiting behind frames that are
    /// no longer matched to commands; from then on nothing is queued.
    async fn forward_subscribe(&self, bytes: Vec<u8>) -> anyhow::Result<()> {
        loop {
            {
                let _order = self.order.lock().await;
                if self.out().queue.is_empty() {
                    self.subscribed.store(true, Ordering::SeqCst);
                    return self
                        .to_target
                        .send(bytes)
                        .await
                        .map_err(|_| anyhow::anyhow!("the Redis connection closed"));
                }
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    fn reply_locally(&self, bytes: Vec<u8>) -> anyhow::Result<()> {
        let mut out = self.out();
        if self.subscribed.load(Ordering::SeqCst) {
            // Replies are no longer matched to commands, so there is no place
            // in line to wait for.
            return self.send_to_client(bytes);
        }
        out.queue.push_back(Pending::Local(bytes));
        self.flush_local(&mut out)
    }

    /// Make the target treat the open `MULTI` as failed, so `EXEC` answers
    /// `EXECABORT` instead of running the commands that weren't refused.
    async fn poison_transaction(&self) -> anyhow::Result<()> {
        let _order = self.order.lock().await;
        self.out().queue.push_back(Pending::Swallow);
        self.to_target
            .send(encode_command(&[b"LIMEN.REFUSED".as_slice()]))
            .await
            .map_err(|_| anyhow::anyhow!("the Redis connection closed"))
    }
}

/// Serve `client` until it or the target goes away.
pub async fn serve<S>(
    client: S,
    prepared: Prepared,
    audit: Emitter,
) -> anyhow::Result<SessionOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Prepared {
        config,
        stream,
        rules,
    } = prepared;
    let (client_read, mut client_write) = tokio::io::split(client);
    let (target_read, mut target_write) = tokio::io::split(stream);
    let (to_target, mut from_client) = mpsc::channel::<Vec<u8>>(32);
    let (to_client, mut for_client) = mpsc::unbounded_channel::<Vec<u8>>();
    let shared = Arc::new(Shared {
        out: std::sync::Mutex::new(Out {
            queue: VecDeque::new(),
        }),
        to_client,
        client_backlog: AtomicUsize::new(0),
        order: Mutex::new(()),
        to_target,
        subscribed: AtomicBool::new(false),
        in_multi: AtomicBool::new(false),
        bytes_in: AtomicU64::new(0),
        bytes_out: AtomicU64::new(0),
    });

    let writer = async {
        while let Some(mut bytes) = from_client.recv().await {
            // A pipeline queues many small commands: send them in one write.
            while bytes.len() < COALESCE {
                match from_client.try_recv() {
                    Ok(more) => bytes.extend_from_slice(&more),
                    Err(_) => break,
                }
            }
            target_write.write_all(&bytes).await?;
            target_write.flush().await?;
        }
        anyhow::Ok(())
    };
    let to_client_task = async {
        while let Some(mut bytes) = for_client.recv().await {
            // Replies that piled up go out in one write.
            while bytes.len() < COALESCE {
                match for_client.try_recv() {
                    Ok(more) => bytes.extend_from_slice(&more),
                    Err(_) => break,
                }
            }
            client_write.write_all(&bytes).await?;
            client_write.flush().await?;
            shared
                .client_backlog
                .fetch_sub(bytes.len(), Ordering::SeqCst);
        }
        anyhow::Ok(())
    };
    let requests = client_to_target(
        client_read,
        Arc::clone(&shared),
        &rules,
        &config,
        audit.clone(),
    );
    let replies = target_to_client(target_read, Arc::clone(&shared));
    let reauth = reauth_loop(Arc::clone(&shared), &config);

    tokio::pin!(requests, replies, writer, reauth, to_client_task);
    let mut requests_ended_first = false;
    let mut client_write_failed = false;
    let mut result = tokio::select! {
        r = &mut requests => { requests_ended_first = true; r },
        r = &mut replies => r,
        r = &mut writer => r,
        r = &mut reauth => r,
        r = &mut to_client_task => { client_write_failed = true; r },
    };
    // Replies already owed still go out: to a client that sent its commands
    // and closed its writing side, and after the target hung up. (Done when
    // the queue is empty, if the target is still there, and nothing waits to
    // be written.)
    if !client_write_failed {
        // After an error, only what is already queued for the client (such as
        // the error that explains it) gets a moment to go out.
        let wait = if result.is_ok() {
            HALF_CLOSE_WAIT
        } else {
            ERROR_FLUSH_WAIT
        };
        let target_is_gone = !requests_ended_first || result.is_err();
        let owed_replies_arrive = async {
            loop {
                let queued = !target_is_gone && !shared.out().queue.is_empty();
                if !queued && shared.client_backlog.load(Ordering::SeqCst) == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::select! {
            () = owed_replies_arrive => {}
            r = &mut replies, if !target_is_gone => result = r,
            r = &mut writer, if result.is_ok() => result = r,
            r = &mut to_client_task => { if result.is_ok() { result = r; } }
            () = tokio::time::sleep(wait) => {}
        }
    }
    // The target connection and the client's half close when these drop.
    let bytes_out = shared.bytes_out.load(Ordering::SeqCst);
    if let Err(e) = result {
        tracing::debug!(session = %config.session_id, error = %e, "Redis session ended with error");
        return Err(e);
    }
    Ok(SessionOutcome {
        output_bytes: bytes_out,
        ..SessionOutcome::default()
    })
}

async fn client_to_target<R>(
    mut reader: R,
    shared: Arc<Shared>,
    rules: &Rules,
    config: &SessionConfig,
    audit: Emitter,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let ctx = Context {
        user: Some(config.username.clone()),
        session_id: Uuid::parse_str(&config.session_id).ok(),
    };
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 32 * 1024];
    let mut scanner = RequestScanner::new();
    // The database the connection has selected, as far as policy allowed it.
    let mut db = 0u32;
    loop {
        // Everything already read may hold many pipelined commands. Plan them
        // all, write their audit events together (the spool's group commit
        // makes that one fsync, not one per command), then act in order.
        let mut batch: Vec<Planned> = Vec::new();
        let mut bad_request: Option<String> = None;
        // Frames are taken by offset and the buffer is trimmed once, not
        // shifted after every command.
        let mut start = 0;
        loop {
            let found = match scanner.advance(&buf[start..]) {
                Ok(found) => found,
                Err(e) => {
                    bad_request = Some(e.to_string());
                    break;
                }
            };
            let Some(len) = found else { break };
            let frame = buf[start..start + len].to_vec();
            start += len;
            scanner = RequestScanner::new();
            shared.bytes_in.fetch_add(len as u64, Ordering::SeqCst);
            match parse_command(&frame) {
                Ok(command) => {
                    if let Some(planned) = plan(rules, config, frame, command, &mut db) {
                        batch.push(planned);
                    }
                }
                Err(e) => {
                    bad_request = Some(e.to_string());
                    break;
                }
            }
        }
        buf.drain(..start);
        let written = futures::future::join_all(
            batch
                .iter()
                .map(|p| audit.emit(p.event.0, ctx.clone(), p.event.1.clone())),
        )
        .await;
        for (planned, written) in batch.into_iter().zip(written) {
            apply(&shared, planned, written.is_ok()).await?;
        }
        if let Some(why) = bad_request {
            let _ = shared.reply_locally(error_reply(&format!("ERR {why}")));
            bail!("{why}");
        }
        if buf.len() > MAX_FRAME {
            let _ = shared.reply_locally(error_reply("ERR request too large"));
            bail!("request too large");
        }
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// One request, checked and ready to act on once its audit event is written.
struct Planned {
    frame: Vec<u8>,
    args: Vec<Vec<u8>>,
    name: String,
    sub: Option<String>,
    /// `Some(reason)` if policy refuses it.
    refused: Option<String>,
    /// The event to write first: `redis.command`, or `auth.denied` if refused.
    event: (EventKind, serde_json::Value),
}

fn plan(
    rules: &Rules,
    config: &SessionConfig,
    frame: Vec<u8>,
    command: Command,
    db: &mut u32,
) -> Option<Planned> {
    let Command { args } = command;
    if args.is_empty() {
        return None; // a blank line
    }
    let insp = rules.inspect(&args);
    let refused = rules.check(&args, &insp, *db).err();
    if refused.is_none()
        && insp.name == "SELECT"
        && let Some(selected) = rules::selected_database(&args)
    {
        *db = selected;
    }
    let event = match &refused {
        Some(reason) => (
            EventKind::AuthDenied,
            json!({
                "action": "redis",
                "resource": config.resource,
                "redis_user": config.redis_user,
                "command": insp.name,
                "subcommand": insp.sub,
                "reason": reason,
            }),
        ),
        None => (
            EventKind::RedisCommand,
            Rules::audit_data(
                &insp,
                &args,
                &config.target.audit,
                &config.resource,
                &config.redis_user,
            ),
        ),
    };
    Some(Planned {
        frame,
        args,
        name: insp.name,
        sub: insp.sub,
        refused,
        event,
    })
}

async fn apply(shared: &Shared, planned: Planned, audited: bool) -> anyhow::Result<()> {
    let Planned {
        frame,
        args,
        name,
        sub,
        refused,
        ..
    } = planned;
    if let Some(reason) = refused {
        // A denial that can't be audited is still a denial.
        if !audited {
            tracing::error!("failed to audit a denied command");
        }
        shared.reply_locally(error_reply(&format!("NOPERM Limen: {reason}")))?;
        if shared.in_multi.load(Ordering::SeqCst) {
            shared.poison_transaction().await?;
        }
        return Ok(());
    }
    if !audited {
        // Fail closed: a command we can't audit doesn't run.
        tracing::error!("audit unavailable; refusing a Redis command");
        shared.reply_locally(error_reply(
            "ERR Limen: audit is unavailable; command refused",
        ))?;
        if shared.in_multi.load(Ordering::SeqCst) {
            shared.poison_transaction().await?;
        }
        return Ok(());
    }
    match (name.as_str(), sub.as_deref()) {
        // The client is already authenticated below Redis. The worker's own
        // login to the target stays; it must never see the client's.
        ("AUTH", _) => shared.reply_locally(codec::OK.to_vec())?,
        ("CLIENT", Some("SETNAME")) => {
            shared.reply_locally(codec::OK.to_vec())?;
        }
        ("HELLO", _) => {
            // Keep the protocol version; drop AUTH and SETNAME.
            let version: Vec<&[u8]> = args.iter().skip(1).take(1).map(Vec::as_slice).collect();
            let mut hello: Vec<&[u8]> = vec![b"HELLO"];
            hello.extend(version);
            shared.forward(encode_command(&hello)).await?;
        }
        (name, _) => {
            match name {
                "MULTI" => shared.in_multi.store(true, Ordering::SeqCst),
                "EXEC" | "DISCARD" => shared.in_multi.store(false, Ordering::SeqCst),
                _ => {}
            }
            // Inline commands are sent as the arrays the server prefers.
            let bytes = if frame.first() == Some(&b'*') {
                frame
            } else {
                encode_command(&args)
            };
            if SUBSCRIBE.contains(&name) {
                shared.forward_subscribe(bytes).await?;
            } else {
                shared.forward(bytes).await?;
            }
        }
    }
    Ok(())
}

async fn target_to_client<R>(mut reader: R, shared: Arc<Shared>) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 32 * 1024];
    let mut scanner = FrameScanner::new();
    loop {
        let mut start = 0;
        while let Some(len) = scanner.advance(&buf[start..])? {
            let frame = &buf[start..start + len];
            start += len;
            scanner = FrameScanner::new();
            shared.bytes_out.fetch_add(len as u64, Ordering::SeqCst);
            // Nothing in this block waits, so the order of the queue and the
            // order of the bytes for the client can't come apart.
            let mut out = shared.out();
            if frame_kind(frame) == FrameKind::Reply && !shared.subscribed.load(Ordering::SeqCst) {
                shared.flush_local(&mut out)?;
                match out.queue.pop_front() {
                    Some(Pending::Internal) => {
                        if is_error(frame) {
                            bail!("the Redis server refused the worker's re-login");
                        }
                        shared.flush_local(&mut out)?;
                        continue;
                    }
                    Some(Pending::Swallow) => {
                        shared.flush_local(&mut out)?;
                        continue;
                    }
                    // A reply nobody asked for: pass it on rather than guess.
                    Some(Pending::Forwarded) | None => {}
                    Some(Pending::Local(_)) => unreachable!("flushed above"),
                }
            }
            shared.send_to_client(frame.to_vec())?;
            shared.flush_local(&mut out)?;
        }
        buf.drain(..start);
        if buf.len() > MAX_FRAME {
            bail!("the Redis server's reply was too large");
        }
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Log in to the target again before an IAM connection hits its 12-hour limit.
/// Never inside `MULTI`, a subscription, or while commands are in flight.
async fn reauth_loop(shared: Arc<Shared>, config: &SessionConfig) -> anyhow::Result<()> {
    if !config.target.iam_auth {
        return std::future::pending().await;
    }
    tokio::time::sleep(config.reauth_after).await;
    let started = tokio::time::Instant::now();
    loop {
        let token = match target::iam_token(&config.target, &config.redis_user).await {
            Ok(token) => token,
            Err(e) => {
                // A passing credential error (the metadata service, say)
                // shouldn't end the session while there is time to retry.
                if started.elapsed() > config.reauth_deadline.saturating_sub(config.reauth_after) {
                    return Err(e);
                }
                tracing::warn!(session = %config.session_id, error = %e, "couldn't sign an IAM token; will retry");
                tokio::time::sleep(REAUTH_RETRY).await;
                continue;
            }
        };
        let sent = {
            let _order = shared.order.lock().await;
            let ready = {
                let mut out = shared.out();
                let ready = out.queue.is_empty()
                    && !shared.in_multi.load(Ordering::SeqCst)
                    && !shared.subscribed.load(Ordering::SeqCst);
                if ready {
                    out.queue.push_back(Pending::Internal);
                }
                ready
            };
            if ready {
                let auth = encode_command(&[
                    b"AUTH".as_slice(),
                    config.redis_user.as_bytes(),
                    token.expose().as_bytes(),
                ]);
                shared
                    .to_target
                    .send(auth)
                    .await
                    .map_err(|_| anyhow::anyhow!("the Redis connection closed"))?;
                true
            } else {
                false
            }
        };
        if sent {
            tracing::info!(session = %config.session_id, "re-authenticated to the Redis server");
            // Done until the next window.
            tokio::time::sleep(config.reauth_after).await;
            continue;
        }
        if started.elapsed() > config.reauth_deadline.saturating_sub(config.reauth_after) {
            bail!("credential_expired: couldn't re-authenticate before the server's limit");
        }
        tokio::time::sleep(REAUTH_RETRY).await;
    }
}

impl SessionConfig {
    #[must_use]
    pub fn new(
        session_id: String,
        username: String,
        redis_user: String,
        resource: String,
        target: RedisTarget,
    ) -> Self {
        Self {
            session_id,
            username,
            redis_user,
            resource,
            target,
            reauth_after: REAUTH_AFTER,
            reauth_deadline: REAUTH_DEADLINE,
        }
    }
}

//! Kafka and Amazon MSK sessions (design §5.6, ADR-0037). The worker is a Kafka
//! broker toward the user's client and a Kafka client toward the cluster:
//!
//! kcat ──(loopback, TLS to proxy, tunnel)── worker ── (TLS, SASL) ── broker
//!
//! A Kafka client talks to every broker, at the addresses `Metadata` and
//! `FindCoordinator` give it. The CLI opens one loopback listener per broker
//! slot; the worker rewrites those addresses to the listeners' ports, and a
//! session on slot *n* talks to the broker of rank *n* (node IDs sorted).
//!
//! Every request is read as far as policy needs (topics, group), checked, and
//! audited before it is forwarded. A request that names topics the role
//! doesn't reach is cut down to the ones it does, and the answer for the
//! rest is added to the broker's response, as the broker's own ACLs would
//! answer. Responses come back in request order, so the worker queues what it
//! owes: either the broker's response (perhaps rewritten) or its own.

pub mod auth;
pub mod proto;
pub mod rules;
pub mod upstream;
pub mod wire;

#[cfg(test)]
mod tests;

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use limen_audit::{Context, Emitter, EventKind};
use limen_core::broker::KafkaSlot;
use limen_policy::{BrokerTarget, KafkaClass, KafkaGrant, KafkaSasl};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use uuid::Uuid;

use self::proto::{
    Broker, CoordinatorResponse, MetadataResponse, MetadataTopic, OffsetFetchResponse, Parsed,
    TopicSpan,
};
use self::rules::Rules;
use self::wire::{api, error, parse_request_header, response_message};
use crate::broker::{Credential, Settings};
use crate::ssh::SessionOutcome;

/// The most a request may take in memory (Kafka's own default is 100 MB).
const MAX_REQUEST: usize = 128 * 1024 * 1024;
/// The most a response may take in memory.
const MAX_RESPONSE: usize = 256 * 1024 * 1024;
/// How long the worker may take to open the broker connection.
const OPEN: Duration = Duration::from_secs(25);
/// How long what is queued for the client gets to go out when the session ends.
const FLUSH_WAIT: Duration = Duration::from_secs(2);
/// More than this waiting for a client that isn't reading ends the session.
const MAX_CLIENT_BACKLOG: usize = 512 * 1024 * 1024;
/// `Produce` and `Fetch` traffic on a topic is logged at first contact and
/// then once per window, with the counts since.
pub const DEDUPE_WINDOW: Duration = Duration::from_mins(1);

/// Everything about a session that is known before the first byte.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub session_id: String,
    pub username: String,
    pub kafka_user: String,
    pub resource: String,
    pub target: BrokerTarget,
    pub slot: KafkaSlot,
    /// A field so tests can shorten it.
    pub dedupe_window: Duration,
    /// What the worker may dial, for a resource from a profile (ADR-0042).
    /// Brokers the cluster names are checked too.
    pub guard: Option<limen_policy::model::Delegated>,
}

impl SessionConfig {
    #[must_use]
    pub fn new(
        session_id: String,
        username: String,
        kafka_user: String,
        resource: String,
        target: BrokerTarget,
        slot: KafkaSlot,
    ) -> Self {
        Self {
            session_id,
            username,
            kafka_user,
            resource,
            target,
            slot,
            dedupe_window: DEDUPE_WINDOW,
            guard: None,
        }
    }
}

/// A session whose grants are loaded and whose credential exists.
pub struct Prepared {
    config: SessionConfig,
    rules: Arc<Rules>,
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

/// Check that the worker can log in as the broker user. The connection is made
/// in [`serve`]: which broker it goes to depends on the slot.
///
/// # Errors
/// If the mechanism needs a password and the worker holds none.
pub fn prepare(
    settings: &Arc<Settings>,
    grants: Vec<KafkaGrant>,
    config: SessionConfig,
) -> anyhow::Result<Prepared> {
    let credential = settings
        .credential(&config.resource, &config.kafka_user)
        .cloned();
    let mech = upstream::mechanism(&config.target);
    let needs_password = matches!(
        mech,
        KafkaSasl::Plain | KafkaSasl::ScramSha256 | KafkaSasl::ScramSha512
    );
    let credential = match credential {
        Some(c) if !needs_password || c.password.is_some() => c,
        None if !needs_password => Credential::default(),
        _ => bail!(
            "the worker has no password for {:?} on {:?} (--broker-credentials-file)",
            config.kafka_user,
            config.resource
        ),
    };
    Ok(Prepared {
        rules: Arc::new(Rules::new(grants)),
        config,
        credential,
        settings: Arc::clone(settings),
    })
}

// ---- the audit trail ---------------------------------------------------------

#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    requests: u64,
    bytes: u64,
}

/// The most (API, name) pairs a session tracks for the audit window.
const MAX_DEDUPE_ENTRIES: usize = 4096;
/// The most names an audit event lists, and the longest one it keeps: what a
/// client sends can't make one event as big as the request.
const MAX_EVENT_NAMES: usize = 32;
const MAX_EVENT_STRING: usize = 256;

/// Cut what a client controls down to what an event should hold: lists of
/// names to [`MAX_EVENT_NAMES`] (with the count in `<key>_total`), strings to
/// [`MAX_EVENT_STRING`] characters.
fn bound_event(data: &mut Value) {
    fn trim(v: &mut Value) {
        match v {
            Value::String(s) if s.chars().count() > MAX_EVENT_STRING => {
                *s = s.chars().take(MAX_EVENT_STRING).collect();
            }
            Value::Array(a) => a.iter_mut().for_each(trim),
            Value::Object(o) => o.values_mut().for_each(trim),
            _ => {}
        }
    }
    let Some(object) = data.as_object_mut() else {
        return;
    };
    let mut totals = Vec::new();
    for (key, value) in object.iter_mut() {
        if let Value::Array(a) = value
            && a.len() > MAX_EVENT_NAMES
        {
            totals.push((format!("{key}_total"), a.len()));
            a.truncate(MAX_EVENT_NAMES);
        }
        trim(value);
    }
    for (key, total) in totals {
        object.insert(key, Value::from(total));
    }
}

/// Which (API, name) pairs were logged recently, and what has happened to
/// them since.
#[derive(Debug)]
struct Dedupe {
    window: Duration,
    entries: HashMap<(i16, String), (Option<Instant>, Counts)>,
}

impl Dedupe {
    fn new(window: Duration) -> Self {
        Self {
            window,
            entries: HashMap::new(),
        }
    }

    /// Count a request. `Some` (the counts since the last event) when an
    /// event is due: the first contact, or a request after the window.
    fn touch(&mut self, key: i16, name: &str, bytes: u64, now: Instant) -> Option<Counts> {
        // A client that varies names without end (any name a wildcard grant
        // covers) can't grow this without bound: past the cap, new names share one entry.
        let name = if self.entries.len() >= MAX_DEDUPE_ENTRIES
            && !self.entries.contains_key(&(key, name.to_owned()))
        {
            "(other)"
        } else {
            name
        };
        let entry = self
            .entries
            .entry((key, name.to_owned()))
            .or_insert((None, Counts::default()));
        entry.1.requests += 1;
        entry.1.bytes += bytes;
        let due = entry
            .0
            .is_none_or(|last| now.duration_since(last) >= self.window);
        if due {
            entry.0 = Some(now);
            Some(std::mem::take(&mut entry.1))
        } else {
            None
        }
    }

    /// What is counted and not yet logged.
    fn leftovers(&self) -> Vec<(i16, String, Counts)> {
        let mut out: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, (_, c))| c.requests > 0)
            .map(|((k, n), (_, c))| (*k, n.clone(), *c))
            .collect();
        out.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        out
    }
}

// ---- the queue of what the client is owed ------------------------------------------

/// What to do to the broker's response before the client sees it.
#[derive(Debug, Clone)]
enum Transform {
    None,
    /// Add the answer for the topics the request was cut down from.
    AppendRefused {
        refused: Vec<TopicSpan>,
        error: i16,
    },
    /// Rewrite the broker addresses; list the topics the role reaches; add
    /// an error entry for each topic that was asked for and refused.
    Metadata {
        refused: Vec<String>,
    },
    Coordinator,
    OffsetFetch {
        group: String,
    },
}

#[derive(Debug, Clone)]
enum Pending {
    /// The broker will answer; this is how to treat it.
    Forwarded {
        correlation: i32,
        key: i16,
        version: i16,
        transform: Transform,
    },
    /// The worker's own answer (a whole message), to send once everything
    /// before it has been answered.
    Local(Vec<u8>),
}

struct Shared {
    out: std::sync::Mutex<VecDeque<Pending>>,
    to_client: mpsc::UnboundedSender<Vec<u8>>,
    client_backlog: Arc<AtomicUsize>,
    to_broker: mpsc::Sender<Vec<u8>>,
    rules: Arc<Rules>,
    /// The cluster's real brokers, as last seen.
    brokers: std::sync::Mutex<Vec<Broker>>,
    slot: KafkaSlot,
    /// The API versions offered to clients.
    offered: Vec<(i16, i16, i16)>,
    dedupe: std::sync::Mutex<Dedupe>,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    requests: AtomicU64,
    refused: AtomicU64,
}

impl Shared {
    fn queue(&self) -> std::sync::MutexGuard<'_, VecDeque<Pending>> {
        self.out
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn send_to_client(&self, bytes: Vec<u8>) -> anyhow::Result<()> {
        let backlog = self.client_backlog.fetch_add(bytes.len(), Ordering::SeqCst) + bytes.len();
        if backlog > MAX_CLIENT_BACKLOG {
            bail!("the client isn't reading its responses");
        }
        self.bytes_out
            .fetch_add(bytes.len() as u64, Ordering::SeqCst);
        self.to_client
            .send(bytes)
            .map_err(|_| anyhow::anyhow!("the client connection closed"))
    }

    /// Send every worker-made answer that is next in line.
    fn flush_local(&self, queue: &mut VecDeque<Pending>) -> anyhow::Result<()> {
        while let Some(Pending::Local(_)) = queue.front() {
            if let Some(Pending::Local(bytes)) = queue.pop_front() {
                self.send_to_client(bytes)?;
            }
        }
        Ok(())
    }

    fn reply_locally(&self, correlation: i32, body: &[u8]) -> anyhow::Result<()> {
        let mut queue = self.queue();
        queue.push_back(Pending::Local(response_message(correlation, body)));
        self.flush_local(&mut queue)
    }

    /// The real brokers, sorted by node ID: the order the CLI's listeners follow.
    fn local_address(&self, node_id: i32) -> Result<(String, i32), String> {
        let brokers = self
            .brokers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut ids: Vec<i32> = brokers.iter().map(|b| b.node_id).collect();
        ids.sort_unstable();
        let rank = ids
            .iter()
            .position(|id| *id == node_id)
            .ok_or_else(|| format!("broker {node_id} is not in the cluster's broker list"))?;
        let port = self.slot.port_for_rank(rank).ok_or_else(|| {
            format!(
                "the cluster has {} brokers but `limen kafka connect` opened listeners for {}; restart it with --brokers {}",
                ids.len(),
                self.slot.ports.len().saturating_sub(1),
                ids.len()
            )
        })?;
        Ok(("127.0.0.1".to_owned(), i32::from(port)))
    }
}

// ---- the session ----------------------------------------------------------------

/// Where the session's broker is: the bootstrap address for slot 0, else the
/// broker of the slot's rank.
async fn broker_address(prepared: &Prepared) -> anyhow::Result<(String, Vec<Broker>)> {
    let c = &prepared.config;
    let Some(rank) = c.slot.rank() else {
        return Ok((c.target.endpoint.clone(), Vec::new()));
    };
    let mut brokers = upstream::cluster_brokers(
        &prepared.settings,
        &c.resource,
        &c.kafka_user,
        &c.target,
        &prepared.credential,
        c.guard.as_ref(),
    )
    .await?;
    brokers.sort_by_key(|b| b.node_id);
    let b = brokers.get(rank).with_context(|| {
        format!(
            "the cluster has {} brokers; this is slot {}",
            brokers.len(),
            c.slot.slot
        )
    })?;
    Ok((format!("{}:{}", b.host, b.port), brokers))
}

/// Serve `client` until it or the broker goes away.
pub async fn serve<S>(
    client: S,
    prepared: Prepared,
    audit: Emitter,
) -> anyhow::Result<SessionOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let c = &prepared.config;
    let (address, brokers) = tokio::time::timeout(OPEN, broker_address(&prepared))
        .await
        .map_err(|_| anyhow::anyhow!("timed out finding the broker for this slot"))??;
    let up = tokio::time::timeout(
        OPEN,
        upstream::connect(
            &prepared.settings,
            &c.target,
            &prepared.credential,
            &address,
            &c.kafka_user,
            c.guard.as_ref(),
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out connecting to the broker"))??;
    relay(client, up, prepared, brokers, audit).await
}

/// Reads size-prefixed messages.
struct MessageReader<R> {
    reader: R,
    buf: Vec<u8>,
    max: usize,
    /// Where reads land, allocated once.
    chunk: Vec<u8>,
}

impl<R: AsyncRead + Unpin> MessageReader<R> {
    fn new(reader: R, max: usize) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            max,
            chunk: vec![0u8; 64 * 1024],
        }
    }

    /// A message already buffered, if a whole one is.
    fn buffered(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let size = i32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]);
        let size = usize::try_from(size).map_err(|_| anyhow::anyhow!("negative message size"))?;
        if size == 0 || size > self.max {
            bail!("a message of {size} bytes is outside what the worker accepts");
        }
        if self.buf.len() < 4 + size {
            return Ok(None);
        }
        let msg = self.buf[4..4 + size].to_vec();
        self.buf.drain(..4 + size);
        Ok(Some(msg))
    }

    /// The next message, or `None` at a clean end of stream.
    async fn next(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        loop {
            if let Some(m) = self.buffered()? {
                return Ok(Some(m));
            }
            let n = self.reader.read(&mut self.chunk).await?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                bail!("the connection closed in the middle of a message");
            }
            self.buf.extend_from_slice(&self.chunk[..n]);
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn relay<S>(
    client: S,
    up: upstream::Upstream,
    prepared: Prepared,
    brokers: Vec<Broker>,
    audit: Emitter,
) -> anyhow::Result<SessionOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Prepared {
        config,
        rules,
        credential,
        settings,
    } = prepared;
    let ctx = Context {
        user: Some(config.username.clone()),
        session_id: Uuid::parse_str(&config.session_id).ok(),
    };
    let (client_read, mut client_write) = tokio::io::split(client);
    let (broker_read, mut broker_write) = tokio::io::split(up.stream);
    let (to_client, mut for_client) = mpsc::unbounded_channel::<Vec<u8>>();
    let (to_broker, mut for_broker) = mpsc::channel::<Vec<u8>>(64);
    let backlog = Arc::new(AtomicUsize::new(0));
    let shared = Arc::new(Shared {
        out: std::sync::Mutex::default(),
        to_client,
        client_backlog: Arc::clone(&backlog),
        to_broker,
        rules,
        brokers: std::sync::Mutex::new(brokers),
        slot: config.slot.clone(),
        offered: proto::offered_versions(&up.versions),
        dedupe: std::sync::Mutex::new(Dedupe::new(config.dedupe_window)),
        bytes_in: AtomicU64::new(0),
        bytes_out: AtomicU64::new(0),
        requests: AtomicU64::new(0),
        refused: AtomicU64::new(0),
    });
    let client_writer = tokio::spawn(async move {
        while let Some(mut bytes) = for_client.recv().await {
            while bytes.len() < 256 * 1024 {
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
            while bytes.len() < 256 * 1024 {
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

    let cx = Arc::new(Cx {
        config,
        credential,
        settings,
        audit: audit.clone(),
        ctx: ctx.clone(),
    });
    let from_client = client_to_broker(
        MessageReader::new(client_read, MAX_REQUEST),
        Arc::clone(&shared),
        Arc::clone(&cx),
    );
    let from_broker = broker_to_client(
        MessageReader::new(broker_read, MAX_RESPONSE),
        Arc::clone(&shared),
        Arc::clone(&cx),
    );
    tokio::pin!(from_client, from_broker);
    let mut result: anyhow::Result<()> = tokio::select! {
        r = &mut from_client => r,
        r = &mut from_broker => r,
    };

    let summary = summary_event(&cx, &shared);
    let output_bytes = shared.bytes_out.load(Ordering::SeqCst);
    drop(shared);
    drop(cx.clone());
    let _ = tokio::time::timeout(FLUSH_WAIT, async {
        let _ = client_writer.await;
        let _ = broker_writer.await;
    })
    .await;
    if let Err(e) = audit.emit(EventKind::KafkaSummary, ctx, summary).await {
        tracing::error!(error = %e, "couldn't write the Kafka session summary");
    }
    if let Err(e) = &result {
        tracing::debug!(error = %e, "Kafka session ended");
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

/// What is shared by both directions and doesn't change.
struct Cx {
    config: SessionConfig,
    credential: Credential,
    settings: Arc<Settings>,
    audit: Emitter,
    ctx: Context,
}

fn summary_event(cx: &Cx, shared: &Shared) -> Value {
    let leftovers: Vec<Value> = shared
        .dedupe
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .leftovers()
        .into_iter()
        .map(|(key, name, c)| json!({ "api": api::name(key), "name": name, "requests": c.requests, "bytes": c.bytes }))
        .collect();
    json!({
        "resource": cx.config.resource,
        "kafka_user": cx.config.kafka_user,
        "requests": shared.requests.load(Ordering::SeqCst),
        "refused": shared.refused.load(Ordering::SeqCst),
        "bytes_in": shared.bytes_in.load(Ordering::SeqCst),
        "bytes_out": shared.bytes_out.load(Ordering::SeqCst),
        "unlogged": leftovers,
    })
}

// ---- client → broker ---------------------------------------------------------------

/// One request, decided but not yet acted on.
struct Planned {
    /// Written before anything is forwarded.
    events: Vec<(EventKind, Value)>,
    /// What to do when they are written.
    ok: Action,
    /// What to do if they can't be: fail closed.
    audit_failed: Action,
}

enum Action {
    Forward {
        bytes: Vec<u8>,
        /// `None` when the broker sends no response (`acks=0`).
        pending: Option<Pending>,
    },
    /// Answer from the worker.
    Local { correlation: i32, body: Vec<u8> },
    /// Nothing to send, nothing to answer.
    Nothing,
    /// End the session.
    Fail(String),
}

async fn client_to_broker<R>(
    mut reader: MessageReader<R>,
    shared: Arc<Shared>,
    cx: Arc<Cx>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let Some(first) = reader.next().await? else {
            return Ok(());
        };
        // Everything already buffered is planned together, so one group
        // commit covers a burst of requests.
        let mut msgs = vec![first];
        while let Some(m) = reader.buffered()? {
            msgs.push(m);
        }
        let mut plan: Vec<Planned> = Vec::with_capacity(msgs.len());
        for msg in msgs {
            shared
                .bytes_in
                .fetch_add(msg.len() as u64 + 4, Ordering::SeqCst);
            shared.requests.fetch_add(1, Ordering::SeqCst);
            plan.push(plan_message(&msg, &shared, &cx, Instant::now()));
        }
        let written = futures::future::join_all(plan.iter().map(|p| async {
            let mut ok = true;
            for (kind, data) in &p.events {
                if cx
                    .audit
                    .emit(*kind, cx.ctx.clone(), data.clone())
                    .await
                    .is_err()
                {
                    ok = false;
                }
            }
            ok
        }))
        .await;
        for (planned, written) in plan.into_iter().zip(written) {
            let action = if written {
                planned.ok
            } else {
                tracing::error!(resource = %cx.config.resource, session = %cx.config.session_id, "audit unavailable; refusing a Kafka request");
                metrics::counter!("limen_broker_audit_failures_total", "protocol" => "kafka")
                    .increment(1);
                planned.audit_failed
            };
            apply(&shared, action).await?;
        }
    }
}

async fn apply(shared: &Shared, action: Action) -> anyhow::Result<()> {
    match action {
        Action::Forward { bytes, pending } => {
            if let Some(p) = pending {
                shared.queue().push_back(p);
            }
            shared
                .to_broker
                .send(bytes)
                .await
                .map_err(|_| anyhow::anyhow!("the broker connection closed"))
        }
        Action::Local { correlation, body } => shared.reply_locally(correlation, &body),
        Action::Nothing => Ok(()),
        Action::Fail(why) => bail!("{why}"),
    }
}

/// A request message with its size prefix.
fn framed(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + msg.len());
    out.extend_from_slice(&i32::try_from(msg.len()).unwrap_or(i32::MAX).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

fn denied_event(cx: &Cx, operation: &str, detail: &Value, reason: &str) -> (EventKind, Value) {
    metrics::counter!("limen_broker_refused_total", "protocol" => "kafka").increment(1);
    let mut data = json!({
        "action": "kafka",
        "operation": operation,
        "resource": cx.config.resource,
        "kafka_user": cx.config.kafka_user,
        "reason": reason,
    });
    if let (Some(d), Some(extra)) = (data.as_object_mut(), detail.as_object()) {
        for (k, v) in extra {
            d.insert(k.clone(), v.clone());
        }
    }
    bound_event(&mut data);
    (EventKind::AuthDenied, data)
}

fn request_event(
    cx: &Cx,
    key: i16,
    version: i16,
    client_id: Option<&str>,
    detail: &Value,
) -> (EventKind, Value) {
    let mut data = json!({
        "api": api::name(key),
        "api_key": key,
        "version": version,
        "resource": cx.config.resource,
        "kafka_user": cx.config.kafka_user,
        "client_id": client_id,
    });
    if let (Some(d), Some(extra)) = (data.as_object_mut(), detail.as_object()) {
        for (k, v) in extra {
            d.insert(k.clone(), v.clone());
        }
    }
    bound_event(&mut data);
    (EventKind::KafkaRequest, data)
}

/// Plan one request.
#[allow(clippy::too_many_lines)]
fn plan_message(msg: &[u8], shared: &Shared, cx: &Cx, now: Instant) -> Planned {
    let fail = |why: String| Planned {
        events: Vec::new(),
        ok: Action::Fail(why.clone()),
        audit_failed: Action::Fail(why),
    };
    let Ok(header) = parse_request_header(msg) else {
        return fail("malformed request header".into());
    };
    let (key, version, correlation) = (header.api_key, header.api_version, header.correlation_id);
    let client_id = header.client_id.as_deref();
    let body = &msg[header.body_at..];

    // ApiVersions is answered here, for any version: a newer one than the
    // worker reads is told so in the shape every client understands.
    if key == api::API_VERSIONS {
        let (err, v) = if version > 2 {
            (error::UNSUPPORTED_VERSION, 0)
        } else {
            (error::NONE, version)
        };
        let body = proto::api_versions_response(v, err, &shared.offered);
        return local(correlation, body);
    }
    let in_range = api::supported(key).is_some_and(|(lo, hi)| (lo..=hi).contains(&version))
        && shared
            .offered
            .iter()
            .any(|(k, lo, hi)| *k == key && (*lo..=*hi).contains(&version));
    if !in_range {
        let reason = format!(
            "{} version {version} is not supported through Limen",
            if api::name(key) == "Unknown" {
                format!("API {key}")
            } else {
                api::name(key).to_owned()
            }
        );
        shared.refused.fetch_add(1, Ordering::SeqCst);
        return Planned {
            events: vec![denied_event(
                cx,
                api::name(key),
                &json!({ "api_key": key, "version": version }),
                &reason,
            )],
            ok: Action::Fail(reason.clone()),
            audit_failed: Action::Fail(reason),
        };
    }
    let Ok(parsed) = proto::parse_request(key, version, body) else {
        return fail(format!("malformed {} request", api::name(key)));
    };
    let rules = &shared.rules;
    let forward = |bytes: &[u8], transform: Transform| Action::Forward {
        bytes: framed(bytes),
        pending: Some(Pending::Forwarded {
            correlation,
            key,
            version,
            transform,
        }),
    };
    let audit_down = |body: Vec<u8>| Action::Local { correlation, body };
    // An audit outage is answered with a retriable error, so clients try again.
    let unavailable = error::REQUEST_TIMED_OUT;
    let mut events: Vec<(EventKind, Value)> = Vec::new();
    let refuse = |events: &mut Vec<(EventKind, Value)>, detail: Value, reason: &str| {
        shared.refused.fetch_add(1, Ordering::SeqCst);
        events.push(denied_event(cx, api::name(key), &detail, reason));
    };

    match &parsed {
        Parsed::Produce {
            acks,
            transactional,
            topics,
        } => {
            if *transactional {
                let reason = "transactions are not supported through Limen";
                refuse(&mut events, json!({ "topics": names(topics) }), reason);
                let resp = refusal(
                    key,
                    version,
                    &parsed,
                    error::TRANSACTIONAL_ID_AUTHORIZATION_FAILED,
                );
                return Planned {
                    events,
                    ok: if *acks == 0 {
                        Action::Nothing
                    } else {
                        local_action(correlation, resp.clone())
                    },
                    audit_failed: if *acks == 0 {
                        Action::Nothing
                    } else {
                        local_action(correlation, resp)
                    },
                };
            }
            topic_request(
                shared,
                cx,
                &parsed,
                topics,
                KafkaClass::Write,
                None,
                key,
                version,
                client_id,
                now,
                body,
                msg,
                header.body_at,
                correlation,
                *acks == 0,
                true,
            )
        }
        Parsed::Fetch { topics } => topic_request(
            shared,
            cx,
            &parsed,
            topics,
            KafkaClass::Read,
            None,
            key,
            version,
            client_id,
            now,
            body,
            msg,
            header.body_at,
            correlation,
            false,
            true,
        ),
        Parsed::ListOffsets { topics } => topic_request(
            shared,
            cx,
            &parsed,
            topics,
            KafkaClass::Read,
            None,
            key,
            version,
            client_id,
            now,
            body,
            msg,
            header.body_at,
            correlation,
            false,
            false,
        ),
        Parsed::OffsetCommit { group, topics } => {
            if let Err(reason) = rules.group(group) {
                refuse(&mut events, json!({ "group": group }), &reason);
                let resp = refusal(key, version, &parsed, error::GROUP_AUTHORIZATION_FAILED);
                return Planned {
                    events,
                    ok: local_action(correlation, resp.clone()),
                    audit_failed: local_action(correlation, resp),
                };
            }
            topic_request(
                shared,
                cx,
                &parsed,
                topics,
                KafkaClass::Read,
                Some(group),
                key,
                version,
                client_id,
                now,
                body,
                msg,
                header.body_at,
                correlation,
                false,
                false,
            )
        }
        Parsed::OffsetFetch { group, topics } => {
            if let Err(reason) = rules.group(group) {
                refuse(&mut events, json!({ "group": group }), &reason);
                let resp = refusal(key, version, &parsed, error::GROUP_AUTHORIZATION_FAILED);
                return Planned {
                    events,
                    ok: local_action(correlation, resp.clone()),
                    audit_failed: local_action(correlation, resp),
                };
            }
            match topics {
                Some(t) => topic_request(
                    shared,
                    cx,
                    &parsed,
                    t,
                    KafkaClass::Read,
                    Some(group),
                    key,
                    version,
                    client_id,
                    now,
                    body,
                    msg,
                    header.body_at,
                    correlation,
                    false,
                    false,
                ),
                None => Planned {
                    events: vec![request_event(
                        cx,
                        key,
                        version,
                        client_id,
                        &json!({ "group": group, "topics": "all" }),
                    )],
                    ok: forward(
                        msg,
                        Transform::OffsetFetch {
                            group: group.clone(),
                        },
                    ),
                    audit_failed: audit_down(retry_response(key, version, &parsed, unavailable)),
                },
            }
        }
        Parsed::FindCoordinator {
            key: name,
            key_type,
        } => {
            let check = if *key_type == 0 {
                rules.group(name)
            } else {
                Err("transactions are not supported through Limen".to_owned())
            };
            match check {
                Err(reason) => {
                    refuse(
                        &mut events,
                        json!({ "key": name, "key_type": key_type }),
                        &reason,
                    );
                    let code = if *key_type == 0 {
                        error::GROUP_AUTHORIZATION_FAILED
                    } else {
                        error::TRANSACTIONAL_ID_AUTHORIZATION_FAILED
                    };
                    let resp = refusal(key, version, &parsed, code);
                    Planned {
                        events,
                        ok: local_action(correlation, resp.clone()),
                        audit_failed: local_action(correlation, resp),
                    }
                }
                Ok(()) => Planned {
                    events: vec![request_event(
                        cx,
                        key,
                        version,
                        client_id,
                        &json!({ "group": name }),
                    )],
                    ok: forward(msg, Transform::Coordinator),
                    audit_failed: audit_down(retry_response(key, version, &parsed, unavailable)),
                },
            }
        }
        Parsed::Group { group } => match rules.group(group) {
            Err(reason) => {
                refuse(&mut events, json!({ "group": group }), &reason);
                let resp = refusal(key, version, &parsed, error::GROUP_AUTHORIZATION_FAILED);
                Planned {
                    events,
                    ok: local_action(correlation, resp.clone()),
                    audit_failed: local_action(correlation, resp),
                }
            }
            Ok(()) => {
                // Heartbeats arrive every few seconds: counted, not logged.
                let events = if key == api::HEARTBEAT {
                    Vec::new()
                } else {
                    vec![request_event(
                        cx,
                        key,
                        version,
                        client_id,
                        &json!({ "group": group }),
                    )]
                };
                Planned {
                    events,
                    ok: forward(msg, Transform::None),
                    audit_failed: audit_down(retry_response(key, version, &parsed, unavailable)),
                }
            }
        },
        Parsed::CreateTopics { topics } | Parsed::DeleteTopics { topics } => admin_request(
            shared,
            cx,
            &parsed,
            topics,
            key,
            version,
            client_id,
            body,
            msg,
            header.body_at,
            correlation,
        ),
        Parsed::InitProducerId { transactional } => {
            if *transactional || !rules.has_class(KafkaClass::Write) {
                let reason = if *transactional {
                    "transactions are not supported through Limen"
                } else {
                    "your role doesn't grant the write permission"
                };
                refuse(&mut events, json!({}), reason);
                let code = if *transactional {
                    error::TRANSACTIONAL_ID_AUTHORIZATION_FAILED
                } else {
                    error::CLUSTER_AUTHORIZATION_FAILED
                };
                let resp = refusal(key, version, &parsed, code);
                return Planned {
                    events,
                    ok: local_action(correlation, resp.clone()),
                    audit_failed: local_action(correlation, resp),
                };
            }
            Planned {
                events: vec![request_event(cx, key, version, client_id, &json!({}))],
                ok: forward(msg, Transform::None),
                audit_failed: audit_down(retry_response(key, version, &parsed, unavailable)),
            }
        }
        Parsed::Metadata { names: requested } => metadata_request(
            shared,
            cx,
            requested.as_deref(),
            key,
            version,
            client_id,
            now,
            body,
            msg,
            header.body_at,
            correlation,
        ),
        Parsed::SaslHandshake => {
            // The client's login is discarded: accept PLAIN, offer only PLAIN.
            let mut r = wire::Reader::new(body);
            let ok = r.string().is_ok_and(|m| m == "PLAIN");
            let code = if ok {
                error::NONE
            } else {
                error::UNSUPPORTED_SASL_MECHANISM
            };
            let resp = wire::Writer::new()
                .i16(code)
                .i32(1)
                .string("PLAIN")
                .finish();
            local(correlation, resp)
        }
        Parsed::SaslAuthenticate => {
            let mut resp = wire::Writer::new()
                .i16(error::NONE)
                .nullable_string(None)
                .bytes(&[]);
            if version >= 1 {
                resp = resp.i64(0);
            }
            local(correlation, resp.finish())
        }
        Parsed::ApiVersions => unreachable!("answered above"),
    }
}

fn local(correlation: i32, body: Vec<u8>) -> Planned {
    Planned {
        events: Vec::new(),
        ok: Action::Local {
            correlation,
            body: body.clone(),
        },
        audit_failed: Action::Local { correlation, body },
    }
}

fn local_action(correlation: i32, body: Vec<u8>) -> Action {
    Action::Local { correlation, body }
}

fn names(topics: &proto::TopicArray) -> Vec<&str> {
    topics.spans.iter().map(|s| s.name.as_str()).collect()
}

fn refusal(key: i16, version: i16, parsed: &Parsed, code: i16) -> Vec<u8> {
    proto::refusal_response(key, version, parsed, code).unwrap_or_default()
}

/// The answer to a request that can't be audited right now.
fn retry_response(key: i16, version: i16, parsed: &Parsed, code: i16) -> Vec<u8> {
    refusal(key, version, parsed, code)
}

/// `Produce`, `Fetch`, `ListOffsets`, `OffsetCommit`, `OffsetFetch` with topics:
/// check every topic, cut the request down to the allowed ones, and audit.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn topic_request(
    shared: &Shared,
    cx: &Cx,
    parsed: &Parsed,
    topics: &proto::TopicArray,
    class: KafkaClass,
    group: Option<&str>,
    key: i16,
    version: i16,
    client_id: Option<&str>,
    now: Instant,
    body: &[u8],
    msg: &[u8],
    body_at: usize,
    correlation: i32,
    no_response: bool,
    sized: bool,
) -> Planned {
    let mut keep = Vec::with_capacity(topics.spans.len());
    let mut refused: Vec<&TopicSpan> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();
    for span in &topics.spans {
        match shared.rules.topic(class, &span.name, group) {
            Ok(()) => keep.push(true),
            Err(reason) => {
                keep.push(false);
                refused.push(span);
                reasons.push(reason);
            }
        }
    }
    let mut events: Vec<(EventKind, Value)> = Vec::new();
    if !refused.is_empty() {
        shared.refused.fetch_add(1, Ordering::SeqCst);
        let mut detail = json!({
            "topics": refused.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        });
        if let Some(g) = group {
            detail["group"] = json!(g);
        }
        events.push(denied_event(
            cx,
            api::name(key),
            &detail,
            reasons.first().map_or("", String::as_str),
        ));
    }
    let allowed: Vec<&TopicSpan> = topics
        .spans
        .iter()
        .zip(&keep)
        .filter_map(|(s, k)| k.then_some(s))
        .collect();
    // Audit what goes through: at first contact with a topic and then once per
    // window, with the counts since. Offset and admin traffic is rarer: always.
    let mut due_topics: Vec<Value> = Vec::new();
    let mut due_requests = 0u64;
    {
        let mut dedupe = shared
            .dedupe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for span in &allowed {
            let bytes = if sized {
                (span.end - span.start) as u64
            } else {
                0
            };
            let counts = if sized {
                dedupe.touch(key, &span.name, bytes, now)
            } else {
                Some(Counts {
                    requests: 1,
                    bytes: 0,
                })
            };
            if let Some(c) = counts {
                due_topics.push(json!({ "name": span.name, "partitions": span.partitions.len(), "requests": c.requests, "bytes": c.bytes }));
                due_requests += c.requests;
            }
        }
    }
    if !due_topics.is_empty() {
        let mut detail = json!({ "topics": due_topics, "requests": due_requests });
        if let Some(g) = group {
            detail["group"] = json!(g);
        }
        events.push(request_event(cx, key, version, client_id, &detail));
    }
    let unavailable = |parsed: &Parsed| -> Action {
        if no_response {
            Action::Nothing
        } else {
            local_action(
                correlation,
                refusal(key, version, parsed, error::REQUEST_TIMED_OUT),
            )
        }
    };
    if allowed.is_empty() {
        let ok = if no_response {
            Action::Nothing
        } else {
            local_action(
                correlation,
                refusal(key, version, parsed, error::TOPIC_AUTHORIZATION_FAILED),
            )
        };
        return Planned {
            events,
            ok,
            audit_failed: unavailable(parsed),
        };
    }
    // The request the broker sees: unchanged if nothing was refused.
    let bytes = if refused.is_empty() {
        msg.to_vec()
    } else {
        let mut cut = msg[..body_at].to_vec();
        cut.extend_from_slice(&topics.cut(body, &keep));
        cut
    };
    let transform = if refused.is_empty() {
        Transform::None
    } else {
        Transform::AppendRefused {
            refused: refused.iter().map(|s| (*s).clone()).collect(),
            error: error::TOPIC_AUTHORIZATION_FAILED,
        }
    };
    let ok = Action::Forward {
        bytes: framed(&bytes),
        pending: (!no_response).then_some(Pending::Forwarded {
            correlation,
            key,
            version,
            transform,
        }),
    };
    Planned {
        events,
        ok,
        audit_failed: unavailable(parsed),
    }
}

#[allow(clippy::too_many_arguments)]
fn admin_request(
    shared: &Shared,
    cx: &Cx,
    parsed: &Parsed,
    topics: &proto::TopicArray,
    key: i16,
    version: i16,
    client_id: Option<&str>,
    body: &[u8],
    msg: &[u8],
    body_at: usize,
    correlation: i32,
) -> Planned {
    // Creating and deleting topics are always logged.
    topic_request(
        shared,
        cx,
        parsed,
        topics,
        KafkaClass::Admin,
        None,
        key,
        version,
        client_id,
        Instant::now(),
        body,
        msg,
        body_at,
        correlation,
        false,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn metadata_request(
    shared: &Shared,
    cx: &Cx,
    requested: Option<&[String]>,
    key: i16,
    version: i16,
    client_id: Option<&str>,
    now: Instant,
    body: &[u8],
    msg: &[u8],
    body_at: usize,
    correlation: i32,
) -> Planned {
    let rules = &shared.rules;
    let mut events: Vec<(EventKind, Value)> = Vec::new();
    let (visible, refused): (Vec<String>, Vec<String>) = match requested {
        Some(names) => names.iter().cloned().partition(|n| rules.visible(n)),
        None => (Vec::new(), Vec::new()),
    };
    if !refused.is_empty() {
        shared.refused.fetch_add(1, Ordering::SeqCst);
        events.push(denied_event(
            cx,
            api::name(key),
            &json!({ "topics": refused }),
            "your role doesn't reach that topic",
        ));
    }
    // Metadata is polled: logged at first contact with a topic list, then once per window.
    let label = match requested {
        Some(_) => visible.join(","),
        None => "*".to_owned(),
    };
    let due = shared
        .dedupe
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .touch(key, &label, 0, now);
    if let Some(c) = due {
        events.push(request_event(
            cx,
            key,
            version,
            client_id,
            &json!({ "topics": requested.map(|_| &visible), "all_topics": requested.is_none(), "requests": c.requests }),
        ));
    }
    // Automatic topic creation is a create: only for a role that may.
    let allow_create = rules.has_class(KafkaClass::Admin);
    let new_body = proto::rewrite_metadata_request(
        version,
        body,
        requested.map(|_| visible.as_slice()),
        allow_create,
    );
    let Ok(new_body) = new_body else {
        return Planned {
            events,
            ok: Action::Fail("malformed Metadata request".into()),
            audit_failed: Action::Fail("malformed Metadata request".into()),
        };
    };
    let mut bytes = msg[..body_at].to_vec();
    bytes.extend_from_slice(&new_body);
    let action = Action::Forward {
        bytes: framed(&bytes),
        pending: Some(Pending::Forwarded {
            correlation,
            key,
            version,
            transform: Transform::Metadata { refused },
        }),
    };
    // Metadata can't be answered locally without lying about the cluster: an
    // outage of the audit trail ends the connection, and the client reconnects.
    Planned {
        events,
        ok: action,
        audit_failed: Action::Fail("audit unavailable".into()),
    }
}

// ---- broker → client ----------------------------------------------------------------

async fn broker_to_client<R>(
    mut reader: MessageReader<R>,
    shared: Arc<Shared>,
    cx: Arc<Cx>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let Some(msg) = reader.next().await? else {
            return Ok(());
        };
        if msg.len() < 4 {
            bail!("a response shorter than its correlation id");
        }
        let correlation = i32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]);
        let front = shared.queue().front().cloned();
        let Some(Pending::Forwarded {
            correlation: want,
            key,
            version,
            transform,
        }) = front
        else {
            bail!("the broker sent a response nobody asked for");
        };
        if correlation != want {
            bail!("the broker answered request {correlation}, not {want}");
        }
        let body = &msg[4..];
        let out = match transform_response(&shared, &cx, key, version, &transform, body).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, resource = %cx.config.resource, "couldn't rewrite a Kafka response");
                let _ = cx
                    .audit
                    .emit(
                        EventKind::AuthDenied,
                        cx.ctx.clone(),
                        json!({ "action": "kafka", "operation": api::name(key), "resource": cx.config.resource, "kafka_user": cx.config.kafka_user, "reason": e.to_string() }),
                    )
                    .await;
                return Err(e);
            }
        };
        // Only now does the response leave the queue, so a worker-made answer
        // queued behind it can't overtake it.
        shared.send_to_client(response_message(correlation, &out))?;
        let mut queue = shared.queue();
        queue.pop_front();
        shared.flush_local(&mut queue)?;
    }
}

async fn transform_response<'a>(
    shared: &Shared,
    cx: &Cx,
    key: i16,
    version: i16,
    transform: &Transform,
    body: &'a [u8],
) -> anyhow::Result<Cow<'a, [u8]>> {
    let malformed = |what: &str| anyhow::anyhow!("a garbled {what} response from the broker");
    match transform {
        Transform::None => Ok(Cow::Borrowed(body)),
        Transform::AppendRefused { refused, error } => {
            let refs: Vec<&TopicSpan> = refused.iter().collect();
            proto::append_refused(key, version, body, &refs, *error)
                .map(Cow::Owned)
                .map_err(|_| malformed(api::name(key)))
        }
        Transform::Metadata { refused } => {
            let mut m =
                MetadataResponse::decode(version, body).map_err(|_| malformed("Metadata"))?;
            // Remember the real brokers; hand out the local ones.
            shared
                .brokers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone_from(&m.brokers);
            m.topics.retain(|t| shared.rules.visible(&t.name));
            for name in refused {
                m.topics.push(MetadataTopic {
                    error: error::TOPIC_AUTHORIZATION_FAILED,
                    name: name.clone(),
                    internal: false,
                    partitions: Vec::new(),
                    authorized_operations: i32::MIN,
                });
            }
            for b in &mut m.brokers {
                let (host, port) = shared
                    .local_address(b.node_id)
                    .map_err(anyhow::Error::msg)?;
                b.host = host;
                b.port = port;
            }
            Ok(Cow::Owned(m.encode(version)))
        }
        Transform::Coordinator => {
            let mut c = CoordinatorResponse::decode(version, body)
                .map_err(|_| malformed("FindCoordinator"))?;
            if c.error == error::NONE {
                let known = shared
                    .brokers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .iter()
                    .any(|b| b.node_id == c.node_id);
                if !known {
                    // The client hasn't asked for Metadata on this connection yet.
                    let fresh = upstream::cluster_brokers(
                        &cx.settings,
                        &cx.config.resource,
                        &cx.config.kafka_user,
                        &cx.config.target,
                        &cx.credential,
                        cx.config.guard.as_ref(),
                    )
                    .await?;
                    *shared
                        .brokers
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = fresh;
                }
                let (host, port) = shared
                    .local_address(c.node_id)
                    .map_err(anyhow::Error::msg)?;
                c.host = host;
                c.port = port;
            }
            Ok(Cow::Owned(c.encode(version)))
        }
        Transform::OffsetFetch { group } => {
            let mut r =
                OffsetFetchResponse::decode(version, body).map_err(|_| malformed("OffsetFetch"))?;
            r.topics.retain(|(name, _)| {
                shared
                    .rules
                    .topic(KafkaClass::Read, name, Some(group))
                    .is_ok()
            });
            Ok(Cow::Owned(r.encode(version)))
        }
    }
}

/// A map of API key to range, as the worker offers it (for the console and tests).
#[must_use]
pub fn offered_map(offered: &[(i16, i16, i16)]) -> BTreeMap<i16, (i16, i16)> {
    offered.iter().map(|&(k, lo, hi)| (k, (lo, hi))).collect()
}

//! MongoDB, Atlas, and `DocumentDB` sessions (design §5.4, ADR-0035).
//!
//! The worker plays the server toward the user's driver (`mongosh`, any
//! driver; no credentials), logs in to the real server itself, and relays
//! `OP_MSG` commands one at a time. It reads each command in full to audit it
//! *before* forwarding, to check its database against policy, and to refuse
//! the few commands that would change who the session is. Replies are read
//! only far enough to learn the outcome and which cursors were opened.

mod audit;
pub mod bson;
mod redact;
mod reply;
mod rules;
pub mod upstream;
pub mod wire;

use std::collections::HashSet;
use std::time::{Duration, Instant};

use limen_audit::Emitter;
use limen_policy::model::{MongoAuth, MongoFlavor, MongoTarget};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::db::sigv4;
use crate::db::target::{ClientIdentity, Target};
use crate::ssh::SessionOutcome;

pub use audit::{Auditor, Status};
pub use rules::Access;
pub use upstream::{Login, Sha, Upstream, UpstreamError};

use bson::Builder;
use rules::{Verdict, judge};
use wire::{Header, OP_MSG, OP_QUERY, OP_REPLY};

/// A session with no client traffic for this long ends.
const IDLE: Duration = Duration::from_hours(1);
/// The longest a server may take to answer one command.
const REPLY: Duration = Duration::from_hours(1);

/// Everything a MongoDB session needs besides the live connection.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub session_id: uuid::Uuid,
    pub username: String,
    pub resource: String,
    /// The role the session is for (what policy and audit name).
    pub role: String,
    pub flavor: MongoFlavor,
    /// `full_commands` on the resource.
    pub full_commands: bool,
    /// Fields so tests can shorten them.
    pub idle: Duration,
    pub reply_timeout: Duration,
}

impl SessionConfig {
    #[must_use]
    pub fn new(
        session_id: uuid::Uuid,
        username: String,
        resource: String,
        role: String,
        target: &MongoTarget,
    ) -> Self {
        Self {
            session_id,
            username,
            resource,
            role,
            flavor: target.flavor,
            full_commands: target.full_commands,
            idle: IDLE,
            reply_timeout: REPLY,
        }
    }
}

/// A session whose connection to the server is open and logged in.
pub struct Prepared {
    config: SessionConfig,
    upstream: Upstream,
    access: Access,
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
    pub fn session_id(&self) -> String {
        self.config.session_id.to_string()
    }
}

/// The login a resource calls for and, for X.509, the certificate to present.
/// `aws` is the worker's IAM credentials, needed only for `auth: aws`.
pub async fn credentials(
    spec: &MongoTarget,
    role: &str,
    aws: Option<sigv4::Credentials>,
) -> Result<(Login, Option<ClientIdentity>), String> {
    if !limen_policy::valid_mongo_role(role) {
        return Err(format!("{role:?} is not a valid MongoDB role name"));
    }
    let dir = spec
        .credentials_dir
        .as_deref()
        .map(|d| d.trim_end_matches('/'));
    match spec.auth {
        MongoAuth::Scram | MongoAuth::ScramSha1 => {
            let dir = dir.ok_or("the resource has no credentials_dir")?;
            let password = crate::db::secret::read(&format!("{dir}/{role}")).await?;
            let sha = Login::sha_for(spec.auth).unwrap_or(Sha::Sha256);
            if sha == Sha::Sha256 && !password.expose().is_ascii() {
                // The server applies SASLprep to the password; without it a
                // non-ASCII one would fail to log in with no useful message.
                return Err(format!(
                    "the password for {role} isn't ASCII, and SCRAM-SHA-256 needs SASLprep, which Limen doesn't implement"
                ));
            }
            Ok((
                Login::Scram {
                    sha,
                    user: role.to_owned(),
                    password,
                },
                None,
            ))
        }
        MongoAuth::X509 => {
            let dir = dir.ok_or("the resource has no credentials_dir")?;
            let path = format!("{dir}/{role}.pem");
            let pem = tokio::fs::read(&path)
                .await
                .map_err(|e| format!("reading the client certificate {path}: {e}"))?;
            Ok((Login::X509, Some(identity_from_pem(&pem, &path)?)))
        }
        MongoAuth::Aws => aws
            .map(|c| (Login::Aws(c), None))
            .ok_or_else(|| "no AWS credentials for MONGODB-AWS".to_owned()),
    }
}

fn identity_from_pem(pem: &[u8], path: &str) -> Result<ClientIdentity, String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    let chain = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{path}: {e}"))?;
    if chain.is_empty() {
        return Err(format!("{path} holds no certificate"));
    }
    let key =
        PrivateKeyDer::from_pem_slice(pem).map_err(|e| format!("{path}: no private key ({e})"))?;
    Ok(ClientIdentity { chain, key })
}

/// Connect to the server and log in. Failing here gives the proxy a clean
/// refusal instead of a session that dies at once.
pub async fn prepare(
    config: SessionConfig,
    target: &Target,
    login: &Login,
    auth_source: &str,
    access: Access,
) -> Result<Prepared, UpstreamError> {
    let app_name = format!("limen:{}", config.session_id);
    let upstream = upstream::connect(target, login, auth_source, &app_name).await?;
    Ok(Prepared {
        config,
        upstream,
        access,
    })
}

/// The answer to a client's handshake. The worker presents itself as a
/// standalone, writable server whatever the real one is: drivers then talk to
/// it as one node (no discovery, no host lists to rewrite), and what it can't
/// carry (retryable writes, transactions) is documented rather than half-done.
fn hello_reply(info: &upstream::ServerInfo, hello_ok: bool, connection_id: i32) -> Vec<u8> {
    let now_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(0);
    let mut b = Builder::new()
        .bool("ismaster", true)
        .bool("isWritablePrimary", true);
    if hello_ok {
        b = b.bool("helloOk", true);
    }
    b = b
        .i32("maxBsonObjectSize", info.max_bson)
        .i32("maxMessageSizeBytes", info.max_message.min(48_000_000))
        .i32("maxWriteBatchSize", info.max_batch)
        .datetime_ms("localTime", now_ms);
    if let Some(minutes) = info.session_timeout_minutes {
        b = b.i32("logicalSessionTimeoutMinutes", minutes);
    }
    b.i32("connectionId", connection_id)
        .i32("minWireVersion", info.min_wire)
        .i32("maxWireVersion", info.max_wire)
        .bool("readOnly", false)
        .f64("ok", 1.0)
        .finish()
}

fn error_reply(code: i32, code_name: &str, message: &str) -> Vec<u8> {
    Builder::new()
        .f64("ok", 0.0)
        .str("errmsg", message)
        .i32("code", code)
        .str("codeName", code_name)
        .finish()
}

/// Serve one client connection until it ends. `client` is the decrypted
/// stream from the proxy.
pub async fn serve<S>(
    mut client: S,
    prepared: Prepared,
    audit: Emitter,
) -> anyhow::Result<SessionOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Prepared {
        config,
        mut upstream,
        access,
    } = prepared;
    let flavor = match config.flavor {
        MongoFlavor::Standard => "standard",
        MongoFlavor::Atlas => "atlas",
        MongoFlavor::Documentdb => "documentdb",
    };
    let auditor = Auditor::new(
        audit,
        config.session_id,
        &config.username,
        &config.resource,
        &config.role,
        flavor,
        config.full_commands,
    );
    let connection_id =
        i32::from_le_bytes(config.session_id.as_bytes()[12..16].try_into()?) & i32::MAX;
    let mut cursors: HashSet<i64> = HashSet::new();
    let mut next_id: i32 = 1;

    loop {
        let message = match tokio::time::timeout(config.idle, wire::read_message(&mut client)).await
        {
            Err(_) => {
                tracing::info!(session = %config.session_id, "MongoDB session idle; closing");
                break;
            }
            Ok(Err(e)) => {
                tracing::debug!(session = %config.session_id, error = %e, "client stream ended");
                break;
            }
            Ok(Ok(None)) => break,
            Ok(Ok(Some(m))) => m,
        };
        let request_id = message.header.request_id;
        let keep_going = match message.header.opcode {
            OP_QUERY => legacy_hello(&mut client, &message, &upstream.info, connection_id).await,
            OP_MSG => {
                let mut ctx = Ctx {
                    client: &mut client,
                    upstream: &mut upstream,
                    access: &access,
                    auditor: &auditor,
                    cursors: &mut cursors,
                    reply_timeout: config.reply_timeout,
                    connection_id,
                    next_id: &mut next_id,
                };
                ctx.command(&message).await
            }
            other => {
                tracing::warn!(session = %config.session_id, opcode = other, "unsupported opcode; closing");
                false
            }
        };
        if !keep_going {
            tracing::debug!(session = %config.session_id, request_id, "ending the MongoDB session");
            break;
        }
    }
    Ok(SessionOutcome::default())
}

/// `OP_QUERY` is accepted only for the first handshake, which drivers still
/// send in the old format. Returns whether the session goes on.
async fn legacy_hello<S>(
    client: &mut S,
    message: &wire::Message,
    info: &upstream::ServerInfo,
    connection_id: i32,
) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let Ok(query) = wire::parse_op_query(&message.body) else {
        return false;
    };
    let is_hello = query.collection.ends_with(".$cmd")
        && query.query.first().ok().flatten().is_some_and(|(name, _)| {
            matches!(name.to_ascii_lowercase().as_str(), "ismaster" | "hello")
        });
    if !is_hello {
        return false;
    }
    let hello_ok = matches!(query.query.get("helloOk"), Ok(Some(v)) if v.is_truthy());
    let doc = hello_reply(info, hello_ok, connection_id);
    let header = Header {
        request_id: 0,
        response_to: message.header.request_id,
        opcode: OP_REPLY,
    };
    wire::write_message(client, header, &wire::op_reply_body(&doc))
        .await
        .is_ok()
}

/// Write the end event. A failure means the session must end: the trail has
/// a command with no outcome.
async fn finish(
    auditor: &Auditor,
    id: uuid::Uuid,
    started: Instant,
    status: Status,
    info: Option<&reply::ReplyInfo>,
) -> bool {
    match auditor.finished(id, started, status, info).await {
        Ok(()) => true,
        Err(e) => {
            tracing::error!(error = %e, "audit write failed for a command's outcome; ending the session");
            false
        }
    }
}

/// One session's mutable view while handling a command.
struct Ctx<'a, S> {
    client: &'a mut S,
    upstream: &'a mut Upstream,
    access: &'a Access,
    auditor: &'a Auditor,
    cursors: &'a mut HashSet<i64>,
    reply_timeout: Duration,
    connection_id: i32,
    next_id: &'a mut i32,
}

impl<S> Ctx<'_, S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn reply(&mut self, request_id: i32, doc: &[u8]) -> bool {
        *self.next_id = self.next_id.wrapping_add(1).max(1);
        let header = Header {
            request_id: *self.next_id,
            response_to: request_id,
            opcode: OP_MSG,
        };
        wire::write_message(self.client, header, &wire::op_msg_body(doc))
            .await
            .is_ok()
    }

    /// Handle one `OP_MSG`. Returns whether the session goes on.
    async fn command(&mut self, message: &wire::Message) -> bool {
        let request_id = message.header.request_id;
        let Ok(parsed) = wire::parse_op_msg(&message.body) else {
            return false;
        };
        let unacknowledged = parsed.flags & wire::MORE_TO_COME != 0;
        let command = match rules::inspect(parsed.command) {
            Ok(c) => c,
            Err(refusal) => {
                return self
                    .refuse("", "", &refusal, request_id, unacknowledged)
                    .await;
            }
        };
        match judge(&command, self.access, self.cursors) {
            Verdict::Hello => {
                let hello_ok = matches!(command.body.get("helloOk"), Ok(Some(v)) if v.is_truthy());
                let doc = hello_reply(&self.upstream.info, hello_ok, self.connection_id);
                self.reply(request_id, &doc).await
            }
            Verdict::Refuse(refusal) => {
                self.refuse(
                    command.name,
                    command.database,
                    &refusal,
                    request_id,
                    unacknowledged,
                )
                .await
            }
            Verdict::Forward => {
                let summary =
                    redact::summarize(parsed.command, &parsed.sequences, self.auditor.full());
                // Written before the command is forwarded; if it can't be, the
                // command doesn't run and the session ends (fail closed).
                let command_id = match self
                    .auditor
                    .command(&command, &summary, request_id, unacknowledged)
                    .await
                {
                    Ok(id) => id,
                    Err(e) => {
                        tracing::error!(error = %e, "audit write failed; refusing the command and ending the session");
                        let doc = error_reply(
                            8000,
                            "AuditUnavailable",
                            "Limen could not record this command, so it was not run",
                        );
                        if !unacknowledged {
                            self.reply(request_id, &doc).await;
                        }
                        return false;
                    }
                };
                let started = Instant::now();
                let header = Header {
                    request_id,
                    response_to: 0,
                    opcode: OP_MSG,
                };
                let forwarded = wire::op_msg_for_server(&parsed);
                if wire::write_message(&mut self.upstream.io, header, &forwarded)
                    .await
                    .is_err()
                {
                    finish(
                        self.auditor,
                        command_id,
                        started,
                        Status::NotCompleted,
                        None,
                    )
                    .await;
                    return false;
                }
                if unacknowledged {
                    return finish(
                        self.auditor,
                        command_id,
                        started,
                        Status::Unacknowledged,
                        None,
                    )
                    .await;
                }
                self.relay_reply(&command, request_id, command_id, started)
                    .await
            }
        }
    }

    async fn refuse(
        &mut self,
        name: &str,
        database: &str,
        refusal: &rules::Refusal,
        request_id: i32,
        unacknowledged: bool,
    ) -> bool {
        if let Err(e) = self
            .auditor
            .refused(name, database, refusal, request_id)
            .await
        {
            tracing::error!(error = %e, "audit write failed for a refused command; ending the session");
            return false;
        }
        if unacknowledged {
            return true;
        }
        let doc = error_reply(refusal.code, refusal.code_name, &refusal.message);
        self.reply(request_id, &doc).await
    }

    async fn relay_reply(
        &mut self,
        command: &rules::Inspected<'_>,
        request_id: i32,
        command_id: uuid::Uuid,
        started: Instant,
    ) -> bool {
        let answer = tokio::time::timeout(
            self.reply_timeout,
            wire::read_message(&mut self.upstream.io),
        )
        .await;
        let Ok(Ok(Some(answer))) = answer else {
            finish(
                self.auditor,
                command_id,
                started,
                Status::NotCompleted,
                None,
            )
            .await;
            return false;
        };
        let well_formed = answer.header.opcode == OP_MSG && answer.header.response_to == request_id;
        let parsed = wire::parse_op_msg(&answer.body);
        let Some(parsed) = parsed
            .ok()
            .filter(|p| well_formed && p.flags & wire::MORE_TO_COME == 0)
        else {
            // A reply that doesn't answer this command (or promises more we
            // didn't ask for) would desynchronize the stream.
            tracing::warn!("unexpected reply from the MongoDB server; ending the session");
            finish(
                self.auditor,
                command_id,
                started,
                Status::NotCompleted,
                None,
            )
            .await;
            return false;
        };
        let info = reply::inspect(parsed.command);
        self.track_cursors(command, &info);
        if wire::write_message(self.client, answer.header, &answer.body)
            .await
            .is_err()
        {
            finish(
                self.auditor,
                command_id,
                started,
                Status::NotCompleted,
                Some(&info),
            )
            .await;
            return false;
        }
        let status = if info.failed() {
            Status::Error
        } else {
            Status::Ok
        };
        finish(self.auditor, command_id, started, status, Some(&info)).await
    }

    /// Remember the cursors the server opened for this session, and forget the
    /// ones that finished or were killed.
    fn track_cursors(&mut self, command: &rules::Inspected<'_>, info: &reply::ReplyInfo) {
        match command.lower.as_str() {
            "getmore" => {
                let id = command
                    .body
                    .first()
                    .ok()
                    .flatten()
                    .and_then(|(_, v)| v.as_i64());
                if let Some(id) = id
                    && info.cursor_id != Some(id)
                {
                    self.cursors.remove(&id);
                }
            }
            "killcursors" => {
                if let Ok(Some(bson::Value::Array(ids))) = command.body.get("cursors") {
                    for id in ids.iter().filter_map(|e| e.ok()?.1.as_i64()) {
                        self.cursors.remove(&id);
                    }
                }
            }
            _ => {}
        }
        if let Some(id) = info.cursor_id {
            if self.cursors.len() < rules::MAX_CURSORS {
                self.cursors.insert(id);
            } else {
                tracing::warn!("too many open cursors in one MongoDB session; not tracking more");
            }
        }
    }
}

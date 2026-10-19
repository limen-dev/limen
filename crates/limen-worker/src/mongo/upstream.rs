//! The worker's own connection to the MongoDB server (ADR-0035): TLS, the
//! handshake, finding the primary, and logging in. The user's client never
//! sees any of it, and no credential leaves this module except on the wire to
//! the server.

use std::time::Duration;

use aws_lc_rs::{digest, hmac, pbkdf2};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use limen_core::secret::Secret;
use limen_policy::model::MongoAuth;
use time::OffsetDateTime;

use super::bson::{Builder, Doc, Value};
use super::wire::{self, Header, OP_MSG};
use crate::db::sigv4;
use crate::db::target::{BoxedIo, Target};

/// Each step of connecting and logging in has this long.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);
/// Most iterations a server may ask SCRAM for. MongoDB defaults to 15,000.
const MAX_ITERATIONS: u32 = 1_000_000;

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Wire(#[from] wire::WireError),
    #[error("{0}")]
    Bson(#[from] super::bson::BsonError),
    #[error("the server answered {code_name} ({code}): {message}")]
    Command {
        code: i32,
        code_name: String,
        message: String,
    },
    #[error("{0}")]
    Protocol(String),
    #[error("timed out {0}")]
    Timeout(&'static str),
}

fn protocol(why: impl Into<String>) -> UpstreamError {
    UpstreamError::Protocol(why.into())
}

/// What the server says about itself in its handshake; the worker answers its
/// own client with the parts that matter to a driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    pub min_wire: i32,
    pub max_wire: i32,
    pub session_timeout_minutes: Option<i32>,
    pub max_bson: i32,
    pub max_message: i32,
    pub max_batch: i32,
    pub set_name: Option<String>,
    pub writable_primary: bool,
    pub primary: Option<String>,
}

impl ServerInfo {
    fn from_hello(doc: Doc<'_>) -> Result<Self, UpstreamError> {
        let int = |key: &str, default: i32| -> Result<i32, UpstreamError> {
            Ok(doc
                .get(key)?
                .and_then(|v| v.as_i64())
                .and_then(|v| i32::try_from(v).ok())
                .unwrap_or(default))
        };
        let text = |key: &str| -> Result<Option<String>, UpstreamError> {
            Ok(doc
                .get(key)?
                .and_then(|v| v.as_str().map(str::to_owned))
                .filter(|s| !s.is_empty()))
        };
        let writable = doc
            .get("isWritablePrimary")?
            .or(doc.get("ismaster")?)
            .is_some_and(|v| v.is_truthy());
        Ok(Self {
            min_wire: int("minWireVersion", 0)?,
            max_wire: int("maxWireVersion", 0)?,
            session_timeout_minutes: doc
                .get("logicalSessionTimeoutMinutes")?
                .and_then(|v| v.as_i64())
                .and_then(|v| i32::try_from(v).ok()),
            max_bson: int("maxBsonObjectSize", 16 * 1024 * 1024)?,
            max_message: int("maxMessageSizeBytes", 48_000_000)?,
            max_batch: int("maxWriteBatchSize", 100_000)?,
            set_name: text("setName")?,
            writable_primary: writable,
            primary: text("primary")?,
        })
    }
}

/// A logged-in connection to the server.
pub struct Upstream {
    pub io: BoxedIo,
    pub info: ServerInfo,
    next_id: i32,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

/// How the worker proves who it is.
#[derive(Debug)]
pub enum Login {
    Scram {
        sha: Sha,
        user: String,
        password: Secret<String>,
    },
    X509,
    Aws(sigv4::Credentials),
}

impl Login {
    /// The mechanism a resource's `auth` selects.
    #[must_use]
    pub fn sha_for(auth: MongoAuth) -> Option<Sha> {
        match auth {
            MongoAuth::Scram => Some(Sha::Sha256),
            MongoAuth::ScramSha1 => Some(Sha::Sha1),
            MongoAuth::X509 | MongoAuth::Aws => None,
        }
    }
}

/// The two SCRAM variants MongoDB servers offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha {
    Sha1,
    Sha256,
}

impl Sha {
    fn mechanism(self) -> &'static str {
        match self {
            Sha::Sha1 => "SCRAM-SHA-1",
            Sha::Sha256 => "SCRAM-SHA-256",
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let alg = match self {
            Sha::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Sha::Sha256 => hmac::HMAC_SHA256,
        };
        hmac::sign(&hmac::Key::new(alg, key), data)
            .as_ref()
            .to_vec()
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        let alg = match self {
            Sha::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            Sha::Sha256 => &digest::SHA256,
        };
        digest::digest(alg, data).as_ref().to_vec()
    }

    fn salted(self, password: &[u8], salt: &[u8], rounds: std::num::NonZeroU32) -> Vec<u8> {
        let (alg, len) = match self {
            Sha::Sha1 => (pbkdf2::PBKDF2_HMAC_SHA1, 20),
            Sha::Sha256 => (pbkdf2::PBKDF2_HMAC_SHA256, 32),
        };
        let mut out = vec![0u8; len];
        pbkdf2::derive(alg, rounds, salt, password, &mut out);
        out
    }

    /// What goes into the key derivation. SHA-1 uses the legacy digest
    /// `hex(md5("user:mongo:password"))`; SHA-256 uses the password.
    fn secret(self, user: &str, password: &str) -> Vec<u8> {
        match self {
            Sha::Sha256 => password.as_bytes().to_vec(),
            Sha::Sha1 => {
                use md5::{Digest, Md5};
                let sum = Md5::new()
                    .chain_update(user.as_bytes())
                    .chain_update(b":mongo:")
                    .chain_update(password.as_bytes())
                    .finalize();
                sum.iter()
                    .fold(String::new(), |mut s, b| {
                        use std::fmt::Write as _;
                        let _ = write!(s, "{b:02x}");
                        s
                    })
                    .into_bytes()
            }
        }
    }
}

/// The client's side of one SCRAM exchange (RFC 5802, RFC 7677).
pub struct Scram {
    sha: Sha,
    bare: String,
    expected_server_signature: Option<Vec<u8>>,
}

impl std::fmt::Debug for Scram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scram")
            .field("sha", &self.sha)
            .finish_non_exhaustive()
    }
}

impl Scram {
    /// The client-first message, and the state to finish the exchange.
    #[must_use]
    pub fn start(sha: Sha, user: &str, nonce: &str) -> (Self, String) {
        // Role names are `[A-Za-z0-9_.-]`: nothing to escape.
        let bare = format!("n={user},r={nonce}");
        let first = format!("n,,{bare}");
        (
            Self {
                sha,
                bare,
                expected_server_signature: None,
            },
            first,
        )
    }

    /// The client-final message, from the server-first message.
    pub fn respond(
        &mut self,
        user: &str,
        password: &str,
        server_first: &str,
    ) -> Result<String, UpstreamError> {
        let (mut nonce, mut salt, mut iterations) = (None, None, None);
        for part in server_first.split(',') {
            match part.split_once('=') {
                Some(("r", v)) => nonce = Some(v),
                Some(("s", v)) => {
                    salt = Some(B64.decode(v).map_err(|_| protocol("bad SCRAM salt"))?);
                }
                Some(("i", v)) => {
                    iterations = Some(v.parse::<u32>().map_err(|_| protocol("bad SCRAM count"))?);
                }
                _ => {}
            }
        }
        let (Some(nonce), Some(salt), Some(iterations)) = (nonce, salt, iterations) else {
            return Err(protocol("malformed SCRAM server-first message"));
        };
        let ours = self
            .bare
            .split(',')
            .find_map(|p| p.strip_prefix("r="))
            .ok_or_else(|| protocol("malformed SCRAM state"))?;
        if !nonce.starts_with(ours) || nonce.len() == ours.len() {
            return Err(protocol("the server's SCRAM nonce doesn't extend ours"));
        }
        let rounds = std::num::NonZeroU32::new(iterations)
            .filter(|n| n.get() <= MAX_ITERATIONS)
            .ok_or_else(|| {
                protocol("the server asked for an unreasonable SCRAM iteration count")
            })?;

        let salted = self
            .sha
            .salted(&self.sha.secret(user, password), &salt, rounds);
        let client_key = self.sha.hmac(&salted, b"Client Key");
        let stored_key = self.sha.hash(&client_key);
        let without_proof = format!("c=biws,r={nonce}");
        let auth_message = format!("{},{server_first},{without_proof}", self.bare);
        let client_signature = self.sha.hmac(&stored_key, auth_message.as_bytes());
        let proof: Vec<u8> = client_key
            .iter()
            .zip(&client_signature)
            .map(|(a, b)| a ^ b)
            .collect();
        let server_key = self.sha.hmac(&salted, b"Server Key");
        self.expected_server_signature = Some(self.sha.hmac(&server_key, auth_message.as_bytes()));
        Ok(format!("{without_proof},p={}", B64.encode(proof)))
    }

    /// Check the `v=` of the server-final message: the server proves it knows
    /// the password too.
    #[must_use]
    pub fn verify_server_final(&self, server_final: &str) -> bool {
        let Some(expected) = &self.expected_server_signature else {
            return false;
        };
        let Some(v) = server_final.strip_prefix("v=") else {
            return false;
        };
        let v = v.split(',').next().unwrap_or_default();
        B64.decode(v.trim())
            .is_ok_and(|got| subtle::ConstantTimeEq::ct_eq(&got[..], &expected[..]).into())
    }
}

fn client_metadata(app_name: &str) -> Builder {
    Builder::new()
        .doc("application", &Builder::new().str("name", app_name))
        .doc(
            "driver",
            &Builder::new()
                .str("name", "limen")
                .str("version", env!("CARGO_PKG_VERSION")),
        )
        .doc("os", &Builder::new().str("type", std::env::consts::OS))
}

impl Upstream {
    /// Send a command and return the answer document. An answer with `ok: 0`
    /// is an error.
    pub async fn run(&mut self, command: Vec<u8>) -> Result<Vec<u8>, UpstreamError> {
        run_on(&mut self.io, &mut self.next_id, command).await
    }
}

async fn run_on(
    io: &mut BoxedIo,
    next_id: &mut i32,
    command: Vec<u8>,
) -> Result<Vec<u8>, UpstreamError> {
    let id = *next_id;
    *next_id = next_id.wrapping_add(1).max(1);
    let header = Header {
        request_id: id,
        response_to: 0,
        opcode: OP_MSG,
    };
    tokio::time::timeout(
        STEP_TIMEOUT,
        wire::write_message(io, header, &wire::op_msg_body(&command)),
    )
    .await
    .map_err(|_| UpstreamError::Timeout("sending a command"))??;
    let reply = tokio::time::timeout(STEP_TIMEOUT, wire::read_message(io))
        .await
        .map_err(|_| UpstreamError::Timeout("waiting for the server"))??
        .ok_or_else(|| protocol("the server closed the connection"))?;
    if reply.header.opcode != OP_MSG || reply.header.response_to != id {
        return Err(protocol("unexpected reply from the server"));
    }
    let msg = wire::parse_op_msg(&reply.body)?;
    let doc = msg.command;
    if doc.get("ok")?.is_some_and(|v| v.is_truthy()) {
        return Ok(doc.as_bytes().to_vec());
    }
    Err(UpstreamError::Command {
        code: doc
            .get("code")?
            .and_then(|v| v.as_i64())
            .and_then(|v| i32::try_from(v).ok())
            .unwrap_or(0),
        code_name: doc
            .get("codeName")?
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default(),
        message: doc
            .get("errmsg")?
            .and_then(|v| v.as_str().map(|s| s.chars().take(200).collect()))
            .unwrap_or_default(),
    })
}

async fn open(target: &Target) -> Result<BoxedIo, UpstreamError> {
    let tcp = target.dial().await?;
    if target.uses_tls() {
        Ok(target.start_tls(tcp).await?)
    } else {
        Ok(Box::new(tcp))
    }
}

/// Connect, find the primary, and log in. `app_name` (`limen:<session>`) goes
/// into the server's log and `currentOp`, tying them to the Limen session.
pub async fn connect(
    target: &Target,
    login: &Login,
    auth_source: &str,
    app_name: &str,
) -> Result<Upstream, UpstreamError> {
    let mut target = target.clone();
    // At most one hop: a secondary names its primary; a primary that names
    // another is a cluster in the middle of an election.
    for hop in 0..2 {
        let mut io = open(&target).await?;
        let mut next_id = 1;
        // `isMaster` is understood by every server, `DocumentDB` included.
        let hello = Builder::new()
            .i32("isMaster", 1)
            .bool("helloOk", true)
            .doc("client", &client_metadata(app_name))
            .str("$db", "admin")
            .finish();
        let reply = run_on(&mut io, &mut next_id, hello).await?;
        let info = ServerInfo::from_hello(Doc::new(&reply)?)?;
        if info.max_wire < 6 {
            return Err(protocol(
                "the server is older than MongoDB 3.6, which Limen needs for OP_MSG",
            ));
        }
        if !info.writable_primary {
            match (&info.primary, hop) {
                (Some(primary), 0) if *primary != target.endpoint => {
                    target = target.with_endpoint(primary).map_err(protocol)?;
                    continue;
                }
                _ => {
                    return Err(protocol(
                        "the server isn't the primary and no primary is known (an election may be running)",
                    ));
                }
            }
        }
        let mut upstream = Upstream { io, info, next_id };
        authenticate(&mut upstream, login, auth_source).await?;
        return Ok(upstream);
    }
    Err(protocol("couldn't reach a writable primary"))
}

async fn authenticate(
    up: &mut Upstream,
    login: &Login,
    auth_source: &str,
) -> Result<(), UpstreamError> {
    match login {
        Login::Scram {
            sha,
            user,
            password,
        } => scram(up, *sha, user, password.expose(), auth_source).await,
        Login::X509 => {
            let cmd = Builder::new()
                .i32("authenticate", 1)
                .str("mechanism", "MONGODB-X509")
                .str("$db", "$external")
                .finish();
            up.run(cmd).await.map(|_| ())
        }
        Login::Aws(creds) => aws(up, creds, OffsetDateTime::now_utc()).await,
    }
}

fn payload(reply: &[u8]) -> Result<(i32, bool, &[u8]), UpstreamError> {
    let doc = Doc::new(reply)?;
    let conversation = doc
        .get("conversationId")?
        .and_then(|v| v.as_i64())
        .and_then(|v| i32::try_from(v).ok())
        .ok_or_else(|| protocol("no conversationId in the SASL reply"))?;
    let done = doc.get("done")?.is_some_and(|v| v.is_truthy());
    let bytes = match doc.get("payload")? {
        Some(Value::Binary { bytes, .. }) => bytes,
        _ => &[],
    };
    Ok((conversation, done, bytes))
}

async fn scram(
    up: &mut Upstream,
    sha: Sha,
    user: &str,
    password: &str,
    auth_source: &str,
) -> Result<(), UpstreamError> {
    let nonce = B64.encode(rand::random::<[u8; 24]>());
    let (mut state, first) = Scram::start(sha, user, &nonce);
    let start = Builder::new()
        .i32("saslStart", 1)
        .str("mechanism", sha.mechanism())
        .binary("payload", first.as_bytes())
        .doc("options", &Builder::new().bool("skipEmptyExchange", true))
        .str("$db", auth_source)
        .finish();
    let reply = up.run(start).await?;
    let (conversation, done, server_first) = payload(&reply)?;
    if done {
        return Err(protocol("the server ended the SCRAM exchange early"));
    }
    let server_first =
        std::str::from_utf8(server_first).map_err(|_| protocol("SCRAM payload isn't text"))?;
    let final_message = state.respond(user, password, server_first)?;
    let next = Builder::new()
        .i32("saslContinue", 1)
        .i32("conversationId", conversation)
        .binary("payload", final_message.as_bytes())
        .str("$db", auth_source)
        .finish();
    let reply = up.run(next).await?;
    let (_, mut done, server_final) = payload(&reply)?;
    let server_final =
        std::str::from_utf8(server_final).map_err(|_| protocol("SCRAM payload isn't text"))?;
    if !state.verify_server_final(server_final) {
        return Err(protocol(
            "the server didn't prove it knows the password (SCRAM server signature mismatch)",
        ));
    }
    // Without `skipEmptyExchange` support the server wants one empty message.
    for _ in 0..2 {
        if done {
            return Ok(());
        }
        let empty = Builder::new()
            .i32("saslContinue", 1)
            .i32("conversationId", conversation)
            .binary("payload", b"")
            .str("$db", auth_source)
            .finish();
        let reply = up.run(empty).await?;
        done = payload(&reply)?.1;
    }
    if done {
        Ok(())
    } else {
        Err(protocol("the SCRAM exchange didn't finish"))
    }
}

/// The region for an STS host, as the `MONGODB-AWS` specification derives it.
fn sts_region(host: &str) -> &str {
    if host == "sts.amazonaws.com" {
        return "us-east-1";
    }
    host.split('.').nth(1).unwrap_or("us-east-1")
}

const STS_BODY: &str = "Action=GetCallerIdentity&Version=2011-06-15";

/// `MONGODB-AWS`: prove the worker's IAM identity by signing an STS
/// `GetCallerIdentity` request that the *server* sends to AWS.
/// *Unverified against Atlas or `DocumentDB`*: written to the specification and
/// checked against a stand-in server only.
async fn aws(
    up: &mut Upstream,
    creds: &sigv4::Credentials,
    now: OffsetDateTime,
) -> Result<(), UpstreamError> {
    let nonce = rand::random::<[u8; 32]>();
    let first = Builder::new().binary("r", &nonce).i32("p", 110).finish();
    let start = Builder::new()
        .i32("saslStart", 1)
        .str("mechanism", "MONGODB-AWS")
        .binary("payload", &first)
        .str("$db", "$external")
        .finish();
    let reply = up.run(start).await?;
    let (conversation, done, server_first) = payload(&reply)?;
    if done {
        return Err(protocol("the server ended the MONGODB-AWS exchange early"));
    }
    let doc = Doc::new(server_first)?;
    let Some(Value::Binary {
        bytes: server_nonce,
        ..
    }) = doc.get("s")?
    else {
        return Err(protocol("MONGODB-AWS reply has no server nonce"));
    };
    if server_nonce.len() != 64 || !server_nonce.starts_with(&nonce) {
        return Err(protocol("MONGODB-AWS server nonce doesn't extend ours"));
    }
    let host = doc
        .get("h")?
        .and_then(|v| v.as_str().map(str::to_owned))
        .filter(|h| {
            !h.is_empty()
                && h.len() <= 255
                && h.split('.').count() >= 3
                && h.starts_with("sts.")
                && h.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        })
        .ok_or_else(|| protocol("MONGODB-AWS reply names an STS host the worker won't sign for"))?;
    let signed = sign_sts(creds, &host, server_nonce, now);
    let mut answer = Builder::new()
        .str("a", &signed.authorization)
        .str("d", &signed.amz_date);
    if let Some(token) = &signed.session_token {
        answer = answer.str("t", token);
    }
    let next = Builder::new()
        .i32("saslContinue", 1)
        .i32("conversationId", conversation)
        .binary("payload", &answer.finish())
        .str("$db", "$external")
        .finish();
    let reply = up.run(next).await?;
    if payload(&reply)?.1 {
        Ok(())
    } else {
        Err(protocol("the MONGODB-AWS exchange didn't finish"))
    }
}

/// The signed STS request the server will forward to AWS.
fn sign_sts(
    creds: &sigv4::Credentials,
    host: &str,
    server_nonce: &[u8],
    now: OffsetDateTime,
) -> sigv4::SignedHeaders {
    let nonce_b64 = B64.encode(server_nonce);
    let length = STS_BODY.len().to_string();
    sigv4::sign_headers(
        &sigv4::Target {
            method: "POST",
            host,
            path: "/",
            region: sts_region(host),
            service: "sts",
        },
        "",
        &[
            ("content-length", length.as_str()),
            ("content-type", "application/x-www-form-urlencoded"),
            ("x-mongodb-gs2-cb-flag", "n"),
            ("x-mongodb-server-nonce", nonce_b64.as_str()),
        ],
        STS_BODY.as_bytes(),
        creds,
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7677 section 3 (SCRAM-SHA-256).
    #[test]
    fn scram_sha256_matches_the_rfc_7677_example() {
        let (mut s, first) = Scram::start(Sha::Sha256, "user", "rOprNGfwEbeRWgbNEkqO");
        assert_eq!(first, "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
        let server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let fin = s.respond("user", "pencil", server_first).expect("final");
        assert_eq!(
            fin,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        assert!(s.verify_server_final("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="));
        assert!(!s.verify_server_final("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        assert!(!s.verify_server_final("e=invalid-proof"));
    }

    // RFC 5802 section 5 (SCRAM-SHA-1), with the password used as the salted
    // input directly (the RFC predates MongoDB's MD5 pre-hash).
    #[test]
    fn scram_sha1_matches_the_rfc_5802_example() {
        let sha = Sha::Sha1;
        let salted = sha.salted(
            b"pencil",
            &B64.decode("QSXCR+Q6sek8bf92").expect("salt"),
            std::num::NonZeroU32::new(4096).expect("n"),
        );
        let client_key = sha.hmac(&salted, b"Client Key");
        let stored = sha.hash(&client_key);
        let auth = "n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j";
        let signature = sha.hmac(&stored, auth.as_bytes());
        let proof: Vec<u8> = client_key
            .iter()
            .zip(&signature)
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(B64.encode(proof), "v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");
        let server_key = sha.hmac(&salted, b"Server Key");
        assert_eq!(
            B64.encode(sha.hmac(&server_key, auth.as_bytes())),
            "rmF9pqV8S7suAoZWja4dJRkFsKQ="
        );
    }

    #[test]
    fn scram_sha1_hashes_the_password_the_way_mongodb_does() {
        // hex(md5("user:mongo:pencil"))
        let secret = Sha::Sha1.secret("user", "pencil");
        assert_eq!(secret.len(), 32);
        assert!(secret.iter().all(u8::is_ascii_hexdigit));
        assert_eq!(Sha::Sha256.secret("user", "pencil"), b"pencil");
    }

    #[test]
    fn scram_refuses_a_foreign_nonce_and_absurd_counts() {
        let (mut s, _) = Scram::start(Sha::Sha256, "u", "abc");
        let err = s
            .respond("u", "p", "r=zzz,s=QQ==,i=4096")
            .expect_err("nonce");
        assert!(err.to_string().contains("nonce"));
        let err = s
            .respond("u", "p", "r=abcdef,s=QQ==,i=4000000000")
            .expect_err("count");
        assert!(err.to_string().contains("iteration"));
        assert!(s.respond("u", "p", "nonsense").is_err());
        assert!(
            !s.verify_server_final("v=AAAA"),
            "nothing to compare with yet"
        );
    }

    #[test]
    fn the_sts_region_comes_from_the_host() {
        assert_eq!(sts_region("sts.amazonaws.com"), "us-east-1");
        assert_eq!(sts_region("sts.eu-west-1.amazonaws.com"), "eu-west-1");
        assert_eq!(sts_region("sts.cn-north-1.amazonaws.com.cn"), "cn-north-1");
    }

    #[test]
    fn the_sts_request_signs_the_server_nonce_and_the_mongodb_headers() {
        let creds = sigv4::Credentials {
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: Secret::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into()),
            session_token: Some(Secret::new("token".into())),
        };
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("time");
        let nonce = [7u8; 64];
        let signed = sign_sts(&creds, "sts.amazonaws.com", &nonce, now);
        assert!(signed.authorization.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231114/us-east-1/sts/aws4_request"
        ));
        assert!(signed.authorization.contains(
            "SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-security-token;x-mongodb-gs2-cb-flag;x-mongodb-server-nonce"
        ));
        assert_eq!(signed.amz_date, "20231114T221320Z");
        assert_eq!(signed.session_token.as_deref(), Some("token"));
        // A different server nonce changes the signature.
        let other = sign_sts(&creds, "sts.amazonaws.com", &[8u8; 64], now);
        assert_ne!(signed.authorization, other.authorization);
    }

    #[test]
    fn reads_the_handshake_the_way_drivers_do() {
        let reply = Builder::new()
            .bool("ismaster", true)
            .bool("isWritablePrimary", true)
            .i32("maxBsonObjectSize", 16_777_216)
            .i32("maxMessageSizeBytes", 48_000_000)
            .i32("maxWriteBatchSize", 100_000)
            .i32("logicalSessionTimeoutMinutes", 30)
            .i32("minWireVersion", 0)
            .i32("maxWireVersion", 25)
            .str("setName", "rs0")
            .f64("ok", 1.0)
            .finish();
        let info = ServerInfo::from_hello(Doc::new(&reply).expect("doc")).expect("info");
        assert_eq!(info.max_wire, 25);
        assert_eq!(info.session_timeout_minutes, Some(30));
        assert_eq!(info.set_name.as_deref(), Some("rs0"));
        assert!(info.writable_primary);

        let secondary = Builder::new()
            .bool("ismaster", false)
            .str("primary", "db1.example.com:27017")
            .i32("maxWireVersion", 17)
            .finish();
        let info = ServerInfo::from_hello(Doc::new(&secondary).expect("doc")).expect("info");
        assert!(!info.writable_primary);
        assert_eq!(info.primary.as_deref(), Some("db1.example.com:27017"));
    }
}

//! Connecting to the Redis or Valkey server and logging in as the role's
//! user (ADR-0034). The credential is the worker's: an ACL password it was
//! given, or an IAM token it signs (`ElastiCache`). The person never sees it.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use aws_lc_rs::hmac;
use limen_core::secret::Secret;
use limen_policy::RedisTarget;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::codec::{FrameScanner, Value, encode_command, parse_value};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest reply the worker reads for itself (`COMMAND INFO` is about 100 KB).
const MAX_SETUP_REPLY: usize = 8 * 1024 * 1024;

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type BoxedStream = Box<dyn Stream>;

/// Settings the operator gives the worker for Redis targets.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// Trust anchors for TLS to the target (the AWS bundle for `ElastiCache`).
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// Passwords by resource name, then Redis user.
    passwords: BTreeMap<String, BTreeMap<String, Secret<String>>>,
}

impl Settings {
    /// Read the CA bundle and the credentials file named in the worker's config.
    pub fn load(ca_file: Option<&Path>, credentials_file: Option<&Path>) -> anyhow::Result<Self> {
        let tls = match ca_file {
            Some(path) => {
                let pem = std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                Some(Arc::new(tls_config(&pem)?))
            }
            None => None,
        };
        let passwords = match credentials_file {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                parse_passwords(&text).with_context(|| format!("parsing {}", path.display()))?
            }
            None => BTreeMap::new(),
        };
        Ok(Self { tls, passwords })
    }

    fn password(&self, resource: &str, user: &str) -> Option<&Secret<String>> {
        self.passwords.get(resource)?.get(user)
    }
}

/// `{"<resource>": {"<redis user>": "<password>"}}`
fn parse_passwords(
    text: &str,
) -> anyhow::Result<BTreeMap<String, BTreeMap<String, Secret<String>>>> {
    let raw: BTreeMap<String, BTreeMap<String, String>> = serde_json::from_str(text)?;
    Ok(raw
        .into_iter()
        .map(|(resource, users)| {
            (
                resource,
                users
                    .into_iter()
                    .map(|(u, p)| (u, Secret::new(p)))
                    .collect(),
            )
        })
        .collect())
}

fn tls_config(pem: &str) -> anyhow::Result<rustls::ClientConfig> {
    use rustls_pki_types::{CertificateDer, pem::PemObject as _};
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        roots.add(cert.context("certificate PEM")?)?;
    }
    if roots.is_empty() {
        bail!("no certificates in the Redis CA file");
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// A logged-in connection and what the worker learned from the server.
impl std::fmt::Debug for Connected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connected").finish_non_exhaustive()
    }
}

pub struct Connected {
    pub stream: BoxedStream,
    /// The raw reply to `COMMAND INFO`, parsed.
    pub command_info: Value,
}

/// Open the connection, log in, and name it after the Limen session.
pub async fn connect(
    settings: &Settings,
    resource: &str,
    target: &RedisTarget,
    redis_user: &str,
    session_id: &str,
) -> anyhow::Result<Connected> {
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&target.endpoint))
        .await
        .context("connecting to the Redis server timed out")?
        .with_context(|| format!("connecting to {}", target.endpoint))?;
    tcp.set_nodelay(true)?;
    let mut stream: BoxedStream = if target.tls {
        let config = settings.tls.clone().context(
            "this resource needs TLS but the worker has no --redis-ca-file (for ElastiCache, the AWS CA bundle)",
        )?;
        let host = target
            .endpoint
            .rsplit_once(':')
            .map_or(target.endpoint.as_str(), |(h, _)| h)
            // `[::1]:6379`: the name has no brackets.
            .trim_matches(['[', ']'])
            .to_owned();
        let name =
            rustls_pki_types::ServerName::try_from(host).context("the endpoint's host name")?;
        // A server that doesn't speak TLS may just sit there.
        let tls = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_rustls::TlsConnector::from(config).connect(name, tcp),
        )
        .await
        .context("the TLS handshake with the Redis server timed out (does it speak TLS?)")?
        .context("TLS to the Redis server")?;
        Box::new(tls)
    } else {
        Box::new(tcp)
    };

    let password = if target.iam_auth {
        iam_token(target, redis_user).await?
    } else {
        settings
            .password(resource, redis_user)
            .with_context(|| {
                format!("the worker has no password for {redis_user:?} on {resource:?} (--redis-credentials-file)")
            })?
            .clone()
    };
    let mut buf = Vec::new();
    // The password goes straight from the secret into the request.
    let auth = encode_command(&[
        b"AUTH".as_slice(),
        redis_user.as_bytes(),
        password.expose().as_bytes(),
    ]);
    if let Value::Error(e) = round_trip(&mut stream, &mut buf, &auth).await? {
        bail!("the Redis server refused the login: {e}");
    }
    // The server's reply may be an error for any of these on old servers; only
    // COMMAND INFO is required.
    let name = format!("limen:{session_id}");
    let _ = round_trip(
        &mut stream,
        &mut buf,
        &encode_command(&[b"CLIENT".as_slice(), b"SETNAME", name.as_bytes()]),
    )
    .await?;
    let _ = round_trip(
        &mut stream,
        &mut buf,
        &encode_command(&[b"CLIENT".as_slice(), b"SETINFO", b"LIB-NAME", b"limen"]),
    )
    .await?;
    let command_info = round_trip(
        &mut stream,
        &mut buf,
        &encode_command(&[b"COMMAND".as_slice(), b"INFO"]),
    )
    .await?;
    if let Value::Error(e) = &command_info {
        bail!("COMMAND INFO failed: {e}");
    }
    Ok(Connected {
        stream,
        command_info,
    })
}

/// Send one request and read its one reply. There is no pipelining at setup,
/// so nothing is left in `buf` afterwards.
async fn round_trip(
    stream: &mut BoxedStream,
    buf: &mut Vec<u8>,
    request: &[u8],
) -> anyhow::Result<Value> {
    stream.write_all(request).await?;
    stream.flush().await?;
    buf.clear();
    let mut scanner = FrameScanner::new();
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        if let Some(len) = scanner.advance(buf)? {
            let value = parse_value(&buf[..len])?;
            buf.drain(..len);
            return Ok(value);
        }
        if buf.len() > MAX_SETUP_REPLY {
            bail!("the Redis server's reply was too large");
        }
        let n = tokio::time::timeout(CONNECT_TIMEOUT, stream.read(&mut chunk))
            .await
            .context("the Redis server didn't answer in time")??;
        if n == 0 {
            bail!("the Redis server closed the connection");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// A fresh `ElastiCache` IAM token for `user` (valid 15 minutes).
pub async fn iam_token(target: &RedisTarget, user: &str) -> anyhow::Result<Secret<String>> {
    use aws_credential_types::provider::ProvideCredentials as _;
    let host = target
        .cache_name
        .as_deref()
        .context("an IAM resource needs cache_name (the replication group ID)")?;
    let region = target
        .region
        .clone()
        .context("an IAM resource needs region")?;
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.clone()))
        .load()
        .await;
    let provider = config
        .credentials_provider()
        .context("the worker has no AWS credentials")?;
    let creds = provider
        .provide_credentials()
        .await
        .context("loading the worker's AWS credentials")?;
    let signing = Credentials {
        access_key: creds.access_key_id().to_owned(),
        secret_key: Secret::new(creds.secret_access_key().to_owned()),
        session_token: creds.session_token().map(str::to_owned),
    };
    Ok(Secret::new(presign_connect(
        &signing,
        &region,
        host,
        user,
        OffsetDateTime::now_utc(),
    )))
}

#[derive(Debug)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: Secret<String>,
    pub session_token: Option<String>,
}

/// The `SigV4` query-signed `connect` request `ElastiCache` takes as a password,
/// without the scheme. *Unverified against a real cluster.*
#[must_use]
pub fn presign_connect(
    creds: &Credentials,
    region: &str,
    host: &str,
    user: &str,
    now: OffsetDateTime,
) -> String {
    const SERVICE: &str = "elasticache";
    let date = format!(
        "{:04}{:02}{:02}",
        now.year(),
        u8::from(now.month()),
        now.day()
    );
    let amz_date = format!(
        "{date}T{:02}{:02}{:02}Z",
        now.hour(),
        now.minute(),
        now.second()
    );
    let scope = format!("{date}/{region}/{SERVICE}/aws4_request");
    let mut params: Vec<(String, String)> = vec![
        ("Action".into(), "connect".into()),
        ("User".into(), user.into()),
        ("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()),
        (
            "X-Amz-Credential".into(),
            format!("{}/{scope}", creds.access_key),
        ),
        ("X-Amz-Date".into(), amz_date.clone()),
        ("X-Amz-Expires".into(), "900".into()),
        ("X-Amz-SignedHeaders".into(), "host".into()),
    ];
    if let Some(token) = &creds.session_token {
        params.push(("X-Amz-Security-Token".into(), token.clone()));
    }
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (uri_encode(k), uri_encode(v)))
        .collect();
    encoded.sort();
    let query = encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let canonical = format!(
        "GET\n/\n{query}\nhost:{host}\n\nhost\n{}",
        hex(&Sha256::digest(b""))
    );
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let signature = hex(&sign(
        &signing_key(creds.secret_key.expose(), &date, region, SERVICE),
        to_sign.as_bytes(),
    ));
    format!("{host}/?{query}&X-Amz-Signature={signature}")
}

fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k = sign(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k = sign(&k, region.as_bytes());
    let k = sign(&k, service.as_bytes());
    sign(&k, b"aws4_request")
}

fn sign(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, data).as_ref().to_vec()
}

pub(super) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// RFC 3986 percent-encoding, as `SigV4` wants it.
fn uri_encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_the_connect_request_like_an_independent_implementation() {
        // Expected value computed with Python's hmac and hashlib, not with this code.
        let creds = Credentials {
            access_key: "AKIDEXAMPLE".into(),
            secret_key: Secret::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into()),
            session_token: Some("TOKEN/abc+=".into()),
        };
        let now = time::macros::datetime!(2026-10-17 12:00:00 UTC);
        let token = presign_connect(&creds, "us-east-1", "my-group", "limen-ro", now);
        assert_eq!(
            token,
            "my-group/?Action=connect&User=limen-ro&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20261017%2Fus-east-1%2Felasticache%2Faws4_request&X-Amz-Date=20261017T120000Z&X-Amz-Expires=900&X-Amz-Security-Token=TOKEN%2Fabc%2B%3D&X-Amz-SignedHeaders=host&X-Amz-Signature=e8b659516dd104d8316d1d96a28fd04a682e9c5a051f41d927cc5a881f9b7fbb"
        );
    }

    #[test]
    fn derives_the_documented_signing_key() {
        // From "Examples of how to derive a signing key" in the AWS docs.
        let key = signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            hex(&key),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    #[test]
    fn reads_the_credentials_file_without_printing_it() {
        let parsed = parse_passwords(r#"{"cache":{"limen-rw":"s3cret"}}"#).expect("parse");
        assert_eq!(parsed["cache"]["limen-rw"].expose(), "s3cret");
        assert!(!format!("{parsed:?}").contains("s3cret"));
        assert!(parse_passwords("[1]").is_err());
    }

    #[test]
    fn tls_needs_a_certificate() {
        assert!(tls_config("not pem").is_err());
    }
}

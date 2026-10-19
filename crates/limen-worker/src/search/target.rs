//! Connecting to the `OpenSearch` or Elasticsearch server and authenticating as
//! the engine role the grant names (ADR-0036). The credential is the worker's:
//! a password, API key, bearer token, or client certificate it was given, or
//! a `SigV4` signature made with its AWS credentials. The person never sees it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use base64::Engine as _;
use http_body_util::BodyExt as _;
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use limen_core::secret::Secret;
use limen_policy::SearchTarget;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use serde::Deserialize;
use time::OffsetDateTime;
use tokio::net::TcpStream;

use crate::db::sigv4::{self, Credentials};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a body stopped: the peer, or the worker's own idle limit.
pub type BodyError = Box<dyn std::error::Error + Send + Sync>;

/// The body type of a request to the target, and of the replies the worker sends.
pub type ReqBody = BoxBody<Bytes, BodyError>;

/// How the worker gets AWS credentials for a `SigV4` target.
pub type AwsSource = Arc<
    dyn Fn() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Credentials, String>> + Send>,
        > + Send
        + Sync,
>;

/// Settings the operator gives the worker for search targets.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// Trust anchors for TLS to the target (the Amazon bundle for `OpenSearch`
    /// Service, or the system bundle for Elastic Cloud).
    roots: Option<Arc<rustls::RootCertStore>>,
    /// Credentials by resource name, then engine role.
    entries: BTreeMap<String, BTreeMap<String, Entry>>,
    /// The most a request body may take in memory when the worker has to read it.
    max_body: usize,
    /// A connection with no request for this long ends.
    idle: Duration,
}

/// The default for [`Settings::with_idle`].
pub const DEFAULT_IDLE: Duration = Duration::from_hours(1);

/// The default for [`Settings::with_max_body`].
pub const DEFAULT_MAX_BODY: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
struct Entry {
    /// The `Authorization` header value to send, if the role uses one.
    authorization: Option<Secret<String>>,
    /// A client certificate chain and key for mTLS, as PEM.
    client: Option<ClientCert>,
}

#[derive(Debug, Clone)]
struct ClientCert {
    chain: Vec<CertificateDer<'static>>,
    key: Arc<Secret<Vec<u8>>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBasic {
    username: String,
    password: String,
}

/// `{"<resource>": {"<engine role>": {"basic": {...}} }}`
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    basic: Option<RawBasic>,
    /// Either the encoded key Elasticsearch shows, or `id:api_key`.
    api_key: Option<String>,
    bearer: Option<String>,
    client_cert_file: Option<PathBuf>,
    client_key_file: Option<PathBuf>,
}

impl Settings {
    /// Read the CA bundle and the credentials file named in the worker's config.
    pub fn load(ca_file: Option<&Path>, credentials_file: Option<&Path>) -> anyhow::Result<Self> {
        let roots = match ca_file {
            Some(path) => {
                let pem =
                    std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
                let mut roots = rustls::RootCertStore::empty();
                for cert in CertificateDer::pem_slice_iter(&pem) {
                    roots
                        .add(cert.context("certificate PEM in the search CA file")?)
                        .context("a certificate in the search CA file")?;
                }
                if roots.is_empty() {
                    bail!("no certificates in the search CA file");
                }
                Some(Arc::new(roots))
            }
            None => None,
        };
        let entries = match credentials_file {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                parse_entries(&text).with_context(|| format!("parsing {}", path.display()))?
            }
            None => BTreeMap::new(),
        };
        Ok(Self {
            roots,
            entries,
            max_body: DEFAULT_MAX_BODY,
            idle: DEFAULT_IDLE,
        })
    }

    /// Change how long a connection may sit with no request before it ends.
    #[must_use]
    pub fn with_idle(mut self, idle: Duration) -> Self {
        self.idle = idle;
        self
    }

    /// Change the cap on bodies the worker must read (`_bulk`, searches, and
    /// everything on a `SigV4` target).
    #[must_use]
    pub fn with_max_body(mut self, bytes: usize) -> Self {
        self.max_body = bytes.max(1024);
        self
    }

    fn entry(&self, resource: &str, role: &str) -> Option<&Entry> {
        self.entries.get(resource)?.get(role)
    }

    /// Whether the worker was given a credential for this role on this resource.
    #[must_use]
    pub fn has_credential(&self, resource: &str, role: &str) -> bool {
        self.entry(resource, role).is_some()
    }
}

fn parse_entries(text: &str) -> anyhow::Result<BTreeMap<String, BTreeMap<String, Entry>>> {
    let raw: BTreeMap<String, BTreeMap<String, RawEntry>> = serde_json::from_str(text)?;
    let mut out = BTreeMap::new();
    for (resource, roles) in raw {
        let mut parsed = BTreeMap::new();
        for (role, e) in roles {
            let what = format!("{resource}/{role}");
            let set = [e.basic.is_some(), e.api_key.is_some(), e.bearer.is_some()];
            if set.into_iter().filter(|s| *s).count() > 1 {
                bail!("{what}: set only one of basic, api_key, and bearer");
            }
            let authorization = if let Some(b) = &e.basic {
                if b.username.contains(':') {
                    bail!("{what}: a basic-auth user name can't contain a colon");
                }
                let token = base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", b.username, b.password));
                Some(Secret::new(format!("Basic {token}")))
            } else if let Some(k) = &e.api_key {
                // `id:api_key` is encoded for the header; the form Elasticsearch
                // displays ("encoded") already is.
                let token = if k.contains(':') {
                    base64::engine::general_purpose::STANDARD.encode(k)
                } else {
                    k.clone()
                };
                Some(Secret::new(format!("ApiKey {token}")))
            } else {
                e.bearer
                    .as_ref()
                    .map(|t| Secret::new(format!("Bearer {t}")))
            };
            if authorization
                .as_ref()
                .is_some_and(|a| a.expose().chars().any(char::is_control))
            {
                bail!("{what}: the credential has a control character");
            }
            let client = match (&e.client_cert_file, &e.client_key_file) {
                (Some(cert), Some(key)) => {
                    let chain = CertificateDer::pem_file_iter(cert)
                        .with_context(|| format!("{what}: reading {}", cert.display()))?
                        .collect::<Result<Vec<_>, _>>()
                        .with_context(|| format!("{what}: certificate PEM"))?;
                    if chain.is_empty() {
                        bail!("{what}: no certificate in {}", cert.display());
                    }
                    let pem = std::fs::read(key)
                        .with_context(|| format!("{what}: reading {}", key.display()))?;
                    // Check now that it parses, so a bad file fails at start-up.
                    PrivateKeyDer::from_pem_slice(&pem)
                        .with_context(|| format!("{what}: private key PEM"))?;
                    Some(ClientCert {
                        chain,
                        key: Arc::new(Secret::new(pem)),
                    })
                }
                (None, None) => None,
                _ => bail!("{what}: set both client_cert_file and client_key_file, or neither"),
            };
            parsed.insert(
                role,
                Entry {
                    authorization,
                    client,
                },
            );
        }
        out.insert(resource, parsed);
    }
    Ok(out)
}

/// How a request to the target is authenticated.
pub enum Auth {
    /// No credential (the server needs none, or authenticates by client certificate).
    None,
    /// A fixed `Authorization` header.
    Header(Secret<String>),
    /// Sign each request with `SigV4`.
    Aws {
        source: AwsSource,
        region: String,
        service: &'static str,
    },
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Auth::None => "Auth::None",
            Auth::Header(_) => "Auth::Header",
            Auth::Aws { .. } => "Auth::Aws",
        })
    }
}

/// A connection to the target, ready for requests.
pub struct Upstream {
    sender: SendRequest<ReqBody>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream").finish_non_exhaustive()
    }
}

impl Upstream {
    /// Whether the connection can take another request.
    pub async fn ready(&mut self) -> bool {
        self.sender.ready().await.is_ok()
    }

    pub async fn send(
        &mut self,
        request: hyper::Request<ReqBody>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, hyper::Error> {
        self.sender.send_request(request).await
    }
}

/// What a session needs to reach the target and to authenticate to it.
#[derive(Debug)]
pub struct Plan {
    pub target: SearchTarget,
    pub auth: Auth,
    /// What goes in `Host` (and what `SigV4` signs).
    pub host: String,
    /// The most a request body may take in memory when the worker has to read it.
    pub max_body: usize,
    /// A connection with no request for this long ends.
    pub idle: Duration,
    connector: Connector,
}

#[derive(Debug)]
struct Connector {
    tls: Option<Arc<rustls::ClientConfig>>,
    server_name: Option<rustls_pki_types::ServerName<'static>>,
}

fn split_endpoint(endpoint: &str) -> (&str, Option<u16>) {
    match endpoint.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(':') || h.starts_with('[') => {
            (h.trim_matches(['[', ']']), p.parse().ok())
        }
        _ => (endpoint.trim_matches(['[', ']']), None),
    }
}

/// The `Host` header: the endpoint, without a default port.
fn host_header(endpoint: &str, tls: bool) -> String {
    let (host, port) = split_endpoint(endpoint);
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    match port {
        Some(443) if tls => host,
        Some(80) if !tls => host,
        Some(p) => format!("{host}:{p}"),
        None => host,
    }
}

/// Work out how to reach the target and authenticate, before any connection.
pub fn plan(
    settings: &Settings,
    resource: &str,
    target: &SearchTarget,
    role: &str,
    aws: Option<AwsSource>,
) -> anyhow::Result<Plan> {
    let entry = settings.entry(resource, role);
    let auth = if target.aws {
        let source = aws.context("this resource needs AWS credentials and the worker has none")?;
        let region = target
            .region
            .clone()
            .context("an AWS search resource needs a region")?;
        Auth::Aws {
            source,
            region,
            service: if target.serverless { "aoss" } else { "es" },
        }
    } else {
        match entry.and_then(|e| e.authorization.clone()) {
            Some(h) => Auth::Header(h),
            None => Auth::None,
        }
    };
    if matches!(auth, Auth::None) && entry.is_none_or(|e| e.client.is_none()) && !target.aws {
        tracing::debug!(
            resource,
            role,
            "no credential for this role: connecting without one"
        );
    }
    let (host, _) = split_endpoint(&target.endpoint);
    let (tls, server_name) = if target.tls {
        let roots = settings.roots.clone().context(
            "this resource needs TLS but the worker has no --search-ca-file (for Amazon OpenSearch Service, the Amazon CA bundle)",
        )?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots);
        let config = match entry.and_then(|e| e.client.as_ref()) {
            Some(c) => {
                let key = PrivateKeyDer::from_pem_slice(c.key.expose())
                    .context("the client key's PEM")?;
                builder
                    .with_client_auth_cert(c.chain.clone(), key)
                    .context("the client certificate and key")?
            }
            None => builder.with_no_client_auth(),
        };
        let name = rustls_pki_types::ServerName::try_from(host.to_owned())
            .context("the endpoint's host name")?;
        (Some(Arc::new(config)), Some(name))
    } else {
        (None, None)
    };
    Ok(Plan {
        target: target.clone(),
        auth,
        host: host_header(&target.endpoint, target.tls),
        max_body: settings.max_body.max(1024),
        idle: settings.idle,
        connector: Connector { tls, server_name },
    })
}

impl Plan {
    /// Open a connection to the target.
    pub async fn connect(&self) -> anyhow::Result<Upstream> {
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.target.endpoint))
            .await
            .context("connecting to the search server timed out")?
            .with_context(|| format!("connecting to {}", self.target.endpoint))?;
        tcp.set_nodelay(true)?;
        let sender = match (&self.connector.tls, &self.connector.server_name) {
            (Some(config), Some(name)) => {
                // A server that doesn't speak TLS may just sit there.
                let tls = tokio::time::timeout(
                    CONNECT_TIMEOUT,
                    tokio_rustls::TlsConnector::from(Arc::clone(config)).connect(name.clone(), tcp),
                )
                .await
                .context("the TLS handshake with the search server timed out")?
                .context("the TLS handshake with the search server failed")?;
                handshake(TokioIo::new(tls)).await?
            }
            _ => handshake(TokioIo::new(tcp)).await?,
        };
        Ok(Upstream { sender })
    }
}

async fn handshake<T>(io: TokioIo<T>) -> anyhow::Result<SendRequest<ReqBody>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("HTTP handshake with the search server")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "search target connection ended");
        }
    });
    Ok(sender)
}

/// Add the `SigV4` headers for a request with a known body.
#[allow(clippy::too_many_arguments)] // a request's parts, as the signer takes them
pub async fn sign(
    headers: &mut hyper::HeaderMap,
    source: &AwsSource,
    region: &str,
    service: &'static str,
    host: &str,
    method: &str,
    path: &str,
    query: Option<&str>,
    body: &[u8],
) -> Result<(), String> {
    let creds = source().await?;
    let pairs: Vec<(String, String)> = query
        .unwrap_or_default()
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode_component(k), decode_component(v))
        })
        .collect();
    let canonical = sigv4::canonical_query(&pairs);
    let content_type = headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let payload = sigv4::sha256_hex(body);
    let mut extra: Vec<(&str, &str)> = vec![("x-amz-content-sha256", payload.as_str())];
    if let Some(ct) = &content_type {
        extra.push(("content-type", ct.as_str()));
    }
    let signed = sigv4::sign_headers(
        &sigv4::Target {
            method,
            host,
            path,
            region,
            service,
        },
        &canonical,
        &extra,
        body,
        &creds,
        OffsetDateTime::now_utc(),
    );
    let mut put = |name: &'static str, value: &str| -> Result<(), String> {
        headers.insert(
            hyper::header::HeaderName::from_static(name),
            hyper::header::HeaderValue::from_str(value).map_err(|e| e.to_string())?,
        );
        Ok(())
    };
    put("x-amz-date", &signed.amz_date)?;
    put("x-amz-content-sha256", &signed.payload_hash)?;
    if let Some(t) = &signed.session_token {
        put("x-amz-security-token", t)?;
    }
    put("authorization", &signed.authorization)?;
    Ok(())
}

fn decode_component(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                if let Some(v) = hex {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Wrap bytes as a request body.
#[must_use]
pub fn full(bytes: Bytes) -> ReqBody {
    http_body_util::Full::new(bytes)
        .map_err(|never| match never {})
        .boxed()
}

/// Wrap a body from the peer.
#[must_use]
pub fn incoming(body: hyper::body::Incoming) -> ReqBody {
    body.map_err(|e| -> BodyError { Box::new(e) }).boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_files_parse_each_kind() {
        let text = r#"{"es": {
            "limen-basic": {"basic": {"username": "limen", "password": "pw"}},
            "limen-key": {"api_key": "id1:secret1"},
            "limen-key-encoded": {"api_key": "aWQxOnNlY3JldDE="},
            "limen-token": {"bearer": "tok"}
        }}"#;
        let e = parse_entries(text).expect("parse");
        let auth = |r: &str| {
            e["es"][r]
                .authorization
                .as_ref()
                .map(|s| s.expose().clone())
                .expect("authorization")
        };
        assert_eq!(auth("limen-basic"), "Basic bGltZW46cHc=");
        assert_eq!(auth("limen-key"), "ApiKey aWQxOnNlY3JldDE=");
        assert_eq!(auth("limen-key-encoded"), "ApiKey aWQxOnNlY3JldDE=");
        assert_eq!(auth("limen-token"), "Bearer tok");
    }

    #[test]
    fn bad_credentials_files_are_refused() {
        for bad in [
            r#"{"es": {"r": {"basic": {"username": "a", "password": "b"}, "bearer": "t"}}}"#,
            r#"{"es": {"r": {"basic": {"username": "a:b", "password": "b"}}}}"#,
            r#"{"es": {"r": {"bearer": "t\nx"}}}"#,
            r#"{"es": {"r": {"client_cert_file": "/nope"}}}"#,
            r#"{"es": {"r": {"mystery": 1}}}"#,
            r#"{"es": {"r": "pw"}}"#,
            "not json",
        ] {
            assert!(parse_entries(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn secrets_do_not_print() {
        let e = parse_entries(r#"{"es": {"r": {"bearer": "super-secret-token"}}}"#).expect("parse");
        assert!(!format!("{e:?}").contains("super-secret-token"));
        let s = Settings {
            entries: e,
            ..Settings::default()
        };
        assert!(!format!("{s:?}").contains("super-secret-token"));
    }

    #[test]
    fn host_headers_drop_default_ports() {
        assert_eq!(host_header("es.example.com:443", true), "es.example.com");
        assert_eq!(
            host_header("es.example.com:9200", true),
            "es.example.com:9200"
        );
        assert_eq!(host_header("es:80", false), "es");
        assert_eq!(host_header("es:443", false), "es:443");
        assert_eq!(host_header("[::1]:9200", false), "[::1]:9200");
        assert_eq!(host_header("localhost", false), "localhost");
    }

    #[test]
    fn query_components_decode() {
        assert_eq!(decode_component("a%20b+c%2F"), "a b c/");
        assert_eq!(decode_component("100%"), "100%");
        assert_eq!(decode_component("%zz"), "%zz");
    }
}

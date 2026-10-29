//! What `RabbitMQ` and Kafka sessions share (ADR-0037): how the worker reaches a
//! broker (TCP, optionally TLS with a CA bundle and a client certificate), the
//! credentials it holds for the broker users a role names, and the name
//! patterns grants are written in. The person never sees any of it.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use limen_core::secret::Secret;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};

/// How long reaching a broker may take, TLS included.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type BoxedStream = Box<dyn Stream>;

/// What the worker holds for one broker user.
#[derive(Clone, Default)]
pub struct Credential {
    pub password: Option<Secret<String>>,
    /// Paths to a PEM client certificate chain and key (mutual TLS).
    pub client_cert: Option<(PathBuf, PathBuf)>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("password", &self.password.as_ref().map(|_| "…"))
            .field("client_cert", &self.client_cert)
            .finish()
    }
}

/// `"password"` or `{ "password": …, "client_cert_file": …, "client_key_file": … }`.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawCredential {
    Password(String),
    Full {
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        client_cert_file: Option<PathBuf>,
        #[serde(default)]
        client_key_file: Option<PathBuf>,
    },
}

/// `(node id, host, port)` of each broker of a cluster, and when it was asked.
type ClusterCache = HashMap<String, (Instant, Vec<(i32, String, i32)>)>;

/// Settings the operator gives the worker for broker targets.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    roots: Option<rustls::RootCertStore>,
    /// By resource name, then broker user.
    credentials: BTreeMap<String, BTreeMap<String, Credential>>,
    /// The brokers of Kafka clusters, as last asked, so that opening a
    /// session for a broker slot doesn't ask the bootstrap every time.
    clusters: Arc<std::sync::Mutex<ClusterCache>>,
}

impl Settings {
    /// Read the CA bundle and the credentials file named in the worker's config.
    pub fn load(ca_file: Option<&Path>, credentials_file: Option<&Path>) -> anyhow::Result<Self> {
        let roots = match ca_file {
            Some(path) => {
                let pem = std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                Some(roots_from_pem(&pem)?)
            }
            None => None,
        };
        let credentials = match credentials_file {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                parse_credentials(&text).with_context(|| format!("parsing {}", path.display()))?
            }
            None => BTreeMap::new(),
        };
        Ok(Self {
            roots,
            credentials,
            clusters: Arc::default(),
        })
    }

    /// The brokers of `key`'s cluster, if they were asked for less than `max_age` ago.
    #[must_use]
    pub fn cached_brokers(&self, key: &str, max_age: Duration) -> Option<Vec<(i32, String, i32)>> {
        let clusters = self
            .clusters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (at, brokers) = clusters.get(key)?;
        (at.elapsed() < max_age).then(|| brokers.clone())
    }

    pub fn cache_brokers(&self, key: String, brokers: Vec<(i32, String, i32)>) {
        self.clusters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, (Instant::now(), brokers));
    }

    #[must_use]
    pub fn credential(&self, resource: &str, user: &str) -> Option<&Credential> {
        self.credentials.get(resource)?.get(user)
    }

    /// Open the connection to `endpoint` (`host:port`), with TLS if asked.
    pub async fn dial(
        &self,
        endpoint: &str,
        tls: bool,
        credential: Option<&Credential>,
        guard: Option<&limen_policy::model::Delegated>,
    ) -> anyhow::Result<BoxedStream> {
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, crate::dial::connect(endpoint, guard))
            .await
            .context("connecting to the broker timed out")?
            .with_context(|| format!("connecting to {endpoint}"))?;
        tcp.set_nodelay(true)?;
        if !tls {
            return Ok(Box::new(tcp));
        }
        let roots = self.roots.clone().context(
            "this resource needs TLS but the worker has no --broker-ca-file (for Amazon MQ and MSK, the AWS CA bundle)",
        )?;
        let config = Arc::new(client_config(roots, credential)?);
        let name = rustls_pki_types::ServerName::try_from(host_of(endpoint).to_owned())
            .context("the endpoint's host name")?;
        // A server that doesn't speak TLS may just sit there.
        let tls = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_rustls::TlsConnector::from(config).connect(name, tcp),
        )
        .await
        .context("the TLS handshake with the broker timed out (does it speak TLS?)")?
        .context("TLS to the broker")?;
        Ok(Box::new(tls))
    }
}

/// `host` of `host:port`, without the brackets of an IPv6 address.
#[must_use]
pub fn host_of(endpoint: &str) -> &str {
    endpoint
        .rsplit_once(':')
        .map_or(endpoint, |(h, _)| h)
        .trim_matches(['[', ']'])
}

fn roots_from_pem(pem: &str) -> anyhow::Result<rustls::RootCertStore> {
    use rustls_pki_types::{CertificateDer, pem::PemObject as _};
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        roots.add(cert.context("certificate PEM")?)?;
    }
    if roots.is_empty() {
        bail!("no certificates in the broker CA file");
    }
    Ok(roots)
}

fn client_config(
    roots: rustls::RootCertStore,
    credential: Option<&Credential>,
) -> anyhow::Result<rustls::ClientConfig> {
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots);
    match credential.and_then(|c| c.client_cert.as_ref()) {
        Some((cert, key)) => {
            let chain = CertificateDer::pem_file_iter(cert)
                .with_context(|| format!("reading {}", cert.display()))?
                .collect::<Result<Vec<_>, _>>()
                .context("client certificate PEM")?;
            let key = PrivateKeyDer::from_pem_file(key)
                .with_context(|| format!("reading {}", key.display()))?;
            Ok(builder.with_client_auth_cert(chain, key)?)
        }
        None => Ok(builder.with_no_client_auth()),
    }
}

/// `{"<resource>": {"<broker user>": "<password>" | {…}}}`
fn parse_credentials(text: &str) -> anyhow::Result<BTreeMap<String, BTreeMap<String, Credential>>> {
    let raw: BTreeMap<String, BTreeMap<String, RawCredential>> = serde_json::from_str(text)?;
    let mut out = BTreeMap::new();
    for (resource, users) in raw {
        let mut parsed = BTreeMap::new();
        for (user, c) in users {
            let credential = match c {
                RawCredential::Password(p) => Credential {
                    password: Some(Secret::new(p)),
                    client_cert: None,
                },
                RawCredential::Full {
                    password,
                    client_cert_file,
                    client_key_file,
                } => Credential {
                    password: password.map(Secret::new),
                    client_cert: match (client_cert_file, client_key_file) {
                        (Some(c), Some(k)) => Some((c, k)),
                        (None, None) => None,
                        _ => bail!(
                            "{resource}/{user}: client_cert_file and client_key_file go together"
                        ),
                    },
                },
            };
            parsed.insert(user, credential);
        }
        out.insert(resource, parsed);
    }
    Ok(out)
}

/// Does `text` match `pattern`, where `*` is the only wildcard and matches
/// any run of characters (including none)?
#[must_use]
pub fn glob(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

/// `glob` over a list, where a name starting with `reserved` matches only a
/// pattern that itself starts with it: `*` never opens the broker's own
/// names (ADR-0037).
#[must_use]
pub fn matches_any(patterns: &[String], name: &str, reserved: &str) -> bool {
    let is_reserved = name.starts_with(reserved);
    patterns
        .iter()
        .any(|p| glob(p, name) && (!is_reserved || p.starts_with(reserved)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_stars_only() {
        for (p, t, want) in [
            ("orders.*", "orders.new", true),
            ("orders.*", "orders.", true),
            ("orders.*", "order", false),
            ("*", "", true),
            ("*", "anything", true),
            ("a*b*c", "aXXbYYc", true),
            ("a*b*c", "aXXbYY", false),
            ("a?c", "a?c", true),
            ("a?c", "abc", false),
            ("exact", "exact", true),
            ("exact", "exacto", false),
            ("**", "x", true),
            ("*.log", "a.b.log", true),
            ("*.log", "a.log.x", false),
        ] {
            assert_eq!(glob(p, t), want, "{p:?} vs {t:?}");
        }
    }

    #[test]
    fn reserved_names_need_a_pattern_that_says_so() {
        let star = vec!["*".to_owned()];
        assert!(matches_any(&star, "orders", "_"));
        assert!(!matches_any(&star, "__consumer_offsets", "_"));
        assert!(matches_any(&["_*".to_owned()], "__consumer_offsets", "_"));
        assert!(!matches_any(&["orders.*".to_owned()], "__x", "_"));
        assert!(matches_any(
            &["amq.rabbitmq.*".to_owned()],
            "amq.rabbitmq.trace",
            "amq.rabbitmq."
        ));
        assert!(matches_any(&star, "amq.topic", "amq.rabbitmq."));
    }

    #[test]
    fn credentials_are_a_password_or_a_certificate() {
        let parsed = parse_credentials(
            r#"{"q": {"a": "pw", "b": {"password": "x", "client_cert_file": "/c", "client_key_file": "/k"}, "c": {}}}"#,
        )
        .expect("parses");
        let q = &parsed["q"];
        assert_eq!(q["a"].password.as_ref().expect("pw").expose(), "pw");
        assert_eq!(
            q["b"].client_cert,
            Some((PathBuf::from("/c"), PathBuf::from("/k")))
        );
        assert!(q["c"].password.is_none() && q["c"].client_cert.is_none());
        assert!(parse_credentials(r#"{"q": {"a": {"client_cert_file": "/c"}}}"#).is_err());
        assert!(parse_credentials("[]").is_err());
    }

    #[test]
    fn debug_never_shows_a_password() {
        let c = Credential {
            password: Some(Secret::new("hunter2".to_owned())),
            client_cert: None,
        };
        assert!(!format!("{c:?}").contains("hunter2"));
    }

    #[test]
    fn host_of_strips_port_and_brackets() {
        assert_eq!(host_of("b-1.mq.example.com:5671"), "b-1.mq.example.com");
        assert_eq!(host_of("[::1]:9092"), "::1");
        assert_eq!(host_of("plain"), "plain");
    }
}

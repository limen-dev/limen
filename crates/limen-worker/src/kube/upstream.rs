//! The connection to the cluster's API server.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use http::HeaderValue;
use limen_core::secret::Secret;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Projected service account tokens rotate; re-read about once a minute.
const TOKEN_TTL: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub(crate) struct Upstream {
    cluster: String,
    addr: String,
    host_header: String,
    server_name: ServerName<'static>,
    tls: std::sync::Arc<rustls::ClientConfig>,
    token_file: PathBuf,
    token: Mutex<Option<(Instant, Secret<String>)>>,
}

impl Upstream {
    /// `api_server` is `https://host[:port]`. Plain HTTP is refused: the
    /// service account token travels on this connection.
    pub(crate) fn new(
        cluster: String,
        api_server: &str,
        ca_file: &Path,
        token_file: PathBuf,
    ) -> anyhow::Result<Self> {
        let url = url::Url::parse(api_server).context("--kube-api-server is not a URL")?;
        anyhow::ensure!(
            url.scheme() == "https",
            "--kube-api-server must be an https:// URL"
        );
        let host = url.host_str().context("--kube-api-server has no host")?;
        let port = url.port().unwrap_or(443);
        let ca = std::fs::read_to_string(ca_file)
            .with_context(|| format!("reading the API server CA {}", ca_file.display()))?;
        let roots = limen_tunnel::tls::certs_from_pem(&ca)?;
        // API servers behind older load balancers may not speak TLS 1.3; this
        // is the one connection that is not between Limen components.
        let mut store = rustls::RootCertStore::empty();
        for root in roots {
            store.add(root).context("adding the API server CA")?;
        }
        let config = rustls::ClientConfig::builder_with_provider(limen_tunnel::tls::provider())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(store)
            .with_no_client_auth();
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| anyhow::anyhow!("invalid API server name {host:?}: {e}"))?;
        let upstream = Self {
            cluster,
            addr: format!("{host}:{port}"),
            host_header: if port == 443 {
                host
            } else {
                format!("{host}:{port}")
            },
            server_name,
            tls: std::sync::Arc::new(config),
            token_file,
            token: Mutex::new(None),
        };
        // Fail at startup, not on the first request, if the token is missing.
        upstream.read_token()?;
        Ok(upstream)
    }

    pub(crate) fn cluster(&self) -> &str {
        &self.cluster
    }

    pub(crate) fn host_header(&self) -> &str {
        &self.host_header
    }

    pub(crate) async fn connect(&self) -> std::io::Result<TlsStream<TcpStream>> {
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.addr))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")
            })??;
        let _ = tcp.set_nodelay(true);
        tokio::time::timeout(
            CONNECT_TIMEOUT,
            TlsConnector::from(std::sync::Arc::clone(&self.tls))
                .connect(self.server_name.clone(), tcp),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out"))?
    }

    fn read_token(&self) -> anyhow::Result<Secret<String>> {
        let token = std::fs::read_to_string(&self.token_file).with_context(|| {
            format!(
                "reading the service account token {}",
                self.token_file.display()
            )
        })?;
        let token = token.trim();
        anyhow::ensure!(!token.is_empty(), "the service account token file is empty");
        Ok(Secret::new(token.to_owned()))
    }

    /// `Bearer <token>`, marked sensitive so it never prints.
    pub(crate) fn authorization(&self) -> anyhow::Result<HeaderValue> {
        let mut cached = self
            .token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fresh = cached
            .as_ref()
            .is_some_and(|(at, _)| at.elapsed() < TOKEN_TTL);
        if !fresh {
            // Kubelet swaps a projected token in place; a read that fails
            // mid-rotation must not take down requests the old token (valid
            // for its full lifetime) can still serve.
            match self.read_token() {
                Ok(token) => *cached = Some((Instant::now(), token)),
                Err(e) if cached.is_some() => {
                    tracing::warn!(error = %e, "kube: cannot refresh the token; using the last one");
                }
                Err(e) => return Err(e),
            }
        }
        let Some((_, token)) = cached.as_ref() else {
            anyhow::bail!("no token");
        };
        let mut value = HeaderValue::from_str(&format!("Bearer {}", token.expose()))
            .context("the service account token is not a valid header value")?;
        value.set_sensitive(true);
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(token_file: PathBuf) -> Upstream {
        let config = rustls::ClientConfig::builder_with_provider(limen_tunnel::tls::provider())
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        Upstream {
            cluster: "c".into(),
            addr: "localhost:6443".into(),
            host_header: "localhost:6443".into(),
            server_name: ServerName::try_from("localhost").expect("name"),
            tls: std::sync::Arc::new(config),
            token_file,
            token: Mutex::new(None),
        }
    }

    #[test]
    fn a_token_that_cannot_be_refreshed_is_still_used() {
        let file = std::env::temp_dir().join(format!("limen-token-{}", uuid::Uuid::new_v4()));
        std::fs::write(&file, "first\n").expect("write");
        let up = upstream(file.clone());
        let first = up.authorization().expect("first");
        assert_eq!(first.to_str().expect("str"), "Bearer first");
        assert!(first.is_sensitive());

        // Expire the cache and break the file, as a kubelet swap can briefly.
        std::fs::remove_file(&file).expect("remove");
        let old = Instant::now()
            .checked_sub(TOKEN_TTL + Duration::from_secs(1))
            .expect("instant");
        let token = up.token.lock().expect("lock").take().expect("cached").1;
        *up.token.lock().expect("lock") = Some((old, token));
        assert_eq!(
            up.authorization().expect("stale").to_str().expect("str"),
            "Bearer first"
        );

        // Once the file is back, the new token is picked up.
        std::fs::write(&file, "second\n").expect("write");
        assert_eq!(
            up.authorization().expect("fresh").to_str().expect("str"),
            "Bearer second"
        );
        std::fs::remove_file(&file).expect("clean up");
    }

    #[test]
    fn no_token_at_all_is_an_error() {
        let up =
            upstream(std::env::temp_dir().join(format!("limen-none-{}", uuid::Uuid::new_v4())));
        assert!(up.authorization().is_err());
    }
}

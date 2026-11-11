//! The proxy's publicly trusted certificate (ADR-0043).
//!
//! The proxy has one TLS listener. Workers and peer proxies pin the internal CA and are given the
//! certificate that CA issued; the CLI and browsers verify against the system trust store, so they
//! are given the operator's public certificate. Which one a connection gets is decided from the
//! protocols it offers (ALPN), before the handshake completes.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context as _;
use limen_core::secret::Secret;
use limen_tunnel::alpn;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::watch;

use crate::config::Config;

/// How often the files are read again.
const RELOAD_EVERY: Duration = Duration::from_secs(60);

/// The public certificate, replaced when its files change. Empty when the operator supplied none.
#[derive(Debug, Default)]
pub struct PublicCert {
    current: RwLock<Option<Arc<CertifiedKey>>>,
}

impl PublicCert {
    fn get(&self) -> Option<Arc<CertifiedKey>> {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn set(&self, key: Arc<CertifiedKey>) {
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(key);
    }

    /// Read the configured files, if any. Files that are missing, not PEM, or whose key does not
    /// belong to the certificate stop the proxy from starting: serving the internal certificate to
    /// browsers when the operator asked for a public one would be a silent downgrade.
    ///
    /// A certificate that has *expired* does not. The proxy is also how workers and peers reach
    /// each other, so a lapsed public certificate must not take them down with it: it starts,
    /// logs an error, and the expiry alert is already firing.
    pub fn from_config(config: &Config) -> anyhow::Result<Arc<Self>> {
        let public = Arc::new(Self::default());
        if let (Some(cert), Some(key)) = (&config.public_cert_file, &config.public_key_file) {
            let (loaded, not_after) = load(cert, key)?;
            record_expiry(not_after);
            if not_after <= now() {
                tracing::error!(cert = %cert.display(), expired = not_after, "the public certificate has expired; the CLI and browsers will refuse it until it is replaced");
            } else {
                tracing::info!(cert = %cert.display(), expires = not_after, "public certificate loaded");
            }
            public.set(Arc::new(loaded));
        }
        Ok(public)
    }

    /// Whether a public certificate is configured.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.get().is_some()
    }
}

/// Picks the certificate for each connection.
#[derive(Debug)]
pub struct Selector {
    internal: Arc<CertifiedKey>,
    public: Arc<PublicCert>,
}

impl Selector {
    pub fn new(internal: Arc<CertifiedKey>, public: Arc<PublicCert>) -> Self {
        Self { internal, public }
    }
}

/// True when the client offers any protocol only Limen's own components speak. The CLI and
/// browsers never do. A worker also offers `h2`, so it is not the *only* protocol that counts.
fn offers_internal<'a>(offered: Option<impl Iterator<Item = &'a [u8]>>) -> bool {
    offered.is_some_and(|mut o| o.any(|p| alpn::INTERNAL.contains(&p)))
}

impl ResolvesServerCert for Selector {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if !offers_internal(hello.alpn())
            && let Some(public) = self.public.get()
        {
            return Some(public);
        }
        Some(Arc::clone(&self.internal))
    }
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Read a PEM chain and key. Returns the certificate and the leaf's expiry (unix seconds).
///
/// Fails if the chain is empty, the key is unreadable, or the key does not belong to the leaf.
/// Does not look at the expiry: what to do about an expired certificate depends on the caller.
pub fn load(cert_file: &Path, key_file: &Path) -> anyhow::Result<(CertifiedKey, i64)> {
    let cert_pem = std::fs::read_to_string(cert_file)
        .with_context(|| format!("reading {}", cert_file.display()))?;
    // The key never leaves this scope except inside the signing key rustls builds from it.
    let key_pem = Secret::new(
        std::fs::read_to_string(key_file)
            .with_context(|| format!("reading {}", key_file.display()))?,
    );
    let chain: Vec<CertificateDer<'static>> = limen_tunnel::tls::certs_from_pem(&cert_pem)
        .with_context(|| format!("{} is not a PEM certificate chain", cert_file.display()))?;
    let key = <PrivateKeyDer<'static> as rustls_pki_types::pem::PemObject>::from_pem_slice(
        key_pem.expose().as_bytes(),
    )
    .with_context(|| format!("{} holds no PEM private key", key_file.display()))?;
    let leaf = chain.first().context("the certificate file is empty")?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|e| anyhow::anyhow!("the first certificate is not valid X.509: {e}"))?;
    let not_after = parsed.validity().not_after.timestamp();
    let certified = CertifiedKey::from_der(chain, key, &limen_tunnel::tls::provider())
        .context("the public key file does not match the certificate")?;
    Ok((certified, not_after))
}

fn record_expiry(not_after: i64) {
    #[allow(clippy::cast_precision_loss)]
    // unix seconds fit a f64 exactly until the year 285 million
    metrics::gauge!("limen_proxy_public_cert_expiry_timestamp_seconds").set(not_after as f64);
}

/// Read the files again every minute and on SIGHUP. A file that fails to parse, expired, or a key
/// that does not match leaves the last good certificate in use, with a warning and a counter.
pub async fn reload_loop(
    public: Arc<PublicCert>,
    cert_file: PathBuf,
    key_file: PathBuf,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(RELOAD_EVERY);
    tick.tick().await; // the first tick is immediate; the files were just read
    #[cfg(unix)]
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
    loop {
        #[cfg(unix)]
        let hangup = async {
            match hup.as_mut() {
                Some(h) => {
                    h.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        #[cfg(not(unix))]
        let hangup = std::future::pending::<()>();
        tokio::select! {
            _ = tick.tick() => {}
            () = hangup => tracing::info!("SIGHUP: reloading the public certificate"),
            _ = shutdown.changed() => return,
        }
        let (cert, key) = (cert_file.clone(), key_file.clone());
        let current = Arc::clone(&public);
        // Reading and parsing is blocking work.
        match tokio::task::spawn_blocking(move || reload_once(&current, &cert, &key)).await {
            Ok(Ok(Some(expires))) => {
                tracing::info!(expires, "public certificate reloaded");
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => {
                metrics::counter!("limen_proxy_public_cert_reload_failures_total").increment(1);
                tracing::warn!(error = %format!("{e:#}"), "public certificate not reloaded; keeping the last good one");
            }
            Err(e) => tracing::warn!(error = %e, "public certificate reload task failed"),
        }
    }
}

/// Read the files and, if the certificate is a different one, start using it. Returns its expiry
/// when it changed. On any error the current certificate stays.
fn reload_once(
    public: &PublicCert,
    cert_file: &Path,
    key_file: &Path,
) -> anyhow::Result<Option<i64>> {
    let (loaded, not_after) = load(cert_file, key_file)?;
    // Swapping one lapsed certificate for another helps nobody; keep what is serving.
    anyhow::ensure!(
        not_after > now(),
        "the replacement certificate has expired (it ended at unix time {not_after})"
    );
    if public
        .get()
        .is_some_and(|current| current.cert == loaded.cert)
    {
        return Ok(None);
    }
    public.set(Arc::new(loaded));
    // The gauge describes the certificate that is serving, so it moves only with the swap: a
    // refused file must not make a good certificate look expired.
    record_expiry(not_after);
    Ok(Some(not_after))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offers(list: &[&'static [u8]]) -> bool {
        offers_internal(Some(list.iter().copied()))
    }

    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    use rustls::pki_types::ServerName;
    use time::{Duration as Span, OffsetDateTime};

    struct TestCa {
        issuer: Issuer<'static, KeyPair>,
        der: CertificateDer<'static>,
    }

    fn test_ca() -> TestCa {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(Vec::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let cert = params.self_signed(&key).expect("ca");
        let der = cert.der().clone();
        let issuer = Issuer::new(
            params,
            KeyPair::from_pem(&key.serialize_pem()).expect("key"),
        );
        TestCa { issuer, der }
    }

    /// A leaf for `localhost`, as (certificate PEM, key PEM).
    fn leaf(ca: &TestCa, valid_for: Span) -> (String, String) {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Span::days(2);
        params.not_after = now + valid_for;
        let cert = params.signed_by(&key, &ca.issuer).expect("leaf");
        (cert.pem(), key.serialize_pem())
    }

    fn certified(ca: &TestCa) -> Arc<CertifiedKey> {
        let (cert, key) = leaf(ca, Span::days(30));
        let dir = tempfile::tempdir().expect("dir");
        let (c, k) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
        std::fs::write(&c, cert).expect("write");
        std::fs::write(&k, key).expect("write");
        Arc::new(load(&c, &k).expect("load").0)
    }

    /// A TLS handshake against a proxy with `internal` and `public`, from a client that offers
    /// `offer` and trusts only `trusts`. The protocol that was negotiated, or the error.
    async fn handshake(
        public: Option<&TestCa>,
        internal: &TestCa,
        trusts: &TestCa,
        offer: &[&[u8]],
    ) -> Result<Vec<u8>, String> {
        let shown = Arc::new(PublicCert::default());
        if let Some(ca) = public {
            shown.set(certified(ca));
        }
        let resolver = Selector::new(certified(internal), shown);
        let server = limen_tunnel::tls::server_config_with_resolver(
            Arc::new(resolver),
            std::slice::from_ref(&internal.der),
            limen_tunnel::tls::ClientAuth::Optional,
            &alpn::ALL,
        )
        .expect("server config");
        let client =
            limen_tunnel::tls::client_config(std::slice::from_ref(&trusts.der), None, offer)
                .expect("client config");
        let (a, b) = tokio::io::duplex(16 * 1024);
        let accept = tokio_rustls::TlsAcceptor::from(Arc::new(server)).accept(a);
        let connect = tokio_rustls::TlsConnector::from(Arc::new(client))
            .connect(ServerName::try_from("localhost").expect("name"), b);
        let (server_side, client_side) = tokio::join!(accept, connect);
        let tls = client_side.map_err(|e| e.to_string())?;
        server_side.map_err(|e| e.to_string())?;
        Ok(tls.get_ref().1.alpn_protocol().unwrap_or_default().to_vec())
    }

    #[tokio::test]
    async fn the_cli_and_browsers_get_the_public_certificate() {
        let (public, internal) = (test_ca(), test_ca());
        // The CLI (h2) and a browser (h2, http/1.1) trust the public CA only.
        for offer in [
            &[alpn::H2][..],
            &[alpn::H2, alpn::HTTP1][..],
            &[alpn::SSH][..],
        ] {
            handshake(Some(&public), &internal, &public, offer)
                .await
                .unwrap_or_else(|e| panic!("{offer:?}: {e}"));
            // ...and would not accept the internal certificate.
            assert!(
                handshake(Some(&public), &internal, &internal, offer)
                    .await
                    .is_err(),
                "{offer:?}"
            );
        }
    }

    #[tokio::test]
    async fn workers_and_peers_keep_the_internal_certificate() {
        let (public, internal) = (test_ca(), test_ca());
        for offer in [
            &[alpn::TUNNEL][..],
            &[alpn::PEER][..],
            &[alpn::WORKER_API, alpn::H2][..],
        ] {
            let negotiated = handshake(Some(&public), &internal, &internal, offer)
                .await
                .unwrap_or_else(|e| panic!("{offer:?}: {e}"));
            assert_eq!(negotiated, offer[0], "{offer:?}");
            // They never accept the public one: they pin the internal CA.
            assert!(
                handshake(Some(&public), &internal, &public, offer)
                    .await
                    .is_err(),
                "{offer:?}"
            );
        }
        // A worker from before this protocol offers only h2: it can't be told from the CLI, so a
        // proxy that has a public certificate is not for it. Workers upgrade first.
        assert!(
            handshake(Some(&public), &internal, &internal, &[alpn::H2])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn without_a_public_certificate_nothing_changes() {
        let internal = test_ca();
        for offer in [
            &[alpn::H2][..],
            &[alpn::TUNNEL][..],
            &[alpn::WORKER_API, alpn::H2][..],
        ] {
            handshake(None, &internal, &internal, offer)
                .await
                .unwrap_or_else(|e| panic!("{offer:?}: {e}"));
        }
    }

    fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).expect("write");
        path
    }

    #[test]
    fn a_bad_certificate_never_replaces_a_good_one() {
        let ca = test_ca();
        let dir = tempfile::tempdir().expect("dir");
        let (cert, key) = leaf(&ca, Span::days(30));
        let (c, k) = (
            write(dir.path(), "c.pem", &cert),
            write(dir.path(), "k.pem", &key),
        );
        let public = PublicCert::default();

        // First read installs it; the same files again change nothing.
        assert!(reload_once(&public, &c, &k).expect("valid").is_some());
        let first = public.get().expect("set");
        assert!(reload_once(&public, &c, &k).expect("unchanged").is_none());

        // Each of these is refused, and the first certificate stays.
        let (other_cert, other_key) = leaf(&ca, Span::days(30));
        let (expired, expired_key) = leaf(&ca, -Span::hours(1));
        let bad: [(&str, &str, &str); 5] = [
            ("garbage certificate", "not pem", &key),
            ("garbage key", &cert, "not pem"),
            ("key of another certificate", &cert, &other_key),
            ("expired", &expired, &expired_key),
            ("empty", "", ""),
        ];
        for (what, c_text, k_text) in bad {
            write(dir.path(), "c.pem", c_text);
            write(dir.path(), "k.pem", k_text);
            assert!(reload_once(&public, &c, &k).is_err(), "{what}");
            assert!(Arc::ptr_eq(&first, &public.get().expect("kept")), "{what}");
        }

        // A renewed certificate is picked up.
        write(dir.path(), "c.pem", &other_cert);
        write(dir.path(), "k.pem", &other_key);
        assert!(reload_once(&public, &c, &k).expect("renewed").is_some());
        assert!(!Arc::ptr_eq(&first, &public.get().expect("new")));
    }

    #[test]
    fn an_expired_certificate_starts_but_is_never_swapped_in() {
        let ca = test_ca();
        let dir = tempfile::tempdir().expect("dir");
        let (cert, key) = leaf(&ca, -Span::hours(1));
        let (c, k) = (
            write(dir.path(), "c.pem", &cert),
            write(dir.path(), "k.pem", &key),
        );
        // Start-up reads it (and logs an error): the proxy is also the workers' way in.
        let (_, not_after) = load(&c, &k).expect("an expired certificate still loads");
        assert!(not_after <= now());
        // A reload refuses it.
        assert!(reload_once(&PublicCert::default(), &c, &k).is_err());
    }

    #[test]
    fn startup_fails_on_a_bad_certificate_instead_of_serving_without_it() {
        let dir = tempfile::tempdir().expect("dir");
        let c = write(dir.path(), "c.pem", "not pem");
        let k = write(dir.path(), "k.pem", "not pem");
        assert!(load(&c, &k).is_err());
        assert!(load(&dir.path().join("missing.pem"), &k).is_err());
    }

    #[test]
    fn the_private_key_is_not_in_the_error() {
        let ca = test_ca();
        let dir = tempfile::tempdir().expect("dir");
        let (cert, _) = leaf(&ca, Span::days(30));
        let (_, other_key) = leaf(&ca, Span::days(30));
        let c = write(dir.path(), "c.pem", &cert);
        let k = write(dir.path(), "k.pem", &other_key);
        let message = format!("{:#}", load(&c, &k).expect_err("mismatch"));
        let body = other_key.lines().nth(1).unwrap_or_default();
        assert!(!message.contains(body), "{message}");
    }

    #[test]
    fn only_limen_components_get_the_internal_certificate() {
        assert!(offers(&[alpn::TUNNEL]));
        assert!(offers(&[alpn::PEER]));
        assert!(offers(&[alpn::WORKER_API]));
        // A worker also offers h2, for a proxy that predates its own protocol.
        assert!(offers(&[alpn::WORKER_API, alpn::H2]));
        // The CLI and browsers.
        assert!(!offers(&[alpn::H2]));
        assert!(!offers(&[alpn::H2, alpn::HTTP1]));
        assert!(!offers(&[alpn::SSH]));
        assert!(!offers(&[]));
        assert!(!offers_internal(None::<std::vec::IntoIter<&[u8]>>));
    }
}

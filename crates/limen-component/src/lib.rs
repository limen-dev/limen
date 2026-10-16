//! Shared runtime for proxies and workers: on-disk identity, enrollment
//! with a join token, and certificate renewal at half-life.

pub mod audit;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use limen_core::backoff::Backoff;
use limen_core::secret::Secret;
use limen_proto::v1::enrollment_client::EnrollmentClient;
use limen_proto::v1::{EnrollRequest, RenewCertificateRequest};
use limen_tunnel::connect::retry_if_went_away;
use limen_tunnel::tls::{self, Identity};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::watch;
use tonic::transport::Channel;

/// A component's credentials, as stored in its data directory.
#[derive(Debug, Clone)]
pub struct ComponentCredentials {
    pub id: String,
    pub kind: String,
    pub labels: std::collections::BTreeMap<String, String>,
    pub key_pem: Secret<String>,
    pub cert_pem: String,
    pub internal_ca_pem: String,
    pub user_ca_pem: String,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
struct Meta {
    id: String,
    kind: String,
    #[serde(default)]
    labels: std::collections::BTreeMap<String, String>,
}

const KEY_FILE: &str = "key.pem";
const CERT_FILE: &str = "cert.pem";
const INTERNAL_CA_FILE: &str = "internal-ca.pem";
const USER_CA_FILE: &str = "user-ca.pem";
const META_FILE: &str = "identity.json";

impl ComponentCredentials {
    /// Load credentials from `dir`. `Ok(None)` if the component hasn't enrolled yet.
    pub fn load(dir: &Path) -> anyhow::Result<Option<Self>> {
        let meta_path = dir.join(META_FILE);
        if !meta_path.exists() {
            return Ok(None);
        }
        let read = |name: &str| {
            std::fs::read_to_string(dir.join(name))
                .with_context(|| format!("reading {}", dir.join(name).display()))
        };
        let meta: Meta = serde_json::from_str(&read(META_FILE)?)?;
        let cert_pem = read(CERT_FILE)?;
        let (not_before, not_after) = validity(&cert_pem)?;
        Ok(Some(Self {
            id: meta.id,
            kind: meta.kind,
            labels: meta.labels,
            key_pem: Secret::new(read(KEY_FILE)?),
            cert_pem,
            internal_ca_pem: read(INTERNAL_CA_FILE)?,
            user_ca_pem: read(USER_CA_FILE)?,
            not_before,
            not_after,
        }))
    }

    /// Write credentials to `dir`. Every file is written to a temporary name
    /// first and renamed, so a crash never leaves a half-written identity.
    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(dir)?;
        let meta = serde_json::to_string_pretty(&Meta {
            id: self.id.clone(),
            kind: self.kind.clone(),
            labels: self.labels.clone(),
        })?;
        for (name, contents, private) in [
            (KEY_FILE, self.key_pem.expose().as_str(), true),
            (CERT_FILE, self.cert_pem.as_str(), false),
            (INTERNAL_CA_FILE, self.internal_ca_pem.as_str(), false),
            (USER_CA_FILE, self.user_ca_pem.as_str(), false),
            // Written last: its presence means the identity is complete.
            (META_FILE, meta.as_str(), false),
        ] {
            write_atomic(&dir.join(name), contents, private)?;
        }
        Ok(())
    }

    /// TLS identity: leaf certificate plus key.
    pub fn tls_identity(&self) -> anyhow::Result<Identity> {
        Ok(Identity::from_pem(&self.cert_pem, self.key_pem.expose())?)
    }

    pub fn internal_ca(&self) -> anyhow::Result<CertificateDer<'static>> {
        first_cert(&self.internal_ca_pem)
    }

    pub fn user_ca(&self) -> anyhow::Result<CertificateDer<'static>> {
        first_cert(&self.user_ca_pem)
    }

    /// When renewal is due: half-way through the certificate's lifetime.
    #[must_use]
    pub fn renew_at(&self) -> OffsetDateTime {
        self.not_before + (self.not_after - self.not_before) / 2
    }
}

fn first_cert(pem: &str) -> anyhow::Result<CertificateDer<'static>> {
    tls::certs_from_pem(pem)?
        .into_iter()
        .next()
        .context("no certificate in PEM")
}

fn validity(cert_pem: &str) -> anyhow::Result<(OffsetDateTime, OffsetDateTime)> {
    let der = first_cert(cert_pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).context("parsing certificate")?;
    Ok((
        cert.validity().not_before.to_datetime(),
        cert.validity().not_after.to_datetime(),
    ))
}

fn write_atomic(path: &Path, contents: &str, private: bool) -> std::io::Result<()> {
    use std::io::Write;
    let tmp: PathBuf = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options.open(&tmp)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// Whether a failed call is worth retrying.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    /// The control plane said no (bad token, revoked, invalid request). Retrying won't help.
    #[error("{0}")]
    Rejected(String),
    /// Network or availability problem. Retry with backoff.
    #[error("{0}")]
    Transient(String),
}

fn classify(context: &str, status: &tonic::Status) -> CallError {
    use tonic::Code;
    let msg = format!("{context}: {} ({:?})", status.message(), status.code());
    match status.code() {
        Code::PermissionDenied
        | Code::InvalidArgument
        | Code::Unauthenticated
        | Code::FailedPrecondition => CallError::Rejected(msg),
        _ => CallError::Transient(msg),
    }
}

fn new_key_and_csr() -> anyhow::Result<(KeyPair, Vec<u8>)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let csr = CertificateParams::default().serialize_request(&key)?;
    Ok((key, csr.der().to_vec()))
}

/// Exchange a join token for credentials. The private key is generated here
/// and never leaves the process (only its CSR is sent).
pub async fn enroll(
    channel: Channel,
    join_token: &Secret<String>,
    kind: &str,
    dns_names: &[String],
) -> anyhow::Result<ComponentCredentials> {
    let (key, csr_der) = new_key_and_csr()?;
    let request = EnrollRequest {
        join_token: join_token.expose().clone(),
        csr_der,
        kind: kind.to_owned(),
        dns_names: dns_names.to_vec(),
        name: String::new(),
    };
    let resp = retry_if_went_away("enrollment", || {
        let mut client = EnrollmentClient::new(channel.clone());
        let request = request.clone();
        async move { client.enroll(request).await }
    })
    .await
    .map_err(|s| classify("enrollment", &s))?
    .into_inner();
    let (not_before, not_after) = validity(&resp.cert_pem)?;
    Ok(ComponentCredentials {
        id: resp.component_id,
        kind: kind.to_owned(),
        labels: resp.labels.into_iter().collect(),
        key_pem: Secret::new(key.serialize_pem()),
        cert_pem: resp.cert_pem,
        internal_ca_pem: resp.internal_ca_pem,
        user_ca_pem: resp.user_ca_pem,
        not_before,
        not_after,
    })
}

/// Get a new certificate (and key) for the same identity. `channel` must
/// present the current certificate.
pub async fn renew(
    channel: Channel,
    current: &ComponentCredentials,
) -> anyhow::Result<ComponentCredentials> {
    let (key, csr_der) = new_key_and_csr()?;
    let resp = retry_if_went_away("renewal", || {
        let mut client = EnrollmentClient::new(channel.clone());
        let csr_der = csr_der.clone();
        async move {
            client
                .renew_certificate(RenewCertificateRequest { csr_der })
                .await
        }
    })
    .await
    .map_err(|s| classify("renewal", &s))?
    .into_inner();
    let (not_before, not_after) = validity(&resp.cert_pem)?;
    Ok(ComponentCredentials {
        key_pem: Secret::new(key.serialize_pem()),
        cert_pem: resp.cert_pem,
        not_before,
        not_after,
        ..current.clone()
    })
}

/// Load credentials from `dir`, or enroll with `join_token` if there are none.
/// Enrollment is retried with backoff (the control plane may still be starting).
pub async fn load_or_enroll<F>(
    dir: &Path,
    kind: &str,
    join_token: Option<&Secret<String>>,
    dns_names: &[String],
    channel: F,
) -> anyhow::Result<ComponentCredentials>
where
    F: Fn() -> anyhow::Result<Channel>,
{
    if let Some(creds) = ComponentCredentials::load(dir)? {
        if creds.kind != kind {
            bail!(
                "{} holds a {} identity, not a {kind} one",
                dir.display(),
                creds.kind
            );
        }
        if creds.not_after <= OffsetDateTime::now_utc() {
            bail!(
                "certificate in {} expired at {}; delete the directory and enroll again with a new join token",
                dir.display(),
                creds.not_after
            );
        }
        tracing::info!(id = %creds.id, expires = %creds.not_after, "loaded identity");
        return Ok(creds);
    }
    let token = join_token.context("not enrolled yet and no join token given (--join-token)")?;
    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
    loop {
        match enroll(channel()?, token, kind, dns_names).await {
            Ok(creds) => {
                creds.save(dir)?;
                tracing::info!(id = %creds.id, expires = %creds.not_after, "enrolled");
                return Ok(creds);
            }
            Err(e) if matches!(e.downcast_ref::<CallError>(), Some(CallError::Rejected(_))) => {
                return Err(e);
            }
            Err(e) => {
                let delay = backoff.next_delay(rand::random());
                tracing::warn!(error = %e, retry_in = ?delay, "enrollment failed; retrying");
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// Renew at half-life, forever. Publishes new credentials on `tx` after
/// saving them. `channel` builds a channel that presents the current cert.
pub async fn renewal_loop<F>(dir: PathBuf, tx: watch::Sender<Arc<ComponentCredentials>>, channel: F)
where
    F: Fn(&ComponentCredentials) -> anyhow::Result<Channel>,
{
    let mut backoff = Backoff::new(Duration::from_secs(5), Duration::from_mins(5));
    loop {
        let current = Arc::clone(&tx.borrow());
        let wait = (current.renew_at() - OffsetDateTime::now_utc()).max(time::Duration::ZERO);
        tokio::time::sleep(wait.unsigned_abs()).await;
        let result = async { renew(channel(&current)?, &current).await }.await;
        match result.and_then(|creds| creds.save(&dir).map(|()| creds)) {
            Ok(creds) => {
                tracing::info!(id = %creds.id, expires = %creds.not_after, "renewed certificate");
                backoff.reset();
                tx.send_replace(Arc::new(creds));
            }
            Err(e) => {
                let delay = backoff.next_delay(rand::random());
                tracing::error!(error = %e, retry_in = ?delay, expires = %current.not_after, "certificate renewal failed");
                tokio::time::sleep(delay).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_and_load_round_trip_with_private_key_permissions() {
        let dir = limen_testkit::temp_dir().expect("tempdir");
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let cert = CertificateParams::new(vec!["localhost".into()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        let (not_before, not_after) = validity(&cert.pem()).expect("validity");
        let creds = ComponentCredentials {
            id: "worker-1".into(),
            kind: "worker".into(),
            labels: [("pool".to_owned(), "dev".to_owned())].into(),
            key_pem: Secret::new(key.serialize_pem()),
            cert_pem: cert.pem(),
            internal_ca_pem: cert.pem(),
            user_ca_pem: cert.pem(),
            not_before,
            not_after,
        };
        assert!(
            ComponentCredentials::load(dir.path())
                .expect("load")
                .is_none()
        );
        creds.save(dir.path()).expect("save");
        let loaded = ComponentCredentials::load(dir.path())
            .expect("load")
            .expect("present");
        assert_eq!(loaded.id, "worker-1");
        assert_eq!(loaded.labels.get("pool").map(String::as_str), Some("dev"));
        assert_eq!(loaded.key_pem.expose(), creds.key_pem.expose());
        assert!(loaded.renew_at() > loaded.not_before && loaded.renew_at() < loaded.not_after);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(KEY_FILE))
                .expect("stat")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        loaded.tls_identity().expect("identity parses");
    }
}

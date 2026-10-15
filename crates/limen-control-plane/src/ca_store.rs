//! Loading the CA keys and their certificates.
//!
//! Keys come from files (development) or KMS (production). Each X.509 CA
//! certificate is created once, under an advisory lock so concurrent replicas
//! agree, and stored in the database keyed by purpose and key reference. SSH
//! CAs have no certificate: their public key is all anyone needs.
//!
//! With file keys (development), the certificate is also kept next to the key
//! (`<purpose>-ca.crt`). If the database is wiped but the key survives, the
//! same certificate is restored from that file, so anything that trusts it keeps
//! trusting it. The database stays the source of truth: the file is only a seed.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use limen_ca::ssh::SshCa;
use limen_ca::{CaPurpose, CertificateAuthority, FileSigner, Signer};

use crate::config::{CaBackend, Config};
use crate::db::{self, Db};

#[derive(Debug, Clone)]
pub struct Cas {
    pub internal: CertificateAuthority,
    pub user: CertificateAuthority,
    pub ssh_user: SshCa,
    pub ssh_host: SshCa,
}

pub async fn load(config: &Config, db: &Db) -> anyhow::Result<Cas> {
    let kms = match config.ca_backend {
        CaBackend::Kms => Some(aws_sdk_kms::Client::new(&aws_config::load_from_env().await)),
        CaBackend::File => None,
    };
    let signer = |purpose: CaPurpose, kms_key: Option<String>| {
        let kms = kms.clone();
        let dir = config.ca_dir.clone();
        async move {
            let result: anyhow::Result<(Arc<dyn Signer>, String)> = match kms {
                Some(client) => {
                    let key = kms_key.with_context(|| {
                        format!(
                            "a KMS key for the {} CA is required with the kms backend",
                            purpose.as_str()
                        )
                    })?;
                    let signer = limen_ca::kms::KmsSigner::new(client, &key).await?;
                    Ok((Arc::new(signer), format!("kms:{key}")))
                }
                None => {
                    let path = dir.join(format!("{}-ca.key", purpose.as_str()));
                    Ok((
                        Arc::new(FileSigner::load_or_create(&path)?),
                        format!("file:{}", path.display()),
                    ))
                }
            };
            result
        }
    };

    let (s, key_ref) = signer(CaPurpose::Internal, config.kms_internal_ca_key.clone()).await?;
    let internal = load_x509(
        db,
        CaPurpose::Internal,
        s,
        &key_ref,
        cert_file(config, CaPurpose::Internal),
    )
    .await?;
    let (s, key_ref) = signer(CaPurpose::UserX509, config.kms_user_ca_key.clone()).await?;
    let user = load_x509(
        db,
        CaPurpose::UserX509,
        s,
        &key_ref,
        cert_file(config, CaPurpose::UserX509),
    )
    .await?;
    let (s, _) = signer(CaPurpose::UserSsh, config.kms_ssh_user_ca_key.clone()).await?;
    let ssh_user = SshCa::new(CaPurpose::UserSsh, s)?;
    let (s, _) = signer(CaPurpose::HostSsh, config.kms_ssh_host_ca_key.clone()).await?;
    let ssh_host = SshCa::new(CaPurpose::HostSsh, s)?;
    Ok(Cas {
        internal,
        user,
        ssh_user,
        ssh_host,
    })
}

/// Where the certificate is kept next to a file key. None with KMS keys.
fn cert_file(config: &Config, purpose: CaPurpose) -> Option<PathBuf> {
    match config.ca_backend {
        CaBackend::File => Some(config.ca_dir.join(format!("{}-ca.crt", purpose.as_str()))),
        CaBackend::Kms => None,
    }
}

async fn load_x509(
    db: &Db,
    purpose: CaPurpose,
    signer: Arc<dyn Signer>,
    key_ref: &str,
    cert_file: Option<PathBuf>,
) -> anyhow::Result<CertificateAuthority> {
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(db::locks::CA_BOOTSTRAP)
        .execute(&mut *tx)
        .await?;
    let ca = if let Some(pem) = db::ca_cert(&mut tx, purpose.as_str(), key_ref).await? {
        CertificateAuthority::from_existing(purpose, signer, &pem).map_err(|error| {
            if cert_file.is_some() {
                // A dev stack from before the limen-dev-ca volume: its key is gone.
                anyhow::anyhow!(
                    "{error}. This dev database was created with a different CA key; run `docker compose -f deploy/compose/docker-compose.yml down -v` once (or deploy/compose/up.sh --reset)"
                )
            } else {
                error.into()
            }
        })?
    } else if let Some(ca) = cert_file
        .as_deref()
        .and_then(|path| restore_cert(path, purpose, &signer))
    {
        db::insert_ca_cert(&mut tx, purpose.as_str(), key_ref, ca.cert_pem()).await?;
        tracing::info!(
            purpose = purpose.as_str(),
            key_ref,
            "restored CA certificate from its file"
        );
        ca
    } else {
        let ca = CertificateAuthority::create_self_signed(purpose, signer).await?;
        db::insert_ca_cert(&mut tx, purpose.as_str(), key_ref, ca.cert_pem()).await?;
        tracing::info!(
            purpose = purpose.as_str(),
            key_ref,
            "created CA certificate"
        );
        ca
    };
    tx.commit().await?;
    if let Some(path) = cert_file.as_deref() {
        keep_cert(path, ca.cert_pem());
    }
    Ok(ca)
}

/// The certificate saved next to the key, if there is one for this key.
fn restore_cert(
    path: &Path,
    purpose: CaPurpose,
    signer: &Arc<dyn Signer>,
) -> Option<CertificateAuthority> {
    let pem = std::fs::read_to_string(path).ok()?;
    match CertificateAuthority::from_existing(purpose, Arc::clone(signer), &pem) {
        Ok(ca) => Some(ca),
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "ignoring a CA certificate that doesn't match its key");
            None
        }
    }
}

/// Saves the (public) certificate next to the key. Failing to is not fatal.
fn keep_cert(path: &Path, pem: &str) {
    if std::fs::read_to_string(path).is_ok_and(|saved| saved == pem) {
        return;
    }
    // Write a temp file and rename it, so a crash can't leave a half-written PEM.
    let tmp = path.with_extension("crt.tmp");
    let saved = std::fs::write(&tmp, pem).and_then(|()| std::fs::rename(&tmp, path));
    if let Err(error) = saved {
        tracing::warn!(path = %path.display(), %error, "couldn't save the CA certificate next to its key");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(path: &Path) -> Arc<dyn Signer> {
        Arc::new(FileSigner::load_or_create(path).expect("key"))
    }

    #[tokio::test]
    async fn certificate_file_restores_the_same_certificate_for_the_same_key() {
        let dir = limen_testkit::temp_dir().expect("tempdir");
        let key = dir.path().join("internal-ca.key");
        let crt = dir.path().join("internal-ca.crt");
        let first = CertificateAuthority::create_self_signed(CaPurpose::Internal, signer(&key))
            .await
            .expect("create");
        keep_cert(&crt, first.cert_pem());

        // A wiped database, the same key: the same certificate comes back.
        let again = restore_cert(&crt, CaPurpose::Internal, &signer(&key)).expect("restored");
        assert_eq!(again.cert_pem(), first.cert_pem());
    }

    #[tokio::test]
    async fn certificate_file_for_another_key_is_ignored() {
        let dir = limen_testkit::temp_dir().expect("tempdir");
        let crt = dir.path().join("internal-ca.crt");
        let old = CertificateAuthority::create_self_signed(
            CaPurpose::Internal,
            signer(&dir.path().join("old.key")),
        )
        .await
        .expect("create");
        keep_cert(&crt, old.cert_pem());

        let other = signer(&dir.path().join("new.key"));
        assert!(restore_cert(&crt, CaPurpose::Internal, &other).is_none());
        assert!(
            restore_cert(&dir.path().join("missing.crt"), CaPurpose::Internal, &other).is_none()
        );
    }
}

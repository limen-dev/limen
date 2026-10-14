//! Loading the CA keys and their certificates.
//!
//! Keys come from files (development) or KMS (production). Each X.509 CA
//! certificate is created once, under an advisory lock so concurrent replicas
//! agree, and stored in the database keyed by purpose and key reference. SSH
//! CAs have no certificate: their public key is all anyone needs.

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
    let internal = load_x509(db, CaPurpose::Internal, s, &key_ref).await?;
    let (s, key_ref) = signer(CaPurpose::UserX509, config.kms_user_ca_key.clone()).await?;
    let user = load_x509(db, CaPurpose::UserX509, s, &key_ref).await?;
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

async fn load_x509(
    db: &Db,
    purpose: CaPurpose,
    signer: Arc<dyn Signer>,
    key_ref: &str,
) -> anyhow::Result<CertificateAuthority> {
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(db::locks::CA_BOOTSTRAP)
        .execute(&mut *tx)
        .await?;
    let ca = if let Some(pem) = db::ca_cert(&mut tx, purpose.as_str(), key_ref).await? {
        CertificateAuthority::from_existing(purpose, signer, &pem)?
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
    Ok(ca)
}

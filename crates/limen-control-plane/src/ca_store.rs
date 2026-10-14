//! Loading the CA keys and their certificates.
//!
//! Keys come from files (development) or KMS (production). Each CA
//! certificate is created once, under an advisory lock so concurrent replicas
//! agree, and stored in the database keyed by purpose and key reference.

use std::sync::Arc;

use anyhow::Context as _;
use limen_ca::{CaPurpose, CertificateAuthority, FileSigner, Signer};

use crate::config::{CaBackend, Config};
use crate::db::{self, Db};

#[derive(Debug, Clone)]
pub struct Cas {
    pub internal: CertificateAuthority,
    pub user: CertificateAuthority,
}

pub async fn load(config: &Config, db: &Db) -> anyhow::Result<Cas> {
    let kms = match config.ca_backend {
        CaBackend::Kms => Some(aws_sdk_kms::Client::new(&aws_config::load_from_env().await)),
        CaBackend::File => None,
    };
    let mut cas = Vec::new();
    for (purpose, kms_key) in [
        (CaPurpose::Internal, &config.kms_internal_ca_key),
        (CaPurpose::UserX509, &config.kms_user_ca_key),
    ] {
        let (signer, key_ref): (Arc<dyn Signer>, String) = match &kms {
            Some(client) => {
                let key = kms_key.as_ref().with_context(|| {
                    format!(
                        "--kms-{}-ca-key is required with the kms backend",
                        purpose.as_str()
                    )
                })?;
                (
                    Arc::new(limen_ca::kms::KmsSigner::new(client.clone(), key).await?),
                    format!("kms:{key}"),
                )
            }
            None => {
                let path = config.ca_dir.join(format!("{}-ca.key", purpose.as_str()));
                (
                    Arc::new(FileSigner::load_or_create(&path)?),
                    format!("file:{}", path.display()),
                )
            }
        };
        cas.push(load_one(db, purpose, signer, &key_ref).await?);
    }
    let user = cas.pop().context("user CA")?;
    let internal = cas.pop().context("internal CA")?;
    Ok(Cas { internal, user })
}

async fn load_one(
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

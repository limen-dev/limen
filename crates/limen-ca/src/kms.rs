//! AWS KMS signer (ADR-0007).
//!
//! The key must be `ECC_NIST_P256` with usage `SIGN_VERIFY`. We hash locally
//! and send the SHA-256 digest with `MessageType::Digest`, so certificate
//! size never runs into KMS's 4096-byte message limit. KMS returns DER
//! ECDSA signatures, which X.509 uses unchanged.

use aws_sdk_kms::Client;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{KeySpec, KeyUsageType, MessageType, SigningAlgorithmSpec};
use futures::future::BoxFuture;
use sha2::{Digest, Sha256};

use crate::{CaError, SignError, Signer};

#[derive(Debug, Clone)]
pub struct KmsSigner {
    client: Client,
    key_id: String,
    public_key_raw: Vec<u8>,
}

impl KmsSigner {
    /// Look up the key's public half and check its spec and usage.
    pub async fn new(client: Client, key_id: impl Into<String>) -> Result<Self, CaError> {
        let key_id = key_id.into();
        let out = client
            .get_public_key()
            .key_id(&key_id)
            .send()
            .await
            .map_err(|e| {
                CaError::Internal(format!(
                    "kms:GetPublicKey {key_id}: {}",
                    aws_sdk_kms::error::DisplayErrorContext(&e)
                ))
            })?;
        if out.key_spec() != Some(&KeySpec::EccNistP256) {
            return Err(CaError::InvalidRequest(format!(
                "KMS key {key_id} must be ECC_NIST_P256, got {:?}",
                out.key_spec()
            )));
        }
        if out.key_usage() != Some(&KeyUsageType::SignVerify) {
            return Err(CaError::InvalidRequest(format!(
                "KMS key {key_id} must have usage SIGN_VERIFY"
            )));
        }
        let spki = out
            .public_key()
            .ok_or_else(|| CaError::Internal(format!("KMS key {key_id} returned no public key")))?;
        let (_, parsed) = x509_parser::x509::SubjectPublicKeyInfo::from_der(spki.as_ref())
            .map_err(|e| CaError::Internal(format!("unparseable KMS public key: {e}")))?;
        Ok(Self {
            client,
            key_id,
            public_key_raw: parsed.subject_public_key.data.to_vec(),
        })
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl Signer for KmsSigner {
    fn public_key_raw(&self) -> &[u8] {
        &self.public_key_raw
    }

    fn sign<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, SignError>> {
        Box::pin(async move {
            let digest = Sha256::digest(message);
            let out = self
                .client
                .sign()
                .key_id(&self.key_id)
                .message(Blob::new(digest.to_vec()))
                .message_type(MessageType::Digest)
                .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
                .send()
                .await
                .map_err(|e| {
                    SignError::Unavailable(aws_sdk_kms::error::DisplayErrorContext(&e).to_string())
                })?;
            out.signature()
                .map(|b| b.as_ref().to_vec())
                .ok_or_else(|| SignError::Rejected("KMS returned no signature".into()))
        })
    }
}

use x509_parser::prelude::FromDer as _;

//! Signed envelopes. The signature covers `label || 0x00 || payload`, so a
//! signature made for one purpose can't be presented as another.

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use limen_ca::verify::{ComponentIdentity, verify_component};
use limen_core::identity::ComponentKind;
use limen_proto::v1::Signed;
use rcgen::{KeyPair, SigningKey as _};
use rustls_pki_types::CertificateDer;

use crate::SessionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    SessionGrant,
    PolicySnapshot,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Purpose::SessionGrant => b"limen/v1/session-grant",
            Purpose::PolicySnapshot => b"limen/v1/policy-snapshot",
        }
    }

    /// Who is allowed to sign this purpose.
    fn signer_kind(self) -> ComponentKind {
        match self {
            Purpose::SessionGrant => ComponentKind::Proxy,
            Purpose::PolicySnapshot => ComponentKind::ControlPlane,
        }
    }
}

fn message(purpose: Purpose, payload: &[u8]) -> Vec<u8> {
    let label = purpose.label();
    let mut m = Vec::with_capacity(label.len() + 1 + payload.len());
    m.extend_from_slice(label);
    m.push(0);
    m.extend_from_slice(payload);
    m
}

/// Signs envelopes with a component's own key (the one in its TLS certificate).
#[derive(Debug)]
pub struct EnvelopeSigner {
    key: KeyPair,
    cert_der: Vec<u8>,
}

impl EnvelopeSigner {
    pub fn new(key_pem: &str, cert_der: Vec<u8>) -> Result<Self, SessionError> {
        Ok(Self {
            key: KeyPair::from_pem(key_pem).map_err(|e| SessionError::Signature(e.to_string()))?,
            cert_der,
        })
    }

    pub fn sign(&self, purpose: Purpose, payload: Vec<u8>) -> Result<Signed, SessionError> {
        let signature = self
            .key
            .sign(&message(purpose, &payload))
            .map_err(|e| SessionError::Signature(e.to_string()))?;
        Ok(Signed {
            payload,
            signature,
            signer_cert_der: self.cert_der.clone(),
        })
    }
}

/// Verify the signer's certificate (internal CA, right component kind for
/// `purpose`) and the signature. Returns the signer and the payload.
pub fn verify<'a>(
    signed: &'a Signed,
    purpose: Purpose,
    internal_ca: &CertificateDer<'_>,
) -> Result<(ComponentIdentity, &'a [u8]), SessionError> {
    let cert = CertificateDer::from(signed.signer_cert_der.as_slice());
    let signed_by = verify_component(&cert, internal_ca, false)
        .map_err(|e| SessionError::Signature(e.to_string()))?;
    if signed_by.kind != purpose.signer_kind() {
        return Err(SessionError::Signature(format!(
            "a {} may not sign {purpose:?}",
            signed_by.kind
        )));
    }
    let (_, parsed) = x509_parser::parse_x509_certificate(&cert)
        .map_err(|e| SessionError::Signature(e.to_string()))?;
    let point = parsed.public_key().subject_public_key.data.as_ref();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
        .verify(&message(purpose, &signed.payload), &signed.signature)
        .map_err(|_| SessionError::Signature("signature does not verify".into()))?;
    Ok((signed_by, &signed.payload))
}

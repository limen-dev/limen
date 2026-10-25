//! Signed envelopes. The signature covers `label || 0x00 || payload`, so a
//! signature made for one purpose can't be presented as another.

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use base64::Engine as _;
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
    /// An S3 audit batch manifest (ADR-0009).
    AuditManifest,
    /// A browser's identity and host-bound app session (ADR-0022).
    WebAppSession,
    /// A pack of compliance evidence (ADR-0029).
    EvidencePack,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Purpose::SessionGrant => b"limen/v1/session-grant",
            Purpose::PolicySnapshot => b"limen/v1/policy-snapshot",
            Purpose::AuditManifest => b"limen/v1/audit-manifest",
            Purpose::WebAppSession => b"limen/v1/web-app-session",
            Purpose::EvidencePack => b"limen/v1/evidence-pack",
        }
    }

    /// Who is allowed to sign this purpose.
    fn signer_kind(self) -> ComponentKind {
        match self {
            Purpose::SessionGrant => ComponentKind::Proxy,
            Purpose::PolicySnapshot
            | Purpose::AuditManifest
            | Purpose::WebAppSession
            | Purpose::EvidencePack => ComponentKind::ControlPlane,
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

    /// Sign a compact ES256 JWT using this component certificate's key.
    pub fn sign_jwt(&self, claims: &serde_json::Value) -> Result<String, SessionError> {
        let jwk = self.jwk()?;
        let kid = jwk["kid"]
            .as_str()
            .ok_or_else(|| SessionError::Signature("missing JWK key id".into()))?;
        let header = serde_json::json!({"alg": "ES256", "typ": "JWT", "kid": kid});
        let encode = |value: &serde_json::Value| {
            serde_json::to_vec(value)
                .map(|bytes| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
                .map_err(|e| SessionError::Malformed(e.to_string()))
        };
        let input = format!("{}.{}", encode(&header)?, encode(claims)?);
        let der = self
            .key
            .sign(input.as_bytes())
            .map_err(|e| SessionError::Signature(e.to_string()))?;
        let signature = ecdsa_der_to_jose(&der)?;
        Ok(format!(
            "{input}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    /// A one-key JWKS for JWT assertions signed by this component.
    pub fn jwks(&self) -> Result<serde_json::Value, SessionError> {
        Ok(serde_json::json!({"keys": [self.jwk()?]}))
    }

    fn jwk(&self) -> Result<serde_json::Value, SessionError> {
        let cert = CertificateDer::from(self.cert_der.as_slice());
        let (_, parsed) = x509_parser::parse_x509_certificate(&cert)
            .map_err(|e| SessionError::Signature(e.to_string()))?;
        let point = parsed.public_key().subject_public_key.data.as_ref();
        if point.len() != 65 || point[0] != 4 {
            return Err(SessionError::Signature(
                "component certificate is not a P-256 public key".into(),
            ));
        }
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&point[1..33]);
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&point[33..65]);
        let kid = format!("{x}.{y}");
        Ok(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": kid,
            "x": x,
            "y": y,
        }))
    }
}

fn ecdsa_der_to_jose(der: &[u8]) -> Result<[u8; 64], SessionError> {
    if der.len() < 8 || der[0] != 0x30 || usize::from(der[1]) != der.len() - 2 {
        return Err(SessionError::Signature("malformed ECDSA signature".into()));
    }
    let mut offset = 2;
    let mut raw = [0_u8; 64];
    for chunk in raw.as_chunks_mut::<32>().0 {
        if der.get(offset) != Some(&0x02) {
            return Err(SessionError::Signature(
                "malformed ECDSA signature integer".into(),
            ));
        }
        let len =
            usize::from(*der.get(offset + 1).ok_or_else(|| {
                SessionError::Signature("malformed ECDSA signature length".into())
            })?);
        offset += 2;
        let integer = der
            .get(offset..offset + len)
            .ok_or_else(|| SessionError::Signature("truncated ECDSA signature integer".into()))?;
        let integer = integer.strip_prefix(&[0]).unwrap_or(integer);
        if integer.len() > 32 {
            return Err(SessionError::Signature(
                "oversized ECDSA signature integer".into(),
            ));
        }
        chunk[32 - integer.len()..].copy_from_slice(integer);
        offset += len;
    }
    if offset != der.len() {
        return Err(SessionError::Signature(
            "trailing data in ECDSA signature".into(),
        ));
    }
    Ok(raw)
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

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    use super::*;

    #[test]
    fn jose_signature_uses_fixed_width_r_and_s() {
        let raw = ecdsa_der_to_jose(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])
            .expect("valid ECDSA signature");
        assert_eq!(raw[31], 1);
        assert_eq!(raw[63], 2);
        assert!(raw[..31].iter().all(|byte| *byte == 0));
        assert!(raw[32..63].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn jwt_signature_verifies_with_the_published_jwk() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let cert = CertificateParams::default()
            .self_signed(&key)
            .expect("certificate");
        let signer = EnvelopeSigner::new(&key.serialize_pem(), cert.der().to_vec())
            .expect("envelope signer");
        let jwt = signer
            .sign_jwt(&serde_json::json!({"sub": "alice", "aud": "app.example"}))
            .expect("signed JWT");
        let mut parts = jwt.split('.');
        let header = parts.next().expect("header");
        let payload = parts.next().expect("payload");
        let signature = parts.next().expect("signature");
        assert!(parts.next().is_none());
        let jwk = &signer.jwks().expect("JWKS")["keys"][0];
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwk["x"].as_str().expect("x"))
            .expect("decode x");
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwk["y"].as_str().expect("y"))
            .expect("decode y");
        let mut point = Vec::with_capacity(65);
        point.push(4);
        point.extend(x);
        point.extend(y);
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature)
            .expect("decode signature");
        assert_eq!(raw.len(), 64);
        let mut der = Vec::from([0x30, 0x00]);
        let mut ints = Vec::with_capacity(70);
        for integer in raw.as_chunks::<32>().0 {
            ints.push(0x02);
            let leading_zero = integer[0] & 0x80 != 0;
            ints.push(u8::try_from(integer.len() + usize::from(leading_zero)).expect("length"));
            if leading_zero {
                ints.push(0);
            }
            ints.extend(integer);
        }
        der[1] = u8::try_from(ints.len()).expect("sequence length");
        der.extend(ints);
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
            .verify(format!("{header}.{payload}").as_bytes(), &der)
            .expect("JWT signature verifies");
    }
}

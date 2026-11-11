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
    verify_as_of(signed, purpose, internal_ca, None)
}

/// [`verify`], with the signer's certificate judged as of `at` instead of now:
/// for something signed in the past, such as an audit manifest, whose signer's
/// short-lived certificate has since expired.
pub fn verify_at<'a>(
    signed: &'a Signed,
    purpose: Purpose,
    internal_ca: &CertificateDer<'_>,
    at: time::OffsetDateTime,
) -> Result<(ComponentIdentity, &'a [u8]), SessionError> {
    verify_as_of(signed, purpose, internal_ca, Some(at))
}

fn verify_as_of<'a>(
    signed: &'a Signed,
    purpose: Purpose,
    internal_ca: &CertificateDer<'_>,
    at: Option<time::OffsetDateTime>,
) -> Result<(ComponentIdentity, &'a [u8]), SessionError> {
    let cert = CertificateDer::from(signed.signer_cert_der.as_slice());
    let signed_by = match at {
        None => verify_component(&cert, internal_ca, false),
        Some(at) => limen_ca::verify::verify_component_at(&cert, internal_ca, false, at),
    }
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
    use aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED;
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    use super::*;

    use std::sync::Arc;
    use std::time::Duration;

    use limen_ca::{CaPurpose, CertificateAuthority, ComponentCertRequest, FileSigner};

    const ALL: [Purpose; 5] = [
        Purpose::SessionGrant,
        Purpose::PolicySnapshot,
        Purpose::AuditManifest,
        Purpose::WebAppSession,
        Purpose::EvidencePack,
    ];

    async fn internal_ca() -> CertificateAuthority {
        CertificateAuthority::create_self_signed(
            CaPurpose::Internal,
            Arc::new(FileSigner::generate().expect("key")),
        )
        .await
        .expect("ca")
    }

    async fn component(ca: &CertificateAuthority, kind: ComponentKind, id: &str) -> EnvelopeSigner {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let csr = CertificateParams::default()
            .serialize_request(&key)
            .expect("csr");
        let cert = ca
            .issue_component(ComponentCertRequest {
                csr_der: csr.der().to_vec(),
                kind,
                id: id.into(),
                dns_names: vec![],
                labels: std::collections::BTreeMap::new(),
                ttl: Duration::from_secs(600),
            })
            .await
            .expect("issue");
        EnvelopeSigner::new(&key.serialize_pem(), cert.der.to_vec()).expect("signer")
    }

    /// The reason an envelope was refused, so each case proves which check fired.
    fn refusal(result: Result<(ComponentIdentity, &[u8]), SessionError>) -> String {
        match result {
            Err(SessionError::Signature(reason)) => reason,
            Err(other) => panic!("expected a signature refusal, got {other:?}"),
            Ok((who, _)) => panic!("expected a refusal, verified as signed by {who:?}"),
        }
    }

    /// The control plane signs four purposes with one key. Only the label in
    /// the signed message keeps, say, a policy snapshot from being replayed as
    /// a browser's web-app session, so the kind check can't be what stops it.
    #[tokio::test]
    async fn a_signature_for_one_purpose_never_verifies_as_another() {
        let ca = internal_ca().await;
        let cp = component(&ca, ComponentKind::ControlPlane, "cp1").await;
        let proxy = component(&ca, ComponentKind::Proxy, "p1").await;
        let signer_for = |p: Purpose| match p {
            Purpose::SessionGrant => &proxy,
            _ => &cp,
        };
        for signed_as in ALL {
            let signed = signer_for(signed_as)
                .sign(signed_as, b"payload".to_vec())
                .expect("sign");
            let (who, payload) = verify(&signed, signed_as, ca.cert_der()).expect("verifies");
            assert_eq!(payload, b"payload");
            assert_eq!(who.kind, signed_as.signer_kind());
            for presented_as in ALL.into_iter().filter(|p| *p != signed_as) {
                let reason = refusal(verify(&signed, presented_as, ca.cert_der()));
                // Same signer kind: the label is the only thing that differs.
                if presented_as.signer_kind() == signed_as.signer_kind() {
                    assert_eq!(
                        reason, "signature does not verify",
                        "{signed_as:?} presented as {presented_as:?}"
                    );
                }
            }
        }
    }

    /// A proxy may sign session grants only, a worker nothing, and the control
    /// plane everything but session grants. A valid signature by the wrong kind
    /// is refused before the signature is even checked.
    #[tokio::test]
    async fn only_the_allowed_component_kind_may_sign_each_purpose() {
        let ca = internal_ca().await;
        let cp = component(&ca, ComponentKind::ControlPlane, "cp1").await;
        let proxy = component(&ca, ComponentKind::Proxy, "p1").await;
        let worker = component(&ca, ComponentKind::Worker, "w1").await;
        for purpose in ALL {
            for (kind, signer) in [
                (ComponentKind::ControlPlane, &cp),
                (ComponentKind::Proxy, &proxy),
                (ComponentKind::Worker, &worker),
            ] {
                let signed = signer.sign(purpose, b"payload".to_vec()).expect("sign");
                let result = verify(&signed, purpose, ca.cert_der());
                if kind == purpose.signer_kind() {
                    assert!(result.is_ok(), "{kind} signing {purpose:?}");
                } else {
                    assert_eq!(
                        refusal(result),
                        format!("a {kind} may not sign {purpose:?}"),
                        "{kind} signing {purpose:?}"
                    );
                }
            }
        }
    }

    /// The certificate in the envelope decides who signed it, so it must chain
    /// to the internal CA and hold the key that made the signature.
    #[tokio::test]
    async fn the_signer_certificate_must_be_trusted_and_match_the_signature() {
        let ca = internal_ca().await;
        let rogue_ca = internal_ca().await;
        let cp = component(&ca, ComponentKind::ControlPlane, "cp1").await;
        let other_cp = component(&ca, ComponentKind::ControlPlane, "cp2").await;
        let rogue = component(&rogue_ca, ComponentKind::ControlPlane, "cp1").await;
        let purpose = Purpose::PolicySnapshot;

        // A well-formed control plane certificate from a CA nobody trusts.
        let by_rogue = rogue.sign(purpose, b"payload".to_vec()).expect("sign");
        assert!(verify(&by_rogue, purpose, rogue_ca.cert_der()).is_ok());
        let reason = refusal(verify(&by_rogue, purpose, ca.cert_der()));
        assert!(
            reason.starts_with("certificate is not valid for this CA"),
            "{reason}"
        );

        // A real signature, but the envelope names another trusted signer.
        let mut swapped = cp.sign(purpose, b"payload".to_vec()).expect("sign");
        swapped.signer_cert_der.clone_from(
            &other_cp
                .sign(purpose, vec![])
                .expect("sign")
                .signer_cert_der,
        );
        assert_eq!(
            refusal(verify(&swapped, purpose, ca.cert_der())),
            "signature does not verify"
        );

        // A changed payload, a missing signature, and no certificate at all.
        let good = cp.sign(purpose, b"payload".to_vec()).expect("sign");
        let mut tampered = good.clone();
        tampered.payload = b"pAyload".to_vec();
        assert_eq!(
            refusal(verify(&tampered, purpose, ca.cert_der())),
            "signature does not verify"
        );
        let mut unsigned = good.clone();
        unsigned.signature.clear();
        assert_eq!(
            refusal(verify(&unsigned, purpose, ca.cert_der())),
            "signature does not verify"
        );
        let mut no_cert = good;
        no_cert.signer_cert_der.clear();
        refusal(verify(&no_cert, purpose, ca.cert_der()));
    }

    #[test]
    fn malformed_der_signatures_are_refused() {
        // r = 1, s = 2: the smallest valid shape.
        let ok = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        assert!(ecdsa_der_to_jose(&ok).is_ok());
        let mut r33 = vec![0x30, 0x26, 0x02, 0x21, 0x01];
        r33.extend([0xaa; 32]);
        r33.extend([0x02, 0x01, 0x02]);
        let cases: [(&str, Vec<u8>); 6] = [
            ("too short", vec![0x30, 0x04, 0x02, 0x01, 0x01, 0x02]),
            (
                "not a sequence",
                vec![0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02],
            ),
            (
                "wrong outer length",
                vec![0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02],
            ),
            (
                "not an integer",
                vec![0x30, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x02],
            ),
            (
                "truncated integer",
                vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x05, 0x02],
            ),
            // 33 bytes with a non-zero first byte can't fit in 32.
            ("oversized integer", r33),
        ];
        for (name, der) in cases {
            assert!(ecdsa_der_to_jose(&der).is_err(), "{name}");
        }
        // A leading zero (DER's sign byte) is stripped, not counted.
        let mut padded = vec![0x30, 0x26, 0x02, 0x21, 0x00];
        padded.extend([0xaa; 32]);
        padded.extend([0x02, 0x01, 0x02]);
        let raw = ecdsa_der_to_jose(&padded).expect("a sign byte is allowed");
        assert_eq!(&raw[..32], &[0xaa; 32]);
        // Bytes after both integers.
        let mut trailing = ok.to_vec();
        trailing[1] = 0x07;
        trailing.push(0x00);
        assert!(ecdsa_der_to_jose(&trailing).is_err(), "trailing data");
    }

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
        // A JWT carries r || s as 64 bytes, so verify it as that (re-encoding it as
        // DER needs minimal-length integers, which fails for 1 in 128 signatures).
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
            .verify(format!("{header}.{payload}").as_bytes(), &raw)
            .expect("JWT signature verifies");
    }
}

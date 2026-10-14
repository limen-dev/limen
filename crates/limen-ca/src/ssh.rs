//! OpenSSH certificate authorities (ADR-0007, amended in Phase 2).
//!
//! Two CAs, both short-lived-certificate only:
//! - the **user** CA signs a one-minute certificate per SSH session, which
//!   the worker presents to the target (`TrustedUserCAKeys`);
//! - the **host** CA signs a per-session host certificate for the worker,
//!   which the user's `ssh` verifies through `@cert-authority` in known_hosts.
//!
//! Signing goes through [`Signer`], so these work with KMS keys too. KMS
//! returns DER ECDSA signatures; OpenSSH wants `mpint(r) || mpint(s)`.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ssh_key::certificate::{Builder, CertType};
use ssh_key::public::{EcdsaPublicKey, KeyData};
use ssh_key::{Algorithm, Certificate, EcdsaCurve, PublicKey, Signature};

use crate::{CaError, CaPurpose, Signer};

/// Back-dating for clock skew, as for X.509.
const BACKDATE: Duration = Duration::from_secs(60);
const MAX_SSH_TTL: Duration = Duration::from_hours(12);

#[derive(Debug, Clone)]
pub struct SshCa {
    purpose: CaPurpose,
    signer: Arc<dyn Signer>,
    public: PublicKey,
}

/// A per-session user certificate for a target host.
#[derive(Debug, Clone)]
pub struct SshUserCertRequest {
    pub public_key: PublicKey,
    /// The Unix login on the target. Exactly one principal per certificate.
    pub principal: String,
    /// Shows up in the target's sshd log, so it's the session ID.
    pub key_id: String,
    pub ttl: Duration,
    pub permit_pty: bool,
    pub permit_port_forwarding: bool,
}

/// A per-session host certificate for a worker.
#[derive(Debug, Clone)]
pub struct SshHostCertRequest {
    pub public_key: PublicKey,
    /// Host names the certificate is valid for: the resource name the user typed.
    pub principals: Vec<String>,
    pub key_id: String,
    pub ttl: Duration,
}

impl SshCa {
    pub fn new(purpose: CaPurpose, signer: Arc<dyn Signer>) -> Result<Self, CaError> {
        if !matches!(purpose, CaPurpose::UserSsh | CaPurpose::HostSsh) {
            return Err(CaError::InvalidRequest(format!(
                "{} is not an SSH CA",
                purpose.as_str()
            )));
        }
        let point = EcdsaPublicKey::from_sec1_bytes(signer.public_key_raw())
            .map_err(|e| CaError::Internal(format!("SSH CA key: {e}")))?;
        let mut public = PublicKey::from(KeyData::Ecdsa(point));
        public.set_comment(format!("limen-{}-ca", purpose.as_str().replace('_', "-")));
        Ok(Self {
            purpose,
            signer,
            public,
        })
    }

    #[must_use]
    pub fn purpose(&self) -> CaPurpose {
        self.purpose
    }

    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// One line in OpenSSH format, for `TrustedUserCAKeys` or known_hosts.
    pub fn public_key_openssh(&self) -> Result<String, CaError> {
        self.public
            .to_openssh()
            .map_err(|e| CaError::Internal(e.to_string()))
    }

    pub async fn issue_user_cert(&self, req: SshUserCertRequest) -> Result<Certificate, CaError> {
        if self.purpose != CaPurpose::UserSsh {
            return Err(CaError::InvalidRequest(
                "only the SSH user CA issues user certificates".into(),
            ));
        }
        validate_principal(&req.principal)?;
        let mut builder = builder(&req.public_key, req.ttl)?;
        builder.cert_type(CertType::User).map_err(ssh_err)?;
        builder.key_id(req.key_id).map_err(ssh_err)?;
        builder.valid_principal(req.principal).map_err(ssh_err)?;
        // Only what the role allows. Agent and X11 forwarding are never granted.
        if req.permit_pty {
            builder.extension("permit-pty", "").map_err(ssh_err)?;
        }
        if req.permit_port_forwarding {
            builder
                .extension("permit-port-forwarding", "")
                .map_err(ssh_err)?;
        }
        self.sign(builder).await
    }

    pub async fn issue_host_cert(&self, req: SshHostCertRequest) -> Result<Certificate, CaError> {
        if self.purpose != CaPurpose::HostSsh {
            return Err(CaError::InvalidRequest(
                "only the SSH host CA issues host certificates".into(),
            ));
        }
        if req.principals.is_empty() {
            return Err(CaError::InvalidRequest(
                "host certificates need at least one principal".into(),
            ));
        }
        let mut builder = builder(&req.public_key, req.ttl)?;
        builder.cert_type(CertType::Host).map_err(ssh_err)?;
        builder.key_id(req.key_id).map_err(ssh_err)?;
        for principal in req.principals {
            validate_principal(&principal)?;
            builder.valid_principal(principal).map_err(ssh_err)?;
        }
        self.sign(builder).await
    }

    async fn sign(&self, builder: Builder) -> Result<Certificate, CaError> {
        let runtime = tokio::runtime::Handle::current();
        let signer = Arc::clone(&self.signer);
        let public = self.public.key_data().clone();
        tokio::task::spawn_blocking(move || {
            builder.sign(&BlockingSshSigner {
                inner: &*signer,
                public,
                runtime,
            })
        })
        .await
        .map_err(|e| CaError::Internal(e.to_string()))?
        .map_err(ssh_err)
    }
}

fn builder(public_key: &PublicKey, ttl: Duration) -> Result<Builder, CaError> {
    if ttl.is_zero() || ttl > MAX_SSH_TTL {
        return Err(CaError::InvalidRequest(format!("ttl {ttl:?} out of range")));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CaError::Internal(e.to_string()))?;
    let valid_after = now.saturating_sub(BACKDATE).as_secs();
    let valid_before = (now + ttl).as_secs();
    let nonce: [u8; 32] = rand::random();
    let mut builder = Builder::new(
        nonce.to_vec(),
        public_key.key_data().clone(),
        valid_after,
        valid_before,
    )
    .map_err(ssh_err)?;
    builder.serial(rand::random()).map_err(ssh_err)?;
    Ok(builder)
}

fn validate_principal(p: &str) -> Result<(), CaError> {
    let ok = !p.is_empty()
        && p.len() <= 256
        && !p.contains(['*', '?', ',', ' '])
        && !p.chars().any(char::is_control);
    if ok {
        Ok(())
    } else {
        Err(CaError::InvalidRequest(format!(
            "invalid SSH principal {p:?}"
        )))
    }
}

// Used as a `map_err` function, so it takes the error by value.
#[allow(clippy::needless_pass_by_value)]
fn ssh_err(e: ssh_key::Error) -> CaError {
    CaError::Internal(format!("ssh certificate: {e}"))
}

/// Adapts an async [`Signer`] to ssh-key's synchronous signing. Runs on the
/// blocking pool, like the X.509 bridge.
struct BlockingSshSigner<'a> {
    inner: &'a dyn Signer,
    public: KeyData,
    runtime: tokio::runtime::Handle,
}

impl signature::Signer<Signature> for BlockingSshSigner<'_> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        let der = self
            .runtime
            .block_on(self.inner.sign(msg))
            .map_err(signature::Error::from_source)?;
        let blob = der_to_ssh_ecdsa(&der).ok_or_else(signature::Error::new)?;
        Signature::new(
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            blob,
        )
        .map_err(signature::Error::from_source)
    }
}

impl From<&BlockingSshSigner<'_>> for KeyData {
    fn from(signer: &BlockingSshSigner<'_>) -> Self {
        signer.public.clone()
    }
}

/// DER `SEQUENCE { INTEGER r, INTEGER s }` to the SSH ECDSA signature blob
/// `mpint(r) || mpint(s)` (RFC 5656 §3.1.2). `None` on malformed input.
#[must_use]
pub fn der_to_ssh_ecdsa(der: &[u8]) -> Option<Vec<u8>> {
    fn read_len(input: &mut &[u8]) -> Option<usize> {
        let (&first, rest) = input.split_first()?;
        *input = rest;
        if first < 0x80 {
            return Some(usize::from(first));
        }
        // Long form, at most 2 length bytes for a P-256 signature.
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 2 || input.len() < n {
            return None;
        }
        let (len_bytes, rest) = input.split_at(n);
        *input = rest;
        Some(
            len_bytes
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b)),
        )
    }
    fn read_integer<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
        let (&tag, rest) = input.split_first()?;
        if tag != 0x02 {
            return None;
        }
        *input = rest;
        let len = read_len(input)?;
        if input.len() < len || len == 0 {
            return None;
        }
        let (value, rest) = input.split_at(len);
        *input = rest;
        Some(value)
    }
    fn mpint(out: &mut Vec<u8>, value: &[u8]) {
        // Minimal two's complement: strip leading zeros, then add one back if
        // the high bit is set so the number stays positive.
        let mut v = value;
        while v.len() > 1 && v[0] == 0 {
            v = &v[1..];
        }
        let pad = v.first().is_some_and(|b| b & 0x80 != 0);
        let len = u32::try_from(v.len() + usize::from(pad)).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        if pad {
            out.push(0);
        }
        out.extend_from_slice(v);
    }

    let mut input = der;
    let (&tag, rest) = input.split_first()?;
    if tag != 0x30 {
        return None;
    }
    input = rest;
    let len = read_len(&mut input)?;
    if input.len() != len {
        return None;
    }
    let r = read_integer(&mut input)?;
    let s = read_integer(&mut input)?;
    if !input.is_empty() || r.len() > 33 || s.len() > 33 {
        return None;
    }
    let mut out = Vec::with_capacity(72);
    mpint(&mut out, r);
    mpint(&mut out, s);
    Some(out)
}

#[cfg(test)]
mod tests {
    use ssh_key::{HashAlg, PrivateKey};

    use super::*;
    use crate::FileSigner;

    fn ca(purpose: CaPurpose) -> SshCa {
        SshCa::new(purpose, Arc::new(FileSigner::generate().expect("key"))).expect("ca")
    }

    fn user_key() -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("key")
    }

    #[tokio::test]
    async fn user_cert_validates_against_ca_and_has_one_principal() {
        let ca = ca(CaPurpose::UserSsh);
        let key = user_key();
        let cert = ca
            .issue_user_cert(SshUserCertRequest {
                public_key: key.public_key().clone(),
                principal: "ubuntu".into(),
                key_id: "session-0192".into(),
                ttl: Duration::from_mins(1),
                permit_pty: true,
                permit_port_forwarding: false,
            })
            .await
            .expect("issue");
        let fingerprint = ca.public_key().fingerprint(HashAlg::Sha256);
        cert.validate([&fingerprint])
            .expect("signature and validity check out");
        assert_eq!(cert.cert_type(), CertType::User);
        assert_eq!(cert.valid_principals(), ["ubuntu"]);
        assert_eq!(cert.key_id(), "session-0192");
        assert!(cert.extensions().contains_key("permit-pty"));
        assert!(!cert.extensions().contains_key("permit-agent-forwarding"));
        assert!(!cert.extensions().contains_key("permit-port-forwarding"));
        let lifetime = cert.valid_before() - cert.valid_after();
        assert!(
            lifetime <= 121,
            "1 minute TTL plus 1 minute back-dating, got {lifetime}s"
        );
        // A different CA doesn't validate it.
        let other = ca_other();
        assert!(
            cert.validate([&other.public_key().fingerprint(HashAlg::Sha256)])
                .is_err()
        );
    }

    fn ca_other() -> SshCa {
        ca(CaPurpose::UserSsh)
    }

    #[tokio::test]
    async fn host_cert_and_purpose_separation() {
        let host_ca = ca(CaPurpose::HostSsh);
        let user_ca = ca(CaPurpose::UserSsh);
        let key = user_key();
        let req = SshHostCertRequest {
            public_key: key.public_key().clone(),
            principals: vec!["web-staging-1".into()],
            key_id: "s".into(),
            ttl: Duration::from_mins(5),
        };
        let cert = host_ca
            .issue_host_cert(req.clone())
            .await
            .expect("host cert");
        assert_eq!(cert.cert_type(), CertType::Host);
        cert.validate([&host_ca.public_key().fingerprint(HashAlg::Sha256)])
            .expect("valid");
        assert!(
            user_ca.issue_host_cert(req).await.is_err(),
            "user CA must not issue host certs"
        );
        let user_req = SshUserCertRequest {
            public_key: key.public_key().clone(),
            principal: "root".into(),
            key_id: "s".into(),
            ttl: Duration::from_mins(1),
            permit_pty: false,
            permit_port_forwarding: false,
        };
        assert!(
            host_ca.issue_user_cert(user_req.clone()).await.is_err(),
            "host CA must not issue user certs"
        );
        for bad in ["", "*", "a,b", "a b"] {
            let req = SshUserCertRequest {
                principal: bad.into(),
                ..user_req.clone()
            };
            assert!(
                user_ca.issue_user_cert(req).await.is_err(),
                "principal {bad:?}"
            );
        }
    }

    #[test]
    fn der_conversion_handles_padding_and_rejects_garbage() {
        // r = 0x80 (DER-padded, high bit set: stays padded in mpint);
        // s = 0x0102 with a superfluous leading zero (stripped).
        let der = [
            0x30, 0x09, 0x02, 0x02, 0x00, 0x80, 0x02, 0x03, 0x00, 0x01, 0x02,
        ];
        let blob = der_to_ssh_ecdsa(&der).expect("valid");
        assert_eq!(blob, [0, 0, 0, 2, 0x00, 0x80, 0, 0, 0, 2, 0x01, 0x02]);
        for bad in [
            &[][..],
            &[0x31, 0x00],
            &[0x30, 0x03, 0x02, 0x01],
            &[0x30, 0x02, 0x05, 0x00],
        ] {
            assert_eq!(der_to_ssh_ecdsa(bad), None, "{bad:?}");
        }
    }
}

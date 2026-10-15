//! Certificate issuance.

use std::sync::Arc;
use std::time::Duration;

use limen_core::identity::{ComponentKind, IdentityUri};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose, SanType, SerialNumber,
    string::Ia5String,
};
use rustls_pki_types::{CertificateDer, CertificateSigningRequestDer};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::signer::BlockingSigner;
use crate::{CaError, CaPurpose, Signer};

/// Certificates are back-dated by this much to tolerate clock skew between hosts.
const BACKDATE: time::Duration = time::Duration::minutes(1);
const CA_VALIDITY: time::Duration = time::Duration::days(3650);
const MAX_NAME_LEN: usize = 256;

/// A certificate authority: a signing key and its self-signed CA certificate.
#[derive(Debug, Clone)]
pub struct CertificateAuthority {
    purpose: CaPurpose,
    signer: Arc<dyn Signer>,
    cert_der: CertificateDer<'static>,
    cert_pem: String,
}

/// A request for a short-lived user client certificate.
#[derive(Debug, Clone)]
pub struct UserCertRequest {
    /// DER PKCS#10 CSR. Its signature proves possession of the private key.
    /// Everything in it except the public key is ignored.
    pub csr_der: Vec<u8>,
    pub username: String,
    pub roles: Vec<String>,
    pub login_id: Uuid,
    pub ttl: Duration,
    /// `Some` makes this a bot certificate: the facts about the CI run behind
    /// the login. The username must then be `bot:<name>`, and a person's
    /// certificate can't carry that prefix.
    pub ci: Option<std::collections::BTreeMap<String, String>>,
}

/// Most CI facts a bot certificate carries, and how long each may be.
pub const MAX_CI_FACTS: usize = 16;
/// In bytes.
pub const MAX_CI_VALUE: usize = 256;

/// A request for a control plane, proxy, or worker certificate.
#[derive(Debug, Clone)]
pub struct ComponentCertRequest {
    pub csr_der: Vec<u8>,
    pub kind: ComponentKind,
    pub id: String,
    /// DNS names for server certificates (proxies and the control plane).
    pub dns_names: Vec<String>,
    /// Labels set at enrollment. Resources select workers by them, so they
    /// are signed into the certificate rather than self-reported.
    pub labels: std::collections::BTreeMap<String, String>,
    pub ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct IssuedCert {
    pub der: CertificateDer<'static>,
    pub pem: String,
    pub serial_hex: String,
    pub not_after: OffsetDateTime,
}

impl CertificateAuthority {
    /// Create a new self-signed CA certificate for `signer`.
    pub async fn create_self_signed(
        purpose: CaPurpose,
        signer: Arc<dyn Signer>,
    ) -> Result<Self, CaError> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "Limen");
        dn.push(DnType::CommonName, purpose.common_name());
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - BACKDATE;
        params.not_after = now + CA_VALIDITY;
        params.serial_number = Some(random_serial());

        let runtime = tokio::runtime::Handle::current();
        let signer_for_task = Arc::clone(&signer);
        let cert = tokio::task::spawn_blocking(move || {
            let key = BlockingSigner {
                inner: &*signer_for_task,
                runtime,
            };
            params.self_signed(&key)
        })
        .await
        .map_err(|e| CaError::Internal(e.to_string()))??;

        Ok(Self {
            purpose,
            signer,
            cert_der: cert.der().clone(),
            cert_pem: cert.pem(),
        })
    }

    /// Load an existing CA certificate, checking that it belongs to `signer`.
    pub fn from_existing(
        purpose: CaPurpose,
        signer: Arc<dyn Signer>,
        cert_pem: &str,
    ) -> Result<Self, CaError> {
        let der = pem_to_der(cert_pem)?;
        let (_, cert) = x509_parser::parse_x509_certificate(&der)
            .map_err(|e| CaError::InvalidRequest(format!("unparseable CA certificate: {e}")))?;
        if cert.public_key().subject_public_key.data.as_ref() != signer.public_key_raw() {
            return Err(CaError::InvalidRequest(format!(
                "{} CA certificate does not match its signing key",
                purpose.as_str()
            )));
        }
        Ok(Self {
            purpose,
            signer,
            cert_der: CertificateDer::from(der),
            cert_pem: cert_pem.to_owned(),
        })
    }

    #[must_use]
    pub fn purpose(&self) -> CaPurpose {
        self.purpose
    }

    #[must_use]
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Issue a user client certificate. Only the user CA may do this.
    pub async fn issue_user(&self, req: UserCertRequest) -> Result<IssuedCert, CaError> {
        self.require(CaPurpose::UserX509)?;
        validate_name("username", &req.username)?;
        for role in &req.roles {
            validate_name("role", role)?;
        }
        if limen_core::identity::is_bot(&req.username) != req.ci.is_some() {
            return Err(CaError::InvalidRequest(
                "only bots use the bot: prefix, and bots always do".into(),
            ));
        }
        if let Some(ci) = &req.ci {
            if ci.len() > MAX_CI_FACTS {
                return Err(CaError::InvalidRequest("too many CI facts".into()));
            }
            for (key, value) in ci {
                validate_name("CI fact name", key)?;
                // An empty value can't be written into a certificate that
                // verifies: the SAN would not parse.
                if value.is_empty()
                    || value.len() > MAX_CI_VALUE
                    || value.chars().any(char::is_control)
                {
                    return Err(CaError::InvalidRequest(format!("invalid CI fact {key}")));
                }
            }
        }
        let csr = parse_csr(&req.csr_der)?;

        let mut params = leaf_params(req.ttl)?;
        params
            .distinguished_name
            .push(DnType::CommonName, req.username.as_str());
        let mut uris = vec![
            IdentityUri::User(req.username.clone()),
            IdentityUri::Login(req.login_id.to_string()),
        ];
        uris.extend(req.roles.iter().cloned().map(IdentityUri::Role));
        if let Some(ci) = &req.ci {
            uris.push(IdentityUri::Bot);
            uris.extend(ci.iter().map(|(key, value)| IdentityUri::Ci {
                key: key.clone(),
                value: value.clone(),
            }));
        }
        params.subject_alt_names = uris
            .iter()
            .map(|u| uri_san(&u.to_uri()))
            .collect::<Result<_, _>>()?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

        self.sign(params, csr).await
    }

    /// Issue a component certificate. Only the internal CA may do this.
    pub async fn issue_component(&self, req: ComponentCertRequest) -> Result<IssuedCert, CaError> {
        self.require(CaPurpose::Internal)?;
        validate_name("component id", &req.id)?;
        let csr = parse_csr(&req.csr_der)?;

        let mut params = leaf_params(req.ttl)?;
        params
            .distinguished_name
            .push(DnType::CommonName, format!("{}:{}", req.kind, req.id));
        let mut sans = vec![uri_san(
            &IdentityUri::Component {
                kind: req.kind,
                id: req.id.clone(),
            }
            .to_uri(),
        )?];
        for (key, value) in &req.labels {
            sans.push(uri_san(
                &IdentityUri::Label {
                    key: key.clone(),
                    value: value.clone(),
                }
                .to_uri(),
            )?);
        }
        for name in &req.dns_names {
            if let Ok(ip) = name.parse::<std::net::IpAddr>() {
                sans.push(SanType::IpAddress(ip));
            } else {
                validate_dns_name(name)?;
                sans.push(SanType::DnsName(ia5(name)?));
            }
        }
        params.subject_alt_names = sans;
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        self.sign(params, csr).await
    }

    fn require(&self, purpose: CaPurpose) -> Result<(), CaError> {
        if self.purpose == purpose {
            Ok(())
        } else {
            Err(CaError::InvalidRequest(format!(
                "{} CA cannot issue {} certificates",
                self.purpose.as_str(),
                purpose.as_str()
            )))
        }
    }

    async fn sign(
        &self,
        params: CertificateParams,
        csr: CertificateSigningRequestParams,
    ) -> Result<IssuedCert, CaError> {
        let runtime = tokio::runtime::Handle::current();
        let signer = Arc::clone(&self.signer);
        let ca_der = self.cert_der.clone();
        let not_after = params.not_after;
        let serial_hex = params
            .serial_number
            .as_ref()
            .map(|s| hex(s.as_ref()))
            .unwrap_or_default();
        let cert = tokio::task::spawn_blocking(move || {
            let issuer = Issuer::from_ca_cert_der(
                &ca_der,
                BlockingSigner {
                    inner: &*signer,
                    runtime,
                },
            )?;
            params.signed_by(&csr.public_key, &issuer)
        })
        .await
        .map_err(|e| CaError::Internal(e.to_string()))??;
        Ok(IssuedCert {
            der: cert.der().clone(),
            pem: cert.pem(),
            serial_hex,
            not_after,
        })
    }
}

fn leaf_params(ttl: Duration) -> Result<CertificateParams, CaError> {
    if ttl.is_zero() || ttl > Duration::from_hours(31 * 24) {
        return Err(CaError::InvalidRequest(format!("ttl {ttl:?} out of range")));
    }
    let ttl = time::Duration::try_from(ttl).map_err(|e| CaError::InvalidRequest(e.to_string()))?;
    let mut params = CertificateParams::default();
    let now = OffsetDateTime::now_utc();
    params.not_before = now - BACKDATE;
    params.not_after = now + ttl;
    params.serial_number = Some(random_serial());
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.use_authority_key_identifier_extension = true;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "Limen");
    params.distinguished_name = dn;
    Ok(params)
}

fn parse_csr(der: &[u8]) -> Result<CertificateSigningRequestParams, CaError> {
    if der.len() > 16 * 1024 {
        return Err(CaError::InvalidCsr("too large".into()));
    }
    let csr = CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(der))
        .map_err(|e| CaError::InvalidCsr(e.to_string()))?;
    if csr.public_key.algorithm() != &rcgen::PKCS_ECDSA_P256_SHA256 {
        return Err(CaError::InvalidCsr("key must be ECDSA P-256".into()));
    }
    Ok(csr)
}

fn validate_name(what: &str, value: &str) -> Result<(), CaError> {
    if value.is_empty() || value.len() > MAX_NAME_LEN || value.chars().any(char::is_control) {
        return Err(CaError::InvalidRequest(format!("invalid {what}")));
    }
    Ok(())
}

fn validate_dns_name(name: &str) -> Result<(), CaError> {
    let ok = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
    if ok {
        Ok(())
    } else {
        Err(CaError::InvalidRequest(format!(
            "invalid DNS name {name:?}"
        )))
    }
}

fn uri_san(uri: &str) -> Result<SanType, CaError> {
    Ok(SanType::URI(ia5(uri)?))
}

fn ia5(s: &str) -> Result<Ia5String, CaError> {
    Ia5String::try_from(s).map_err(|e| CaError::InvalidRequest(e.to_string()))
}

fn random_serial() -> SerialNumber {
    // 16 random bytes with the top bit cleared keeps the serial a positive INTEGER.
    let mut bytes = *Uuid::new_v4().as_bytes();
    bytes[0] &= 0x7f;
    SerialNumber::from(bytes.to_vec())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Decode the first PEM `CERTIFICATE` block.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, CaError> {
    use rustls_pki_types::pem::PemObject;
    CertificateDer::from_pem_slice(pem.as_bytes())
        .map(|c| c.to_vec())
        .map_err(|e| CaError::InvalidRequest(format!("invalid certificate PEM: {e}")))
}

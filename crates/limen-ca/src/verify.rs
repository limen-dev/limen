//! Offline certificate verification and identity extraction.

use limen_core::identity::{ComponentKind, IdentityUri};
use rustls_pki_types::{CertificateDer, UnixTime};
use time::OffsetDateTime;
use webpki::{EndEntityCert, KeyUsage};
use x509_parser::extensions::GeneralName;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("certificate is not valid for this CA: {0}")]
    Chain(String),
    #[error("certificate does not carry a valid Limen identity: {0}")]
    Identity(String),
}

/// A user identity read from a certificate issued by the user CA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIdentity {
    pub username: String,
    pub roles: Vec<String>,
    pub login_id: String,
    pub not_after: OffsetDateTime,
    /// A bot's certificate. Always agrees with the `bot:` username prefix.
    pub bot: bool,
    /// Facts about the CI run behind a bot login. Empty for people.
    pub ci: std::collections::BTreeMap<String, String>,
}

impl UserIdentity {
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// A component identity read from a certificate issued by the internal CA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentIdentity {
    pub kind: ComponentKind,
    pub id: String,
    pub labels: std::collections::BTreeMap<String, String>,
    pub not_after: OffsetDateTime,
}

/// Verify `cert` chains to `ca_cert` and is valid now for client
/// authentication, then extract the user identity.
pub fn verify_user(
    cert: &CertificateDer<'_>,
    ca_cert: &CertificateDer<'_>,
) -> Result<UserIdentity, VerifyError> {
    verify_chain(cert, ca_cert, KeyUsage::client_auth())?;
    let (uris, not_after) = identity_uris(cert)?;
    user_identity(uris, not_after)
}

/// The user identity a certificate's SAN URIs describe. Strict: anything
/// repeated, oversized, or inconsistent is an error, because the issuer never
/// produces it.
fn user_identity(
    uris: Vec<IdentityUri>,
    not_after: OffsetDateTime,
) -> Result<UserIdentity, VerifyError> {
    let mut username = None;
    let mut login_id = None;
    let mut roles = Vec::new();
    let mut bot = false;
    let mut ci = std::collections::BTreeMap::new();
    for uri in uris {
        match uri {
            IdentityUri::User(u) if username.is_none() => username = Some(u),
            IdentityUri::Login(l) if login_id.is_none() => login_id = Some(l),
            IdentityUri::Role(r) => roles.push(r),
            IdentityUri::Bot if !bot => bot = true,
            IdentityUri::Ci { key, value } => {
                if value.len() > crate::authority::MAX_CI_VALUE {
                    return Err(VerifyError::Identity(format!("CI fact {key} is too long")));
                }
                if ci.insert(key.clone(), value).is_some() {
                    return Err(VerifyError::Identity(format!("CI fact {key} is repeated")));
                }
                if ci.len() > crate::authority::MAX_CI_FACTS {
                    return Err(VerifyError::Identity("too many CI facts".into()));
                }
            }
            other => {
                return Err(VerifyError::Identity(format!(
                    "unexpected SAN in user cert: {other:?}"
                )));
            }
        }
    }
    let username = username.ok_or_else(|| VerifyError::Identity("missing user".into()))?;
    if limen_core::identity::is_bot(&username) != bot || (!bot && !ci.is_empty()) {
        return Err(VerifyError::Identity(
            "the bot marker and the bot: username prefix must agree".into(),
        ));
    }
    Ok(UserIdentity {
        username,
        login_id: login_id.ok_or_else(|| VerifyError::Identity("missing login id".into()))?,
        roles,
        not_after,
        bot,
        ci,
    })
}

/// Verify `cert` chains to the internal CA, then extract the component identity.
/// `server` selects the server-auth rather than the client-auth key usage.
pub fn verify_component(
    cert: &CertificateDer<'_>,
    ca_cert: &CertificateDer<'_>,
    server: bool,
) -> Result<ComponentIdentity, VerifyError> {
    let usage = if server {
        KeyUsage::server_auth()
    } else {
        KeyUsage::client_auth()
    };
    verify_chain(cert, ca_cert, usage)?;
    let (uris, not_after) = identity_uris(cert)?;
    let mut found = None;
    let mut labels = std::collections::BTreeMap::new();
    for uri in uris {
        match uri {
            IdentityUri::Component { kind, id } if found.is_none() => found = Some((kind, id)),
            IdentityUri::Label { key, value } => {
                labels.insert(key, value);
            }
            other => {
                return Err(VerifyError::Identity(format!(
                    "unexpected SAN in component cert: {other:?}"
                )));
            }
        }
    }
    let (kind, id) = found.ok_or_else(|| VerifyError::Identity("missing component".into()))?;
    Ok(ComponentIdentity {
        kind,
        id,
        labels,
        not_after,
    })
}

fn verify_chain(
    cert: &CertificateDer<'_>,
    ca_cert: &CertificateDer<'_>,
    usage: KeyUsage,
) -> Result<(), VerifyError> {
    let anchor =
        webpki::anchor_from_trusted_cert(ca_cert).map_err(|e| VerifyError::Chain(e.to_string()))?;
    let ee = EndEntityCert::try_from(cert).map_err(|e| VerifyError::Chain(e.to_string()))?;
    ee.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &[anchor],
        &[],
        UnixTime::now(),
        usage,
        None,
        None,
    )
    .map(|_| ())
    .map_err(|e| VerifyError::Chain(e.to_string()))
}

/// Limen identity URIs in the SAN extension. Non-Limen URIs are ignored, and
/// DNS and IP SANs are allowed (server certificates carry them).
fn identity_uris(
    cert: &CertificateDer<'_>,
) -> Result<(Vec<IdentityUri>, OffsetDateTime), VerifyError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert)
        .map_err(|e| VerifyError::Identity(e.to_string()))?;
    let not_after = parsed.validity().not_after.to_datetime();
    let Some(san) = parsed
        .subject_alternative_name()
        .map_err(|e| VerifyError::Identity(e.to_string()))?
    else {
        return Err(VerifyError::Identity("no subject alternative names".into()));
    };
    let mut out = Vec::new();
    for name in &san.value.general_names {
        if let GeneralName::URI(uri) = name
            && uri.starts_with("limen://")
        {
            out.push(
                IdentityUri::parse(uri).ok_or_else(|| {
                    VerifyError::Identity(format!("malformed identity URI {uri:?}"))
                })?,
            );
        }
    }
    Ok((out, not_after))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
    use uuid::Uuid;

    use super::*;
    use crate::{
        CaPurpose, CertificateAuthority, ComponentCertRequest, FileSigner, UserCertRequest,
    };

    fn csr() -> (KeyPair, Vec<u8>) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let csr = CertificateParams::default()
            .serialize_request(&key)
            .expect("csr");
        (key, csr.der().to_vec())
    }

    async fn ca(purpose: CaPurpose) -> CertificateAuthority {
        CertificateAuthority::create_self_signed(
            purpose,
            Arc::new(FileSigner::generate().expect("key")),
        )
        .await
        .expect("ca")
    }

    #[tokio::test]
    async fn issues_and_verifies_user_cert() {
        let user_ca = ca(CaPurpose::UserX509).await;
        let (_key, csr_der) = csr();
        let login = Uuid::now_v7();
        let issued = user_ca
            .issue_user(UserCertRequest {
                csr_der,
                username: "admin@example.com".into(),
                roles: vec!["db-readonly".into(), "limen:admin".into()],
                login_id: login,
                ttl: Duration::from_secs(600),
                ci: None,
            })
            .await
            .expect("issue");
        let id = verify_user(&issued.der, user_ca.cert_der()).expect("verify");
        assert_eq!(id.username, "admin@example.com");
        assert_eq!(id.roles, ["db-readonly", "limen:admin"]);
        assert_eq!(id.login_id, login.to_string());
        assert!(id.has_role("limen:admin"));
        let ttl = id.not_after - OffsetDateTime::now_utc();
        assert!(ttl <= time::Duration::minutes(10) && ttl > time::Duration::minutes(9));
    }

    #[tokio::test]
    async fn bot_cert_carries_the_marker_and_the_ci_facts() {
        let user_ca = ca(CaPurpose::UserX509).await;
        let (_key, csr_der) = csr();
        let ci: std::collections::BTreeMap<String, String> = [
            ("provider", "github_actions"),
            ("repository", "acme/infra"),
            ("run_id", "42"),
            ("workflow", "deploy / staging"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let issued = user_ca
            .issue_user(UserCertRequest {
                csr_der,
                username: "bot:deploy-staging".into(),
                roles: vec!["deployer".into()],
                login_id: Uuid::now_v7(),
                ttl: Duration::from_secs(600),
                ci: Some(ci.clone()),
            })
            .await
            .expect("issue");
        let id = verify_user(&issued.der, user_ca.cert_der()).expect("verify");
        assert!(id.bot);
        assert_eq!(id.username, "bot:deploy-staging");
        assert_eq!(id.ci, ci, "values with spaces and slashes survive");
        assert_eq!(id.roles, ["deployer"]);
    }

    #[tokio::test]
    async fn people_never_get_the_bot_marker_and_bots_always_do() {
        let user_ca = ca(CaPurpose::UserX509).await;
        let request = |username: &str, ci: Option<std::collections::BTreeMap<String, String>>| {
            let (_k, csr_der) = csr();
            UserCertRequest {
                csr_der,
                username: username.into(),
                roles: vec![],
                login_id: Uuid::now_v7(),
                ttl: Duration::from_secs(60),
                ci,
            }
        };
        let facts: std::collections::BTreeMap<String, String> =
            [("repository".to_owned(), "acme/infra".to_owned())].into();
        // A person whose IdP name starts with `bot:` can't get a bot's identity...
        assert!(user_ca.issue_user(request("bot:evil", None)).await.is_err());
        // ...and a bot can't be issued a name that looks like a person's.
        assert!(
            user_ca
                .issue_user(request("alice@example.com", Some(facts.clone())))
                .await
                .is_err()
        );
        // CI facts stay small.
        let many = (0..40).map(|i| (format!("k{i}"), "v".to_owned())).collect();
        assert!(
            user_ca
                .issue_user(request("bot:x", Some(many)))
                .await
                .is_err()
        );
        let long: std::collections::BTreeMap<String, String> =
            [("k".to_owned(), "x".repeat(300))].into();
        assert!(
            user_ca
                .issue_user(request("bot:x", Some(long)))
                .await
                .is_err()
        );
        // A person's certificate has no marker and no facts.
        let issued = user_ca
            .issue_user(request("alice@example.com", None))
            .await
            .expect("issue");
        let id = verify_user(&issued.der, user_ca.cert_der()).expect("verify");
        assert!(!id.bot && id.ci.is_empty());
    }

    fn uris(parts: &[&str]) -> Vec<IdentityUri> {
        parts
            .iter()
            .map(|p| IdentityUri::parse(p).expect("valid SAN"))
            .collect()
    }

    #[test]
    fn the_identity_parser_is_strict_about_ci_facts() {
        let now = OffsetDateTime::now_utc();
        let base = [
            "limen://user/bot:deploy",
            "limen://login/0192f1d2-0000-7000-8000-000000000000",
            "limen://actor/bot",
        ];
        let with = |extra: &[&str]| uris(&[&base[..], extra].concat());
        let ok = user_identity(with(&["limen://ci/repository/acme%2Finfra"]), now).expect("valid");
        assert_eq!(ok.ci["repository"], "acme/infra");
        // The same fact twice: the issuer never writes that, so the last can't win.
        let dup = user_identity(
            with(&["limen://ci/repository/a", "limen://ci/repository/b"]),
            now,
        );
        assert!(matches!(dup, Err(VerifyError::Identity(m)) if m.contains("repeated")));
        // More facts than the issuer allows.
        let many: Vec<String> = (0..=crate::authority::MAX_CI_FACTS)
            .map(|i| format!("limen://ci/k{i}/v"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(matches!(
            user_identity(with(&many), now),
            Err(VerifyError::Identity(m)) if m.contains("too many")
        ));
        // A value longer than the issuer allows.
        let long = format!(
            "limen://ci/k/{}",
            "x".repeat(crate::authority::MAX_CI_VALUE + 1)
        );
        assert!(user_identity(with(&[long.as_str()]), now).is_err());
        // A marker twice, or facts on a person.
        assert!(user_identity(with(&["limen://actor/bot"]), now).is_err());
        assert!(
            user_identity(
                uris(&["limen://user/alice", "limen://login/x", "limen://ci/k/v"]),
                now
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn empty_ci_values_are_refused_at_issuance() {
        let user_ca = ca(CaPurpose::UserX509).await;
        let (_k, csr_der) = csr();
        let facts: std::collections::BTreeMap<String, String> =
            [("repository".to_owned(), String::new())].into();
        let refused = user_ca
            .issue_user(UserCertRequest {
                csr_der,
                username: "bot:x".into(),
                roles: vec![],
                login_id: Uuid::now_v7(),
                ttl: Duration::from_secs(60),
                ci: Some(facts),
            })
            .await;
        assert!(
            refused.is_err(),
            "an empty value would make a certificate that can't verify"
        );
    }

    #[tokio::test]
    async fn user_cert_rejected_by_other_ca_and_as_component() {
        let user_ca = ca(CaPurpose::UserX509).await;
        let internal = ca(CaPurpose::Internal).await;
        let (_k, csr_der) = csr();
        let issued = user_ca
            .issue_user(UserCertRequest {
                csr_der,
                username: "mallory".into(),
                roles: vec![],
                login_id: Uuid::now_v7(),
                ttl: Duration::from_secs(60),
                ci: None,
            })
            .await
            .expect("issue");
        assert!(matches!(
            verify_user(&issued.der, internal.cert_der()),
            Err(VerifyError::Chain(_))
        ));
        assert!(verify_component(&issued.der, user_ca.cert_der(), false).is_err());
    }

    #[tokio::test]
    async fn component_cert_has_dns_and_identity() {
        let internal = ca(CaPurpose::Internal).await;
        let (_k, csr_der) = csr();
        let issued = internal
            .issue_component(ComponentCertRequest {
                csr_der,
                kind: ComponentKind::Proxy,
                id: "proxy-1".into(),
                dns_names: vec![
                    "localhost".into(),
                    "127.0.0.1".into(),
                    "limen.example.com".into(),
                ],
                labels: [("pool".to_owned(), "payments vpc".to_owned())].into(),
                ttl: Duration::from_secs(3600),
            })
            .await
            .expect("issue");
        let id = verify_component(&issued.der, internal.cert_der(), true).expect("server verify");
        assert_eq!((id.kind, id.id.as_str()), (ComponentKind::Proxy, "proxy-1"));
        assert_eq!(
            id.labels.get("pool").map(String::as_str),
            Some("payments vpc")
        );
        verify_component(&issued.der, internal.cert_der(), false).expect("client verify");
    }

    #[tokio::test]
    async fn wrong_purpose_and_bad_input_rejected() {
        let internal = ca(CaPurpose::Internal).await;
        let user_ca = ca(CaPurpose::UserX509).await;
        let (_k, csr_der) = csr();
        let user_req = UserCertRequest {
            csr_der: csr_der.clone(),
            username: "a".into(),
            roles: vec![],
            login_id: Uuid::now_v7(),
            ttl: Duration::from_secs(60),
            ci: None,
        };
        assert!(
            internal.issue_user(user_req.clone()).await.is_err(),
            "internal CA must not issue user certs"
        );
        let bad_name = UserCertRequest {
            username: "a\nb".into(),
            ci: None,
            ..user_req.clone()
        };
        assert!(user_ca.issue_user(bad_name).await.is_err());
        let mut tampered = csr_der;
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        let bad_csr = UserCertRequest {
            csr_der: tampered,
            ci: None,
            ..user_req.clone()
        };
        assert!(
            user_ca.issue_user(bad_csr).await.is_err(),
            "CSR signature must be checked"
        );
        let zero_ttl = UserCertRequest {
            ttl: Duration::ZERO,
            ci: None,
            ..user_req
        };
        assert!(user_ca.issue_user(zero_ttl).await.is_err());
        let bad_dns = ComponentCertRequest {
            csr_der: csr().1,
            kind: ComponentKind::Proxy,
            id: "p".into(),
            dns_names: vec!["evil/../x".into()],
            labels: std::collections::BTreeMap::new(),
            ttl: Duration::from_secs(60),
        };
        assert!(internal.issue_component(bad_dns).await.is_err());
    }

    #[tokio::test]
    async fn from_existing_checks_key_match() {
        let signer: Arc<dyn crate::Signer> = Arc::new(FileSigner::generate().expect("key"));
        let ca1 =
            CertificateAuthority::create_self_signed(CaPurpose::Internal, Arc::clone(&signer))
                .await
                .expect("ca");
        CertificateAuthority::from_existing(CaPurpose::Internal, signer, ca1.cert_pem())
            .expect("same key");
        let other: Arc<dyn crate::Signer> = Arc::new(FileSigner::generate().expect("key"));
        assert!(
            CertificateAuthority::from_existing(CaPurpose::Internal, other, ca1.cert_pem())
                .is_err()
        );
    }
}

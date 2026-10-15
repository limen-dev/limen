//! ID token verification against the IdP's published keys.

use std::sync::Arc;
use std::time::{Duration, Instant};

use openidconnect::core::{
    CoreGenderClaim, CoreIdTokenVerifier, CoreJsonWebKeySet, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
};
use openidconnect::{AdditionalClaims, ClientId, IdToken, IssuerUrl, JsonWebKeySetUrl, Nonce};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::config::UsernameClaim;
use crate::http_client::HttpClient;

/// Claims beyond the OIDC core set that Limen reads.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LimenClaims {
    #[serde(default)]
    pub groups: Vec<String>,
}

impl AdditionalClaims for LimenClaims {}

type LimenIdToken = IdToken<
    LimenClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

/// The parts of a verified ID token Limen uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub subject: String,
    pub username: String,
    pub groups: Vec<String>,
    /// The token's `nonce` claim, if any.
    pub nonce: Option<String>,
    pub expires_at: time::OffsetDateTime,
}

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("identity provider unreachable: {0}")]
    Unavailable(String),
    #[error("invalid ID token: {0}")]
    Invalid(String),
}

#[derive(Debug)]
struct Keys {
    jwks: CoreJsonWebKeySet,
    fetched: Instant,
}

const REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(30);

/// An issuer's published signing keys, cached. Refetched at most every 30
/// seconds when verification fails, so key rotation is picked up. Shared by
/// people's logins and bots' (ADR-0019).
#[derive(Debug, Clone)]
pub struct KeyCache {
    issuer: IssuerUrl,
    internal_base: String,
    http: HttpClient,
    keys: Arc<RwLock<Option<Keys>>>,
    /// Refuse a `jwks_uri` on another origin than the issuer's.
    same_origin_keys: bool,
}

impl KeyCache {
    pub fn new(
        issuer: &str,
        internal_url: Option<&str>,
        http: HttpClient,
    ) -> Result<Self, OidcError> {
        let issuer = IssuerUrl::new(issuer.to_owned())
            .map_err(|e| OidcError::Invalid(format!("issuer URL: {e}")))?;
        let internal_base = internal_url
            .unwrap_or(issuer.as_str())
            .trim_end_matches('/')
            .to_owned();
        Ok(Self {
            issuer,
            internal_base,
            http,
            keys: Arc::new(RwLock::new(None)),
            same_origin_keys: false,
        })
    }

    /// Only fetch signing keys from the issuer's own origin. The discovery
    /// document is the issuer's to write, and without this a compromised
    /// issuer could make the control plane fetch any URL it names. Used for
    /// bots' issuers (ADR-0019); people's IdP keeps its own, internal, address.
    #[must_use]
    pub fn same_origin_keys(mut self) -> Self {
        self.same_origin_keys = true;
        self
    }

    #[must_use]
    pub fn issuer(&self) -> &IssuerUrl {
        &self.issuer
    }

    /// Fetch the discovery document and the JWKS. Paths published by the IdP
    /// under the public issuer are rewritten to the internal base URL.
    async fn fetch_keys(&self) -> Result<CoreJsonWebKeySet, OidcError> {
        let discovery_url = format!("{}/.well-known/openid-configuration", self.internal_base);
        let discovery: serde_json::Value = self
            .http
            .inner()
            .get(&discovery_url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| OidcError::Unavailable(format!("{discovery_url}: {e}")))?
            .json()
            .await
            .map_err(|e| OidcError::Unavailable(format!("{discovery_url}: {e}")))?;
        let advertised_issuer = discovery
            .get("issuer")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if advertised_issuer.trim_end_matches('/') != self.issuer.as_str().trim_end_matches('/') {
            return Err(OidcError::Unavailable(format!(
                "discovery issuer {advertised_issuer:?} does not match configured issuer {:?}",
                self.issuer.as_str()
            )));
        }
        let jwks_uri = discovery
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OidcError::Unavailable("discovery document has no jwks_uri".into()))?;
        if self.same_origin_keys && !same_origin(self.issuer.as_str(), jwks_uri) {
            return Err(OidcError::Unavailable(format!(
                "jwks_uri {jwks_uri:?} is not on the issuer's origin"
            )));
        }
        let public_base = self.issuer.as_str().trim_end_matches('/');
        let jwks_uri = match jwks_uri.strip_prefix(public_base) {
            Some(path) => format!("{}{path}", self.internal_base),
            None => jwks_uri.to_owned(),
        };
        let url = JsonWebKeySetUrl::new(jwks_uri.clone())
            .map_err(|e| OidcError::Unavailable(format!("jwks_uri: {e}")))?;
        CoreJsonWebKeySet::fetch_async(&url, &self.http)
            .await
            .map_err(|e| OidcError::Unavailable(format!("{jwks_uri}: {e}")))
    }

    pub async fn current_keys(&self, force: bool) -> Result<CoreJsonWebKeySet, OidcError> {
        {
            let guard = self.keys.read().await;
            if let Some(keys) = guard.as_ref()
                && (!force || keys.fetched.elapsed() < REFRESH_MIN_INTERVAL)
            {
                return Ok(keys.jwks.clone());
            }
        }
        let jwks = self.fetch_keys().await?;
        *self.keys.write().await = Some(Keys {
            jwks: jwks.clone(),
            fetched: Instant::now(),
        });
        Ok(jwks)
    }
}

/// Whether two URLs share a scheme, host, and port.
fn same_origin(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(a), Ok(b)) => {
            a.scheme() == b.scheme()
                && a.host_str().is_some()
                && a.host_str() == b.host_str()
                && a.port_or_known_default() == b.port_or_known_default()
        }
        _ => false,
    }
}

/// Verifies ID tokens for people's logins.
#[derive(Debug, Clone)]
pub struct OidcVerifier {
    keys: KeyCache,
    client_id: ClientId,
    username_claim: UsernameClaim,
}

impl OidcVerifier {
    pub fn new(
        issuer: &str,
        internal_url: Option<&str>,
        client_id: &str,
        username_claim: UsernameClaim,
        http: HttpClient,
    ) -> Result<Self, OidcError> {
        Ok(Self {
            keys: KeyCache::new(issuer, internal_url, http)?,
            client_id: ClientId::new(client_id.to_owned()),
            username_claim,
        })
    }

    /// Verify signature, issuer, audience, and expiry. When `required_nonce`
    /// is set, the token's `nonce` claim must equal it.
    pub async fn verify(
        &self,
        raw: String,
        required_nonce: Option<String>,
    ) -> Result<VerifiedIdentity, OidcError> {
        if raw.len() > 64 * 1024 {
            return Err(OidcError::Invalid("token too large".into()));
        }
        let token: LimenIdToken = raw
            .parse()
            .map_err(|e| OidcError::Invalid(format!("malformed: {e}")))?;
        let mut last_err = None;
        for force in [false, true] {
            let jwks = self.keys.current_keys(force).await?;
            // Asymmetric algorithms only. RS256 is what Okta and Dex use.
            let verifier = CoreIdTokenVerifier::new_public_client(
                self.client_id.clone(),
                self.keys.issuer().clone(),
                jwks,
            )
            .set_allowed_algs([
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                CoreJwsSigningAlgorithm::EcdsaP256Sha256,
                CoreJwsSigningAlgorithm::EdDsa,
            ]);
            let check = |n: Option<&Nonce>| match (required_nonce.as_deref(), n) {
                (None, _) => Ok(()),
                (Some(want), Some(got)) if constant_time_eq(want, got.secret()) => Ok(()),
                (Some(_), _) => Err("nonce does not bind the presented key".to_owned()),
            };
            match token.claims(&verifier, check) {
                Ok(claims) => return self.extract(claims),
                Err(e) => last_err = Some(e.to_string()),
            }
        }
        Err(OidcError::Invalid(last_err.unwrap_or_default()))
    }

    fn extract(
        &self,
        claims: &openidconnect::IdTokenClaims<LimenClaims, CoreGenderClaim>,
    ) -> Result<VerifiedIdentity, OidcError> {
        let subject = claims.subject().to_string();
        let username = match self.username_claim {
            UsernameClaim::Email => {
                if claims.email_verified() == Some(false) {
                    return Err(OidcError::Invalid("email is not verified".into()));
                }
                claims.email().map(|e| e.to_string())
            }
            UsernameClaim::PreferredUsername => claims.preferred_username().map(|u| u.to_string()),
            UsernameClaim::Sub => Some(subject.clone()),
        }
        .ok_or_else(|| OidcError::Invalid("username claim missing".into()))?;
        let expires_at = time::OffsetDateTime::from_unix_timestamp(claims.expiration().timestamp())
            .map_err(|e| OidcError::Invalid(format!("exp: {e}")))?;
        Ok(VerifiedIdentity {
            subject,
            username,
            groups: claims.additional_claims().groups.clone(),
            nonce: claims.nonce().map(|n| n.secret().clone()),
            expires_at,
        })
    }
}

/// Compare by hash so the comparison time doesn't depend on where they differ.
fn constant_time_eq(a: &str, b: &str) -> bool {
    use sha2::{Digest, Sha256};
    Sha256::digest(a.as_bytes()) == Sha256::digest(b.as_bytes())
}

#[cfg(test)]
mod origin_tests {
    use super::same_origin;

    #[test]
    fn origins_compare_scheme_host_and_port() {
        assert!(same_origin(
            "https://i.example.com",
            "https://i.example.com/keys"
        ));
        assert!(same_origin(
            "https://i.example.com:443/",
            "https://i.example.com/a/b"
        ));
        assert!(!same_origin(
            "https://i.example.com",
            "http://i.example.com/keys"
        ));
        assert!(!same_origin(
            "https://i.example.com",
            "https://evil.example.com/keys"
        ));
        assert!(!same_origin(
            "https://i.example.com",
            "https://i.example.com.evil.net/keys"
        ));
        assert!(!same_origin(
            "https://i.example.com",
            "https://i.example.com:8443/keys"
        ));
        assert!(!same_origin(
            "https://i.example.com",
            "https://169.254.169.254/latest"
        ));
        assert!(!same_origin("https://i.example.com", "not a url"));
    }
}

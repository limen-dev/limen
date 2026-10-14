//! A minimal OIDC provider for tests. It serves discovery and JWKS, and
//! mints Ed25519-signed ID tokens with whatever claims a test needs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::{Json, Router};
use openidconnect::core::{
    CoreEdDsaPrivateSigningKey, CoreGenderClaim, CoreJsonWebKeySet,
    CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
};
use openidconnect::{
    AdditionalClaims, Audience, EndUserEmail, IdToken, IdTokenClaims, IssuerUrl, JsonWebKeyId,
    Nonce, PrivateSigningKey, StandardClaims, SubjectIdentifier,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupClaims {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

impl AdditionalClaims for GroupClaims {}

/// What to put in a minted ID token.
#[derive(Debug, Clone)]
pub struct Claims {
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub groups: Vec<String>,
    pub nonce: Option<String>,
    /// Defaults to the IdP's client ID.
    pub audience: Option<String>,
    /// Negative values produce an already-expired token.
    pub ttl_secs: i64,
    /// Overrides the `iss` claim, to test issuer mismatches.
    pub issuer: Option<String>,
}

impl Claims {
    #[must_use]
    pub fn user(email: &str, groups: &[&str]) -> Self {
        Self {
            subject: format!("sub-{email}"),
            email: Some(email.to_owned()),
            email_verified: Some(true),
            groups: groups.iter().map(|g| (*g).to_owned()).collect(),
            nonce: None,
            audience: None,
            ttl_secs: 300,
            issuer: None,
        }
    }

    #[must_use]
    pub fn with_nonce(mut self, nonce: &str) -> Self {
        self.nonce = Some(nonce.to_owned());
        self
    }
}

#[derive(Clone)]
pub struct MockIdp {
    pub issuer: String,
    pub client_id: String,
    pub addr: SocketAddr,
    key: Arc<CoreEdDsaPrivateSigningKey>,
}

impl std::fmt::Debug for MockIdp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockIdp")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl MockIdp {
    /// Start serving on 127.0.0.1 with a random port.
    ///
    /// # Panics
    /// If the listener can't be bound or the key can't be generated. Tests only.
    pub async fn start(client_id: &str) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock IdP");
        let addr = listener.local_addr().expect("addr");
        let issuer = format!("http://{addr}");
        let pem = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .expect("ed25519 key")
            .serialize_pem();
        let key = Arc::new(
            CoreEdDsaPrivateSigningKey::from_ed25519_pem(
                &pem,
                Some(JsonWebKeyId::new("test-key".into())),
            )
            .expect("signing key"),
        );

        let jwks = serde_json::to_value(CoreJsonWebKeySet::new(vec![key.as_verification_key()]))
            .expect("jwks");
        let discovery = serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/auth"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/keys"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["EdDSA"],
        });
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move { Json(discovery) }),
            )
            .route("/keys", get(move || async move { Json(jwks) }));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            issuer,
            client_id: client_id.to_owned(),
            addr,
            key,
        }
    }

    /// Mint a signed ID token.
    ///
    /// # Panics
    /// If the claims can't be encoded. Tests only.
    #[must_use]
    pub fn id_token(&self, claims: &Claims) -> String {
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::seconds(claims.ttl_secs);
        let issuer = IssuerUrl::new(claims.issuer.clone().unwrap_or_else(|| self.issuer.clone()))
            .expect("issuer");
        let audience = Audience::new(
            claims
                .audience
                .clone()
                .unwrap_or_else(|| self.client_id.clone()),
        );
        let mut standard = StandardClaims::new(SubjectIdentifier::new(claims.subject.clone()));
        if let Some(email) = &claims.email {
            standard = standard.set_email(Some(EndUserEmail::new(email.clone())));
        }
        standard = standard.set_email_verified(claims.email_verified);
        let id_claims = IdTokenClaims::new(
            issuer,
            vec![audience],
            exp,
            now - chrono::Duration::seconds(5),
            standard,
            GroupClaims {
                groups: claims.groups.clone(),
            },
        )
        .set_nonce(claims.nonce.clone().map(Nonce::new));
        let token: IdToken<
            GroupClaims,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
        > = IdToken::new(
            id_claims,
            self.key.as_ref(),
            CoreJwsSigningAlgorithm::EdDsa,
            None,
            None,
        )
        .expect("sign ID token");
        token.to_string()
    }

    /// How long until tokens minted with the default claims expire.
    #[must_use]
    pub fn default_ttl() -> Duration {
        Duration::from_secs(300)
    }
}

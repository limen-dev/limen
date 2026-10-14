//! A minimal OIDC provider for tests. It serves discovery and JWKS, and
//! mints Ed25519-signed ID tokens with whatever claims a test needs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Form, Query, State};
use axum::response::Redirect;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use openidconnect::core::{
    CoreEdDsaPrivateSigningKey, CoreGenderClaim, CoreJsonWebKeySet,
    CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
};
use openidconnect::{
    AdditionalClaims, Audience, EndUserEmail, IdToken, IdTokenClaims, IssuerUrl, JsonWebKeyId,
    Nonce, PrivateSigningKey, StandardClaims, SubjectIdentifier,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

/// What the browser flow (`/auth`, `/token`) needs: who the "user at the
/// keyboard" is, the console client's secret, and codes handed out so far.
#[derive(Debug, Default)]
struct Browser {
    user: Option<(String, Vec<String>)>,
    client: Option<(String, String)>,
    codes: std::collections::HashMap<String, PendingCode>,
}

#[derive(Debug, Clone)]
struct PendingCode {
    email: String,
    groups: Vec<String>,
    nonce: String,
    challenge: String,
    redirect_uri: String,
    client_id: String,
}

#[derive(Clone)]
pub struct MockIdp {
    pub issuer: String,
    pub client_id: String,
    pub addr: SocketAddr,
    key: Arc<CoreEdDsaPrivateSigningKey>,
    browser: Arc<std::sync::Mutex<Browser>>,
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
        let idp = Self {
            issuer,
            client_id: client_id.to_owned(),
            addr,
            key,
            browser: Arc::default(),
        };
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move { Json(discovery) }),
            )
            .route("/keys", get(move || async move { Json(jwks) }))
            .route("/auth", get(browser_auth))
            .route("/token", post(browser_token))
            .with_state(idp.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        idp
    }

    /// Register the console's OIDC client (confidential).
    ///
    /// # Panics
    /// If the internal lock is poisoned. Tests only.
    pub fn set_browser_client(&self, client_id: &str, secret: &str) {
        self.browser.lock().expect("lock").client = Some((client_id.to_owned(), secret.to_owned()));
    }

    /// Who signs in at `/auth` next: the user at the keyboard.
    ///
    /// # Panics
    /// If the internal lock is poisoned. Tests only.
    pub fn set_browser_user(&self, email: &str, groups: &[&str]) {
        self.browser.lock().expect("lock").user = Some((
            email.to_owned(),
            groups.iter().map(|g| (*g).to_owned()).collect(),
        ));
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

#[derive(Deserialize)]
struct AuthQuery {
    client_id: String,
    redirect_uri: String,
    state: String,
    nonce: String,
    code_challenge: String,
    code_challenge_method: String,
    response_type: String,
}

/// The authorization endpoint: signs in whoever `set_browser_user` named and
/// redirects back with a one-time code.
async fn browser_auth(State(idp): State<MockIdp>, Query(q): Query<AuthQuery>) -> Redirect {
    let mut browser = idp.browser.lock().expect("lock");
    assert_eq!(q.response_type, "code");
    assert_eq!(q.code_challenge_method, "S256", "PKCE is required");
    let (email, groups) = browser.user.clone().expect("a browser user was set");
    let code = format!("code-{}", uuid::Uuid::now_v7().simple());
    browser.codes.insert(
        code.clone(),
        PendingCode {
            email,
            groups,
            nonce: q.nonce,
            challenge: q.code_challenge,
            redirect_uri: q.redirect_uri.clone(),
            client_id: q.client_id,
        },
    );
    let sep = if q.redirect_uri.contains('?') {
        '&'
    } else {
        '?'
    };
    Redirect::to(&format!(
        "{}{sep}code={code}&state={}",
        q.redirect_uri, q.state
    ))
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    client_secret: String,
    code_verifier: String,
}

/// The token endpoint: checks the client secret, the redirect URI, and PKCE.
async fn browser_token(
    State(idp): State<MockIdp>,
    Form(f): Form<TokenForm>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, &'static str)> {
    use axum::http::StatusCode;
    let pending = {
        let mut browser = idp.browser.lock().expect("lock");
        let secret_ok = browser
            .client
            .as_ref()
            .is_some_and(|(id, secret)| *id == f.client_id && *secret == f.client_secret);
        if f.grant_type != "authorization_code" || !secret_ok {
            return Err((StatusCode::UNAUTHORIZED, "invalid_client"));
        }
        browser
            .codes
            .remove(&f.code)
            .ok_or((StatusCode::BAD_REQUEST, "invalid_grant"))?
    };
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(f.code_verifier.as_bytes()));
    if pending.challenge != challenge
        || pending.redirect_uri != f.redirect_uri
        || pending.client_id != f.client_id
    {
        return Err((StatusCode::BAD_REQUEST, "invalid_grant"));
    }
    let mut claims = Claims::user(
        &pending.email,
        &pending
            .groups
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )
    .with_nonce(&pending.nonce);
    claims.audience = Some(pending.client_id);
    Ok(Json(serde_json::json!({
        "id_token": idp.id_token(&claims),
        "access_token": "unused",
        "token_type": "Bearer",
    })))
}

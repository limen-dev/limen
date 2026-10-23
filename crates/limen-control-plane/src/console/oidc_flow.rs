//! The browser side of OIDC for the console: authorization code with PKCE,
//! as a confidential client. ID tokens are verified by the same
//! [`OidcVerifier`] the CLI login uses, with the console's client ID.

use std::sync::Arc;
use std::time::{Duration, Instant};

use limen_core::secret::Secret;
use serde::Deserialize;
use tokio::sync::RwLock;
use url::Url;

use crate::http_client::HttpClient;
use crate::oidc::{OidcError, OidcVerifier, VerifiedIdentity};

const DISCOVERY_TTL: Duration = Duration::from_mins(5);

#[derive(Debug, Clone)]
struct Endpoints {
    authorization: String,
    token: String,
    fetched: Instant,
}

#[derive(Debug, Clone)]
pub struct BrowserOidc {
    issuer: String,
    internal_base: String,
    client_id: String,
    client_secret: Secret<String>,
    redirect_uri: String,
    scopes: Vec<String>,
    http: HttpClient,
    verifier: OidcVerifier,
    endpoints: Arc<RwLock<Option<Endpoints>>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

impl BrowserOidc {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        issuer: &str,
        internal_url: Option<&str>,
        client_id: String,
        client_secret: Secret<String>,
        redirect_uri: String,
        scopes: Vec<String>,
        http: HttpClient,
        verifier: OidcVerifier,
    ) -> Self {
        Self {
            issuer: issuer.trim_end_matches('/').to_owned(),
            internal_base: internal_url
                .unwrap_or(issuer)
                .trim_end_matches('/')
                .to_owned(),
            client_id,
            client_secret,
            redirect_uri,
            scopes,
            http,
            verifier,
            endpoints: Arc::new(RwLock::new(None)),
        }
    }

    async fn endpoints(&self) -> Result<Endpoints, OidcError> {
        if let Some(e) = self.endpoints.read().await.as_ref()
            && e.fetched.elapsed() < DISCOVERY_TTL
        {
            return Ok(e.clone());
        }
        let url = format!("{}/.well-known/openid-configuration", self.internal_base);
        let discovery: serde_json::Value = self
            .http
            .inner()
            .get(&url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| OidcError::Unavailable(format!("{url}: {e}")))?
            .json()
            .await
            .map_err(|e| OidcError::Unavailable(format!("{url}: {e}")))?;
        let field = |name: &str| {
            discovery
                .get(name)
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .ok_or_else(|| OidcError::Unavailable(format!("discovery has no {name}")))
        };
        let issuer = field("issuer")?;
        if issuer.trim_end_matches('/') != self.issuer {
            return Err(OidcError::Unavailable(format!(
                "discovery issuer {issuer:?} does not match configured issuer {:?}",
                self.issuer
            )));
        }
        // The browser goes to the public authorization endpoint. We call the
        // token endpoint ourselves, by its internal address.
        let token = field("token_endpoint")?;
        let token = match token.strip_prefix(&self.issuer) {
            Some(path) => format!("{}{path}", self.internal_base),
            None => token,
        };
        let endpoints = Endpoints {
            authorization: field("authorization_endpoint")?,
            token,
            fetched: Instant::now(),
        };
        *self.endpoints.write().await = Some(endpoints.clone());
        Ok(endpoints)
    }

    /// Where to send the browser to log in.
    pub async fn authorization_url(
        &self,
        state: &str,
        nonce: &str,
        code_challenge: &str,
    ) -> Result<String, OidcError> {
        self.authorization_url_with_redirect(state, nonce, code_challenge, &self.redirect_uri)
            .await
    }

    /// Start a login using another registered callback URI on the same client.
    pub async fn authorization_url_with_redirect(
        &self,
        state: &str,
        nonce: &str,
        code_challenge: &str,
        redirect_uri: &str,
    ) -> Result<String, OidcError> {
        let endpoints = self.endpoints().await?;
        let mut url = Url::parse(&endpoints.authorization)
            .map_err(|e| OidcError::Unavailable(format!("authorization endpoint: {e}")))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &self.scopes.join(" "))
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url.into())
    }

    /// Exchange an authorization code for an ID token, and verify it.
    /// Nothing from the token response is logged.
    pub async fn complete(
        &self,
        code: &str,
        code_verifier: &str,
        nonce: &str,
    ) -> Result<VerifiedIdentity, OidcError> {
        self.complete_with_redirect(code, code_verifier, nonce, &self.redirect_uri)
            .await
    }

    /// Exchange an authorization code issued for another registered callback URI.
    pub async fn complete_with_redirect(
        &self,
        code: &str,
        code_verifier: &str,
        nonce: &str,
        redirect_uri: &str,
    ) -> Result<VerifiedIdentity, OidcError> {
        let endpoints = self.endpoints().await?;
        let response = self
            .http
            .inner()
            .post(&endpoints.token)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.expose().as_str()),
                ("code_verifier", code_verifier),
            ])
            .send()
            .await
            .map_err(|e| OidcError::Unavailable(format!("token endpoint: {e}")))?;
        let status = response.status();
        if status.is_server_error() {
            return Err(OidcError::Unavailable(format!("token endpoint: {status}")));
        }
        if !status.is_success() {
            return Err(OidcError::Invalid(format!("token endpoint: {status}")));
        }
        let token: TokenResponse = response
            .json()
            .await
            .map_err(|e| OidcError::Invalid(format!("token response: {e}")))?;
        self.verifier
            .verify(token.id_token, Some(nonce.to_owned()))
            .await
    }
}

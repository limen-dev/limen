//! Talking to the identity provider: authorization code with PKCE through a
//! loopback redirect (RFC 8252), or the device authorization grant (RFC 8628).
//!
//! The CLI is a public OIDC client. It doesn't verify the ID token itself:
//! the control plane does, and it also checks that the nonce binds our key.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context as _, bail};
use axum::extract::Query;
use axum::response::Html;
use axum::routing::get;
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthenticationFlow, CoreClaimName, CoreClaimType, CoreClient,
    CoreClientAuthMethod, CoreDeviceAuthorizationResponse, CoreGrantType, CoreJsonWebKey,
    CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreResponseMode,
    CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::{
    AdditionalProviderMetadata, AuthorizationCode, ClientId, CsrfToken, DeviceAuthorizationUrl,
    IssuerUrl, Nonce, OAuth2TokenResponse as _, PkceCodeChallenge, ProviderMetadata, RedirectUrl,
    Scope,
};
use serde::{Deserialize, Serialize};

const LOGIN_TIMEOUT: Duration = Duration::from_mins(5);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceMetadata {
    #[serde(default)]
    device_authorization_endpoint: Option<DeviceAuthorizationUrl>,
}
impl AdditionalProviderMetadata for DeviceMetadata {}

type Metadata = ProviderMetadata<
    DeviceMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Http(#[from] http::Error),
}

/// HTTP client for the IdP. Redirects are off, as openidconnect recommends.
#[derive(Debug, Clone)]
pub struct HttpClient(reqwest::Client);

impl HttpClient {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build()?,
        ))
    }
}

async fn execute(
    client: reqwest::Client,
    request: openidconnect::HttpRequest,
) -> Result<openidconnect::HttpResponse, HttpError> {
    let response = client.execute(reqwest::Request::try_from(request)?).await?;
    let mut builder = http::Response::builder().status(response.status());
    for (name, value) in response.headers() {
        builder = builder.header(name, value);
    }
    Ok(builder.body(response.bytes().await?.to_vec())?)
}

impl<'c> openidconnect::AsyncHttpClient<'c> for HttpClient {
    type Error = HttpError;
    type Future =
        Pin<Box<dyn Future<Output = Result<openidconnect::HttpResponse, HttpError>> + Send + 'c>>;

    fn call(&'c self, request: openidconnect::HttpRequest) -> Self::Future {
        Box::pin(execute(self.0.clone(), request))
    }
}

#[derive(Debug, Clone)]
pub struct IdpSettings {
    pub issuer: String,
    pub client_id: String,
    pub scopes: Vec<String>,
}

async fn discover(settings: &IdpSettings, http: &HttpClient) -> anyhow::Result<Metadata> {
    let issuer = IssuerUrl::new(settings.issuer.clone()).context("invalid issuer URL")?;
    Metadata::discover_async(issuer, http)
        .await
        .with_context(|| format!("discovering the identity provider at {}", settings.issuer))
}

fn scopes(settings: &IdpSettings) -> impl Iterator<Item = Scope> + '_ {
    settings
        .scopes
        .iter()
        .filter(|s| *s != "openid")
        .map(|s| Scope::new(s.clone()))
}

#[derive(Debug, Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Authorization code flow with PKCE. Opens the browser unless `open_browser`
/// is false, waits for the redirect to a loopback port, and returns the raw ID token.
pub async fn pkce_login(
    settings: &IdpSettings,
    nonce: String,
    open_browser: bool,
) -> anyhow::Result<String> {
    let http = HttpClient::new()?;
    let metadata = discover(settings, &http).await?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("binding the loopback callback listener")?;
    let port = listener.local_addr()?.port();
    let redirect = RedirectUrl::new(format!("http://127.0.0.1:{port}/callback"))?;
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(settings.client_id.clone()),
        None,
    )
    .set_redirect_uri(redirect);

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, csrf, _nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            move || Nonce::new(nonce),
        )
        .add_scopes(scopes(settings))
        .set_pkce_challenge(challenge)
        .url();

    let (tx, rx) = tokio::sync::oneshot::channel::<Callback>();
    let tx = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));
    let app = axum::Router::new().route(
        "/callback",
        get(move |Query(cb): Query<Callback>| {
            let tx = std::sync::Arc::clone(&tx);
            async move {
                let ok = cb.error.is_none();
                if let Some(tx) = tx.lock().ok().and_then(|mut g| g.take()) {
                    let _ = tx.send(cb);
                }
                Html(if ok {
                    callback_page(
                        "Login complete.",
                        "You can close this tab and return to the terminal.",
                    )
                } else {
                    callback_page("Login failed.", "See the terminal for details.")
                })
            }
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    eprintln!("Opening your browser to log in. If it doesn't open, visit:\n\n  {url}\n");
    if open_browser && webbrowser::open(url.as_str()).is_err() {
        eprintln!("(could not open a browser automatically)");
    }
    let callback = tokio::time::timeout(LOGIN_TIMEOUT, rx)
        .await
        .context("timed out waiting for the browser login")?
        .context("callback listener stopped")?;
    server.abort();

    if let Some(error) = callback.error {
        bail!(
            "identity provider returned an error: {error}: {}",
            callback.error_description.unwrap_or_default()
        );
    }
    if callback.state.as_deref() != Some(csrf.secret().as_str()) {
        bail!("login callback state did not match; possible CSRF, aborting");
    }
    let code = callback.code.context("login callback had no code")?;
    let token = client
        .exchange_code(AuthorizationCode::new(code))?
        .set_pkce_verifier(verifier)
        .request_async(&http)
        .await
        .context("exchanging the authorization code")?;
    let _ = token.access_token();
    Ok(token
        .extra_fields()
        .id_token()
        .context("the identity provider returned no ID token")?
        .to_string())
}

/// Device authorization grant, for machines without a browser.
pub async fn device_login(settings: &IdpSettings) -> anyhow::Result<String> {
    let http = HttpClient::new()?;
    let metadata = discover(settings, &http).await?;
    let device_url = metadata
        .additional_metadata()
        .device_authorization_endpoint
        .clone()
        .context("the identity provider doesn't support the device flow")?;
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(settings.client_id.clone()),
        None,
    )
    .set_device_authorization_url(device_url);
    let details: CoreDeviceAuthorizationResponse = client
        .exchange_device_code()
        .add_scopes(scopes(settings))
        .request_async(&http)
        .await
        .context("requesting a device code")?;
    let uri = details.verification_uri_complete().map_or_else(
        || details.verification_uri().to_string(),
        |u| u.secret().clone(),
    );
    eprintln!(
        "To log in, visit:\n\n  {uri}\n\nand enter the code: {}\n",
        details.user_code().secret()
    );
    let token = client
        .exchange_device_access_token(&details)?
        .request_async(&http, tokio::time::sleep, Some(LOGIN_TIMEOUT))
        .await
        .context("waiting for device authorization")?;
    Ok(token
        .extra_fields()
        .id_token()
        .context("the identity provider returned no ID token")?
        .to_string())
}

/// The logo mark, inlined so the page needs no further requests.
const LOGO_MARK: &str = include_str!("../../../assets/logo-mark.svg");

fn callback_page(heading: &str, detail: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Limen</title></head>\
         <body style=\"font-family:system-ui,sans-serif;text-align:center;margin-top:4rem\">\
         <div style=\"width:96px;margin:0 auto\">{LOGO_MARK}</div>\
         <h3>Limen: {heading}</h3><p>{detail}</p></body></html>"
    )
}

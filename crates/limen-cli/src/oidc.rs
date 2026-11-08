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

/// Refuse a URL the proxy or the identity provider handed us unless it is
/// `https`, or `http` to a loopback host (the dev stack). The CLI opens these
/// in a browser, so `file:`, `javascript:` and custom schemes must not pass.
fn require_secure_url(raw: &str, what: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(raw).with_context(|| format!("{what} is not a valid URL"))?;
    let host = url.host_str().unwrap_or_default();
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match url.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        other => bail!(
            "refusing {what}: scheme `{other}` is not https (http is allowed only for loopback hosts)"
        ),
    }
}

async fn discover(settings: &IdpSettings, http: &HttpClient) -> anyhow::Result<Metadata> {
    require_secure_url(&settings.issuer, "the identity provider issuer")?;
    let issuer = IssuerUrl::new(settings.issuer.clone()).context("invalid issuer URL")?;
    Metadata::discover_async(issuer, http)
        .await
        .with_context(|| format!("discovering the identity provider at {}", settings.issuer))
}

/// The scopes the control plane advertises. It adds `offline_access` only when
/// it keeps refresh tokens (ADR-0046), so an IdP that has not enabled refresh
/// tokens is never asked for one.
fn scopes(settings: &IdpSettings) -> impl Iterator<Item = Scope> + '_ {
    settings
        .scopes
        .iter()
        .filter(|s| *s != "openid")
        .map(|s| Scope::new(s.clone()))
}

/// What a login returned: the ID token, and the refresh token if the IdP
/// issued one.
pub struct Tokens {
    pub id_token: String,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// The terminal message for an `error` callback. Any web page can hit the
/// loopback port first, so both fields are untrusted: no control characters
/// (escape sequences), bounded length.
fn callback_error_message(error: &str, description: &str) -> String {
    format!(
        "identity provider returned an error: {}: {}",
        crate::ui::plain_line(error, 200),
        crate::ui::plain_line(description, 500)
    )
}

/// Authorization code flow with PKCE. Opens the browser unless `open_browser`
/// is false, waits for the redirect to a loopback port, and returns the tokens.
pub async fn pkce_login(
    settings: &IdpSettings,
    nonce: String,
    open_browser: bool,
) -> anyhow::Result<Tokens> {
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

    require_secure_url(url.as_str(), "the authorization URL")?;

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

    anstream::eprintln!(
        "{} Opening your browser to sign in. If it doesn't open, visit:\n\n  {}\n",
        crate::ui::accent("›"),
        crate::ui::bold(url.as_str())
    );
    if open_browser && webbrowser::open(url.as_str()).is_err() {
        crate::ui::warn("could not open a browser automatically");
    }
    let waiting = crate::ui::spinner("Waiting for you to finish signing in");
    let callback = tokio::time::timeout(LOGIN_TIMEOUT, rx)
        .await
        .context("timed out waiting for the browser login")?
        .context("callback listener stopped")?;
    server.abort();
    waiting.finish();

    if let Some(error) = callback.error {
        bail!(callback_error_message(
            &error,
            &callback.error_description.unwrap_or_default()
        ));
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
    Ok(Tokens {
        id_token: token
            .extra_fields()
            .id_token()
            .context("the identity provider returned no ID token")?
            .to_string(),
        refresh_token: token.refresh_token().map(|r| r.secret().clone()),
    })
}

/// Device authorization grant, for machines without a browser.
pub async fn device_login(settings: &IdpSettings) -> anyhow::Result<Tokens> {
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
    anstream::eprintln!(
        "{} To sign in, visit:\n\n  {}\n\nand enter the code: {}\n",
        crate::ui::accent("›"),
        crate::ui::bold(&uri),
        crate::ui::accent(details.user_code().secret())
    );
    let token = client
        .exchange_device_access_token(&details)?
        .request_async(&http, tokio::time::sleep, Some(LOGIN_TIMEOUT))
        .await
        .context("waiting for device authorization")?;
    Ok(Tokens {
        id_token: token
            .extra_fields()
            .id_token()
            .context("the identity provider returned no ID token")?
            .to_string(),
        refresh_token: token.refresh_token().map(|r| r.secret().clone()),
    })
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

#[cfg(test)]
mod tests {
    use super::{callback_error_message, require_secure_url};

    #[test]
    fn callback_error_text_cannot_inject_terminal_escapes() {
        let msg = callback_error_message(
            "bad\u{1b}[2J",
            &format!("x\u{1b}]0;pwn\u{7}\n{}", "y".repeat(5000)),
        );
        assert!(!msg.chars().any(char::is_control), "{msg:?}");
        assert!(msg.len() < 1000, "{}", msg.len());
    }

    #[test]
    fn only_https_or_loopback_http_urls_pass() {
        for ok in [
            "https://idp.example.com/auth",
            "http://localhost:5556/dex",
            "http://127.0.0.1:5556/",
            "http://[::1]:5556/",
        ] {
            assert!(require_secure_url(ok, "x").is_ok(), "{ok}");
        }
        for bad in [
            "http://idp.example.com/auth",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "myapp://open?x=1",
            "http://localhost.evil.com/",
            "not a url",
        ] {
            assert!(require_secure_url(bad, "x").is_err(), "{bad}");
        }
    }
}

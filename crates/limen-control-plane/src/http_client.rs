//! HTTP client for OIDC discovery and JWKS fetches. Redirects are disabled
//! so a compromised or misconfigured endpoint can't send us elsewhere.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Http(#[from] http::Error),
}

#[derive(Debug, Clone)]
pub struct HttpClient(reqwest::Client);

impl HttpClient {
    pub fn new() -> Result<Self, reqwest::Error> {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map(Self)
    }

    #[must_use]
    pub fn inner(&self) -> &reqwest::Client {
        &self.0
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

/// Implemented on the type, with a future that owns its client. A borrowing
/// closure here makes every enclosing future fail rustc's higher-ranked
/// `Send` check.
impl<'c> openidconnect::AsyncHttpClient<'c> for HttpClient {
    type Error = HttpError;
    type Future =
        Pin<Box<dyn Future<Output = Result<openidconnect::HttpResponse, HttpError>> + Send + 'c>>;

    fn call(&'c self, request: openidconnect::HttpRequest) -> Self::Future {
        Box::pin(execute(self.0.clone(), request))
    }
}

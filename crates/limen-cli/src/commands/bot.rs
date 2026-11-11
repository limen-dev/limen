//! `limen login --bot`: a CI job logs in with the workload identity token its
//! platform minted for it (ADR-0019). No secret is configured anywhere: the
//! token exists only for this job and is used once.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use limen_proto::v1::auth_client::AuthClient;
use limen_proto::v1::{BotLoginRequest, GetAuthConfigRequest};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

use super::login::{CaChoice, apply_ca_choice, finish};
use crate::api;

/// How the token is found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSource {
    /// Ask the CI platform for one: GitHub Actions' token endpoint.
    GithubRuntime,
    Env(String),
    File(PathBuf),
}

/// The environment variable `gitlab` and `oidc` jobs put their token in unless told otherwise.
pub const DEFAULT_TOKEN_ENV: &str = "LIMEN_ID_TOKEN";

pub struct BotLogin<'a> {
    pub proxy: Option<&'a str>,
    /// `github_actions`, `gitlab`, or `oidc`.
    pub method: &'a str,
    pub bot: Option<&'a str>,
    pub token_env: Option<&'a str>,
    pub token_file: Option<&'a Path>,
    pub audience: Option<&'a str>,
    pub ca: CaChoice<'a>,
}

/// Where this method's token comes from, given what the user passed.
pub fn token_source(method: &str, env: Option<&str>, file: Option<&Path>) -> TokenSource {
    if let Some(file) = file {
        return TokenSource::File(file.to_path_buf());
    }
    if let Some(env) = env {
        return TokenSource::Env(env.to_owned());
    }
    if method == "github_actions" {
        TokenSource::GithubRuntime
    } else {
        TokenSource::Env(DEFAULT_TOKEN_ENV.to_owned())
    }
}

/// The URL GitHub Actions serves tokens at, asking for `audience`.
pub fn github_token_url(base: &str, audience: &str) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let encoded: String = audience
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    format!("{base}{sep}audience={encoded}")
}

/// The `value` field of GitHub's token response.
pub fn github_token_from_response(body: &str) -> anyhow::Result<String> {
    let v: serde_json::Value = serde_json::from_str(body).context("GitHub's answer wasn't JSON")?;
    v.get("value")
        .and_then(serde_json::Value::as_str)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .context("GitHub's answer had no token")
}

/// How long to wait for GitHub's token endpoint, connect to last byte.
const GITHUB_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A bare `reqwest::Client` waits forever and follows redirects, so a stalled
/// endpoint would hang the CI job until its own limit, and the request
/// carries a bearer token.
fn github_client(timeout: std::time::Duration) -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building the HTTP client")
}

async fn github_token(audience: &str) -> anyhow::Result<String> {
    let (Ok(url), Ok(bearer)) = (
        std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL"),
        std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
    ) else {
        bail!(
            "this doesn't look like a GitHub Actions job with OIDC enabled \
             (ACTIONS_ID_TOKEN_REQUEST_URL is not set). Add `permissions: id-token: write` to the job"
        );
    };
    let client = github_client(GITHUB_TIMEOUT)?;
    let response = client
        .get(github_token_url(&url, audience))
        .bearer_auth(bearer)
        .header("Accept", "application/json; api-version=2.0")
        .send()
        .await
        .context("asking GitHub for an identity token")?;
    let status = response.status();
    let body = response.text().await.context("reading GitHub's answer")?;
    if !status.is_success() {
        bail!("GitHub refused to issue an identity token ({status})");
    }
    github_token_from_response(&body)
}

fn read_token(source: &TokenSource) -> anyhow::Result<String> {
    let raw = match source {
        TokenSource::Env(name) => std::env::var(name).with_context(|| {
            format!("the environment variable {name} is not set (it should hold the job\'s identity token)")
        })?,
        TokenSource::File(path) if path == Path::new("-") => {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
                .context("reading the token from standard input")?;
            text
        }
        TokenSource::File(path) => std::fs::read_to_string(path)
            .with_context(|| format!("reading the token from {}", path.display()))?,
        TokenSource::GithubRuntime => bail!("internal error: no GitHub token here"),
    };
    let token = raw.trim().to_owned();
    if token.is_empty() {
        bail!("the identity token is empty");
    }
    Ok(token)
}

pub async fn run(args: BotLogin<'_>) -> anyhow::Result<()> {
    let proxy = api::resolve_server(args.proxy)?;
    api::server_name(&proxy)?;
    apply_ca_choice(&proxy, args.ca)?;

    let mut auth = AuthClient::new(api::connect(&proxy, None)?);
    let config = auth
        .get_auth_config(GetAuthConfigRequest {})
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();

    let source = token_source(args.method, args.token_env, args.token_file);
    // The token never reaches a log or a message: it is passed along and dropped.
    let token = match &source {
        TokenSource::GithubRuntime => {
            let audience = args.audience.unwrap_or(&config.bot_audience);
            github_token(audience).await?
        }
        other => read_token(other)?,
    };

    // The key is generated here and never leaves this machine.
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let csr_der = CertificateParams::default()
        .serialize_request(&key)?
        .der()
        .to_vec();
    let resp = auth
        .bot_login(BotLoginRequest {
            method: args.method.to_owned(),
            token,
            csr_der,
            bot: args.bot.unwrap_or_default().to_owned(),
        })
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    finish(&proxy, &key, resp).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_is_asked_unless_the_user_names_a_token() {
        assert_eq!(
            token_source("github_actions", None, None),
            TokenSource::GithubRuntime
        );
        assert_eq!(
            token_source("github_actions", Some("MY_TOKEN"), None),
            TokenSource::Env("MY_TOKEN".into())
        );
        assert_eq!(
            token_source("gitlab", None, None),
            TokenSource::Env(DEFAULT_TOKEN_ENV.into())
        );
        assert_eq!(
            token_source("oidc", Some("A"), Some(Path::new("t.jwt"))),
            TokenSource::File("t.jwt".into()),
            "a file wins over an environment variable"
        );
    }

    #[tokio::test]
    async fn a_stalled_token_endpoint_times_out() {
        // Accepts the connection and never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}/token", listener.local_addr().expect("addr"));
        let _hold = tokio::spawn(async move {
            let _conn = listener.accept().await;
            std::future::pending::<()>().await;
        });
        let client = github_client(std::time::Duration::from_millis(200)).expect("client");
        let started = std::time::Instant::now();
        let err = client.get(&url).send().await.expect_err("must not hang");
        assert!(err.is_timeout(), "{err}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}/token", listener.local_addr().expect("addr"));
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let (mut conn, _) = listener.accept().await.expect("accept");
            // Read the whole request head first: closing a socket with unread
            // data resets the connection and can eat the response.
            let mut head = Vec::new();
            let mut buf = [0u8; 512];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = conn.read(&mut buf).await.expect("read");
                assert!(n > 0, "client hung up before sending a request");
                head.extend_from_slice(&buf[..n]);
            }
            conn.write_all(
                b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/steal\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .expect("write");
            // Keep the connection open until the client is done with it.
            let _ = conn.read(&mut buf).await;
        });
        let client = github_client(GITHUB_TIMEOUT).expect("client");
        let response = client.get(&url).send().await.expect("answer");
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    }

    #[test]
    fn the_audience_is_appended_and_encoded() {
        assert_eq!(
            github_token_url("https://x.example/token?api=1", "limen"),
            "https://x.example/token?api=1&audience=limen"
        );
        assert_eq!(
            github_token_url("https://x.example/token", "https://limen.example.com/a b"),
            "https://x.example/token?audience=https%3A%2F%2Flimen.example.com%2Fa%20b"
        );
    }

    #[test]
    fn github_answers_are_parsed() {
        assert_eq!(
            github_token_from_response(r#"{"value":"abc.def.ghi"}"#).expect("token"),
            "abc.def.ghi"
        );
        assert!(github_token_from_response(r#"{"value":""}"#).is_err());
        assert!(github_token_from_response(r#"{"nope":1}"#).is_err());
        assert!(github_token_from_response("<html>").is_err());
    }

    #[test]
    fn tokens_are_trimmed_and_must_not_be_empty() {
        let dir = std::env::temp_dir().join(format!("limen-cli-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("t.jwt");
        std::fs::write(&file, "  abc.def.ghi\n").expect("write");
        assert_eq!(
            read_token(&TokenSource::File(file.clone())).expect("token"),
            "abc.def.ghi"
        );
        std::fs::write(&file, "  \n").expect("write");
        assert!(read_token(&TokenSource::File(file)).is_err());
        assert!(read_token(&TokenSource::File(dir.join("missing"))).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}

//! Calling AWS describe APIs with `SigV4` (ADR-0027). The query-protocol
//! services (EC2, RDS, Redshift, `ElastiCache`, STS) take a form POST and
//! answer XML; EKS is a REST API that answers JSON. Everything here is
//! read-only by construction: the only actions are `Describe*`, `List*`,
//! `GetConsoleOutput` and the STS calls that give the worker its role.

use std::time::Duration;

use time::OffsetDateTime;

use super::xml::{self, Node};
use crate::db::sigv4::{self, Credentials};

const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE: usize = 16 * 1024 * 1024;

/// Read a response body, giving up as soon as it passes `max` bytes rather
/// than after buffering all of it.
async fn capped_body(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>, String> {
    const TOO_LARGE: &str = "the response is too large";
    if resp
        .content_length()
        .is_some_and(|n| n > u64::try_from(max).unwrap_or(u64::MAX))
    {
        return Err(TOO_LARGE.into());
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if out.len().saturating_add(chunk.len()) > max {
            return Err(TOO_LARGE.into());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct Aws {
    http: reqwest::Client,
    /// Replaces `https://<service>.<region>.amazonaws.com`: a stand-in for
    /// tests and the dev stack.
    endpoint: Option<String>,
}

impl Aws {
    pub fn new(endpoint: Option<String>) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { http, endpoint })
    }

    fn base(&self, service: &str, region: &str) -> String {
        self.endpoint
            .clone()
            .unwrap_or_else(|| format!("https://{service}.{region}.amazonaws.com"))
    }

    fn host(url: &reqwest::Url) -> String {
        match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_owned(),
        }
    }

    async fn finish(&self, req: reqwest::RequestBuilder) -> Result<String, String> {
        let resp = req.send().await.map_err(|e| e.to_string())?;
        let status = resp.status();
        let bytes = capped_body(resp, MAX_RESPONSE).await?;
        let body = String::from_utf8_lossy(&bytes).into_owned();
        if status.is_success() {
            return Ok(body);
        }
        // AWS puts a code and a message in the body; neither holds a secret.
        let detail = xml::parse(&body)
            .ok()
            .and_then(|n| {
                let e = n
                    .path(&["Error"])
                    .cloned()
                    .or_else(|| n.path(&["Errors", "Error"]).cloned())?;
                Some(format!(
                    "{}: {}",
                    e.text_of("Code").unwrap_or("error"),
                    e.text_of("Message").unwrap_or_default()
                ))
            })
            .unwrap_or_else(|| body.chars().take(120).collect());
        Err(format!(
            "{status}: {}",
            detail.chars().take(200).collect::<String>()
        ))
    }

    /// A query-protocol call. `service` names the endpoint and the signing
    /// scope. Returns the root of the response.
    pub async fn query(
        &self,
        creds: &Credentials,
        service: &str,
        region: &str,
        version: &str,
        action: &str,
        params: &[(String, String)],
    ) -> Result<Node, String> {
        let url = reqwest::Url::parse(&self.base(service, region)).map_err(|e| e.to_string())?;
        let mut all = vec![
            ("Action".to_owned(), action.to_owned()),
            ("Version".to_owned(), version.to_owned()),
        ];
        all.extend_from_slice(params);
        let body = all
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    sigv4::uri_encode(k, false),
                    sigv4::uri_encode(v, false)
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        let content_type = "application/x-www-form-urlencoded; charset=utf-8";
        let host = Self::host(&url);
        let signed = sigv4::sign_headers(
            &sigv4::Target {
                method: "POST",
                host: &host,
                path: "/",
                region,
                service,
            },
            "",
            &[("content-type", content_type)],
            body.as_bytes(),
            creds,
            OffsetDateTime::now_utc(),
        );
        let mut req = self
            .http
            .post(url)
            .header("content-type", content_type)
            .header("authorization", signed.authorization)
            .header("x-amz-date", signed.amz_date)
            .body(body);
        if let Some(t) = signed.session_token {
            req = req.header("x-amz-security-token", t);
        }
        let text = self
            .finish(req)
            .await
            .map_err(|e| format!("{service} {action}: {e}"))?;
        xml::parse(&text).map_err(|e| format!("{service} {action}: {e}"))
    }

    /// A GET against a REST API (EKS) that answers JSON.
    pub async fn rest_get(
        &self,
        creds: &Credentials,
        service: &str,
        region: &str,
        path: &str,
        query: &[(String, String)],
    ) -> Result<serde_json::Value, String> {
        let url = reqwest::Url::parse(&self.base(service, region)).map_err(|e| e.to_string())?;
        let canonical = sigv4::canonical_query(query);
        let host = Self::host(&url);
        let signed = sigv4::sign_headers(
            &sigv4::Target {
                method: "GET",
                host: &host,
                path,
                region,
                service,
            },
            &canonical,
            &[],
            b"",
            creds,
            OffsetDateTime::now_utc(),
        );
        let mut full = url;
        full.set_path(path);
        full.set_query((!canonical.is_empty()).then_some(canonical.as_str()));
        let mut req = self
            .http
            .get(full)
            .header("authorization", signed.authorization)
            .header("x-amz-date", signed.amz_date);
        if let Some(t) = signed.session_token {
            req = req.header("x-amz-security-token", t);
        }
        let text = self
            .finish(req)
            .await
            .map_err(|e| format!("{service} {path}: {e}"))?;
        serde_json::from_str(&text).map_err(|e| format!("{service} {path}: {e}"))
    }

    /// Credentials for `role_arn`, from the worker's own.
    pub async fn assume_role(
        &self,
        creds: &Credentials,
        role_arn: &str,
        region: &str,
    ) -> Result<(Credentials, OffsetDateTime), String> {
        let root = self
            .query(
                creds,
                "sts",
                region,
                "2011-06-15",
                "AssumeRole",
                &[
                    ("RoleArn".into(), role_arn.into()),
                    ("RoleSessionName".into(), "limen-discovery".into()),
                    ("DurationSeconds".into(), "900".into()),
                ],
            )
            .await?;
        let c = root
            .path(&["AssumeRoleResult", "Credentials"])
            .ok_or("sts AssumeRole: no credentials in the answer")?;
        let field = |n: &str| {
            c.text_of(n)
                .map(str::to_owned)
                .ok_or_else(|| format!("sts AssumeRole: no {n}"))
        };
        let expires = OffsetDateTime::parse(
            &field("Expiration")?,
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap_or_else(|_| OffsetDateTime::now_utc() + Duration::from_mins(10));
        Ok((
            Credentials {
                access_key: field("AccessKeyId")?,
                secret_key: limen_core::secret::Secret::new(field("SecretAccessKey")?),
                session_token: Some(limen_core::secret::Secret::new(field("SessionToken")?)),
            },
            expires,
        ))
    }

    /// The account the credentials belong to.
    pub async fn account_of(&self, creds: &Credentials, region: &str) -> Result<String, String> {
        let root = self
            .query(creds, "sts", region, "2011-06-15", "GetCallerIdentity", &[])
            .await?;
        root.text_at(&["GetCallerIdentityResult", "Account"])
            .map(str::to_owned)
            .ok_or_else(|| "sts GetCallerIdentity: no account in the answer".to_owned())
    }
}

/// `Name.1`, `Name.2`, ... for a list parameter.
#[must_use]
pub fn indexed(prefix: &str, values: &[String]) -> Vec<(String, String)> {
    values
        .iter()
        .enumerate()
        .map(|(i, v)| (format!("{prefix}.{}", i + 1), v.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A server that sends a little more than the limit and then goes quiet
    /// with the connection open: the worker must answer at the limit, not
    /// wait for the end of the body (which never comes).
    #[tokio::test]
    async fn a_response_is_cut_off_at_the_limit_not_after_it_ends() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let mut req = [0u8; 4096];
            let _ = s.read(&mut req).await;
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await;
            let mut sent = 0;
            while sent < MAX_RESPONSE + 64 * 1024 {
                let chunk = format!("{:x}\r\n{}\r\n", 65536, "a".repeat(65536));
                if s.write_all(chunk.as_bytes()).await.is_err() {
                    return;
                }
                sent += 65536;
            }
            // Hold the socket open, say nothing.
            tokio::time::sleep(Duration::from_secs(120)).await;
        });
        let aws = Aws::new(None).expect("client");
        let started = std::time::Instant::now();
        let got = aws.finish(aws.http.get(format!("http://{addr}/"))).await;
        assert_eq!(got, Err("the response is too large".to_owned()), "{got:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}

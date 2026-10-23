//! IAM database authentication (ADR-0015, ADR-0033 section 3).
//!
//! * RDS and Aurora (PostgreSQL and MySQL): a 15-minute token, which is a
//!   SigV4-presigned `connect` request for the `rds-db` service. It is used as
//!   the password, over TLS, at connect time only.
//! * Redshift: temporary credentials from `GetClusterCredentials`
//!   (provisioned) or `redshift-serverless:GetCredentials`. The returned user
//!   (`IAM:<name>`) and password are used to log in.
//!
//! **Unverified against the real services**: no AWS account has been available.
//! The signer matches AWS's published examples (`sigv4`), and the Redshift
//! calls are exercised against a local stand-in only.

use aws_credential_types::provider::ProvideCredentials as _;
use limen_core::secret::Secret;
use serde_json::json;
use time::OffsetDateTime;

use super::sigv4::{self, Credentials, EMPTY_PAYLOAD_SHA256, Target};

/// RDS tokens are valid for 15 minutes.
const TOKEN_LIFETIME_SECS: u32 = 900;

/// Where the worker gets AWS credentials: the default chain (environment,
/// shared config, ECS task role, EC2 instance profile, ...).
#[derive(Debug)]
pub struct CredentialSource {
    provider: aws_credential_types::provider::SharedCredentialsProvider,
}

impl CredentialSource {
    pub async fn from_environment() -> Result<Self, String> {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        let provider = config
            .credentials_provider()
            .ok_or("no AWS credentials provider is configured on this worker")?;
        Ok(Self { provider })
    }

    pub async fn get(&self) -> Result<Credentials, String> {
        let c = self
            .provider
            .provide_credentials()
            .await
            .map_err(|e| format!("AWS credentials: {e}"))?;
        Ok(Credentials {
            access_key: c.access_key_id().to_owned(),
            secret_key: Secret::new(c.secret_access_key().to_owned()),
            session_token: c.session_token().map(|t| Secret::new(t.to_owned())),
        })
    }
}

/// The password for `db_user` on an RDS or Aurora endpoint (`host:port`).
#[must_use]
pub fn rds_auth_token(
    creds: &Credentials,
    region: &str,
    endpoint: &str,
    db_user: &str,
    now: OffsetDateTime,
) -> Secret<String> {
    let query = sigv4::presign_query(
        &Target {
            method: "GET",
            host: endpoint,
            path: "/",
            region,
            service: "rds-db",
        },
        &[
            ("Action".into(), "connect".into()),
            ("DBUser".into(), db_user.into()),
        ],
        creds,
        TOKEN_LIFETIME_SECS,
        EMPTY_PAYLOAD_SHA256,
        now,
    );
    Secret::new(format!("{endpoint}/?{query}"))
}

/// A database login from a Redshift credential API.
#[derive(Debug)]
pub struct RedshiftLogin {
    /// The user to log in as, such as `IAM:limen_read`.
    pub user: String,
    pub password: Secret<String>,
}

/// How a Redshift resource asks for credentials.
#[derive(Debug, Clone, Copy)]
pub enum RedshiftKind<'a> {
    Provisioned { cluster_identifier: &'a str },
    Serverless { workgroup: &'a str },
}

/// Where the Redshift APIs are, when not at their public addresses (the
/// standard `AWS_ENDPOINT_URL_REDSHIFT` and `AWS_ENDPOINT_URL_REDSHIFT_SERVERLESS`
/// variables, for private endpoints and local stand-ins).
#[derive(Debug, Clone, Default)]
pub struct Endpoints {
    pub redshift: Option<String>,
    pub serverless: Option<String>,
}

impl Endpoints {
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            redshift: std::env::var("AWS_ENDPOINT_URL_REDSHIFT").ok(),
            serverless: std::env::var("AWS_ENDPOINT_URL_REDSHIFT_SERVERLESS").ok(),
        }
    }
}

fn base_url(configured: Option<&String>, default: String) -> String {
    configured
        .cloned()
        .unwrap_or(default)
        .trim_end_matches('/')
        .to_owned()
}

/// Ask Redshift for credentials for `db_user`. `db_name` is the database the
/// session was granted.
pub async fn redshift_login(
    endpoints: &Endpoints,
    creds: &Credentials,
    region: &str,
    kind: RedshiftKind<'_>,
    db_user: &str,
    db_name: &str,
    now: OffsetDateTime,
) -> Result<RedshiftLogin, String> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    match kind {
        RedshiftKind::Provisioned { cluster_identifier } => {
            let base = base_url(
                endpoints.redshift.as_ref(),
                format!("https://redshift.{region}.amazonaws.com"),
            );
            let body = format!(
                "Action=GetClusterCredentials&Version=2012-12-01&ClusterIdentifier={}&DbUser={}&DbName={}&AutoCreate=false&DurationSeconds=900",
                sigv4::uri_encode(cluster_identifier, false),
                sigv4::uri_encode(db_user, false),
                sigv4::uri_encode(db_name, false),
            );
            let text = post(
                &http,
                &base,
                "redshift",
                region,
                creds,
                now,
                "application/x-www-form-urlencoded; charset=utf-8",
                None,
                body,
            )
            .await?;
            Ok(RedshiftLogin {
                user: xml_tag(&text, "DbUser").ok_or("Redshift answered without a DbUser")?,
                password: Secret::new(
                    xml_tag(&text, "DbPassword").ok_or("Redshift answered without a DbPassword")?,
                ),
            })
        }
        RedshiftKind::Serverless { workgroup } => {
            let base = base_url(
                endpoints.serverless.as_ref(),
                format!("https://redshift-serverless.{region}.amazonaws.com"),
            );
            let body = json!({
                "workgroupName": workgroup,
                "dbName": db_name,
                "durationSeconds": 900,
            })
            .to_string();
            let text = post(
                &http,
                &base,
                "redshift-serverless",
                region,
                creds,
                now,
                "application/x-amz-json-1.1",
                Some("RedshiftServerless.GetCredentials"),
                body,
            )
            .await?;
            let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            Ok(RedshiftLogin {
                user: v["dbUser"]
                    .as_str()
                    .ok_or("Redshift answered without a dbUser")?
                    .to_owned(),
                password: Secret::new(
                    v["dbPassword"]
                        .as_str()
                        .ok_or("Redshift answered without a dbPassword")?
                        .to_owned(),
                ),
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn post(
    http: &reqwest::Client,
    base: &str,
    service: &str,
    region: &str,
    creds: &Credentials,
    now: OffsetDateTime,
    content_type: &str,
    target: Option<&str>,
    body: String,
) -> Result<String, String> {
    let url = reqwest::Url::parse(base).map_err(|e| format!("{base}: {e}"))?;
    let host = match url.port() {
        Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_owned(),
    };
    let mut extra: Vec<(&str, &str)> = vec![("content-type", content_type)];
    if let Some(t) = target {
        extra.push(("x-amz-target", t));
    }
    let signed = sigv4::sign_headers(
        &Target {
            method: "POST",
            host: &host,
            path: "/",
            region,
            service,
        },
        "",
        &extra,
        body.as_bytes(),
        creds,
        now,
    );
    let mut request = http
        .post(url)
        .header("content-type", content_type)
        .header("x-amz-date", &signed.amz_date)
        .header("authorization", &signed.authorization)
        .body(body);
    if let Some(t) = target {
        request = request.header("x-amz-target", t);
    }
    if let Some(token) = &signed.session_token {
        request = request.header("x-amz-security-token", token);
    }
    let response = request
        .send()
        .await
        .map_err(|e| format!("{service}: {e}"))?;
    let status = response.status();
    let text = response.text().await.map_err(|e| e.to_string())?;
    if status.is_success() {
        Ok(text)
    } else {
        // The body names the problem (AccessDenied, ...) and holds no secret.
        Err(format!(
            "{service} answered {status}: {}",
            text.chars().take(300).collect::<String>()
        ))
    }
}

/// The text of `<tag>...</tag>`, unescaped for the entities AWS uses.
fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    Some(
        xml[start..end]
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> Credentials {
        Credentials {
            access_key: "AKIDEXAMPLE".into(),
            secret_key: Secret::new("secret".into()),
            session_token: None,
        }
    }

    fn at() -> OffsetDateTime {
        OffsetDateTime::parse(
            "2026-10-17T09:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .expect("time")
    }

    #[test]
    fn the_rds_token_is_a_presigned_connect_request() {
        let token = rds_auth_token(
            &creds(),
            "eu-west-1",
            "orders.cluster-x.eu-west-1.rds.amazonaws.com:5432",
            "limen_read",
            at(),
        );
        let t = token.expose();
        assert!(
            t.starts_with("orders.cluster-x.eu-west-1.rds.amazonaws.com:5432/?Action=connect&DBUser=limen_read&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20261017%2Feu-west-1%2Frds-db%2Faws4_request&X-Amz-Date=20261017T090000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Signature="),
            "{t}"
        );
        assert!(!t.starts_with("https://"));
        assert!(t.len() > 200, "tokens are long, as AWS's are");
        assert_eq!(format!("{token:?}"), "[REDACTED]");
    }

    #[test]
    fn xml_values_are_found_and_unescaped() {
        let xml = "<R><DbUser>IAM:limen_ro</DbUser><DbPassword>a&amp;b&lt;c</DbPassword></R>";
        assert_eq!(xml_tag(xml, "DbUser").as_deref(), Some("IAM:limen_ro"));
        assert_eq!(xml_tag(xml, "DbPassword").as_deref(), Some("a&b<c"));
        assert_eq!(xml_tag(xml, "Nope"), None);
    }

    /// A local stand-in for the Redshift endpoints.
    async fn fake(seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String, String)>>>) -> String {
        use axum::extract::State;
        use axum::http::HeaderMap;
        use axum::routing::post;
        type Seen = std::sync::Arc<std::sync::Mutex<Vec<(String, String, String)>>>;
        async fn handle(State(seen): State<Seen>, headers: HeaderMap, body: String) -> String {
            let auth = headers["authorization"]
                .to_str()
                .unwrap_or_default()
                .to_owned();
            let target = headers
                .get("x-amz-target")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            seen.lock()
                .expect("lock")
                .push((auth, target.clone(), body));
            if target.is_empty() {
                "<GetClusterCredentialsResponse><GetClusterCredentialsResult><DbUser>IAM:limen_ro</DbUser><DbPassword>pw&amp;1</DbPassword></GetClusterCredentialsResult></GetClusterCredentialsResponse>".into()
            } else {
                r#"{"dbUser":"IAMR:limen_ro","dbPassword":"pw2"}"#.into()
            }
        }
        let app = axum::Router::new()
            .route("/", post(handle))
            .with_state(seen);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn redshift_credentials_are_requested_signed_and_parsed() {
        let seen = std::sync::Arc::default();
        let base = fake(std::sync::Arc::clone(&seen)).await;
        let endpoints = Endpoints {
            redshift: Some(base.clone()),
            serverless: Some(base),
        };
        let p = redshift_login(
            &endpoints,
            &creds(),
            "eu-west-1",
            RedshiftKind::Provisioned {
                cluster_identifier: "warehouse",
            },
            "limen_ro",
            "dev",
            at(),
        )
        .await
        .expect("provisioned");
        assert_eq!(
            (p.user.as_str(), p.password.expose().as_str()),
            ("IAM:limen_ro", "pw&1")
        );
        let s = redshift_login(
            &endpoints,
            &creds(),
            "eu-west-1",
            RedshiftKind::Serverless { workgroup: "wg" },
            "limen_ro",
            "dev",
            at(),
        )
        .await
        .expect("serverless");
        assert_eq!(
            (s.user.as_str(), s.password.expose().as_str()),
            ("IAMR:limen_ro", "pw2")
        );

        let seen = seen.lock().expect("lock");
        assert!(
            seen[0]
                .0
                .contains("Credential=AKIDEXAMPLE/20261017/eu-west-1/redshift/aws4_request"),
            "{:?}",
            seen[0]
        );
        assert!(
            seen[0]
                .0
                .contains("SignedHeaders=content-type;host;x-amz-date")
        );
        assert!(
            seen[0].2.contains("Action=GetClusterCredentials")
                && seen[0].2.contains("ClusterIdentifier=warehouse")
                && seen[0].2.contains("AutoCreate=false")
        );
        assert_eq!(seen[1].1, "RedshiftServerless.GetCredentials");
        assert!(
            seen[1].0.contains("/redshift-serverless/aws4_request")
                && seen[1].0.contains("x-amz-target")
        );
        assert!(seen[1].2.contains("\"workgroupName\":\"wg\""));
    }
}

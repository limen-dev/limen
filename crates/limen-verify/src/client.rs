/// Build an S3 client, honoring an endpoint override and path-style addressing.
pub async fn s3_client(endpoint: Option<&str>, path_style: bool) -> aws_sdk_s3::Client {
    let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let mut builder = aws_sdk_s3::config::Builder::from(&shared).force_path_style(path_style);
    if let Some(endpoint) = endpoint {
        builder = builder.endpoint_url(endpoint);
    }
    aws_sdk_s3::Client::from_conf(builder.build())
}

/// Read-only access to the audit bucket, as Limen hands it out.
#[derive(Clone)]
pub struct Access {
    pub endpoint: Option<String>,
    pub path_style: bool,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    /// Unix seconds; `None` for a key that does not expire.
    pub expires_unix: Option<u64>,
}

// Credentials never reach a log or a panic message through `{:?}`.
impl std::fmt::Debug for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Access")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &"<redacted>")
            .field("session_token", &"<redacted>")
            .field("expires_unix", &self.expires_unix)
            .finish_non_exhaustive()
    }
}

/// An S3 client that uses only `access`. It never reads the caller's own AWS
/// credentials, so a verification can't quietly use a different identity.
#[must_use]
pub fn s3_client_with(access: &Access) -> aws_sdk_s3::Client {
    use aws_sdk_s3::config::{BehaviorVersion, Builder, Credentials, Region};
    let expires = access
        .expires_unix
        .map(|s| std::time::UNIX_EPOCH + std::time::Duration::from_secs(s));
    let creds = Credentials::new(
        &access.access_key_id,
        &access.secret_access_key,
        access.session_token.clone(),
        expires,
        "limen",
    );
    let mut builder = Builder::new()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(access.region.clone()))
        .credentials_provider(creds)
        .force_path_style(access.path_style);
    if let Some(endpoint) = &access.endpoint {
        builder = builder.endpoint_url(endpoint);
    }
    aws_sdk_s3::Client::from_conf(builder.build())
}

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

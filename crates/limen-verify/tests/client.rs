//! `s3_client_with` against a real S3-compatible store. Set
//! `LIMEN_TEST_S3_ENDPOINT` (the dev stack's `SeaweedFS`) to run it.

#[tokio::test]
async fn a_client_built_from_lent_access_can_talk_to_s3() {
    let Ok(endpoint) = std::env::var("LIMEN_TEST_S3_ENDPOINT") else {
        return;
    };
    let client = limen_verify::s3_client_with(&limen_verify::Access {
        endpoint: Some(endpoint),
        path_style: true,
        region: "us-east-1".into(),
        access_key_id: "dev".into(),
        secret_access_key: "dev-only-secret".into(),
        session_token: None,
        expires_unix: None,
    });
    client.list_buckets().send().await.expect("list buckets");
}

#[test]
fn debug_never_shows_credentials() {
    let access = limen_verify::Access {
        endpoint: None,
        path_style: false,
        region: "r".into(),
        access_key_id: "AKIA-SHOULD-NOT-SHOW".into(),
        secret_access_key: "SECRET-SHOULD-NOT-SHOW".into(),
        session_token: Some("TOKEN-SHOULD-NOT-SHOW".into()),
        expires_unix: None,
    };
    let shown = format!("{access:?}");
    assert!(!shown.contains("SHOULD-NOT-SHOW"), "{shown}");
}

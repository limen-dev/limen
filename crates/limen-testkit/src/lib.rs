//! Shared test fixtures: temporary directories, a mock OIDC provider, and
//! access to the test database.

pub mod fake_aws;
pub mod fake_datadog;
pub mod idp;
pub mod kube_api;
pub mod ssh_target;
pub mod toggle_proxy;
pub mod users;

/// A temporary directory that is removed on drop, for spool and state tests.
pub fn temp_dir() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new().prefix("limen-test-").tempdir()
}

/// PostgreSQL URL for integration tests, from `LIMEN_TEST_DATABASE_URL`.
///
/// Tests that need a database call this and return early when it's unset,
/// printing why. CI sets it, so the tests always run there. Locally, start
/// the dev database with `docker compose -f deploy/compose/docker-compose.yml up -d postgres`.
#[must_use]
pub fn database_url() -> Option<String> {
    env_or_skip("LIMEN_TEST_DATABASE_URL")
}

/// S3-compatible endpoint for integration tests, from `LIMEN_TEST_S3_ENDPOINT`
/// (`SeaweedFS` in the dev stack: `http://localhost:8333`).
#[must_use]
pub fn s3_endpoint() -> Option<String> {
    env_or_skip("LIMEN_TEST_S3_ENDPOINT")
}

fn env_or_skip(name: &str) -> Option<String> {
    let value = std::env::var(name).ok();
    if value.is_none() {
        eprintln!("SKIPPED: {name} is not set");
    }
    value
}

#[cfg(test)]
mod tests {
    #[test]
    fn temp_dir_exists_until_dropped() {
        let dir = super::temp_dir().expect("tempdir");
        let path = dir.path().to_owned();
        assert!(path.is_dir());
        drop(dir);
        assert!(!path.exists());
    }
}

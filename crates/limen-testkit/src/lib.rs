//! Shared test fixtures: temporary directories, a mock OIDC provider, and
//! access to the test database.

pub mod idp;
pub mod ssh_target;

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
    let url = std::env::var("LIMEN_TEST_DATABASE_URL").ok();
    if url.is_none() {
        eprintln!("SKIPPED: LIMEN_TEST_DATABASE_URL is not set");
    }
    url
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

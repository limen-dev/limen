//! Shared test fixtures. Grows as integration tests are added in Phase 1.

/// A temporary directory that is removed on drop, for spool and state tests.
pub fn temp_dir() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new().prefix("limen-test-").tempdir()
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

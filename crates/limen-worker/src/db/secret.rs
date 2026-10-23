//! Secret mode (ADR-0033 section 3): a database role's password comes from a
//! file on the worker, read when a session starts and never logged.

use limen_core::secret::Secret;

/// The password of `role`, from `<dir>/<role>`. The role name is checked so
/// it can't climb out of `dir`.
pub async fn role_password(dir: &str, role: &str) -> Result<Secret<String>, String> {
    if !limen_policy::valid_db_role(role) {
        return Err(format!("{role:?} is not a limen_* role"));
    }
    read(&format!("{}/{role}", dir.trim_end_matches('/'))).await
}

/// A password file, minus its trailing newline.
pub async fn read(path: &str) -> Result<Secret<String>, String> {
    let raw = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| format!("reading the password file {path}: {e}"))?;
    let password = raw.trim_end_matches(['\n', '\r']).to_owned();
    if password.is_empty() {
        return Err(format!("the password file {path} is empty"));
    }
    Ok(Secret::new(password))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_the_role_file_and_trims_the_newline() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("limen_read"), "s3cret\n").expect("write");
        let dir_str = dir.path().to_str().expect("utf8");
        let pw = role_password(dir_str, "limen_read").await.expect("pw");
        assert_eq!(pw.expose(), "s3cret");
        assert_eq!(format!("{pw:?}"), "[REDACTED]");
    }

    #[tokio::test]
    async fn refuses_other_names_and_empty_files() {
        let dir = tempfile::tempdir().expect("dir");
        let dir_str = dir.path().to_str().expect("utf8");
        assert!(role_password(dir_str, "../etc/passwd").await.is_err());
        assert!(role_password(dir_str, "postgres").await.is_err());
        std::fs::write(dir.path().join("limen_x"), "\n").expect("write");
        assert!(role_password(dir_str, "limen_x").await.is_err());
        assert!(role_password(dir_str, "limen_missing").await.is_err());
    }
}

//! Local credentials, one profile per proxy, under `$LIMEN_HOME` (default `~/.limen`).
//!
//! The private key never leaves this machine and is written with mode 0600.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use limen_core::secret::Secret;
use limen_tunnel::tls::Identity;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMeta {
    pub proxy: String,
    pub username: String,
    pub roles: Vec<String>,
    pub login_id: String,
    pub expires_at_unix: i64,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub meta: ProfileMeta,
    pub key_pem: Secret<String>,
    pub cert_pem: String,
}

/// `$LIMEN_HOME`, else `~/.limen`.
pub fn home() -> anyhow::Result<PathBuf> {
    if let Some(dir) = std::env::var_os("LIMEN_HOME") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME").context("HOME is not set; set LIMEN_HOME")?;
    Ok(PathBuf::from(home).join(".limen"))
}

/// Directory for a proxy's profile. `host:port` with the colon replaced.
pub fn dir_for(proxy: &str) -> anyhow::Result<PathBuf> {
    let safe: String = proxy
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // `.` and `..` survive the filter but name directories, not profiles.
    let safe = if safe.is_empty() || safe.chars().all(|c| c == '.') {
        "_".repeat(safe.len().max(1))
    } else {
        safe
    };
    Ok(home()?.join("profiles").join(safe))
}

/// The proxy of the profile used last.
pub fn current_proxy() -> anyhow::Result<Option<String>> {
    match std::fs::read_to_string(home()?.join("current")) {
        Ok(s) => Ok(Some(s.trim().to_owned()).filter(|s| !s.is_empty())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn set_current(proxy: &str) -> anyhow::Result<()> {
    write_file(&home()?.join("current"), proxy, false)
}

/// CA certificate this machine trusts for `proxy`, if one was pinned.
pub fn trusted_ca(proxy: &str) -> anyhow::Result<Option<String>> {
    match std::fs::read_to_string(dir_for(proxy)?.join("proxy-ca.pem")) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn pin_ca(proxy: &str, pem: &str) -> anyhow::Result<()> {
    write_file(&dir_for(proxy)?.join("proxy-ca.pem"), pem, false)
}

/// Forget the CA pinned for `proxy`, so its certificate is checked against the system trust
/// store again. True if there was one. Logout keeps the pin; this is the only way to drop it.
pub fn unpin_ca(proxy: &str) -> anyhow::Result<bool> {
    remove_if_present(&dir_for(proxy)?.join("proxy-ca.pem"))
}

fn remove_if_present(path: &Path) -> anyhow::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

impl Profile {
    pub fn save(
        dir: &Path,
        meta: &ProfileMeta,
        key_pem: &str,
        cert_pem: &str,
    ) -> anyhow::Result<()> {
        write_file(&dir.join("key.pem"), key_pem, true)?;
        write_file(&dir.join("cert.pem"), cert_pem, false)?;
        write_file(
            &dir.join("profile.json"),
            &serde_json::to_string_pretty(meta)?,
            false,
        )
    }

    /// Load the profile for `proxy`. `Ok(None)` if not logged in there.
    pub fn load(proxy: &str) -> anyhow::Result<Option<Self>> {
        let dir = dir_for(proxy)?;
        let meta_path = dir.join("profile.json");
        if !meta_path.exists() {
            return Ok(None);
        }
        let meta: ProfileMeta = serde_json::from_str(&std::fs::read_to_string(&meta_path)?)?;
        Ok(Some(Self {
            key_pem: Secret::new(std::fs::read_to_string(dir.join("key.pem"))?),
            cert_pem: std::fs::read_to_string(dir.join("cert.pem"))?,
            meta,
        }))
    }

    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.meta.expires_at_unix)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at() <= OffsetDateTime::now_utc()
    }

    /// The TLS client identity, refusing expired credentials.
    pub fn identity(&self) -> anyhow::Result<Identity> {
        if self.is_expired() {
            bail!(
                "your credentials for {} expired at {}; run `limen login`",
                self.meta.proxy,
                self.expires_at()
            );
        }
        Ok(Identity::from_pem(&self.cert_pem, self.key_pem.expose())?)
    }

    /// Delete key and certificate. The pinned CA is kept.
    pub fn delete(proxy: &str) -> anyhow::Result<bool> {
        let dir = dir_for(proxy)?;
        let mut removed = false;
        for name in ["key.pem", "cert.pem", "profile.json"] {
            match std::fs::remove_file(dir.join(name)) {
                Ok(()) => removed = true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(removed)
    }
}

/// Write `contents` atomically, mode 0600 if `private` else 0644, in a 0700 directory.
pub fn write_file(path: &Path, contents: &str, private: bool) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    atomic_write(
        path,
        contents.as_bytes(),
        if private { 0o600 } else { 0o644 },
    )?;
    Ok(())
}

/// Replace `path` with `contents` through a temporary sibling, so a reader
/// never sees half a file and nobody can read the contents with more access
/// than `mode` gives (ignored off Unix). The temporary file is created
/// fresh with that mode: `OpenOptions::mode` does not apply to a file that
/// already exists, so a leftover from a crash would keep its old, maybe
/// wider, permissions.
pub(crate) fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    let mut name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("path has no file name"))?
        .to_os_string();
    // Appended, not `with_extension`, which would make `a.pem` and `a.key` share one.
    name.push(".limen-tmp");
    let tmp = path.with_file_name(name);
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let written = (|| {
        let mut file = options.open(&tmp)?;
        #[cfg(unix)]
        {
            // The umask may have taken bits away; ask for exactly `mode`.
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    #[test]
    fn a_private_file_is_never_wider_than_0600_even_over_a_stale_temp_file() {
        let dir = tempfile::tempdir().expect("dir");
        let key = dir.path().join("key.pem");
        // A leftover from a crashed write, world-readable.
        let stale = dir.path().join("key.pem.limen-tmp");
        std::fs::write(&stale, "old").expect("stale");
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        write_file(&key, "secret", true).expect("write");
        assert_eq!(mode(&key), 0o600);
        assert_eq!(std::fs::read_to_string(&key).expect("read"), "secret");
        assert!(!stale.exists(), "no temp file is left behind");
    }

    #[test]
    fn files_with_the_same_stem_do_not_share_a_temp_file() {
        let dir = tempfile::tempdir().expect("dir");
        write_file(&dir.path().join("a.pem"), "public", false).expect("pem");
        write_file(&dir.path().join("a.key"), "private", true).expect("key");
        assert_eq!(mode(&dir.path().join("a.pem")), 0o644);
        assert_eq!(mode(&dir.path().join("a.key")), 0o600);
    }

    #[test]
    fn replacing_keeps_the_mode_asked_for() {
        let dir = tempfile::tempdir().expect("dir");
        let file = dir.path().join("config");
        atomic_write(&file, b"one", 0o640).expect("first");
        atomic_write(&file, b"two", 0o640).expect("second");
        assert_eq!(std::fs::read_to_string(&file).expect("read"), "two");
        assert_eq!(mode(&file), 0o640);
    }
}

#[cfg(test)]
mod dir_for_tests {
    use super::{dir_for, remove_if_present};

    #[test]
    fn forgetting_a_pin_that_is_not_there_is_not_an_error() {
        let dir = tempfile::tempdir().expect("dir");
        let pin = dir.path().join("proxy-ca.pem");
        assert!(!remove_if_present(&pin).expect("absent"));
        std::fs::write(&pin, "pem").expect("write");
        assert!(remove_if_present(&pin).expect("present"));
        assert!(!pin.exists());
    }

    #[test]
    fn dir_for_never_names_a_parent_directory() {
        for proxy in ["..", ".", "...", ""] {
            let dir = dir_for(proxy).expect("dir");
            assert!(
                dir.file_name()
                    .is_some_and(|n| n.to_string_lossy().chars().all(|c| c == '_')),
                "{proxy:?} -> {}",
                dir.display()
            );
        }
        assert!(
            dir_for("proxy.example.com:8443")
                .expect("dir")
                .ends_with("proxy.example.com_8443")
        );
    }
}

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

fn write_file(path: &Path, contents: &str, private: bool) -> anyhow::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let tmp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options.open(&tmp)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

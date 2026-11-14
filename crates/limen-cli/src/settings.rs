//! Preferences for how the CLI looks and moves, in `$LIMEN_HOME/settings.json`
//! (default `~/.limen`). Changed with `limen config animations`. Nothing secret
//! lives here, and an unreadable file never stops a command: the defaults apply.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::Context as _;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// How fast the logo and spinner move.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Speed {
    /// About 1.8 s for the logo.
    Slow,
    /// About 1 s for the logo.
    #[default]
    Normal,
    /// About 0.4 s for the logo.
    Fast,
}

impl Speed {
    /// Time between columns of the logo wipe.
    pub fn banner_step_ms(self) -> u64 {
        match self {
            Self::Slow => 50,
            Self::Normal => 28,
            Self::Fast => 12,
        }
    }

    /// Time between lines when a table or a list is revealed.
    pub fn reveal_ms(self) -> u64 {
        match self {
            Self::Slow => 40,
            Self::Normal => 22,
            Self::Fast => 10,
        }
    }

    /// Time between one `doctor` check and the next.
    pub fn pace_ms(self) -> u64 {
        match self {
            Self::Slow => 90,
            Self::Normal => 50,
            Self::Fast => 20,
        }
    }

    /// Time between spinner frames, in whole tens of milliseconds.
    pub fn frame_tens(self) -> u32 {
        match self {
            Self::Slow => 11,
            Self::Normal => 8,
            Self::Fast => 5,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Slow => "slow",
            Self::Normal => "normal",
            Self::Fast => "fast",
        }
    }
}

/// On or off, for flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Switch {
    On,
    Off,
}

impl Switch {
    pub fn is_on(self) -> bool {
        self == Self::On
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Spinners, the logo wipe and streamed output. Off prints plain lines.
    pub animations: bool,
    pub speed: Speed,
    /// The logo at the top of `limen`, `limen --help` and `limen login`.
    pub logo: bool,
    /// A spinner while a call to the proxy is slow.
    pub call_spinner: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            animations: true,
            speed: Speed::Normal,
            logo: true,
            call_spinner: true,
        }
    }
}

/// Where the settings live.
pub fn path() -> anyhow::Result<PathBuf> {
    Ok(crate::profile::home()?.join("settings.json"))
}

/// The settings file, or the defaults when it does not exist. An invalid file is an error here,
/// so `limen config animations` can say so instead of overwriting it.
pub fn load_from(path: &Path) -> anyhow::Result<Settings> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("{} is not valid settings JSON", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Write the settings, replacing the file in one step.
pub fn save_to(path: &Path, settings: &Settings) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    let mut text = serde_json::to_string_pretty(settings)?;
    text.push('\n');
    std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

/// The settings for this run. Read once; a missing or unreadable file means the defaults, with a
/// warning in the unreadable case, because a preference must never break a command.
pub fn get() -> &'static Settings {
    static SETTINGS: OnceLock<Settings> = OnceLock::new();
    SETTINGS.get_or_init(|| {
        let loaded = path().and_then(|p| load_from(&p));
        loaded.unwrap_or_else(|e| {
            crate::ui::warn(&format!("ignoring the CLI settings: {e:#}"));
            Settings::default()
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_is_the_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = load_from(&dir.path().join("settings.json")).expect("loads");
        assert_eq!(s, Settings::default());
        assert!(s.animations && s.logo && s.call_spinner);
        assert_eq!(s.speed, Speed::Normal);
    }

    #[test]
    fn settings_round_trip_and_unset_fields_keep_their_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("nested").join("settings.json");
        let changed = Settings {
            animations: false,
            speed: Speed::Slow,
            ..Settings::default()
        };
        save_to(&file, &changed).expect("saves");
        assert_eq!(load_from(&file).expect("loads"), changed);
        // A file with only one field set leaves the others at their defaults.
        std::fs::write(&file, r#"{"speed":"fast"}"#).expect("write");
        let partial = load_from(&file).expect("loads");
        assert_eq!(partial.speed, Speed::Fast);
        assert!(partial.animations && partial.logo && partial.call_spinner);
    }

    #[test]
    fn an_invalid_file_is_an_error_not_a_silent_reset() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("settings.json");
        std::fs::write(&file, "{ not json").expect("write");
        let err = load_from(&file).expect_err("invalid");
        assert!(format!("{err:#}").contains("not valid settings JSON"));
        std::fs::write(&file, r#"{"speed":"warp"}"#).expect("write");
        assert!(load_from(&file).is_err(), "an unknown speed is refused");
    }

    #[test]
    fn slower_means_longer() {
        assert!(Speed::Slow.banner_step_ms() > Speed::Normal.banner_step_ms());
        assert!(Speed::Normal.banner_step_ms() > Speed::Fast.banner_step_ms());
        assert!(Speed::Slow.frame_tens() > Speed::Fast.frame_tens());
    }
}

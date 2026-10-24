//! Detached connections: `limen <type> connect <resource> --detach`, `limen conns ls|stop`.
//!
//! `--detach` re-runs the same command as a background process (its own process
//! group, output to a log file), waits until it has printed its address, shows
//! that, and returns. Each detached connection has a small state file under
//! `$LIMEN_HOME/conns/`. A connection ends when its certificate expires, on
//! `limen logout`, on `limen conns stop`, or when it idles out like a foreground one.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};

use crate::profile::{self, Profile};
use crate::{api, ui};

/// Set in the environment of a detached process; its value is the connection id.
pub const ENV_ID: &str = "LIMEN_DETACHED_ID";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conn {
    pub id: String,
    pub pid: u32,
    pub proxy: String,
    /// The command line, without the program name and `--detach`.
    pub command: Vec<String>,
    pub log: PathBuf,
    pub started_unix: i64,
    pub expires_at_unix: i64,
}

fn dir() -> anyhow::Result<PathBuf> {
    Ok(profile::home()?.join("conns"))
}

fn state_path(id: &str) -> anyhow::Result<PathBuf> {
    anyhow::ensure!(
        valid_id(id),
        "`{id}` is not a connection id; see `limen conns ls`"
    );
    Ok(dir()?.join(format!("{id}.json")))
}

#[cfg(unix)]
fn signal(pid: u32, sig: &str) -> bool {
    std::process::Command::new("kill")
        .args([sig, &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Whether `pid` is a live `limen` process. A bare liveness check isn't enough: after a
/// reboot or a crash the pid may belong to something else, which `stop` must never signal.
#[cfg(unix)]
fn alive(pid: u32) -> bool {
    if !signal(pid, "-0") {
        return false;
    }
    std::process::Command::new("ps")
        .args(["-o", "command=", "-p", &pid.to_string()])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("limen"))
}

/// Ids are the six hex digits we generate; anything else could escape the directory.
fn valid_id(id: &str) -> bool {
    id.len() == 6 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether `args` contain a flag that is `--detach` or `-d`.
fn is_detach_flag(a: &std::ffi::OsStr) -> bool {
    a == "--detach" || a == "-d"
}

/// The arguments to start the background copy with: ours without `--detach`.
fn child_args(args: impl IntoIterator<Item = std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    args.into_iter().filter(|a| !is_detach_flag(a)).collect()
}

/// Start the current command in the background and print where it listens.
#[cfg(unix)]
pub async fn detach(proxy: Option<&str>) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::process::CommandExt as _;

    let proxy = api::resolve_proxy(proxy)?;
    let profile = Profile::load(&proxy)?
        .filter(|p| !p.is_expired())
        .context("not logged in; run `limen login`")?;
    let id = format!("{:06x}", rand::random::<u32>() & 0x00ff_ffff);
    let dir = dir()?;
    std::fs::create_dir_all(&dir)?;
    let log_path = dir.join(format!("{id}.log"));
    let log = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&log_path)?;
    let args = child_args(std::env::args_os().skip(1));
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args(&args)
        .env(ENV_ID, &id)
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .process_group(0)
        .spawn()
        .context("starting the background process")?;
    // Ready once the command has printed its address and gone quiet.
    let mut last = 0;
    let mut stable = 0;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if child.try_wait()?.is_some() {
            let out = std::fs::read_to_string(&log_path).unwrap_or_default();
            let _ = std::fs::remove_file(&log_path);
            bail!("the background process exited:\n{}", out.trim_end());
        }
        let len = std::fs::metadata(&log_path).map_or(0, |m| m.len());
        stable = if len > 0 && len == last {
            stable + 1
        } else {
            0
        };
        last = len;
        if stable >= 2 {
            break;
        }
    }
    if stable < 2 {
        let _ = signal(child.id(), "-TERM");
        let _ = std::fs::remove_file(&log_path);
        bail!("the background process did not report an address in time");
    }
    let conn = Conn {
        id: id.clone(),
        pid: child.id(),
        proxy,
        command: args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect(),
        log: log_path.clone(),
        started_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
        expires_at_unix: profile.meta.expires_at_unix,
    };
    write_state(&conn)?;
    print!("{}", std::fs::read_to_string(&log_path).unwrap_or_default());
    ui::success(&format!("Running in the background as {}.", ui::bold(&id)));
    ui::hint(&format!(
        "`limen conns ls` lists connections, `limen conns stop {id}` ends this one. It also ends when your login expires or on `limen logout`."
    ));
    Ok(())
}

#[cfg(not(unix))]
pub async fn detach(_proxy: Option<&str>) -> anyhow::Result<()> {
    bail!("--detach is supported on macOS and Linux only")
}

fn write_state(conn: &Conn) -> anyhow::Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(state_path(&conn.id)?)?;
    f.write_all(serde_json::to_string_pretty(conn)?.as_bytes())?;
    Ok(())
}

/// Inside the detached process: end when the certificate expires.
pub async fn watch_expiry(id: String, proxy: Option<String>) {
    let Ok(proxy) = api::resolve_proxy(proxy.as_deref()) else {
        return;
    };
    let Ok(Some(profile)) = Profile::load(&proxy) else {
        return;
    };
    let left = profile.expires_at() - time::OffsetDateTime::now_utc();
    let secs = u64::try_from(left.whole_seconds()).unwrap_or(0);
    tokio::time::sleep(Duration::from_secs(secs)).await;
    eprintln!("limen: login expired; closing this connection.");
    forget(&id);
    std::process::exit(0);
}

/// Remove a detached connection's state and log (the process is gone or going).
pub fn forget(id: &str) {
    if !valid_id(id) {
        return;
    }
    if let Ok(d) = dir() {
        let _ = std::fs::remove_file(d.join(format!("{id}.json")));
        let _ = std::fs::remove_file(d.join(format!("{id}.log")));
    }
}

/// Live detached connections, dropping the state of any whose process is gone.
pub fn list(only_proxy: Option<&str>) -> anyhow::Result<Vec<Conn>> {
    let dir = dir()?;
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let Some(conn) = read_state(&path) else {
            continue;
        };
        #[cfg(unix)]
        if !alive(conn.pid) {
            forget(&conn.id);
            continue;
        }
        if only_proxy.is_none_or(|p| p == conn.proxy) {
            out.push(conn);
        }
    }
    out.sort_by_key(|c| c.started_unix);
    Ok(out)
}

fn read_state(path: &Path) -> Option<Conn> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// End one connection. Returns whether it existed.
pub fn stop(id: &str) -> anyhow::Result<bool> {
    let Some(conn) = read_state(&state_path(id)?) else {
        return Ok(false);
    };
    #[cfg(unix)]
    if alive(conn.pid) {
        signal(conn.pid, "-TERM");
    }
    forget(id);
    Ok(true)
}

/// End every detached connection of a proxy (used by `limen logout`). Returns how many.
pub fn stop_all(proxy: &str) -> usize {
    list(Some(proxy)).map_or(0, |conns| {
        conns
            .iter()
            .filter(|c| stop(&c.id).unwrap_or(false))
            .count()
    })
}

pub fn ls(proxy: Option<&str>, json: bool) -> anyhow::Result<()> {
    let proxy = api::resolve_proxy(proxy).ok();
    let conns = list(proxy.as_deref())?;
    if json {
        println!("{}", serde_json::to_string_pretty(&conns)?);
        return Ok(());
    }
    if conns.is_empty() {
        ui::info("No detached connections.");
        ui::hint("Start one with `limen <type> connect <resource> --detach`.");
        return Ok(());
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let rows: Vec<[String; 4]> = conns
        .iter()
        .map(|c| {
            let line = std::fs::read_to_string(&c.log)
                .ok()
                .and_then(|s| s.lines().next().map(str::to_owned))
                .unwrap_or_default();
            [
                ui::bold(&c.id),
                c.command.join(" "),
                ui::dim(&line),
                format!("{}m", ((c.expires_at_unix - now) / 60).max(0)),
            ]
        })
        .collect();
    ui::print_table(["id", "command", "output", "login left"], &rows);
    ui::hint("`limen conns stop <id>` ends one; `limen conns stop --all` ends them all.");
    Ok(())
}

pub fn stop_command(proxy: Option<&str>, ids: &[String], all: bool) -> anyhow::Result<()> {
    let targets: Vec<String> = if all {
        let proxy = api::resolve_proxy(proxy).ok();
        list(proxy.as_deref())?.into_iter().map(|c| c.id).collect()
    } else {
        ids.to_vec()
    };
    if targets.is_empty() {
        bail!("name a connection id (see `limen conns ls`) or pass --all");
    }
    for id in &targets {
        if stop(id)? {
            ui::success(&format!("Stopped {id}."));
        } else {
            bail!("no detached connection `{id}`; see `limen conns ls`");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_cannot_escape_the_directory() {
        assert!(valid_id("0a1b2c"));
        assert!(!valid_id("../x"));
        assert!(!valid_id("0a1b2c/.."));
        assert!(!valid_id(""));
        assert!(state_path("../../etc/passwd").is_err());
    }

    #[test]
    fn strips_only_the_detach_flag() {
        let args = [
            "redis", "connect", "-d", "cache", "--detach", "--listen", "x",
        ]
        .map(std::ffi::OsString::from);
        let kept: Vec<_> = child_args(args)
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(kept, ["redis", "connect", "cache", "--listen", "x"]);
    }
}

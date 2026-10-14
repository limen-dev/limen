//! Session recordings in asciicast v3 (<https://docs.asciinema.org/manual/asciicast/v3/>).
//!
//! One JSON header line, then one `[interval, code, data]` line per event,
//! where `interval` is seconds since the previous event. We record output
//! (`o`), terminal resizes (`r`), and the exit status (`x`). Input (`i`)
//! is not recorded: keystrokes include passwords typed at prompts.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::json;

#[derive(Debug)]
pub struct Recorder {
    path: PathBuf,
    file: std::io::BufWriter<std::fs::File>,
    last: Instant,
    /// Bytes of an incomplete UTF-8 sequence carried over to the next chunk.
    pending: Vec<u8>,
    bytes: u64,
}

impl Recorder {
    pub fn create(path: &Path, cols: u32, rows: u32, title: &str) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = std::io::BufWriter::new(options.open(path)?);
        let header = json!({
            "version": 3,
            "term": { "cols": cols, "rows": rows },
            "timestamp": time::OffsetDateTime::now_utc().unix_timestamp(),
            "title": title,
        });
        writeln!(file, "{header}")?;
        Ok(Self {
            path: path.to_owned(),
            file,
            last: Instant::now(),
            pending: Vec::new(),
            bytes: 0,
        })
    }

    fn event(&mut self, code: &str, data: &str) -> std::io::Result<()> {
        let now = Instant::now();
        let interval = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        // Millisecond precision, as the asciinema CLI writes.
        let line = json!([(interval * 1000.0).round() / 1000.0, code, data]);
        writeln!(self.file, "{line}")
    }

    /// Terminal output. Splits are handled: an incomplete UTF-8 sequence at
    /// the end of `data` waits for the next call.
    pub fn output(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.bytes += data.len() as u64;
        self.pending.extend_from_slice(data);
        // An incomplete sequence at the end waits for more bytes. Anything
        // else, including invalid bytes, is written (lossily) now.
        let valid_up_to = match std::str::from_utf8(&self.pending) {
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            _ => self.pending.len(),
        };
        if valid_up_to == 0 {
            return Ok(());
        }
        let chunk: Vec<u8> = self.pending.drain(..valid_up_to).collect();
        let text = String::from_utf8_lossy(&chunk).into_owned();
        self.event("o", &text)
    }

    pub fn resize(&mut self, cols: u32, rows: u32) -> std::io::Result<()> {
        self.event("r", &format!("{cols}x{rows}"))
    }

    pub fn exit(&mut self, status: u32) -> std::io::Result<()> {
        self.event("x", &status.to_string())
    }

    /// Flush and return the path, output byte count, and SHA-256 of the file.
    pub fn finish(mut self) -> std::io::Result<(PathBuf, u64, String)> {
        if !self.pending.is_empty() {
            let rest = String::from_utf8_lossy(&std::mem::take(&mut self.pending)).into_owned();
            self.event("o", &rest)?;
        }
        self.file.flush()?;
        self.file.get_ref().sync_all()?;
        let digest = sha256_file(&self.path)?;
        Ok((self.path, self.bytes, digest))
    }
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_v3_and_reassembles_split_utf8() {
        let dir = std::env::temp_dir().join(format!("limen-rec-{}", uuid::Uuid::now_v7()));
        let path = dir.join("s.cast");
        let mut rec = Recorder::create(&path, 80, 24, "test").expect("create");
        let euro = "€".as_bytes(); // 3 bytes
        rec.output(b"hello ").expect("o");
        rec.output(&euro[..2]).expect("partial"); // incomplete: nothing written yet
        rec.output(&euro[2..]).expect("rest");
        rec.resize(100, 30).expect("r");
        rec.exit(0).expect("x");
        let (path, bytes, digest) = rec.finish().expect("finish");
        assert_eq!(bytes, 9);
        assert_eq!(digest.len(), 64);
        let text = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).expect("json"))
            .collect();
        assert_eq!(lines[0]["version"], 3);
        assert_eq!(lines[0]["term"]["cols"], 80);
        let events: Vec<(String, String)> = lines[1..]
            .iter()
            .map(|e| {
                (
                    e[1].as_str().unwrap_or_default().to_owned(),
                    e[2].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            events,
            [
                ("o".into(), "hello ".into()),
                ("o".into(), "€".into()),
                ("r".into(), "100x30".into()),
                ("x".into(), "0".into())
            ]
        );
        assert!(
            Recorder::create(&path, 80, 24, "again").is_err(),
            "never overwrites a recording"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

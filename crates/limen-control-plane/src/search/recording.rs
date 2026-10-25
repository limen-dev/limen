//! Text out of a session recording (ADR-0026), only when the operator turns
//! `--search-recordings` on, because a terminal echoes whatever is on screen,
//! passwords included. Output only (`o` events), never input; control
//! sequences dropped; secret shapes masked; the amount per session capped.
//! The recording itself is never changed.

use serde_json::Value;

use super::mask;

/// The most text kept for one session.
pub const MAX_SESSION_TEXT: usize = 256 * 1024;
/// A chunk is cut when it passes this, so a hit lands near its moment.
const CHUNK: usize = 1800;

#[derive(Debug, Clone, PartialEq)]
pub struct Chunk {
    /// Seconds from the start of the recording.
    pub t: f64,
    pub text: String,
}

#[derive(Debug, Default, PartialEq)]
pub struct Extracted {
    pub chunks: Vec<Chunk>,
    pub bytes: usize,
    /// More output than the cap.
    pub truncated: bool,
}

/// Rebuilds what the terminal showed, one line at a time: carriage returns
/// and backspaces edit the line, escape sequences vanish.
#[derive(Default)]
struct Screen {
    line: Vec<char>,
    cursor: usize,
    escape: Esc,
    /// Time of the event that began the line.
    line_t: Option<f64>,
}

#[derive(Default, Clone, Copy, PartialEq)]
enum Esc {
    #[default]
    None,
    Start,
    Csi,
    Osc,
    /// An escape inside an OSC string, which ends it.
    OscEscape,
    Other,
}

impl Screen {
    fn feed(&mut self, c: char, t: f64, out: &mut Vec<(f64, String)>) {
        match self.escape {
            Esc::Start => {
                self.escape = match c {
                    '[' => Esc::Csi,
                    ']' => Esc::Osc,
                    '(' | ')' | '#' | '%' => Esc::Other,
                    _ => Esc::None,
                };
                return;
            }
            // A CSI sequence ends at a byte from 0x40 to 0x7e.
            Esc::Csi => {
                if ('\u{40}'..='\u{7e}').contains(&c) {
                    self.escape = Esc::None;
                }
                return;
            }
            // An OSC string ends at BEL or ESC \.
            Esc::Osc => {
                self.escape = match c {
                    '\u{7}' => Esc::None,
                    '\u{1b}' => Esc::OscEscape,
                    _ => Esc::Osc,
                };
                return;
            }
            Esc::OscEscape | Esc::Other => {
                self.escape = Esc::None;
                return;
            }
            Esc::None => {}
        }
        match c {
            '\u{1b}' => self.escape = Esc::Start,
            '\n' => {
                self.flush(out);
            }
            '\r' => self.cursor = 0,
            '\u{8}' | '\u{7f}' => self.cursor = self.cursor.saturating_sub(1),
            '\t' => self.put(' ', t),
            c if c.is_control() => {}
            c => self.put(c, t),
        }
    }

    fn put(&mut self, c: char, t: f64) {
        self.line_t.get_or_insert(t);
        if self.cursor < self.line.len() {
            self.line[self.cursor] = c;
        } else {
            self.line.push(c);
        }
        self.cursor += 1;
    }

    fn flush(&mut self, out: &mut Vec<(f64, String)>) {
        let text: String = self.line.iter().collect();
        let text = text.trim_end();
        if !text.is_empty() {
            out.push((self.line_t.unwrap_or(0.0), text.to_owned()));
        }
        self.line.clear();
        self.cursor = 0;
        self.line_t = None;
    }
}

/// Text out of an asciicast v3 (or v2) recording. Never fails on a bad line:
/// whatever can be read is kept.
#[must_use]
pub fn extract(cast: &[u8]) -> Extracted {
    let text = String::from_utf8_lossy(cast);
    let mut lines = text.lines();
    let Some(header) = lines
        .next()
        .and_then(|l| serde_json::from_str::<Value>(l).ok())
    else {
        return Extracted::default();
    };
    // v3 events carry the time since the previous one; v2, since the start.
    let relative = header.get("version").and_then(Value::as_u64) == Some(3);
    let mut screen = Screen::default();
    let mut finished: Vec<(f64, String)> = Vec::new();
    let mut now = 0.0f64;
    for line in lines {
        let Ok(Value::Array(ev)) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let (Some(dt), Some("o"), Some(data)) = (
            ev.first().and_then(Value::as_f64),
            ev.get(1).and_then(Value::as_str),
            ev.get(2).and_then(Value::as_str),
        ) else {
            continue;
        };
        now = if relative { now + dt } else { dt };
        for c in data.chars() {
            screen.feed(c, now, &mut finished);
        }
    }
    screen.flush(&mut finished);

    let mut out = Extracted::default();
    let mut current: Option<Chunk> = None;
    for (t, line) in finished {
        let line = mask::mask(&line);
        if out.bytes + line.len() + 1 > MAX_SESSION_TEXT {
            out.truncated = true;
            break;
        }
        out.bytes += line.len() + 1;
        let chunk = current.get_or_insert_with(|| Chunk {
            t,
            text: String::new(),
        });
        if !chunk.text.is_empty() {
            chunk.text.push('\n');
        }
        chunk.text.push_str(&line);
        if chunk.text.len() >= CHUNK
            && let Some(done) = current.take()
        {
            out.chunks.push(done);
        }
    }
    out.chunks.extend(current);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cast(events: &[(&str, f64, &str)]) -> Vec<u8> {
        let mut s = String::from("{\"version\":3,\"term\":{\"cols\":80,\"rows\":24}}\n");
        for (code, dt, data) in events {
            s.push_str(&serde_json::to_string(&serde_json::json!([dt, code, data])).expect("json"));
            s.push('\n');
        }
        s.into_bytes()
    }

    #[test]
    fn lines_come_out_as_the_terminal_showed_them() {
        let c = cast(&[
            ("o", 0.1, "\u{1b}[32mubuntu@web\u{1b}[0m:~$ "),
            ("o", 0.5, "ls -l"),
            ("o", 0.2, "\r\n"),
            (
                "o",
                0.3,
                "total 4\r\ndrwxr-xr-x 2 ubuntu ubuntu 4096 backup\r\n",
            ),
        ]);
        let got = extract(&c);
        assert_eq!(got.chunks.len(), 1);
        assert_eq!(
            got.chunks[0].text,
            "ubuntu@web:~$ ls -l\ntotal 4\ndrwxr-xr-x 2 ubuntu ubuntu 4096 backup"
        );
        assert!(
            (got.chunks[0].t - 0.1).abs() < 1e-9,
            "the chunk starts at its first line"
        );
        assert!(!got.truncated);
    }

    #[test]
    fn backspaces_and_carriage_returns_edit_the_line() {
        let c = cast(&[
            ("o", 0.0, "$ lss\u{8} -a\r\n"),
            ("o", 0.1, "progress 10%\rprogress 99%\r\n"),
        ]);
        let got = extract(&c);
        assert_eq!(got.chunks[0].text, "$ ls -a\nprogress 99%");
    }

    #[test]
    fn input_is_never_read() {
        let c = cast(&[
            ("i", 0.1, "hunter2\r"),
            ("o", 0.1, "Password: \r\n"),
            ("r", 0.1, "80x24"),
        ]);
        let got = extract(&c);
        assert_eq!(got.chunks[0].text, "Password:");
        assert!(!got.chunks[0].text.contains("hunter2"));
    }

    #[test]
    fn secrets_on_screen_are_masked() {
        let c = cast(&[(
            "o",
            0.0,
            "export AWS_KEY=AKIAIOSFODNN7EXAMPLE\r\nDB_PASSWORD=swordfish\r\n",
        )]);
        let text = &extract(&c).chunks[0].text;
        assert!(
            !text.contains("IOSFODNN7EXAMPLE") && !text.contains("swordfish"),
            "{text}"
        );
    }

    #[test]
    fn a_long_session_is_cut_into_timed_chunks_and_capped() {
        let mut events = Vec::new();
        let line = format!("{}\r\n", "x".repeat(99));
        let line: &'static str = Box::leak(line.into_boxed_str());
        for _ in 0..4000 {
            events.push(("o", 0.01, line));
        }
        let got = extract(&cast(&events));
        assert!(got.truncated, "400 KB of output exceeds the cap");
        assert!(got.bytes <= MAX_SESSION_TEXT);
        assert!(got.chunks.len() > 100);
        assert!(
            got.chunks.windows(2).all(|w| w[0].t < w[1].t),
            "chunks keep their order in time"
        );
    }

    #[test]
    fn garbage_gives_nothing_instead_of_failing() {
        assert_eq!(extract(b""), Extracted::default());
        assert_eq!(extract(b"not json\n[1,2"), Extracted::default());
        let got = extract(b"{\"version\":2}\n[1.5,\"o\",\"hi\\r\\n\"]\nnot json\n[\"x\"]\n");
        assert_eq!(got.chunks[0].text, "hi");
        assert!(
            (got.chunks[0].t - 1.5).abs() < 1e-9,
            "v2 times are from the start"
        );
    }
}

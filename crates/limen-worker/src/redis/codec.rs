//! A RESP2 and RESP3 codec, written for a proxy (ADR-0012, ADR-0034).
//!
//! The worker never needs to build most values. It needs to know where one
//! frame ends (so it can forward bytes untouched and keep replies in order),
//! to read a client command, and to read the one reply it asks for itself
//! (`COMMAND INFO`). So the codec is a resumable frame scanner plus a small
//! value parser, not a general client library.

use std::fmt;

/// Longest line (a header, a simple string, or an inline command).
const MAX_LINE: usize = 64 * 1024;
/// Deepest aggregate nesting accepted.
const MAX_DEPTH: usize = 64;
/// Largest single bulk string. Redis' own default limit is 512 MiB.
pub const MAX_BULK: u64 = 512 * 1024 * 1024;
/// Most elements in one aggregate.
const MAX_ELEMENTS: i64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The bytes aren't RESP.
    Protocol(&'static str),
    /// A frame, line, or aggregate is bigger than we accept.
    TooLarge(&'static str),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(m) => write!(f, "protocol error: {m}"),
            Self::TooLarge(m) => write!(f, "too large: {m}"),
        }
    }
}

impl std::error::Error for CodecError {}

/// Finds where the first RESP frame in a growing buffer ends, without
/// copying or re-reading what it has already seen.
#[derive(Debug, Default)]
pub struct FrameScanner {
    pos: usize,
    /// How many values each open aggregate still has to read. The bottom
    /// entry is the frame itself.
    stack: Vec<u64>,
    started: bool,
}

impl FrameScanner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `buf` (which only ever grows between calls). `Ok(Some(n))` means
    /// the first `n` bytes are one complete frame.
    pub fn advance(&mut self, buf: &[u8]) -> Result<Option<usize>, CodecError> {
        if !self.started {
            self.started = true;
            self.stack.push(1);
        }
        loop {
            while self.stack.last() == Some(&0) {
                self.stack.pop();
            }
            if self.stack.is_empty() {
                return Ok(Some(self.pos));
            }
            let rest = &buf[self.pos..];
            let Some(&kind) = rest.first() else {
                return Ok(None);
            };
            let Some(line_end) = find_crlf(rest) else {
                if rest.len() > MAX_LINE {
                    return Err(CodecError::TooLarge("line"));
                }
                return Ok(None);
            };
            if line_end > MAX_LINE {
                return Err(CodecError::TooLarge("line"));
            }
            let header = &rest[1..line_end];
            let after_line = line_end + 2;
            let consumed = match kind {
                b'+' | b'-' | b':' | b',' | b'#' | b'_' | b'(' => after_line,
                b'$' | b'!' | b'=' => match parse_len(header)? {
                    None => after_line,
                    Some(n) => {
                        let n = u64::try_from(n).map_err(|_| CodecError::Protocol("length"))?;
                        if n > MAX_BULK {
                            return Err(CodecError::TooLarge("bulk string"));
                        }
                        let total = after_line as u64 + n + 2;
                        if (rest.len() as u64) < total {
                            return Ok(None);
                        }
                        let total = usize::try_from(total)
                            .map_err(|_| CodecError::TooLarge("bulk string"))?;
                        if &rest[total - 2..total] != b"\r\n" {
                            return Err(CodecError::Protocol("bulk string not terminated"));
                        }
                        total
                    }
                },
                b'*' | b'~' | b'>' | b'%' | b'|' => {
                    let count = parse_len(header)?;
                    self.take_one();
                    if let Some(n) = count {
                        if n > MAX_ELEMENTS {
                            return Err(CodecError::TooLarge("aggregate"));
                        }
                        let n = u64::try_from(n).map_err(|_| CodecError::Protocol("length"))?;
                        let children = if matches!(kind, b'%' | b'|') {
                            n * 2
                        } else {
                            n
                        };
                        if self.stack.len() >= MAX_DEPTH {
                            return Err(CodecError::TooLarge("nesting"));
                        }
                        self.stack.push(children);
                    }
                    self.pos += after_line;
                    continue;
                }
                _ => return Err(CodecError::Protocol("unknown type byte")),
            };
            self.take_one();
            self.pos += consumed;
        }
    }

    fn take_one(&mut self) {
        if let Some(top) = self.stack.last_mut() {
            *top -= 1;
        }
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// `None` is a RESP2 null (`-1`).
fn parse_len(header: &[u8]) -> Result<Option<i64>, CodecError> {
    let text = std::str::from_utf8(header).map_err(|_| CodecError::Protocol("length"))?;
    let n: i64 = text.parse().map_err(|_| CodecError::Protocol("length"))?;
    match n {
        -1 => Ok(None),
        n if n < 0 => Err(CodecError::Protocol("negative length")),
        n => Ok(Some(n)),
    }
}

/// What kind of frame this is, from its first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// A reply to the oldest command still waiting.
    Reply,
    /// RESP3 push (`>`) or attribute (`|`): not a reply, never consumes one.
    Out,
}

#[must_use]
pub fn frame_kind(frame: &[u8]) -> FrameKind {
    match frame.first() {
        Some(b'>' | b'|') => FrameKind::Out,
        _ => FrameKind::Reply,
    }
}

/// Whether a reply is an error (`-` or RESP3 `!`).
#[must_use]
pub fn is_error(frame: &[u8]) -> bool {
    matches!(frame.first(), Some(b'-' | b'!'))
}

/// A client request, as the arguments it carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub args: Vec<Vec<u8>>,
}

/// Finds where the first client request ends: a RESP array of bulk strings,
/// or an inline command (one line of words). Unlike [`FrameScanner`] it
/// refuses anything else inside the array as soon as it sees it.
#[derive(Debug, Default)]
pub struct RequestScanner {
    pos: usize,
    /// Bulk strings still to read, once the array header is in.
    remaining: Option<u64>,
}

impl RequestScanner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn advance(&mut self, buf: &[u8]) -> Result<Option<usize>, CodecError> {
        match buf.first() {
            None => return Ok(None),
            Some(b'*') => {}
            Some(_) => {
                return match buf.iter().position(|b| *b == b'\n') {
                    Some(i) => Ok(Some(i + 1)),
                    None if buf.len() > MAX_LINE => Err(CodecError::TooLarge("inline command")),
                    None => Ok(None),
                };
            }
        }
        loop {
            if self.remaining == Some(0) {
                return Ok(Some(self.pos));
            }
            let rest = &buf[self.pos..];
            let Some(end) = find_crlf(rest) else {
                return if rest.len() > MAX_LINE {
                    Err(CodecError::TooLarge("line"))
                } else {
                    Ok(None)
                };
            };
            let after_line = end + 2;
            match self.remaining {
                None => {
                    if rest.first() != Some(&b'*') {
                        return Err(CodecError::Protocol("not an array"));
                    }
                    let count = parse_len(&rest[1..end])?;
                    self.pos += after_line;
                    match count {
                        None | Some(0) => return Ok(Some(self.pos)),
                        Some(n) if n > MAX_ELEMENTS => {
                            return Err(CodecError::TooLarge("request"));
                        }
                        Some(n) => self.remaining = Some(n.unsigned_abs()),
                    }
                }
                Some(left) => {
                    if rest.first() != Some(&b'$') {
                        return Err(CodecError::Protocol("requests are arrays of bulk strings"));
                    }
                    let len =
                        parse_len(&rest[1..end])?.ok_or(CodecError::Protocol("null argument"))?;
                    let len = u64::try_from(len).map_err(|_| CodecError::Protocol("length"))?;
                    if len > MAX_BULK {
                        return Err(CodecError::TooLarge("bulk string"));
                    }
                    let total = after_line as u64 + len + 2;
                    if (rest.len() as u64) < total {
                        return Ok(None);
                    }
                    let total =
                        usize::try_from(total).map_err(|_| CodecError::TooLarge("bulk string"))?;
                    if &rest[total - 2..total] != b"\r\n" {
                        return Err(CodecError::Protocol("bulk string not terminated"));
                    }
                    self.pos += total;
                    self.remaining = Some(left - 1);
                }
            }
        }
    }
}

/// Read the arguments from one complete request frame. An empty line
/// yields no arguments.
pub fn parse_command(frame: &[u8]) -> Result<Command, CodecError> {
    if frame.first() != Some(&b'*') {
        let line = std::str::from_utf8(frame)
            .map(str::trim)
            .map_err(|_| CodecError::Protocol("inline command isn't UTF-8"))?;
        return Ok(Command {
            args: split_inline(line)?,
        });
    }
    let mut pos = 0;
    let count = read_header(frame, &mut pos, b'*')?.ok_or(CodecError::Protocol("null request"))?;
    let mut args = Vec::with_capacity(usize::try_from(count).unwrap_or(0).min(1024));
    for _ in 0..count {
        let len =
            read_header(frame, &mut pos, b'$')?.ok_or(CodecError::Protocol("null argument"))?;
        let len = usize::try_from(len).map_err(|_| CodecError::Protocol("length"))?;
        let end = pos + len;
        let arg = frame
            .get(pos..end)
            .ok_or(CodecError::Protocol("short argument"))?;
        args.push(arg.to_vec());
        pos = end + 2;
    }
    Ok(Command { args })
}

fn read_header(frame: &[u8], pos: &mut usize, kind: u8) -> Result<Option<i64>, CodecError> {
    let rest = frame.get(*pos..).ok_or(CodecError::Protocol("truncated"))?;
    if rest.first() != Some(&kind) {
        return Err(CodecError::Protocol("requests are arrays of bulk strings"));
    }
    let end = find_crlf(rest).ok_or(CodecError::Protocol("truncated"))?;
    let n = parse_len(&rest[1..end])?;
    *pos += end + 2;
    Ok(n)
}

/// Split an inline command the way Redis does: whitespace separates words,
/// and double or single quotes group them.
fn split_inline(line: &str) -> Result<Vec<Vec<u8>>, CodecError> {
    let mut words = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut word = String::new();
        if c == '"' || c == '\'' {
            let quote = c;
            chars.next();
            loop {
                match chars.next() {
                    None => return Err(CodecError::Protocol("unbalanced quotes")),
                    Some(ch) if ch == quote => break,
                    Some('\\') if quote == '"' => match chars.next() {
                        Some('n') => word.push('\n'),
                        Some('r') => word.push('\r'),
                        Some('t') => word.push('\t'),
                        Some(other) => word.push(other),
                        None => return Err(CodecError::Protocol("unbalanced quotes")),
                    },
                    Some(ch) => word.push(ch),
                }
            }
        } else {
            while let Some(&ch) = chars.peek() {
                if ch.is_whitespace() {
                    break;
                }
                word.push(ch);
                chars.next();
            }
        }
        words.push(word.into_bytes());
    }
    Ok(words)
}

/// Encode a command as a RESP array of bulk strings.
#[must_use]
pub fn encode_command<A: AsRef<[u8]>>(args: &[A]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        let arg = arg.as_ref();
        out.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        out.extend_from_slice(arg);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// A simple error reply. Newlines would end it early, so they become spaces.
#[must_use]
pub fn error_reply(message: &str) -> Vec<u8> {
    let clean: String = message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    format!("-{clean}\r\n").into_bytes()
}

pub const OK: &[u8] = b"+OK\r\n";

/// A reply value, for the replies the worker reads itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Simple(String),
    Error(String),
    Integer(i64),
    Bulk(Vec<u8>),
    Null,
    Array(Vec<Value>),
    /// Anything else (doubles, maps, ...) that we don't need to look inside.
    Other,
}

/// Parse one complete frame (as found by [`FrameScanner`]).
pub fn parse_value(frame: &[u8]) -> Result<Value, CodecError> {
    let mut pos = 0;
    let value = parse_at(frame, &mut pos, 0)?;
    Ok(value)
}

fn parse_at(buf: &[u8], pos: &mut usize, depth: usize) -> Result<Value, CodecError> {
    if depth > MAX_DEPTH {
        return Err(CodecError::TooLarge("nesting"));
    }
    let rest = buf.get(*pos..).ok_or(CodecError::Protocol("truncated"))?;
    let kind = *rest.first().ok_or(CodecError::Protocol("truncated"))?;
    let end = find_crlf(rest).ok_or(CodecError::Protocol("truncated"))?;
    let header = &rest[1..end];
    *pos += end + 2;
    let text = || String::from_utf8_lossy(header).into_owned();
    match kind {
        b'+' => Ok(Value::Simple(text())),
        b'-' => Ok(Value::Error(text())),
        b':' => text()
            .parse()
            .map(Value::Integer)
            .map_err(|_| CodecError::Protocol("integer")),
        b'_' => Ok(Value::Null),
        b'$' | b'=' | b'!' => match parse_len(header)? {
            None => Ok(Value::Null),
            Some(n) => {
                let n = usize::try_from(n).map_err(|_| CodecError::Protocol("length"))?;
                let body = buf
                    .get(*pos..*pos + n)
                    .ok_or(CodecError::Protocol("truncated"))?
                    .to_vec();
                *pos += n + 2;
                Ok(match kind {
                    b'!' => Value::Error(String::from_utf8_lossy(&body).into_owned()),
                    _ => Value::Bulk(body),
                })
            }
        },
        b'*' | b'~' | b'>' => match parse_len(header)? {
            None => Ok(Value::Null),
            Some(n) => {
                let mut items = Vec::new();
                for _ in 0..n {
                    items.push(parse_at(buf, pos, depth + 1)?);
                }
                Ok(Value::Array(items))
            }
        },
        b'%' | b'|' => {
            for _ in 0..parse_len(header)?.unwrap_or(0) * 2 {
                parse_at(buf, pos, depth + 1)?;
            }
            Ok(Value::Other)
        }
        b',' | b'#' | b'(' => Ok(Value::Other),
        _ => Err(CodecError::Protocol("unknown type byte")),
    }
}

impl Value {
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bulk(b) => Some(b),
            Value::Simple(s) => Some(s.as_bytes()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(buf: &[u8]) -> Result<Option<usize>, CodecError> {
        FrameScanner::new().advance(buf)
    }

    #[test]
    fn finds_the_end_of_every_frame_type() {
        for frame in [
            &b"+OK\r\n"[..],
            b"-ERR nope\r\n",
            b":42\r\n",
            b"$5\r\nhello\r\n",
            b"$-1\r\n",
            b"$0\r\n\r\n",
            b"_\r\n",
            b"#t\r\n",
            b",1.5\r\n",
            b"(12345678901234567890\r\n",
            b"!5\r\nOOPS!\r\n",
            b"=9\r\ntxt:hello\r\n",
            b"*-1\r\n",
            b"*0\r\n",
            b"*2\r\n$3\r\nfoo\r\n:1\r\n",
            b"*2\r\n*1\r\n+a\r\n*1\r\n+b\r\n",
            b"%1\r\n+k\r\n+v\r\n",
            b"~2\r\n:1\r\n:2\r\n",
            b">2\r\n+message\r\n+hi\r\n",
            b"|1\r\n+ttl\r\n:3\r\n",
        ] {
            let mut padded = frame.to_vec();
            padded.extend_from_slice(b"+next\r\n");
            assert_eq!(scan(&padded), Ok(Some(frame.len())), "{frame:?}");
        }
    }

    #[test]
    fn an_incomplete_frame_asks_for_more_at_every_cut() {
        let frame = b"*3\r\n$3\r\nSET\r\n$5\r\nhello\r\n*1\r\n:7\r\n";
        for cut in 0..frame.len() {
            assert_eq!(scan(&frame[..cut]), Ok(None), "cut at {cut}");
        }
        assert_eq!(scan(frame), Ok(Some(frame.len())));
    }

    #[test]
    fn resumes_without_losing_its_place() {
        let frame = b"*2\r\n$3\r\nfoo\r\n*2\r\n:1\r\n$3\r\nbar\r\n";
        let mut scanner = FrameScanner::new();
        for end in 1..frame.len() {
            assert_eq!(scanner.advance(&frame[..end]), Ok(None));
        }
        assert_eq!(scanner.advance(frame), Ok(Some(frame.len())));
    }

    #[test]
    fn rejects_garbage_and_oversize() {
        assert!(scan(b"?what\r\n").is_err());
        assert!(scan(b"$abc\r\n").is_err());
        assert!(scan(b"$-5\r\n").is_err());
        assert!(scan(b"$3\r\nfooXX").is_err());
        assert!(scan(format!("${}\r\n", MAX_BULK + 1).as_bytes()).is_err());
        assert!(scan(&vec![b'+'; MAX_LINE + 10]).is_err());
        let deep = "*1\r\n".repeat(MAX_DEPTH + 2);
        assert!(scan(deep.as_bytes()).is_err());
    }

    #[test]
    fn reads_array_and_inline_commands() {
        let cmd = parse_command(b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$2\r\n\r\n\r\n").expect("array");
        assert_eq!(cmd.args, [b"SET".to_vec(), b"k".to_vec(), b"\r\n".to_vec()]);
        let inline = parse_command(b"set \"a b\" 'c'\r\n").expect("inline");
        assert_eq!(
            inline.args,
            [b"set".to_vec(), b"a b".to_vec(), b"c".to_vec()]
        );
        assert!(parse_command(b"get \"open\r\n").is_err());
        assert!(parse_command(b"*1\r\n:1\r\n").is_err());
    }

    #[test]
    fn request_scanner_handles_inline_lines() {
        let mut scanner = RequestScanner::new();
        assert_eq!(scanner.advance(b"PING"), Ok(None));
        assert_eq!(
            RequestScanner::new().advance(b"PING\r\nPING\r\n"),
            Ok(Some(6))
        );
        // Anything but bulk strings inside the array is refused at once.
        assert!(RequestScanner::new().advance(b"*2\r\n:5\r\n").is_err());
        assert!(RequestScanner::new().advance(b"*1\r\n$-1\r\n").is_err());
        let full = b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n+extra";
        let mut sc = RequestScanner::new();
        for cut in 0..full.len() - 6 {
            assert_eq!(sc.advance(&full[..cut]), Ok(None), "{cut}");
        }
        assert_eq!(sc.advance(full), Ok(Some(full.len() - 6)));
    }

    #[test]
    fn encodes_commands_that_parse_back() {
        let args: [&[u8]; 3] = [b"SET", b"key", b"va\r\nlue"];
        let bytes = encode_command(&args);
        assert_eq!(scan(&bytes), Ok(Some(bytes.len())));
        let back = parse_command(&bytes).expect("parse");
        assert_eq!(back.args, args.map(<[u8]>::to_vec));
    }

    #[test]
    fn parses_nested_values() {
        let v = parse_value(b"*3\r\n$3\r\nget\r\n:2\r\n*2\r\n+readonly\r\n_\r\n").expect("parse");
        assert_eq!(
            v,
            Value::Array(vec![
                Value::Bulk(b"get".to_vec()),
                Value::Integer(2),
                Value::Array(vec![Value::Simple("readonly".into()), Value::Null]),
            ])
        );
        assert!(is_error(b"-ERR x\r\n"));
        assert!(is_error(b"!3\r\nERR\r\n"));
        assert_eq!(frame_kind(b">1\r\n+x\r\n"), FrameKind::Out);
        assert_eq!(frame_kind(b"+OK\r\n"), FrameKind::Reply);
    }

    #[test]
    fn error_replies_cannot_be_split_by_newlines() {
        assert_eq!(error_reply("a\r\nb"), b"-a  b\r\n");
    }
}

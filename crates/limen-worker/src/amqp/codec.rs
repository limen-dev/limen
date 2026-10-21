//! AMQP 0-9-1 framing and the few method layouts the worker reads or writes
//! (ADR-0037). Everything here is a pure function over bytes, so it can be
//! tested (and fuzzed) without a socket.
//!
//! A frame is `type(1) channel(2) size(4) payload(size) 0xCE`. The worker
//! decodes method frames only far enough to see which exchange, queue,
//! vhost, and routing key they name. Content headers and bodies are
//! relayed as they are; only the body size in the header is read.

use std::fmt;

/// What a client sends first: `AMQP`, 0, the protocol 0-9-1.
pub const PROTOCOL_HEADER: [u8; 8] = *b"AMQP\x00\x00\x09\x01";
pub const FRAME_END: u8 = 0xCE;

pub const METHOD: u8 = 1;
pub const HEADER: u8 = 2;
pub const BODY: u8 = 3;
pub const HEARTBEAT: u8 = 8;

/// Classes and methods the worker acts on, as `(class, method)`.
pub mod ids {
    pub const CONNECTION: u16 = 10;
    pub const CHANNEL: u16 = 20;
    pub const EXCHANGE: u16 = 40;
    pub const QUEUE: u16 = 50;
    pub const BASIC: u16 = 60;
    pub const CONFIRM: u16 = 85;
    pub const TX: u16 = 90;

    pub const START: u16 = 10;
    pub const START_OK: u16 = 11;
    pub const TUNE: u16 = 30;
    pub const TUNE_OK: u16 = 31;
    pub const OPEN: u16 = 40;
    pub const OPEN_OK: u16 = 41;
    pub const CLOSE: u16 = 50;
    pub const CLOSE_OK: u16 = 51;
    pub const CHANNEL_CLOSE: u16 = 40;
    pub const CHANNEL_CLOSE_OK: u16 = 41;
    pub const CHANNEL_OPEN: u16 = 10;
    pub const QUEUE_DECLARE_OK: u16 = 11;
    pub const BASIC_DELIVER: u16 = 60;
    pub const BASIC_GET_OK: u16 = 71;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The frame announces more payload than was agreed.
    TooLarge(usize),
    /// The byte after the payload is not `0xCE`.
    BadEnd,
    UnknownType(u8),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::TooLarge(n) => write!(f, "frame of {n} bytes is over the agreed maximum"),
            FrameError::BadEnd => write!(f, "frame does not end with 0xCE"),
            FrameError::UnknownType(t) => write!(f, "unknown frame type {t}"),
        }
    }
}

impl std::error::Error for FrameError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub channel: u16,
    pub payload: Vec<u8>,
}

impl Frame {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.payload.len());
        out.push(self.kind);
        out.extend_from_slice(&self.channel.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(self.payload.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.payload);
        out.push(FRAME_END);
        out
    }

    #[must_use]
    pub fn method(channel: u16, class: u16, method: u16, args: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(4 + args.len());
        payload.extend_from_slice(&class.to_be_bytes());
        payload.extend_from_slice(&method.to_be_bytes());
        payload.extend_from_slice(args);
        Self {
            kind: METHOD,
            channel,
            payload,
        }
    }

    #[must_use]
    pub fn heartbeat() -> Self {
        Self {
            kind: HEARTBEAT,
            channel: 0,
            payload: Vec::new(),
        }
    }

    /// `(class, method, arguments)` of a method frame.
    #[must_use]
    pub fn as_method(&self) -> Option<(u16, u16, &[u8])> {
        if self.kind != METHOD || self.payload.len() < 4 {
            return None;
        }
        Some((
            u16::from_be_bytes([self.payload[0], self.payload[1]]),
            u16::from_be_bytes([self.payload[2], self.payload[3]]),
            &self.payload[4..],
        ))
    }

    /// The body size a content header announces.
    #[must_use]
    pub fn body_size(&self) -> Option<u64> {
        if self.kind != HEADER || self.payload.len() < 12 {
            return None;
        }
        let mut size = [0u8; 8];
        size.copy_from_slice(&self.payload[4..12]);
        Some(u64::from_be_bytes(size))
    }
}

/// Take one frame off the front of `buf`. `Ok(None)` means more bytes are
/// needed; otherwise the frame and how many bytes it took.
///
/// # Errors
/// If the frame is oversize, ends wrongly, or has a type AMQP doesn't define.
pub fn parse_frame(buf: &[u8], max_payload: usize) -> Result<Option<(Frame, usize)>, FrameError> {
    if buf.len() < 7 {
        return Ok(None);
    }
    let kind = buf[0];
    if !matches!(kind, METHOD | HEADER | BODY | HEARTBEAT) {
        return Err(FrameError::UnknownType(kind));
    }
    let size = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]) as usize;
    if size > max_payload {
        return Err(FrameError::TooLarge(size));
    }
    let total = 7 + size + 1;
    if buf.len() < total {
        return Ok(None);
    }
    if buf[total - 1] != FRAME_END {
        return Err(FrameError::BadEnd);
    }
    Ok(Some((
        Frame {
            kind,
            channel: u16::from_be_bytes([buf[1], buf[2]]),
            payload: buf[7..total - 1].to_vec(),
        },
        total,
    )))
}

/// The method arguments ended early or hold a string that doesn't fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed method arguments")
    }
}

impl std::error::Error for Malformed {}

/// Reads method arguments.
#[derive(Debug)]
pub struct Args<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Args<'a> {
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        let end = self.pos.checked_add(n).ok_or(Malformed)?;
        let slice = self.buf.get(self.pos..end).ok_or(Malformed)?;
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, Malformed> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, Malformed> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A short string (`u8` length, at most 255 bytes).
    pub fn shortstr(&mut self) -> Result<String, Malformed> {
        let n = usize::from(self.u8()?);
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }

    /// A long string or a field table, skipped (`u32` length).
    pub fn skip_long(&mut self) -> Result<(), Malformed> {
        let n = self.u32()? as usize;
        self.take(n).map(|_| ())
    }

    /// A long string, as bytes.
    pub fn longstr(&mut self) -> Result<&'a [u8], Malformed> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    /// A field table, reduced to the string values of the top-level entries
    /// named in `keys` (every other value is skipped, whatever its type).
    pub fn table_strings(&mut self, keys: &[&str]) -> Result<Vec<(String, String)>, Malformed> {
        let mut table = Args::new(self.longstr()?);
        let mut found = Vec::new();
        while table.pos < table.buf.len() {
            let key = table.shortstr()?;
            let kind = table.u8()?;
            if kind == b'S' && keys.contains(&key.as_str()) {
                let value = String::from_utf8_lossy(table.longstr()?).into_owned();
                found.push((key, value));
            } else {
                table.skip_value(kind, 0)?;
            }
        }
        Ok(found)
    }

    /// Skip one field-table value of type `kind`. Nesting is bounded so a
    /// hostile table can't exhaust the stack.
    fn skip_value(&mut self, kind: u8, depth: u8) -> Result<(), Malformed> {
        if depth > 16 {
            return Err(Malformed);
        }
        match kind {
            b't' | b'b' | b'B' => self.take(1).map(|_| ()),
            b's' | b'u' => self.take(2).map(|_| ()),
            b'I' | b'i' | b'f' => self.take(4).map(|_| ()),
            b'l' | b'L' | b'd' | b'T' => self.take(8).map(|_| ()),
            b'D' => self.take(5).map(|_| ()),
            b'S' | b'x' => self.skip_long(),
            b'V' => Ok(()),
            b'F' => {
                let mut inner = Args::new(self.longstr()?);
                while inner.pos < inner.buf.len() {
                    inner.shortstr()?;
                    let k = inner.u8()?;
                    inner.skip_value(k, depth + 1)?;
                }
                Ok(())
            }
            b'A' => {
                let mut inner = Args::new(self.longstr()?);
                while inner.pos < inner.buf.len() {
                    let k = inner.u8()?;
                    inner.skip_value(k, depth + 1)?;
                }
                Ok(())
            }
            _ => Err(Malformed),
        }
    }
}

/// Writes method arguments.
#[derive(Debug, Default)]
pub struct Out(pub Vec<u8>);

impl Out {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }

    #[must_use]
    pub fn u16(mut self, v: u16) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    #[must_use]
    pub fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// A short string, cut at 255 bytes on a character boundary.
    #[must_use]
    pub fn shortstr(mut self, s: &str) -> Self {
        let mut end = s.len().min(255);
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        self.0.push(u8::try_from(end).unwrap_or(255));
        self.0.extend_from_slice(&s.as_bytes()[..end]);
        self
    }

    #[must_use]
    pub fn longstr(mut self, b: &[u8]) -> Self {
        self.0
            .extend_from_slice(&u32::try_from(b.len()).unwrap_or(u32::MAX).to_be_bytes());
        self.0.extend_from_slice(b);
        self
    }

    /// A field table of the value types the worker sends.
    #[must_use]
    pub fn table(self, entries: &[(&str, Field<'_>)]) -> Self {
        let mut body = Vec::new();
        for (key, value) in entries {
            body.push(u8::try_from(key.len()).unwrap_or(255));
            body.extend_from_slice(key.as_bytes());
            value.write(&mut body);
        }
        self.longstr(&body)
    }

    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// A field-table value.
#[derive(Debug)]
pub enum Field<'a> {
    Bool(bool),
    Str(&'a str),
    Table(Vec<(&'a str, Field<'a>)>),
}

impl Field<'_> {
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Field::Bool(b) => {
                out.push(b't');
                out.push(u8::from(*b));
            }
            Field::Str(s) => {
                out.push(b'S');
                out.extend_from_slice(&u32::try_from(s.len()).unwrap_or(u32::MAX).to_be_bytes());
                out.extend_from_slice(s.as_bytes());
            }
            Field::Table(entries) => {
                out.push(b'F');
                let table = Out::new().table(entries).finish();
                out.extend_from_slice(&table);
            }
        }
    }
}

/// What the worker says it is, and what the broker behind it can do, so that
/// clients that check capabilities (publisher confirms, `basic.nack`,
/// connection blocking) behave as they would against `RabbitMQ`.
fn capabilities() -> Field<'static> {
    Field::Table(vec![
        ("publisher_confirms", Field::Bool(true)),
        ("exchange_exchange_bindings", Field::Bool(true)),
        ("basic.nack", Field::Bool(true)),
        ("consumer_cancel_notify", Field::Bool(true)),
        ("connection.blocked", Field::Bool(true)),
        ("consumer_priorities", Field::Bool(true)),
        ("authentication_failure_close", Field::Bool(true)),
        ("per_consumer_qos", Field::Bool(true)),
        ("direct_reply_to", Field::Bool(true)),
    ])
}

/// `Connection.Start`: the worker offers `PLAIN` and `AMQPLAIN`, and accepts
/// whatever the client sends (it authenticates below AMQP).
#[must_use]
pub fn connection_start() -> Frame {
    let args = Out::new()
        .u8(0)
        .u8(9)
        .table(&[
            ("product", Field::Str("Limen")),
            ("capabilities", capabilities()),
        ])
        .longstr(b"PLAIN AMQPLAIN")
        .longstr(b"en_US")
        .finish();
    Frame::method(0, ids::CONNECTION, ids::START, &args)
}

#[must_use]
pub fn connection_tune(channel_max: u16, frame_max: u32, heartbeat: u16) -> Frame {
    let args = Out::new()
        .u16(channel_max)
        .u32(frame_max)
        .u16(heartbeat)
        .finish();
    Frame::method(0, ids::CONNECTION, ids::TUNE, &args)
}

#[must_use]
pub fn connection_open_ok() -> Frame {
    Frame::method(
        0,
        ids::CONNECTION,
        ids::OPEN_OK,
        &Out::new().shortstr("").finish(),
    )
}

#[must_use]
pub fn connection_close(code: u16, text: &str, class: u16, method: u16) -> Frame {
    let args = Out::new()
        .u16(code)
        .shortstr(text)
        .u16(class)
        .u16(method)
        .finish();
    Frame::method(0, ids::CONNECTION, ids::CLOSE, &args)
}

#[must_use]
pub fn connection_close_ok() -> Frame {
    Frame::method(0, ids::CONNECTION, ids::CLOSE_OK, &[])
}

#[must_use]
pub fn channel_close(channel: u16, code: u16, text: &str, class: u16, method: u16) -> Frame {
    let args = Out::new()
        .u16(code)
        .shortstr(text)
        .u16(class)
        .u16(method)
        .finish();
    Frame::method(channel, ids::CHANNEL, ids::CHANNEL_CLOSE, &args)
}

#[must_use]
pub fn channel_close_ok(channel: u16) -> Frame {
    Frame::method(channel, ids::CHANNEL, ids::CHANNEL_CLOSE_OK, &[])
}

/// `Connection.StartOk` toward the broker: `PLAIN`, named after the Limen session.
#[must_use]
pub fn connection_start_ok(connection_name: &str, user: &str, password: &str) -> Frame {
    let mut response = vec![0];
    response.extend_from_slice(user.as_bytes());
    response.push(0);
    response.extend_from_slice(password.as_bytes());
    let args = Out::new()
        .table(&[
            ("product", Field::Str("Limen")),
            ("connection_name", Field::Str(connection_name)),
            ("capabilities", capabilities()),
        ])
        .shortstr("PLAIN")
        .longstr(&response)
        .shortstr("en_US")
        .finish();
    Frame::method(0, ids::CONNECTION, ids::START_OK, &args)
}

#[must_use]
pub fn connection_tune_ok(channel_max: u16, frame_max: u32, heartbeat: u16) -> Frame {
    let args = Out::new()
        .u16(channel_max)
        .u32(frame_max)
        .u16(heartbeat)
        .finish();
    Frame::method(0, ids::CONNECTION, ids::TUNE_OK, &args)
}

#[must_use]
pub fn connection_open(vhost: &str) -> Frame {
    let args = Out::new().shortstr(vhost).shortstr("").u8(0).finish();
    Frame::method(0, ids::CONNECTION, ids::OPEN, &args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_wait_for_more_bytes() {
        let f = Frame::method(3, 60, 40, b"abc");
        let bytes = f.encode();
        assert_eq!(
            parse_frame(&bytes, 1024),
            Ok(Some((f.clone(), bytes.len())))
        );
        for cut in 0..bytes.len() {
            assert_eq!(parse_frame(&bytes[..cut], 1024), Ok(None), "cut at {cut}");
        }
        let mut two = bytes.clone();
        two.extend_from_slice(&Frame::heartbeat().encode());
        let (first, used) = parse_frame(&two, 1024).expect("ok").expect("frame");
        assert_eq!(first, f);
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn refuses_what_amqp_does_not_define() {
        let mut bytes = Frame::method(1, 10, 10, b"").encode();
        *bytes.last_mut().expect("end") = 0xCF;
        assert_eq!(parse_frame(&bytes, 1024), Err(FrameError::BadEnd));
        assert_eq!(
            parse_frame(&[9, 0, 0, 0, 0, 0, 0, 0xCE], 1024),
            Err(FrameError::UnknownType(9))
        );
        let big = Frame {
            kind: BODY,
            channel: 1,
            payload: vec![0; 2000],
        }
        .encode();
        assert_eq!(parse_frame(&big, 1024), Err(FrameError::TooLarge(2000)));
        // The size is checked before the bytes arrive, so a hostile length
        // never makes the worker buffer.
        assert_eq!(
            parse_frame(&[3, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF], 1024),
            Err(FrameError::TooLarge(u32::MAX as usize))
        );
    }

    #[test]
    fn arguments_read_back_what_was_written() {
        let args = Out::new()
            .u16(0)
            .shortstr("orders")
            .shortstr("new.order")
            .u8(1)
            .table(&[("x", Field::Str("y"))])
            .finish();
        let mut a = Args::new(&args);
        assert_eq!(a.u16(), Ok(0));
        assert_eq!(a.shortstr().as_deref(), Ok("orders"));
        assert_eq!(a.shortstr().as_deref(), Ok("new.order"));
        assert_eq!(a.u8(), Ok(1));
        assert_eq!(a.skip_long(), Ok(()));
        assert_eq!(a.u8(), Err(Malformed));
    }

    #[test]
    fn a_short_string_that_overruns_is_malformed() {
        let mut a = Args::new(&[5, b'a', b'b']);
        assert_eq!(a.shortstr(), Err(Malformed));
        let mut a = Args::new(&[0, 0, 0, 9, 1]);
        assert_eq!(a.skip_long(), Err(Malformed));
    }

    #[test]
    fn long_short_strings_are_cut_on_a_character_boundary() {
        let s = "é".repeat(200);
        let out = Out::new().shortstr(&s).finish();
        assert_eq!(out[0], 254);
        assert!(String::from_utf8(out[1..].to_vec()).is_ok());
    }

    #[test]
    fn body_size_comes_from_the_content_header() {
        let mut payload = vec![0, 60, 0, 0];
        payload.extend_from_slice(&1234u64.to_be_bytes());
        payload.extend_from_slice(&[0, 0]);
        let h = Frame {
            kind: HEADER,
            channel: 1,
            payload,
        };
        assert_eq!(h.body_size(), Some(1234));
        assert_eq!(Frame::heartbeat().body_size(), None);
    }

    #[test]
    fn the_handshake_frames_decode() {
        let start = connection_start();
        let (class, method, args) = start.as_method().expect("method");
        assert_eq!((class, method), (10, 10));
        let mut a = Args::new(args);
        assert_eq!((a.u8(), a.u8()), (Ok(0), Ok(9)));
        a.skip_long().expect("properties");
        assert_eq!(a.longstr().expect("mechanisms"), b"PLAIN AMQPLAIN");

        let ok = connection_start_ok("limen:abc", "bob", "pw");
        let (_, _, args) = ok.as_method().expect("method");
        let mut a = Args::new(args);
        a.skip_long().expect("properties");
        assert_eq!(a.shortstr().as_deref(), Ok("PLAIN"));
        assert_eq!(a.longstr().expect("response"), b"\0bob\0pw");
    }
}

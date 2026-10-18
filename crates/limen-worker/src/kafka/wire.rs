//! Kafka wire primitives (ADR-0037): a bounds-checked reader and a writer for
//! the non-flexible encodings, the request header, and the table of API
//! versions the worker reads. Pure functions over bytes.
//!
//! Every request is `size(i32) api_key(i16) api_version(i16)
//! correlation_id(i32) client_id(nullable string)` and a body; every
//! response is `size(i32) correlation_id(i32)` and a body. The worker only
//! speaks versions below the *flexible* ones (compact strings, tagged
//! fields), which keeps the hand-written readers small; it says so in its
//! `ApiVersions` answer, and clients negotiate down.

use std::fmt;

/// The request or response is cut short, or a length doesn't fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed Kafka message")
    }
}

impl std::error::Error for Malformed {}

/// The most elements an array may announce, so a hostile length can't make
/// the worker reserve memory for them.
const MAX_ARRAY: usize = 1 << 20;

/// Reads from a message body.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[must_use]
    pub fn pos(&self) -> usize {
        self.pos
    }

    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        let end = self.pos.checked_add(n).ok_or(Malformed)?;
        let s = self.buf.get(self.pos..end).ok_or(Malformed)?;
        self.pos = end;
        Ok(s)
    }

    pub fn skip(&mut self, n: usize) -> Result<(), Malformed> {
        self.take(n).map(|_| ())
    }

    pub fn i8(&mut self) -> Result<i8, Malformed> {
        Ok(i8::from_be_bytes([self.take(1)?[0]]))
    }

    pub fn i16(&mut self) -> Result<i16, Malformed> {
        let b = self.take(2)?;
        Ok(i16::from_be_bytes([b[0], b[1]]))
    }

    pub fn i32(&mut self) -> Result<i32, Malformed> {
        let b = self.take(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn i64(&mut self) -> Result<i64, Malformed> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(i64::from_be_bytes(a))
    }

    /// A string (`i16` length). A negative length is malformed here.
    pub fn string(&mut self) -> Result<String, Malformed> {
        let n = usize::try_from(self.i16()?).map_err(|_| Malformed)?;
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }

    /// A nullable string: length -1 is null.
    pub fn nullable_string(&mut self) -> Result<Option<String>, Malformed> {
        let n = self.i16()?;
        if n < 0 {
            return Ok(None);
        }
        let n = usize::try_from(n).map_err(|_| Malformed)?;
        Ok(Some(String::from_utf8_lossy(self.take(n)?).into_owned()))
    }

    /// Bytes (`i32` length) or null (-1), skipped.
    pub fn skip_nullable_bytes(&mut self) -> Result<(), Malformed> {
        let n = self.i32()?;
        if n < 0 {
            return Ok(());
        }
        self.skip(usize::try_from(n).map_err(|_| Malformed)?)
    }

    /// Bytes (`i32` length) or null.
    pub fn nullable_bytes(&mut self) -> Result<Option<&'a [u8]>, Malformed> {
        let n = self.i32()?;
        if n < 0 {
            return Ok(None);
        }
        Ok(Some(self.take(usize::try_from(n).map_err(|_| Malformed)?)?))
    }

    /// The length of an array, `None` for a null array (-1).
    pub fn array_len(&mut self) -> Result<Option<usize>, Malformed> {
        let n = self.i32()?;
        if n < 0 {
            return Ok(None);
        }
        let n = usize::try_from(n).map_err(|_| Malformed)?;
        if n > MAX_ARRAY || n > self.remaining() {
            // Every element takes at least one byte, so a count beyond what is
            // left can't be real.
            return Err(Malformed);
        }
        Ok(Some(n))
    }

    /// Read an array with `each`; a null array is `None`.
    pub fn array<T>(
        &mut self,
        mut each: impl FnMut(&mut Self) -> Result<T, Malformed>,
    ) -> Result<Option<Vec<T>>, Malformed> {
        let Some(n) = self.array_len()? else {
            return Ok(None);
        };
        let mut out = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            out.push(each(self)?);
        }
        Ok(Some(out))
    }

    /// Skip an array whose elements `each` consumes.
    pub fn skip_array(
        &mut self,
        mut each: impl FnMut(&mut Self) -> Result<(), Malformed>,
    ) -> Result<(), Malformed> {
        if let Some(n) = self.array_len()? {
            for _ in 0..n {
                each(self)?;
            }
        }
        Ok(())
    }
}

/// Builds a message body.
#[derive(Debug, Default, Clone)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn i8(mut self, v: i8) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    #[must_use]
    pub fn i16(mut self, v: i16) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    #[must_use]
    pub fn i32(mut self, v: i32) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    #[must_use]
    pub fn i64(mut self, v: i64) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    #[must_use]
    pub fn string(mut self, s: &str) -> Self {
        let len = i16::try_from(s.len()).unwrap_or(i16::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0
            .extend_from_slice(&s.as_bytes()[..usize::try_from(len).unwrap_or(0)]);
        self
    }

    #[must_use]
    pub fn nullable_string(self, s: Option<&str>) -> Self {
        match s {
            Some(s) => self.string(s),
            None => self.i16(-1),
        }
    }

    #[must_use]
    pub fn bytes(mut self, b: &[u8]) -> Self {
        self.0
            .extend_from_slice(&i32::try_from(b.len()).unwrap_or(i32::MAX).to_be_bytes());
        self.0.extend_from_slice(b);
        self
    }

    #[must_use]
    pub fn raw(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(b);
        self
    }

    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// A request's header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    pub api_key: i16,
    pub api_version: i16,
    pub correlation_id: i32,
    pub client_id: Option<String>,
    /// Where the body starts in the message.
    pub body_at: usize,
}

/// Read the header of a request message (without its size prefix).
///
/// # Errors
/// If the message is shorter than a header.
pub fn parse_request_header(msg: &[u8]) -> Result<RequestHeader, Malformed> {
    let mut r = Reader::new(msg);
    let api_key = r.i16()?;
    let api_version = r.i16()?;
    let correlation_id = r.i32()?;
    // Header v1 has a client id; the flexible v2 (tagged fields) is never read.
    let client_id = r.nullable_string()?;
    Ok(RequestHeader {
        api_key,
        api_version,
        correlation_id,
        client_id,
        body_at: r.pos(),
    })
}

/// Frame a response: `size`, `correlation_id`, then the body.
#[must_use]
pub fn response_message(correlation_id: i32, body: &[u8]) -> Vec<u8> {
    let size = i32::try_from(4 + body.len()).unwrap_or(i32::MAX);
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(&correlation_id.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// The API keys the worker relays, with the highest non-flexible version it
/// can read and the lowest it will speak. Anything else is not advertised and
/// is refused (ADR-0037 item 16).
pub mod api {
    pub const PRODUCE: i16 = 0;
    pub const FETCH: i16 = 1;
    pub const LIST_OFFSETS: i16 = 2;
    pub const METADATA: i16 = 3;
    pub const OFFSET_COMMIT: i16 = 8;
    pub const OFFSET_FETCH: i16 = 9;
    pub const FIND_COORDINATOR: i16 = 10;
    pub const JOIN_GROUP: i16 = 11;
    pub const HEARTBEAT: i16 = 12;
    pub const LEAVE_GROUP: i16 = 13;
    pub const SYNC_GROUP: i16 = 14;
    pub const SASL_HANDSHAKE: i16 = 17;
    pub const API_VERSIONS: i16 = 18;
    pub const CREATE_TOPICS: i16 = 19;
    pub const DELETE_TOPICS: i16 = 20;
    pub const INIT_PRODUCER_ID: i16 = 22;
    pub const SASL_AUTHENTICATE: i16 = 36;

    /// `(api key, min version, max version)`.
    pub const SUPPORTED: [(i16, i16, i16); 17] = [
        (PRODUCE, 3, 8),
        (FETCH, 4, 11),
        (LIST_OFFSETS, 1, 5),
        (METADATA, 1, 8),
        (OFFSET_COMMIT, 2, 7),
        (OFFSET_FETCH, 1, 5),
        (FIND_COORDINATOR, 0, 2),
        (JOIN_GROUP, 0, 5),
        (HEARTBEAT, 0, 3),
        (LEAVE_GROUP, 0, 3),
        (SYNC_GROUP, 0, 3),
        (SASL_HANDSHAKE, 1, 1),
        (API_VERSIONS, 0, 2),
        (CREATE_TOPICS, 0, 4),
        (DELETE_TOPICS, 0, 3),
        (INIT_PRODUCER_ID, 0, 1),
        (SASL_AUTHENTICATE, 0, 1),
    ];

    /// The range the worker reads for `key`.
    #[must_use]
    pub fn supported(key: i16) -> Option<(i16, i16)> {
        SUPPORTED
            .iter()
            .find(|(k, _, _)| *k == key)
            .map(|(_, lo, hi)| (*lo, *hi))
    }

    /// A readable name for the audit trail.
    #[must_use]
    pub fn name(key: i16) -> &'static str {
        match key {
            PRODUCE => "Produce",
            FETCH => "Fetch",
            LIST_OFFSETS => "ListOffsets",
            METADATA => "Metadata",
            OFFSET_COMMIT => "OffsetCommit",
            OFFSET_FETCH => "OffsetFetch",
            FIND_COORDINATOR => "FindCoordinator",
            JOIN_GROUP => "JoinGroup",
            HEARTBEAT => "Heartbeat",
            LEAVE_GROUP => "LeaveGroup",
            SYNC_GROUP => "SyncGroup",
            SASL_HANDSHAKE => "SaslHandshake",
            API_VERSIONS => "ApiVersions",
            CREATE_TOPICS => "CreateTopics",
            DELETE_TOPICS => "DeleteTopics",
            INIT_PRODUCER_ID => "InitProducerId",
            SASL_AUTHENTICATE => "SaslAuthenticate",
            _ => "Unknown",
        }
    }
}

/// The error codes the worker answers with.
pub mod error {
    pub const NONE: i16 = 0;
    pub const UNSUPPORTED_VERSION: i16 = 35;
    pub const TOPIC_AUTHORIZATION_FAILED: i16 = 29;
    pub const GROUP_AUTHORIZATION_FAILED: i16 = 30;
    pub const CLUSTER_AUTHORIZATION_FAILED: i16 = 31;
    pub const TRANSACTIONAL_ID_AUTHORIZATION_FAILED: i16 = 53;
    pub const UNSUPPORTED_SASL_MECHANISM: i16 = 33;
    pub const INVALID_REQUEST: i16 = 42;
    pub const REQUEST_TIMED_OUT: i16 = 7;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_and_writer_agree() {
        let bytes = Writer::new()
            .i8(-3)
            .i16(7)
            .i32(-9)
            .i64(1 << 40)
            .string("topic")
            .nullable_string(None)
            .nullable_string(Some("x"))
            .bytes(b"abc")
            .finish();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.i8(), Ok(-3));
        assert_eq!(r.i16(), Ok(7));
        assert_eq!(r.i32(), Ok(-9));
        assert_eq!(r.i64(), Ok(1 << 40));
        assert_eq!(r.string().as_deref(), Ok("topic"));
        assert_eq!(r.nullable_string(), Ok(None));
        assert_eq!(r.nullable_string(), Ok(Some("x".to_owned())));
        assert_eq!(r.nullable_bytes(), Ok(Some(&b"abc"[..])));
        assert_eq!(r.remaining(), 0);
        assert_eq!(r.i8(), Err(Malformed));
    }

    #[test]
    fn short_and_hostile_input_is_malformed_not_a_panic() {
        assert_eq!(Reader::new(&[0, 5, b'a']).string(), Err(Malformed));
        assert_eq!(
            Reader::new(&[0xFF, 0xFE]).string(),
            Err(Malformed),
            "negative length"
        );
        // A count far beyond what could follow.
        assert_eq!(
            Reader::new(&[0x7F, 0xFF, 0xFF, 0xFF, 0]).array_len(),
            Err(Malformed)
        );
        assert_eq!(Reader::new(&[0xFF, 0xFF, 0xFF, 0xFF]).array_len(), Ok(None));
        assert_eq!(
            Reader::new(&[0, 0, 0, 9, 1]).nullable_bytes(),
            Err(Malformed)
        );
        let mut r = Reader::new(&[0, 0, 0, 2, 0, 1, 0, 2]);
        #[allow(clippy::redundant_closure_for_method_calls)] // a path fails to unify the lifetimes
        let v = r.array(|r| r.i16()).expect("ok").expect("not null");
        assert_eq!(v, [1, 2]);
    }

    #[test]
    fn request_headers_parse() {
        let mut msg = Writer::new()
            .i16(3)
            .i16(8)
            .i32(42)
            .string("rdkafka")
            .finish();
        msg.extend_from_slice(b"body");
        let h = parse_request_header(&msg).expect("header");
        assert_eq!((h.api_key, h.api_version, h.correlation_id), (3, 8, 42));
        assert_eq!(h.client_id.as_deref(), Some("rdkafka"));
        assert_eq!(&msg[h.body_at..], b"body");
        let null_client = Writer::new()
            .i16(18)
            .i16(0)
            .i32(1)
            .nullable_string(None)
            .finish();
        assert_eq!(
            parse_request_header(&null_client).expect("h").client_id,
            None
        );
        assert_eq!(parse_request_header(&[0, 3, 0]), Err(Malformed));
    }

    #[test]
    fn responses_are_framed_with_their_size() {
        let m = response_message(9, b"xy");
        assert_eq!(m, [0, 0, 0, 6, 0, 0, 0, 9, b'x', b'y']);
    }

    #[test]
    fn no_flexible_version_is_in_the_table() {
        // First flexible version of each API the worker relays.
        for (key, flexible_from) in [
            (api::PRODUCE, 9),
            (api::FETCH, 12),
            (api::LIST_OFFSETS, 6),
            (api::METADATA, 9),
            (api::OFFSET_COMMIT, 8),
            (api::OFFSET_FETCH, 6),
            (api::FIND_COORDINATOR, 3),
            (api::JOIN_GROUP, 6),
            (api::HEARTBEAT, 4),
            (api::LEAVE_GROUP, 4),
            (api::SYNC_GROUP, 4),
            (api::API_VERSIONS, 3),
            (api::CREATE_TOPICS, 5),
            (api::DELETE_TOPICS, 4),
            (api::INIT_PRODUCER_ID, 2),
            (api::SASL_AUTHENTICATE, 2),
        ] {
            let (_, hi) = api::supported(key).expect("in the table");
            assert!(hi < flexible_from, "{} v{hi}", api::name(key));
        }
        assert_eq!(api::supported(99), None);
    }
}

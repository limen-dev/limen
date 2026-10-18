//! The MongoDB wire protocol, as much as a relay needs (ADR-0035): the
//! 16-byte header, `OP_MSG` (every command since 3.6), and the legacy
//! `OP_QUERY`/`OP_REPLY` pair that drivers still use for the first
//! handshake. `OP_COMPRESSED` is never negotiated, so it is refused.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::bson::{BsonError, Doc};

pub const OP_REPLY: i32 = 1;
pub const OP_QUERY: i32 = 2004;
pub const OP_COMPRESSED: i32 = 2012;
pub const OP_MSG: i32 = 2013;

pub const HEADER_LEN: usize = 16;

/// `OP_MSG` flag bits.
pub const CHECKSUM_PRESENT: u32 = 1;
pub const MORE_TO_COME: u32 = 1 << 1;
pub const EXHAUST_ALLOWED: u32 = 1 << 16;

/// The most a message may be. The server's own limit is 48,000,000 bytes
/// (`maxMessageSizeBytes`); a message the worker holds in full is capped at
/// 64 MiB, like the SQL relays.
pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("message length {0} is out of range")]
    Length(i64),
    #[error("{0}")]
    Bson(#[from] BsonError),
    #[error("{0}")]
    Malformed(&'static str),
    #[error("unsupported opcode {0}")]
    Opcode(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub request_id: i32,
    pub response_to: i32,
    pub opcode: i32,
}

/// A message with its header taken apart. `body` is what follows the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub body: Vec<u8>,
}

/// Read one message. `Ok(None)` is a clean end of stream before any byte.
pub async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Message>, WireError> {
    let mut head = [0u8; HEADER_LEN];
    let mut got = 0;
    while got < HEADER_LEN {
        let n = r.read(&mut head[got..]).await?;
        if n == 0 {
            return if got == 0 {
                Ok(None)
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into())
            };
        }
        got += n;
    }
    let word = |i: usize| i32::from_le_bytes([head[i], head[i + 1], head[i + 2], head[i + 3]]);
    let length = word(0);
    let len = usize::try_from(length)
        .ok()
        .filter(|l| (HEADER_LEN..=MAX_MESSAGE).contains(l))
        .ok_or(WireError::Length(i64::from(length)))?;
    // Grow with what arrives instead of reserving what the header claims:
    // a client that announces 64 MiB and sends nothing costs nothing.
    let want = len - HEADER_LEN;
    let mut body = Vec::with_capacity(want.min(64 * 1024));
    let got = r.take(want as u64).read_to_end(&mut body).await?;
    if got != want {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
    }
    Ok(Some(Message {
        header: Header {
            request_id: word(4),
            response_to: word(8),
            opcode: word(12),
        },
        body,
    }))
}

/// A whole message, ready to write.
#[must_use]
pub fn encode(header: Header, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    let length = i32::try_from(HEADER_LEN + body.len()).unwrap_or(i32::MAX);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&header.request_id.to_le_bytes());
    out.extend_from_slice(&header.response_to.to_le_bytes());
    out.extend_from_slice(&header.opcode.to_le_bytes());
    out.extend_from_slice(body);
    out
}

pub async fn write_message<W: AsyncWrite + Unpin>(
    w: &mut W,
    header: Header,
    body: &[u8],
) -> std::io::Result<()> {
    w.write_all(&encode(header, body)).await?;
    w.flush().await
}

/// A parsed `OP_MSG` body.
#[derive(Debug, Clone)]
pub struct OpMsg<'a> {
    pub flags: u32,
    /// The kind-0 section: the command.
    pub command: Doc<'a>,
    /// Kind-1 sections: a named run of documents (`documents`, `updates`, ...).
    pub sequences: Vec<Sequence<'a>>,
    /// The sections as they were on the wire, without flags or checksum.
    pub sections: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct Sequence<'a> {
    pub identifier: &'a str,
    pub docs: Vec<Doc<'a>>,
}

/// Most documents one kind-1 section may hold (a batch is at most 100,000).
const MAX_SEQUENCE_DOCS: usize = 100_000;

/// Parse an `OP_MSG` body. Unknown required flag bits (0 to 15 other than
/// the checksum and `moreToCome`) are an error, as the specification says.
pub fn parse_op_msg(body: &[u8]) -> Result<OpMsg<'_>, WireError> {
    if body.len() < 4 {
        return Err(WireError::Malformed("OP_MSG is shorter than its flags"));
    }
    let flags = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    if flags & 0xFFFF & !(CHECKSUM_PRESENT | MORE_TO_COME) != 0 {
        return Err(WireError::Malformed("OP_MSG has an unknown required flag"));
    }
    let end = if flags & CHECKSUM_PRESENT != 0 {
        body.len()
            .checked_sub(4)
            .filter(|e| *e >= 4)
            .ok_or(WireError::Malformed("OP_MSG checksum is missing"))?
    } else {
        body.len()
    };
    let sections = &body[4..end];
    let mut rest = sections;
    let mut command = None;
    let mut sequences = Vec::new();
    while !rest.is_empty() {
        let kind = rest[0];
        rest = &rest[1..];
        match kind {
            0 => {
                let (doc, tail) = Doc::split(rest)?;
                if command.replace(doc).is_some() {
                    return Err(WireError::Malformed("OP_MSG has two command sections"));
                }
                rest = tail;
            }
            1 => {
                if rest.len() < 4 {
                    return Err(WireError::Malformed("truncated document sequence"));
                }
                let size = i32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
                let size = usize::try_from(size)
                    .ok()
                    .filter(|s| *s >= 5 && *s <= rest.len())
                    .ok_or(WireError::Malformed("bad document sequence size"))?;
                let (section, tail) = rest.split_at(size);
                let mut inner = &section[4..];
                let nul = inner
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or(WireError::Malformed("document sequence has no identifier"))?;
                let identifier = std::str::from_utf8(&inner[..nul])
                    .map_err(|_| WireError::Malformed("document sequence identifier"))?;
                inner = &inner[nul + 1..];
                let mut docs = Vec::new();
                while !inner.is_empty() {
                    if docs.len() >= MAX_SEQUENCE_DOCS {
                        return Err(WireError::Malformed("too many documents in a sequence"));
                    }
                    let (doc, t) = Doc::split(inner)?;
                    docs.push(doc);
                    inner = t;
                }
                sequences.push(Sequence { identifier, docs });
                rest = tail;
            }
            _ => return Err(WireError::Malformed("unknown OP_MSG section kind")),
        }
    }
    Ok(OpMsg {
        flags,
        command: command.ok_or(WireError::Malformed("OP_MSG has no command section"))?,
        sequences,
        sections,
    })
}

/// The `OP_MSG` body to forward to the server: the client's sections with
/// `exhaustAllowed` cleared (so the server never streams replies the worker
/// isn't waiting for) and the checksum dropped (the flags changed, and the
/// hop is TLS).
#[must_use]
pub fn op_msg_for_server(msg: &OpMsg<'_>) -> Vec<u8> {
    let flags = msg.flags & !(CHECKSUM_PRESENT | EXHAUST_ALLOWED);
    let mut out = Vec::with_capacity(4 + msg.sections.len());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(msg.sections);
    out
}

/// An `OP_MSG` body that holds one document and no flags.
#[must_use]
pub fn op_msg_body(doc: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + doc.len());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.push(0);
    out.extend_from_slice(doc);
    out
}

/// A parsed `OP_QUERY`, which the worker accepts only for the handshake.
#[derive(Debug, Clone)]
pub struct OpQuery<'a> {
    pub collection: &'a str,
    pub query: Doc<'a>,
}

pub fn parse_op_query(body: &[u8]) -> Result<OpQuery<'_>, WireError> {
    if body.len() < 4 {
        return Err(WireError::Malformed("OP_QUERY is shorter than its flags"));
    }
    let rest = &body[4..];
    let nul = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or(WireError::Malformed("OP_QUERY has no collection name"))?;
    let collection = std::str::from_utf8(&rest[..nul])
        .map_err(|_| WireError::Malformed("OP_QUERY collection name"))?;
    let rest = &rest[nul + 1..];
    if rest.len() < 8 {
        return Err(WireError::Malformed("OP_QUERY is truncated"));
    }
    // numberToSkip and numberToReturn are ignored: only the handshake uses this.
    let (query, _) = Doc::split(&rest[8..])?;
    Ok(OpQuery { collection, query })
}

/// An `OP_REPLY` body with one document, the answer to an `OP_QUERY`.
#[must_use]
pub fn op_reply_body(doc: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + doc.len());
    out.extend_from_slice(&8i32.to_le_bytes()); // AwaitCapable
    out.extend_from_slice(&0i64.to_le_bytes()); // cursorID
    out.extend_from_slice(&0i32.to_le_bytes()); // startingFrom
    out.extend_from_slice(&1i32.to_le_bytes()); // numberReturned
    out.extend_from_slice(doc);
    out
}

#[cfg(test)]
mod tests {
    use super::super::bson::{Builder, Value};
    use super::*;

    fn cmd() -> Vec<u8> {
        Builder::new()
            .str("insert", "customers")
            .str("$db", "orders")
            .finish()
    }

    fn docs_section(identifier: &str, docs: &[Vec<u8>]) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(identifier.as_bytes());
        inner.push(0);
        for d in docs {
            inner.extend_from_slice(d);
        }
        let mut out = vec![1u8];
        out.extend_from_slice(&i32::try_from(inner.len() + 4).expect("len").to_le_bytes());
        out.extend_from_slice(&inner);
        out
    }

    #[tokio::test]
    async fn round_trips_a_message_through_a_stream() {
        let body = op_msg_body(&cmd());
        let header = Header {
            request_id: 7,
            response_to: 0,
            opcode: OP_MSG,
        };
        let (mut a, mut b) = tokio::io::duplex(4096);
        write_message(&mut a, header, &body).await.expect("write");
        drop(a);
        let msg = read_message(&mut b).await.expect("read").expect("message");
        assert_eq!(msg.header, header);
        assert_eq!(msg.body, body);
        assert!(read_message(&mut b).await.expect("eof").is_none());
    }

    #[tokio::test]
    async fn refuses_absurd_or_cut_messages() {
        for length in [0i32, 15, -1, i32::MAX] {
            let mut bytes = length.to_le_bytes().to_vec();
            bytes.extend_from_slice(&[0; 12]);
            let err = read_message(&mut bytes.as_slice()).await.expect_err("bad");
            assert!(matches!(err, WireError::Length(_)), "{length}: {err}");
        }
        // Declares 100 bytes, delivers 20.
        let mut cut = 100i32.to_le_bytes().to_vec();
        cut.extend_from_slice(&[0; 16]);
        assert!(matches!(
            read_message(&mut cut.as_slice()).await,
            Err(WireError::Io(_))
        ));
        // A huge claim with nothing behind it fails without reserving it.
        let mut huge = i32::try_from(MAX_MESSAGE)
            .expect("fits")
            .to_le_bytes()
            .to_vec();
        huge.extend_from_slice(&[0; 12]);
        huge.extend_from_slice(&[1, 2, 3]);
        assert!(matches!(
            read_message(&mut huge.as_slice()).await,
            Err(WireError::Io(_))
        ));
        // A header cut in the middle is an error, not a clean end.
        assert!(read_message(&mut [1u8, 2, 3].as_slice()).await.is_err());
    }

    #[test]
    fn parses_the_command_and_document_sequences() {
        let docs = vec![
            Builder::new().str("name", "Ada").finish(),
            Builder::new().str("name", "Grace").finish(),
        ];
        let mut body = 0u32.to_le_bytes().to_vec();
        body.push(0);
        body.extend_from_slice(&cmd());
        body.extend_from_slice(&docs_section("documents", &docs));
        let msg = parse_op_msg(&body).expect("parse");
        assert_eq!(msg.command.first().expect("ok").expect("first").0, "insert");
        assert_eq!(msg.sequences.len(), 1);
        assert_eq!(msg.sequences[0].identifier, "documents");
        assert_eq!(msg.sequences[0].docs.len(), 2);
        assert_eq!(
            msg.sequences[0].docs[1].get("name").expect("ok"),
            Some(Value::Str("Grace"))
        );
    }

    #[test]
    fn rejects_malformed_op_msg() {
        assert!(parse_op_msg(&[0, 0]).is_err());
        // No command section.
        assert!(parse_op_msg(&0u32.to_le_bytes()).is_err());
        // Two command sections.
        let mut two = 0u32.to_le_bytes().to_vec();
        for _ in 0..2 {
            two.push(0);
            two.extend_from_slice(&cmd());
        }
        assert!(parse_op_msg(&two).is_err());
        // An unknown required flag.
        let mut flagged = (1u32 << 3).to_le_bytes().to_vec();
        flagged.push(0);
        flagged.extend_from_slice(&cmd());
        assert!(parse_op_msg(&flagged).is_err());
        // An unknown section kind.
        let mut kind = 0u32.to_le_bytes().to_vec();
        kind.push(9);
        kind.extend_from_slice(&cmd());
        assert!(parse_op_msg(&kind).is_err());
        // A sequence whose size lies.
        let mut lie = 0u32.to_le_bytes().to_vec();
        lie.push(0);
        lie.extend_from_slice(&cmd());
        lie.extend_from_slice(&[1, 0xff, 0xff, 0xff, 0x7f, b'x', 0]);
        assert!(parse_op_msg(&lie).is_err());
        // checksumPresent with no room for it.
        let mut sum = CHECKSUM_PRESENT.to_le_bytes().to_vec();
        sum.extend_from_slice(&[0, 0]);
        assert!(parse_op_msg(&sum).is_err());
    }

    #[test]
    fn the_server_copy_drops_exhaust_and_the_checksum() {
        let mut body = (CHECKSUM_PRESENT | EXHAUST_ALLOWED | MORE_TO_COME)
            .to_le_bytes()
            .to_vec();
        body.push(0);
        body.extend_from_slice(&cmd());
        body.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // a checksum
        let msg = parse_op_msg(&body).expect("parse");
        let forwarded = op_msg_for_server(&msg);
        let again = parse_op_msg(&forwarded).expect("still valid");
        assert_eq!(again.flags, MORE_TO_COME, "only moreToCome survives");
        assert_eq!(again.command.as_bytes(), msg.command.as_bytes());
        assert_eq!(forwarded.len(), body.len() - 4);
    }

    #[test]
    fn reads_a_handshake_op_query_and_builds_the_reply() {
        let query = Builder::new().i32("isMaster", 1).finish();
        let mut body = 0i32.to_le_bytes().to_vec();
        body.extend_from_slice(b"admin.$cmd\0");
        body.extend_from_slice(&0i32.to_le_bytes());
        body.extend_from_slice(&(-1i32).to_le_bytes());
        body.extend_from_slice(&query);
        let q = parse_op_query(&body).expect("query");
        assert_eq!(q.collection, "admin.$cmd");
        assert_eq!(q.query.first().expect("ok").expect("first").0, "isMaster");
        assert!(parse_op_query(&body[..8]).is_err());

        let reply = op_reply_body(&Builder::new().f64("ok", 1.0).finish());
        assert_eq!(i32::from_le_bytes(reply[16..20].try_into().expect("4")), 1);
        assert!(Doc::new(&reply[20..]).is_ok());
    }
}

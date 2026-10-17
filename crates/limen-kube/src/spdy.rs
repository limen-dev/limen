//! A passive SPDY/3.1 frame decoder, enough to follow `kubectl exec`,
//! `attach`, and `port-forward` over the `SPDY/3.1` upgrade.
//!
//! Streams are opened by the client (`SYN_STREAM`), and the stream type
//! (`stdin`, `stdout`, `error`, `resize`, `data`, ...) is in a header that is
//! compressed with zlib and the SPDY/3 dictionary. Each direction has its own
//! compression context, so the client's header blocks (`SYN_STREAM`,
//! `SYN_REPLY`, `HEADERS`) must all be inflated, in order, to keep that
//! context in step. The server's control frames are skipped: we never need
//! what they carry.

use flate2::{Decompress, FlushDecompress};

use crate::Error;
use crate::spdy_dictionary::HEADER_DICTIONARY;
use crate::ws::Sender;

const MAX_DATA_FRAME: usize = 4 * 1024 * 1024;
/// Control frames carry settings and header blocks, never bulk data.
const MAX_CONTROL_FRAME: usize = 256 * 1024;
/// Inflated size of one header block. Real ones are a few hundred bytes; the
/// cap stops a compression bomb.
const MAX_HEADER_BLOCK: usize = 256 * 1024;
const VERSION: u16 = 3;

const SYN_STREAM: u16 = 1;
const SYN_REPLY: u16 = 2;
const HEADERS: u16 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// The client opened a stream.
    SynStream {
        stream_id: u32,
        headers: Vec<(String, String)>,
    },
    Data {
        stream_id: u32,
        fin: bool,
        data: Vec<u8>,
    },
    /// Settings, pings, window updates, resets, and server header blocks.
    Other,
}

#[derive(Debug)]
pub struct Decoder {
    sender: Sender,
    buf: Vec<u8>,
    inflater: Option<Decompress>,
}

impl Decoder {
    #[must_use]
    pub fn new(sender: Sender) -> Self {
        Self {
            sender,
            buf: Vec::new(),
            inflater: None,
        }
    }

    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Frame>, Error> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        let mut at = 0;
        loop {
            let rest = &self.buf[at..];
            let Some(header) = rest.get(..8) else { break };
            let length =
                usize::from(header[5]) << 16 | usize::from(header[6]) << 8 | usize::from(header[7]);
            let control = header[0] & 0x80 != 0;
            let max = if control {
                MAX_CONTROL_FRAME
            } else {
                MAX_DATA_FRAME
            };
            if length > max {
                return Err(Error::Spdy("frame too large"));
            }
            let Some(payload) = rest.get(8..8 + length) else {
                break;
            };
            let header: [u8; 8] = header.try_into().map_err(|_| Error::Spdy("short header"))?;
            let frame = if control {
                let version = u16::from_be_bytes([header[0] & 0x7f, header[1]]);
                if version != VERSION {
                    return Err(Error::Spdy("not SPDY/3"));
                }
                let kind = u16::from_be_bytes([header[2], header[3]]);
                let payload = payload.to_vec();
                self.control(kind, &payload)?
            } else {
                Frame::Data {
                    stream_id: u32::from_be_bytes([
                        header[0] & 0x7f,
                        header[1],
                        header[2],
                        header[3],
                    ]),
                    fin: header[4] & 1 != 0,
                    data: payload.to_vec(),
                }
            };
            out.push(frame);
            at += 8 + length;
        }
        self.buf.drain(..at);
        Ok(out)
    }

    fn control(&mut self, kind: u16, payload: &[u8]) -> Result<Frame, Error> {
        if self.sender == Sender::Server || !matches!(kind, SYN_STREAM | SYN_REPLY | HEADERS) {
            return Ok(Frame::Other);
        }
        // SYN_STREAM: stream id, associated stream id, priority and slot, block.
        // SYN_REPLY and HEADERS: stream id, block.
        let skip = if kind == SYN_STREAM { 10 } else { 4 };
        let (Some(id), Some(block)) = (payload.get(..4), payload.get(skip..)) else {
            return Err(Error::Spdy("control frame too short"));
        };
        let stream_id = u32::from_be_bytes([id[0] & 0x7f, id[1], id[2], id[3]]);
        let inflated = self.inflate(block)?;
        if kind == SYN_STREAM {
            Ok(Frame::SynStream {
                stream_id,
                headers: parse_headers(&inflated)?,
            })
        } else {
            Ok(Frame::Other)
        }
    }

    fn inflate(&mut self, block: &[u8]) -> Result<Vec<u8>, Error> {
        let z = self.inflater.get_or_insert_with(|| Decompress::new(true));
        let mut out = Vec::with_capacity(1024);
        let mut input = block;
        // Enough rounds for the dictionary request plus the data; more means
        // the stream is not making progress.
        for _ in 0..64 {
            let before = z.total_in();
            let result = z.decompress_vec(input, &mut out, FlushDecompress::Sync);
            let used = usize::try_from(z.total_in() - before)
                .map_err(|_| Error::SpdyHeaders("size overflow".into()))?;
            input = input.get(used..).unwrap_or_default();
            match result {
                Ok(_) => {}
                Err(e) if e.needs_dictionary().is_some() => {
                    z.set_dictionary(&HEADER_DICTIONARY)
                        .map_err(|e| Error::SpdyHeaders(e.to_string()))?;
                    continue;
                }
                Err(e) => return Err(Error::SpdyHeaders(e.to_string())),
            }
            if out.len() > MAX_HEADER_BLOCK {
                return Err(Error::SpdyHeaders("header block too large".into()));
            }
            if input.is_empty() && out.len() < out.capacity() {
                return Ok(out);
            }
            if out.len() == out.capacity() {
                out.reserve(4096);
            } else if used == 0 {
                break;
            }
        }
        Err(Error::SpdyHeaders("inflate made no progress".into()))
    }
}

/// `count`, then `count` pairs of length-prefixed name and value (all u32 big-endian).
fn parse_headers(block: &[u8]) -> Result<Vec<(String, String)>, Error> {
    fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], Error> {
        let (head, tail) = buf
            .split_at_checked(n)
            .ok_or_else(|| Error::SpdyHeaders("truncated".into()))?;
        *buf = tail;
        Ok(head)
    }
    fn number(buf: &mut &[u8]) -> Result<usize, Error> {
        let bytes: [u8; 4] = take(buf, 4)?
            .try_into()
            .map_err(|_| Error::SpdyHeaders("truncated".into()))?;
        usize::try_from(u32::from_be_bytes(bytes))
            .map_err(|_| Error::SpdyHeaders("overflow".into()))
    }
    let mut buf = block;
    let count = number(&mut buf)?;
    let mut headers = Vec::new();
    for _ in 0..count.min(256) {
        let name_len = number(&mut buf)?;
        let name = String::from_utf8_lossy(take(&mut buf, name_len)?).into_owned();
        let value_len = number(&mut buf)?;
        let value = String::from_utf8_lossy(take(&mut buf, value_len)?).into_owned();
        headers.push((name, value));
    }
    Ok(headers)
}

/// Build frames, for tests.
#[doc(hidden)]
#[allow(clippy::cast_possible_truncation)] // test frames are tiny
pub mod build {
    use flate2::{Compress, Compression, FlushCompress};

    use super::{HEADER_DICTIONARY, VERSION};

    /// A client-side header compressor that keeps its context across blocks.
    #[derive(Debug)]
    pub struct Compressor(Compress);

    impl Default for Compressor {
        fn default() -> Self {
            let mut z = Compress::new(Compression::default(), true);
            z.set_dictionary(&HEADER_DICTIONARY).expect("dictionary");
            Self(z)
        }
    }

    impl Compressor {
        fn block(&mut self, headers: &[(&str, &str)]) -> Vec<u8> {
            let mut raw = (headers.len() as u32).to_be_bytes().to_vec();
            for (name, value) in headers {
                raw.extend((name.len() as u32).to_be_bytes());
                raw.extend(name.as_bytes());
                raw.extend((value.len() as u32).to_be_bytes());
                raw.extend(value.as_bytes());
            }
            let mut out = Vec::with_capacity(raw.len() + 64);
            self.0
                .compress_vec(&raw, &mut out, FlushCompress::Sync)
                .expect("compress");
            out
        }

        #[must_use]
        pub fn syn_stream(&mut self, stream_id: u32, headers: &[(&str, &str)]) -> Vec<u8> {
            let mut payload = stream_id.to_be_bytes().to_vec();
            payload.extend([0, 0, 0, 0, 0, 0]); // associated stream, priority, slot
            payload.extend(self.block(headers));
            control(1, 0, &payload)
        }
    }

    fn control(kind: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = (0x8000 | VERSION).to_be_bytes().to_vec();
        out.extend(kind.to_be_bytes());
        out.push(flags);
        out.extend(&(payload.len() as u32).to_be_bytes()[1..]);
        out.extend(payload);
        out
    }

    #[must_use]
    pub fn data(stream_id: u32, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mut out = stream_id.to_be_bytes().to_vec();
        out.push(u8::from(fin));
        out.extend(&(payload.len() as u32).to_be_bytes()[1..]);
        out.extend(payload);
        out
    }

    #[must_use]
    pub fn ping() -> Vec<u8> {
        control(6, 0, &[0, 0, 0, 1])
    }
}

#[cfg(test)]
mod tests {
    use super::build::{Compressor, data, ping};
    use super::*;

    #[test]
    fn inflates_client_headers_across_blocks_with_one_context() {
        let mut z = Compressor::default();
        let mut wire = z.syn_stream(1, &[("streamtype", "error")]);
        wire.extend(ping());
        wire.extend(z.syn_stream(3, &[("streamtype", "stdout"), ("port", "8080")]));
        wire.extend(data(3, false, b"hi"));
        let mut decoder = Decoder::new(Sender::Client);
        // Feed it in awkward pieces.
        let mut frames = Vec::new();
        for chunk in wire.chunks(7) {
            frames.extend(decoder.push(chunk).expect("decode"));
        }
        assert_eq!(
            frames,
            [
                Frame::SynStream {
                    stream_id: 1,
                    headers: vec![("streamtype".into(), "error".into())]
                },
                Frame::Other,
                Frame::SynStream {
                    stream_id: 3,
                    headers: vec![
                        ("streamtype".into(), "stdout".into()),
                        ("port".into(), "8080".into())
                    ]
                },
                Frame::Data {
                    stream_id: 3,
                    fin: false,
                    data: b"hi".to_vec()
                },
            ]
        );
    }

    #[test]
    fn server_control_frames_are_skipped_not_inflated() {
        let mut wire = ping();
        wire.extend(data(1, true, b"out"));
        let frames = Decoder::new(Sender::Server).push(&wire).expect("decode");
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], Frame::Other);
    }

    #[test]
    fn refuses_garbage() {
        // Wrong protocol version.
        let mut wire = ping();
        wire[1] = 2;
        assert!(Decoder::new(Sender::Client).push(&wire).is_err());
        // A header block that is not zlib.
        let mut wire = vec![0x80, 3, 0, 1, 0, 0, 0, 16];
        wire.extend([
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
        ]);
        assert!(Decoder::new(Sender::Client).push(&wire).is_err());
        // A data frame that claims 16 MiB.
        assert!(
            Decoder::new(Sender::Server)
                .push(&[0, 0, 0, 1, 0, 0xff, 0xff, 0xff])
                .is_err()
        );
    }
}

//! A passive RFC 6455 frame decoder.
//!
//! The worker forwards WebSocket bytes untouched and feeds a copy here. The
//! decoder reassembles messages so [`crate::stream`] can read the Kubernetes
//! channel byte at the front of each one. It never writes.
//!
//! The worker removes `Sec-WebSocket-Extensions` from the upgrade request, so
//! compression is never negotiated and no frame has a reserved bit set.

use crate::Error;

/// Largest single message we reassemble. Exec output frames are a few KiB;
/// anything bigger is not a kubectl stream.
const MAX_MESSAGE: usize = 4 * 1024 * 1024;

/// Which end sent the bytes being decoded. Clients mask their frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sender {
    Client,
    Server,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Binary(Vec<u8>),
    Text(Vec<u8>),
    Ping,
    Pong,
    Close,
}

#[derive(Debug)]
pub struct Decoder {
    sender: Sender,
    buf: Vec<u8>,
    /// A fragmented data message in progress: its opcode and bytes so far.
    partial: Option<(u8, Vec<u8>)>,
}

impl Decoder {
    #[must_use]
    pub fn new(sender: Sender) -> Self {
        Self {
            sender,
            buf: Vec::new(),
            partial: None,
        }
    }

    /// Add bytes read from the connection and return every message they complete.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Message>, Error> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        let mut at = 0;
        while let Some((frame, used)) = parse_frame(&self.buf[at..], self.sender)? {
            at += used;
            if let Some(message) = self.assemble(frame)? {
                out.push(message);
            }
        }
        self.buf.drain(..at);
        Ok(out)
    }

    fn assemble(&mut self, frame: Frame) -> Result<Option<Message>, Error> {
        match frame.opcode {
            0x8 => Ok(Some(Message::Close)),
            0x9 => Ok(Some(Message::Ping)),
            0xA => Ok(Some(Message::Pong)),
            0x0 => {
                let Some((opcode, mut bytes)) = self.partial.take() else {
                    return Err(Error::WebSocket("continuation without a start"));
                };
                if bytes.len() + frame.payload.len() > MAX_MESSAGE {
                    return Err(Error::WebSocket("message too large"));
                }
                bytes.extend_from_slice(&frame.payload);
                if frame.fin {
                    Ok(Some(data_message(opcode, bytes)))
                } else {
                    self.partial = Some((opcode, bytes));
                    Ok(None)
                }
            }
            opcode @ (0x1 | 0x2) => {
                if self.partial.is_some() {
                    return Err(Error::WebSocket("new message inside a fragmented one"));
                }
                if frame.fin {
                    Ok(Some(data_message(opcode, frame.payload)))
                } else {
                    self.partial = Some((opcode, frame.payload));
                    Ok(None)
                }
            }
            _ => Err(Error::WebSocket("unknown opcode")),
        }
    }
}

fn data_message(opcode: u8, bytes: Vec<u8>) -> Message {
    if opcode == 0x1 {
        Message::Text(bytes)
    } else {
        Message::Binary(bytes)
    }
}

struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

#[allow(clippy::many_single_char_names)]
/// One whole frame from the front of `buf`, and how many bytes it used.
/// `Ok(None)` means more bytes are needed.
fn parse_frame(buf: &[u8], sender: Sender) -> Result<Option<(Frame, usize)>, Error> {
    let [b0, b1, rest @ ..] = buf else {
        return Ok(None);
    };
    if b0 & 0x70 != 0 {
        return Err(Error::WebSocket(
            "reserved bits set (extension negotiated?)",
        ));
    }
    let masked = b1 & 0x80 != 0;
    if masked != (sender == Sender::Client) {
        return Err(Error::WebSocket("wrong masking for the sender"));
    }
    let opcode = b0 & 0x0f;
    let (len, rest, header) = match b1 & 0x7f {
        126 => match rest {
            [h, l, rest @ ..] => (usize::from(u16::from_be_bytes([*h, *l])), rest, 4),
            _ => return Ok(None),
        },
        127 => match rest {
            [a, b, c, d, e, f, g, h, rest @ ..] => {
                let len = u64::from_be_bytes([*a, *b, *c, *d, *e, *f, *g, *h]);
                let len = usize::try_from(len)
                    .ok()
                    .filter(|l| *l <= MAX_MESSAGE)
                    .ok_or(Error::WebSocket("frame too large"))?;
                (len, rest, 10)
            }
            _ => return Ok(None),
        },
        n => (usize::from(n), rest, 2),
    };
    if opcode >= 0x8 && (len > 125 || b0 & 0x80 == 0) {
        return Err(Error::WebSocket("invalid control frame"));
    }
    if len > MAX_MESSAGE {
        return Err(Error::WebSocket("frame too large"));
    }
    let (key, rest, header) = if masked {
        match rest {
            [a, b, c, d, rest @ ..] => (Some([*a, *b, *c, *d]), rest, header + 4),
            _ => return Ok(None),
        }
    } else {
        (None, rest, header)
    };
    if rest.len() < len {
        return Ok(None);
    }
    let mut payload = rest[..len].to_vec();
    if let Some(key) = key {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[i % 4];
        }
    }
    Ok(Some((
        Frame {
            fin: b0 & 0x80 != 0,
            opcode,
            payload,
        },
        header + len,
    )))
}

/// Encode one unfragmented frame. For tests and for answering a stream we
/// ourselves have to close; the worker's relay never re-frames live traffic.
#[must_use]
pub fn encode(sender: Sender, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    let mask_bit = if sender == Sender::Client { 0x80 } else { 0 };
    match payload.len() {
        n if n < 126 => out.push(mask_bit | u8::try_from(n).unwrap_or(0)),
        n if u16::try_from(n).is_ok() => {
            out.push(mask_bit | 0x7e);
            out.extend_from_slice(&u16::try_from(n).unwrap_or(0).to_be_bytes());
        }
        n => {
            out.push(mask_bit | 0x7f);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    if sender == Sender::Client {
        let key = [0x37, 0xfa, 0x21, 0x3d];
        out.extend_from_slice(&key);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    } else {
        out.extend_from_slice(payload);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_masked_client_and_plain_server_frames() {
        let mut client = Decoder::new(Sender::Client);
        let wire = encode(Sender::Client, 0x2, b"\x04{\"Width\":80,\"Height\":24}");
        assert_eq!(
            client.push(&wire).expect("decode"),
            [Message::Binary(
                b"\x04{\"Width\":80,\"Height\":24}".to_vec()
            )]
        );
        let mut server = Decoder::new(Sender::Server);
        let wire = encode(Sender::Server, 0x2, b"\x01hello");
        assert_eq!(
            server.push(&wire).expect("decode"),
            [Message::Binary(b"\x01hello".to_vec())]
        );
    }

    #[test]
    fn frames_split_at_every_byte_still_decode() {
        let mut wire = encode(Sender::Server, 0x2, &[1; 300]); // 16-bit length
        wire.extend(encode(Sender::Server, 0x2, b"\x02err"));
        let mut server = Decoder::new(Sender::Server);
        let mut messages = Vec::new();
        for byte in &wire {
            messages.extend(server.push(std::slice::from_ref(byte)).expect("decode"));
        }
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[1], Message::Binary(b"\x02err".to_vec()));
    }

    #[test]
    fn fragments_reassemble_around_control_frames() {
        let mut wire = Vec::new();
        wire.extend([0x02, 3, 1, 2, 3]); // binary, not final
        wire.extend(encode(Sender::Server, 0x9, b"")); // ping in between
        wire.extend([0x80, 2, 4, 5]); // continuation, final
        let messages = Decoder::new(Sender::Server).push(&wire).expect("decode");
        assert_eq!(
            messages,
            [Message::Ping, Message::Binary(vec![1, 2, 3, 4, 5])]
        );
    }

    #[test]
    fn refuses_what_it_cannot_record() {
        // Compression bit (RSV1): permessage-deflate was negotiated.
        assert!(Decoder::new(Sender::Server).push(&[0xC2, 1, 0]).is_err());
        // An unmasked client frame.
        let plain = encode(Sender::Server, 0x2, b"x");
        assert!(Decoder::new(Sender::Client).push(&plain).is_err());
        // A continuation with nothing to continue.
        assert!(Decoder::new(Sender::Server).push(&[0x80, 0]).is_err());
        // A huge declared length is refused before any allocation.
        let mut huge = vec![0x82, 127];
        huge.extend(u64::MAX.to_be_bytes());
        assert!(Decoder::new(Sender::Server).push(&huge).is_err());
    }
}

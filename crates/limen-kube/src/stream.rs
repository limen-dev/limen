//! What a recording and an audit event need from an upgraded stream.
//!
//! Two protocols carry the same Kubernetes channels (stdin, stdout, stderr,
//! error, resize):
//!
//! - **WebSocket** (`v4.channel.k8s.io`, `v5.channel.k8s.io`): every binary
//!   message starts with a channel byte. 0 is stdin, 1 stdout, 2 stderr, 3 the
//!   error/status channel, 4 resize.
//! - **SPDY/3.1**: one stream per channel, typed by a `streamtype` header.
//!
//! Port-forward uses the same transports with pairs of data and error streams.

use std::collections::{BTreeMap, BTreeSet};

use crate::Error;
use crate::spdy::{self, Frame};
use crate::ws::{self, Message, Sender};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    ExecWebSocket,
    ExecSpdy,
    /// `v?.portforward.k8s.io` or `v?.channel.k8s.io`: channel-prefixed messages.
    PortForwardWebSocket,
    PortForwardSpdy,
    /// `SPDY/3.1+portforward.k8s.io`: SPDY frames carried in WebSocket messages,
    /// which is what kubectl 1.31 and later use.
    PortForwardSpdyOverWebSocket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Bytes a container wrote to stdout or stderr.
    Output(Vec<u8>),
    /// The client's terminal changed size.
    Resize { cols: u32, rows: u32 },
    /// The remote command finished with this status.
    Exit(u32),
    /// A port-forward carries traffic for this container port.
    Port(u16),
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum Transport {
    WebSocket {
        client: ws::Decoder,
        server: ws::Decoder,
    },
    Spdy {
        client: spdy::Decoder,
        server: spdy::Decoder,
    },
    /// SPDY inside WebSocket messages: unwrap, then decode as SPDY.
    SpdyTunnel {
        ws_client: ws::Decoder,
        ws_server: ws::Decoder,
        client: spdy::Decoder,
        server: spdy::Decoder,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpdyStream {
    Stdin,
    Stdout,
    Stderr,
    Error,
    Resize,
    Data,
    Other,
}

#[derive(Debug)]
pub struct StreamDecoder {
    port_forward: bool,
    transport: Transport,
    spdy_streams: BTreeMap<u32, SpdyStream>,
    /// Port-forward WebSocket channels whose opening port message was seen.
    announced: BTreeSet<u8>,
    ports: BTreeSet<u16>,
}

impl StreamDecoder {
    #[must_use]
    pub fn new(kind: StreamKind) -> Self {
        let transport = match kind {
            StreamKind::ExecWebSocket | StreamKind::PortForwardWebSocket => Transport::WebSocket {
                client: ws::Decoder::new(Sender::Client),
                server: ws::Decoder::new(Sender::Server),
            },
            StreamKind::ExecSpdy | StreamKind::PortForwardSpdy => Transport::Spdy {
                client: spdy::Decoder::new(Sender::Client),
                server: spdy::Decoder::new(Sender::Server),
            },
            StreamKind::PortForwardSpdyOverWebSocket => Transport::SpdyTunnel {
                ws_client: ws::Decoder::new(Sender::Client),
                ws_server: ws::Decoder::new(Sender::Server),
                client: spdy::Decoder::new(Sender::Client),
                server: spdy::Decoder::new(Sender::Server),
            },
        };
        Self {
            port_forward: matches!(
                kind,
                StreamKind::PortForwardWebSocket
                    | StreamKind::PortForwardSpdy
                    | StreamKind::PortForwardSpdyOverWebSocket
            ),
            transport,
            spdy_streams: BTreeMap::new(),
            announced: BTreeSet::new(),
            ports: BTreeSet::new(),
        }
    }

    /// Bytes the client sent toward the cluster.
    pub fn client(&mut self, bytes: &[u8]) -> Result<Vec<Event>, Error> {
        let mut events = Vec::new();
        match &mut self.transport {
            Transport::WebSocket { client, .. } => {
                for message in client.push(bytes)? {
                    if let Message::Binary(m) = message
                        && let [4, body @ ..] = m.as_slice()
                        && !self.port_forward
                        && let Some(resize) = parse_resize(body)
                    {
                        events.push(resize);
                    }
                }
            }
            Transport::Spdy { client, .. } => {
                let frames = client.push(bytes)?;
                self.spdy_client_frames(frames, &mut events);
            }
            Transport::SpdyTunnel {
                ws_client, client, ..
            } => {
                let mut frames = Vec::new();
                for message in ws_client.push(bytes)? {
                    if let Message::Binary(payload) = message {
                        frames.extend(client.push(&payload)?);
                    }
                }
                self.spdy_client_frames(frames, &mut events);
            }
        }
        Ok(events)
    }

    /// Bytes the cluster sent toward the client.
    pub fn server(&mut self, bytes: &[u8]) -> Result<Vec<Event>, Error> {
        let mut events = Vec::new();
        match &mut self.transport {
            Transport::WebSocket { server, .. } => {
                for message in server.push(bytes)? {
                    let Message::Binary(m) = message else {
                        continue;
                    };
                    let [channel, body @ ..] = m.as_slice() else {
                        continue;
                    };
                    if self.port_forward {
                        // The first message on each data channel is the port,
                        // two bytes little-endian.
                        if channel % 2 == 0
                            && self.announced.insert(*channel)
                            && let [lo, hi] = body
                        {
                            let port = u16::from_le_bytes([*lo, *hi]);
                            if self.ports.insert(port) {
                                events.push(Event::Port(port));
                            }
                        }
                        continue;
                    }
                    match channel {
                        1 | 2 if !body.is_empty() => events.push(Event::Output(body.to_vec())),
                        3 => events.extend(parse_status(body).map(Event::Exit)),
                        _ => {}
                    }
                }
            }
            Transport::Spdy { server, .. } => {
                let frames = server.push(bytes)?;
                self.spdy_server_frames(frames, &mut events);
            }
            Transport::SpdyTunnel {
                ws_server, server, ..
            } => {
                let mut frames = Vec::new();
                for message in ws_server.push(bytes)? {
                    if let Message::Binary(payload) = message {
                        frames.extend(server.push(&payload)?);
                    }
                }
                self.spdy_server_frames(frames, &mut events);
            }
        }
        Ok(events)
    }

    fn spdy_client_frames(&mut self, frames: Vec<Frame>, events: &mut Vec<Event>) {
        for frame in frames {
            match frame {
                Frame::SynStream { stream_id, headers } => {
                    let find = |name: &str| {
                        headers
                            .iter()
                            .find(|(n, _)| n.eq_ignore_ascii_case(name))
                            .map(|(_, v)| v.as_str())
                    };
                    let kind = match find("streamtype") {
                        Some("stdin") => SpdyStream::Stdin,
                        Some("stdout") => SpdyStream::Stdout,
                        Some("stderr") => SpdyStream::Stderr,
                        Some("error") => SpdyStream::Error,
                        Some("resize") => SpdyStream::Resize,
                        Some("data") => SpdyStream::Data,
                        _ => SpdyStream::Other,
                    };
                    // A long port-forward opens two streams per forwarded
                    // connection and never says when one is done. Forget the
                    // oldest rather than fail a healthy forward.
                    if self.spdy_streams.len() >= 1024
                        && let Some(oldest) = self.spdy_streams.keys().next().copied()
                    {
                        self.spdy_streams.remove(&oldest);
                    }
                    self.spdy_streams.insert(stream_id, kind);
                    if let Some(port) = find("port").and_then(|p| p.parse::<u16>().ok())
                        && self.ports.insert(port)
                    {
                        events.push(Event::Port(port));
                    }
                }
                Frame::Data {
                    stream_id, data, ..
                } => {
                    if self.spdy_streams.get(&stream_id) == Some(&SpdyStream::Resize)
                        && let Some(resize) = parse_resize(&data)
                    {
                        events.push(resize);
                    }
                }
                Frame::Other => {}
            }
        }
    }

    fn spdy_server_frames(&self, frames: Vec<Frame>, events: &mut Vec<Event>) {
        for frame in frames {
            let Frame::Data {
                stream_id, data, ..
            } = frame
            else {
                continue;
            };
            match self.spdy_streams.get(&stream_id) {
                Some(SpdyStream::Stdout | SpdyStream::Stderr) if !data.is_empty() => {
                    if !self.port_forward {
                        events.push(Event::Output(data));
                    }
                }
                Some(SpdyStream::Error) if !self.port_forward => {
                    events.extend(parse_status(&data).map(Event::Exit));
                }
                _ => {}
            }
        }
    }
}

/// `{"Width":120,"Height":40}`.
fn parse_resize(body: &[u8]) -> Option<Event> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let cols = u32::try_from(v.get("Width")?.as_u64()?).ok()?;
    let rows = u32::try_from(v.get("Height")?.as_u64()?).ok()?;
    Some(Event::Resize { cols, rows })
}

/// The exit status in the error channel's `metav1.Status`.
///
/// `Success` is 0. `NonZeroExitCode` carries the code in a cause with reason
/// `ExitCode`. Any other failure (a signal, a broken exec) is reported as 1.
fn parse_status(body: &[u8]) -> Option<u32> {
    if body.is_empty() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    match v.get("status")?.as_str()? {
        "Success" => Some(0),
        "Failure" => Some(
            v.pointer("/details/causes")
                .and_then(|c| c.as_array())
                .into_iter()
                .flatten()
                .find(|c| c.get("reason").and_then(|r| r.as_str()) == Some("ExitCode"))
                .and_then(|c| c.get("message")?.as_str()?.parse().ok())
                .unwrap_or(1),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spdy::build::{Compressor, data};

    fn server_msg(channel: u8, body: &[u8]) -> Vec<u8> {
        let mut payload = vec![channel];
        payload.extend(body);
        ws::encode(Sender::Server, 0x2, &payload)
    }

    #[test]
    fn websocket_exec_yields_output_resize_and_exit() {
        let mut d = StreamDecoder::new(StreamKind::ExecWebSocket);
        let mut stdin = vec![0u8];
        stdin.extend(b"secret typed\n");
        assert_eq!(
            d.client(&ws::encode(Sender::Client, 0x2, &stdin))
                .expect("client"),
            [],
            "stdin is never an event: it can hold passwords"
        );
        let mut resize = vec![4u8];
        resize.extend(br#"{"Width":132,"Height":43}"#);
        assert_eq!(
            d.client(&ws::encode(Sender::Client, 0x2, &resize))
                .expect("client"),
            [Event::Resize {
                cols: 132,
                rows: 43
            }]
        );
        let mut wire = server_msg(1, b"hello\r\n");
        wire.extend(server_msg(2, b"oops\r\n"));
        wire.extend(server_msg(
            3,
            br#"{"metadata":{},"status":"Failure","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"3"}]}}"#,
        ));
        assert_eq!(
            d.server(&wire).expect("server"),
            [
                Event::Output(b"hello\r\n".to_vec()),
                Event::Output(b"oops\r\n".to_vec()),
                Event::Exit(3)
            ]
        );
        assert_eq!(
            d.server(&server_msg(3, br#"{"status":"Success"}"#))
                .expect("server"),
            [Event::Exit(0)]
        );
    }

    /// A long port-forward opens two streams per forwarded connection and never
    /// closes them from our point of view; it must not die at a fixed count.
    #[test]
    fn a_busy_spdy_port_forward_outlives_a_thousand_streams() {
        let mut d = StreamDecoder::new(StreamKind::PortForwardSpdy);
        let mut z = Compressor::default();
        let mut ports = std::collections::BTreeSet::new();
        for pair in 0..1500u32 {
            let (data_id, error_id) = (2 * pair * 2 + 1, 2 * pair * 2 + 3);
            let mut wire = z.syn_stream(
                data_id,
                &[
                    ("streamtype", "data"),
                    ("port", "8080"),
                    ("requestid", &pair.to_string()),
                ],
            );
            wire.extend(z.syn_stream(error_id, &[("streamtype", "error"), ("port", "8080")]));
            let events = d.client(&wire).expect("no limit on forwarded connections");
            ports.extend(events.into_iter().filter_map(|e| match e {
                Event::Port(p) => Some(p),
                _ => None,
            }));
        }
        assert_eq!(ports.into_iter().collect::<Vec<_>>(), [8080]);
    }

    #[test]
    fn spdy_exec_follows_stream_types() {
        let mut d = StreamDecoder::new(StreamKind::ExecSpdy);
        let mut z = Compressor::default();
        let mut open = Vec::new();
        for (id, kind) in [
            (1, "error"),
            (3, "stdin"),
            (5, "stdout"),
            (7, "stderr"),
            (9, "resize"),
        ] {
            open.extend(z.syn_stream(id, &[("streamtype", kind)]));
        }
        open.extend(data(3, false, b"password\n"));
        open.extend(data(9, false, br#"{"Width":90,"Height":30}"#));
        assert_eq!(
            d.client(&open).expect("client"),
            [Event::Resize { cols: 90, rows: 30 }]
        );
        let mut wire = data(5, false, b"out");
        wire.extend(data(7, false, b"err"));
        wire.extend(data(1, true, br#"{"status":"Success"}"#));
        assert_eq!(
            d.server(&wire).expect("server"),
            [
                Event::Output(b"out".to_vec()),
                Event::Output(b"err".to_vec()),
                Event::Exit(0)
            ]
        );
    }

    #[test]
    fn port_forward_reports_ports_and_never_output() {
        let mut ws = StreamDecoder::new(StreamKind::PortForwardWebSocket);
        let mut wire = server_msg(0, &8080u16.to_le_bytes());
        wire.extend(server_msg(1, &8080u16.to_le_bytes()));
        wire.extend(server_msg(0, b"HTTP/1.1 200 OK"));
        assert_eq!(ws.server(&wire).expect("server"), [Event::Port(8080)]);

        let mut spdy = StreamDecoder::new(StreamKind::PortForwardSpdy);
        let mut z = Compressor::default();
        let mut open = z.syn_stream(1, &[("streamtype", "error"), ("port", "9090")]);
        open.extend(z.syn_stream(3, &[("streamtype", "data"), ("port", "9090")]));
        assert_eq!(spdy.client(&open).expect("client"), [Event::Port(9090)]);
        assert_eq!(
            spdy.server(&data(3, false, b"payload")).expect("server"),
            []
        );
    }

    #[test]
    fn spdy_port_forward_inside_websocket_messages() {
        let mut d = StreamDecoder::new(StreamKind::PortForwardSpdyOverWebSocket);
        let mut z = Compressor::default();
        let frames = z.syn_stream(1, &[("streamtype", "error"), ("port", "8080")]);
        // The same bytes, split across two client messages.
        let (a, b) = frames.split_at(10);
        let mut wire = ws::encode(Sender::Client, 0x2, a);
        wire.extend(ws::encode(Sender::Client, 0x2, b));
        assert_eq!(d.client(&wire).expect("client"), [Event::Port(8080)]);
        let reply = ws::encode(Sender::Server, 0x2, &data(1, false, b"x"));
        assert_eq!(d.server(&reply).expect("server"), []);
    }

    #[test]
    fn undecodable_streams_are_errors() {
        let mut d = StreamDecoder::new(StreamKind::ExecWebSocket);
        assert!(d.server(&[0xC2, 0]).is_err());
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // test noise and tiny test frames
mod robustness {
    use super::*;
    use crate::spdy::build::{Compressor, data};

    /// xorshift: deterministic noise without a dependency.
    struct Noise(u64);
    impl Noise {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| (self.next() >> 24) as u8).collect()
        }
    }

    const KINDS: [StreamKind; 5] = [
        StreamKind::ExecWebSocket,
        StreamKind::ExecSpdy,
        StreamKind::PortForwardWebSocket,
        StreamKind::PortForwardSpdy,
        StreamKind::PortForwardSpdyOverWebSocket,
    ];

    /// Whatever arrives, the decoders return events or an error. They do not
    /// panic, and they do not grow without bound.
    #[test]
    fn random_bytes_in_random_chunks_never_panic() {
        let mut noise = Noise(0x9e37_79b9_7f4a_7c15);
        for round in 0..4000 {
            let mut d = StreamDecoder::new(KINDS[round % KINDS.len()]);
            for _ in 0..=(noise.next() % 6) {
                let n = (noise.next() % 400) as usize;
                let mut chunk = noise.bytes(n);
                // Bias some chunks toward plausible headers so deeper states are reached.
                if noise.next().is_multiple_of(3) && chunk.len() > 8 {
                    chunk[..4].copy_from_slice(if noise.next().is_multiple_of(2) {
                        &[0x80, 0x03, 0x00, 0x01]
                    } else {
                        &[0x82, 0x7e, 0x00, 0x10]
                    });
                }
                let _ = d.client(&chunk);
                let _ = d.server(&chunk);
            }
        }
    }

    /// A valid stream cut at every byte, and fed one byte at a time, gives
    /// the same events as when it arrives whole.
    #[test]
    fn valid_streams_decode_the_same_however_they_are_split() {
        let mut z = Compressor::default();
        let mut client = z.syn_stream(1, &[("streamtype", "error")]);
        client.extend(z.syn_stream(3, &[("streamtype", "resize")]));
        client.extend(data(3, false, br#"{"Width":80,"Height":24}"#));
        let mut server = data(1, false, br#"{"status":"Success"}"#);
        server.extend(data(5, false, b"unknown stream"));

        let whole = {
            let mut d = StreamDecoder::new(StreamKind::ExecSpdy);
            let mut ev = d.client(&client).expect("client");
            ev.extend(d.server(&server).expect("server"));
            ev
        };
        assert_eq!(
            whole,
            [Event::Resize { cols: 80, rows: 24 }, Event::Exit(0)]
        );
        for split in 0..client.len() {
            let mut d = StreamDecoder::new(StreamKind::ExecSpdy);
            let mut ev = d.client(&client[..split]).expect("first half");
            ev.extend(d.client(&client[split..]).expect("second half"));
            ev.extend(d.server(&server).expect("server"));
            assert_eq!(ev, whole, "split at {split}");
        }
    }

    /// A header block that inflates to far more than it should is refused
    /// without allocating what it claims.
    #[test]
    fn a_header_compression_bomb_is_refused() {
        use flate2::{Compress, Compression, FlushCompress};
        let mut z = Compress::new(Compression::best(), true);
        z.set_dictionary(&crate::spdy_dictionary::HEADER_DICTIONARY)
            .expect("dictionary");
        let zeros = vec![0u8; 8 * 1024 * 1024];
        let mut block = Vec::with_capacity(64 * 1024);
        z.compress_vec(&zeros, &mut block, FlushCompress::Sync)
            .expect("compress");
        assert!(
            block.len() < 20_000,
            "the bomb is small on the wire: {}",
            block.len()
        );
        let mut payload = 1u32.to_be_bytes().to_vec();
        payload.extend([0u8; 6]);
        payload.extend(&block);
        let mut frame = vec![0x80, 3, 0, 1, 0];
        frame.extend(&(payload.len() as u32).to_be_bytes()[1..]);
        frame.extend(&payload);
        let mut d = StreamDecoder::new(StreamKind::ExecSpdy);
        assert!(
            d.client(&frame).is_err(),
            "inflating 8 MiB of headers must fail"
        );
    }
}

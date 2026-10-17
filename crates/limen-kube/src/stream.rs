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
                self.spdy_client_frames(frames, &mut events)?;
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
                self.spdy_client_frames(frames, &mut events)?;
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

    fn spdy_client_frames(
        &mut self,
        frames: Vec<Frame>,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
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
                    if self.spdy_streams.len() >= 1024 {
                        return Err(Error::Spdy("too many streams"));
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
        Ok(())
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

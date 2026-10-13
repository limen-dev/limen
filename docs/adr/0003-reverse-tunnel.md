# ADR-0003: Reverse tunnel with gRPC served by the worker over an outbound connection

- Status: Proposed
- Date: 2026-10-13

## Context
Workers must not open inbound ports. The proxy has to open many concurrent sessions to a worker with per-stream flow control, heartbeats, and graceful drain.

## Options
1. **Worker dials over TLS, then serves HTTP/2 gRPC on that connection** (the roles flip after the handshake). (Chosen.)
2. SSH reverse tunnel (Teleport style). This adds a second auth system and key type for the transport.
3. A custom multiplexer (yamux) under gRPC. Extra framing, and a less-used crate.
4. Worker-initiated bidirectional gRPC stream with our own sub-stream multiplexing inside it. This reinvents HTTP/2 stream flow control.

## Decision
Option 1.
- The worker connects to the proxy NLB with ALPN `limen-tunnel/1`, presenting its internal-CA worker cert and verifying the proxy cert.
- After the TLS handshake, the worker runs `tonic` server on the established stream (`serve_with_incoming` with a single-connection stream), and the proxy runs a `tonic` client over the accepted TLS stream.
- Each session is one `OpenSession` bidirectional stream of `TunnelFrame`s.
- Reconnect uses full-jitter exponential backoff (1 s base, 60 s cap). Liveness uses HTTP/2 keepalive PING plus a `Ping` RPC every 15 s, with a 45 s timeout.
- Each worker holds 2 tunnels by default. Drain is signaled through `PingResponse.draining`.

## Consequences
- \+ Standard HTTP/2 multiplexing and flow control. Backpressure comes for free. Tooling (tracing, metrics) is shared with every other gRPC surface.
- − Running a tonic server over an outbound connection is less common. A Phase 1 spike must prove it, including h2 keepalive and the max concurrent streams setting.
- *Assumption to verify in Phase 1:* the tonic 0.14 `Server::serve_with_incoming` API accepts a custom `AsyncRead + AsyncWrite` stream that implements `Connected`.

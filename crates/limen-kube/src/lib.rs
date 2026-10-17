//! Kubernetes protocol pieces for the Limen worker (ADR-0033).
//!
//! - [`info`]: which verb, resource, namespace, and name an API request is for.
//! - [`ws`] and [`spdy`]: passive decoders for the two stream protocols
//!   `kubectl exec`, `attach`, and `port-forward` upgrade to. They never change
//!   the bytes; the worker forwards those untouched and decodes a copy.
//! - [`stream`]: turns decoded frames into what a recording needs (output,
//!   resizes, the exit status).
//!
//! Everything here is pure and synchronous so it can be unit-tested and fuzzed
//! without a cluster. Malformed input is an error, never a panic.

pub mod info;
pub mod spdy;
mod spdy_dictionary;
pub mod stream;
pub mod ws;

pub use info::RequestInfo;
pub use stream::{Event, StreamDecoder, StreamKind};

/// A stream could not be decoded. The worker ends the session: a stream it
/// cannot read is a stream it cannot record.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed WebSocket frame: {0}")]
    WebSocket(&'static str),
    #[error("malformed SPDY frame: {0}")]
    Spdy(&'static str),
    #[error("SPDY header block: {0}")]
    SpdyHeaders(String),
}

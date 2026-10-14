//! Generated protobuf and gRPC types. The sources live in `proto/`.

#[allow(clippy::pedantic, missing_debug_implementations)]
pub mod v1 {
    tonic::include_proto!("limen.v1");
}

/// Metadata the proxy adds to requests it relays to the control plane. The
/// proxy strips any client-supplied copies first.
pub mod relay {
    /// Present on every relayed request.
    pub const FORWARDED: &str = "x-limen-forwarded";
    /// Base64 (standard, padded) DER of the client certificate, when one was presented.
    pub const CLIENT_CERT: &str = "x-limen-client-cert";
    /// Client socket address as the proxy saw it.
    pub const CLIENT_ADDR: &str = "x-limen-client-addr";
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::v1::{SessionOpen, TunnelFrame, tunnel_frame::Frame};

    #[test]
    fn tunnel_frame_round_trips() {
        let frame = TunnelFrame {
            frame: Some(Frame::Open(SessionOpen {
                signed_grant: vec![1, 2, 3],
            })),
        };
        let bytes = frame.encode_to_vec();
        let decoded = TunnelFrame::decode(bytes.as_slice()).expect("decode");
        assert_eq!(decoded, frame);
    }
}

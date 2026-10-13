//! Generated protobuf and gRPC types. The sources live in `proto/`.

#[allow(clippy::pedantic, missing_debug_implementations)]
pub mod v1 {
    tonic::include_proto!("limen.v1");
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

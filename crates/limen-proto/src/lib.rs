//! Generated protobuf and gRPC types. The sources live in `proto/`.

#[allow(clippy::pedantic, missing_debug_implementations)]
pub mod v1 {
    tonic::include_proto!("limen.v1");
}

/// The management API (ADR-0042), kept compatible: see `proto/limen/manage/v1`.
pub mod manage {
    #[allow(clippy::pedantic, missing_debug_implementations)]
    pub mod v1 {
        tonic::include_proto!("limen.manage.v1");
    }
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

    use super::v1::{SessionOpen, Signed, TunnelFrame, tunnel_frame::Frame};

    #[test]
    fn tunnel_frame_round_trips() {
        let frame = TunnelFrame {
            frame: Some(Frame::Open(SessionOpen {
                traceparent: String::new(),
                grant: Some(Signed {
                    payload: vec![1, 2, 3],
                    signature: vec![4],
                    signer_cert_der: vec![5],
                }),
            })),
        };
        let bytes = frame.encode_to_vec();
        let decoded = TunnelFrame::decode(bytes.as_slice()).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn management_batch_round_trips() {
        use super::manage::v1::{
            BatchWriteRequest, CreateDocumentRequest, DeleteDocumentRequest, Document,
            DocumentKind, Ownership, Write, WriteOptions, write::Operation,
        };

        let request = BatchWriteRequest {
            writes: vec![
                Write {
                    operation: Some(Operation::Create(CreateDocumentRequest {
                        document: Some(Document {
                            kind: DocumentKind::Resource.into(),
                            name: "payments-orders-db".into(),
                            spec_json:
                                r#"{"postgres":{"endpoint":"orders.payments.internal:5432"}}"#
                                    .into(),
                            profile: "payments-postgres".into(),
                            ..Document::default()
                        }),
                        ownership: Some(Ownership {
                            source: "terraform/payments-prod".into(),
                            namespace: "payments".into(),
                            ..Ownership::default()
                        }),
                        options: None,
                    })),
                },
                Write {
                    operation: Some(Operation::Delete(DeleteDocumentRequest {
                        kind: DocumentKind::Resource.into(),
                        name: "payments-old-db".into(),
                        etag: "e1".into(),
                        ..DeleteDocumentRequest::default()
                    })),
                },
            ],
            options: Some(WriteOptions {
                validate_only: true,
                request_id: "4b1c9a4e-6a52-4c86-9f39-2f4a3f1f5e10".into(),
                ..WriteOptions::default()
            }),
        };
        let bytes = request.encode_to_vec();
        let decoded = BatchWriteRequest::decode(bytes.as_slice()).expect("decode");
        assert_eq!(decoded, request);
    }

    /// Clients match on `ErrorInfo.reason`, the value's name without its
    /// prefix (manage.proto). A rename is a breaking change.
    #[test]
    fn error_reasons_keep_their_names() {
        use super::manage::v1::ErrorReason;

        let reason = |r: ErrorReason| {
            r.as_str_name()
                .strip_prefix("ERROR_REASON_")
                .expect("prefix")
                .to_owned()
        };
        assert_eq!(reason(ErrorReason::EtagMismatch), "ETAG_MISMATCH");
        assert_eq!(reason(ErrorReason::OwnedElsewhere), "OWNED_ELSEWHERE");
        assert_eq!(reason(ErrorReason::OutsideGrant), "OUTSIDE_GRANT");
        assert_eq!(reason(ErrorReason::AuditUnavailable), "AUDIT_UNAVAILABLE");
        assert_eq!(
            reason(ErrorReason::ChangeNotDecidable),
            "CHANGE_NOT_DECIDABLE"
        );
    }
}

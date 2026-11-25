//! Length-prefixed protobuf messages on a byte stream: a big-endian `u32`
//! length, then the encoded message. Used for the session handshake on
//! client streams (`SessionRequest`, `SessionResponse`) before the stream
//! switches to raw protocol bytes.

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Handshake messages are small. Anything bigger is a protocol error.
pub const MAX_MESSAGE: u32 = 16 * 1024;

pub async fn write_message<W: AsyncWrite + Unpin, M: Message>(
    w: &mut W,
    message: &M,
) -> std::io::Result<()> {
    let bytes = message.encode_to_vec();
    let len = u32::try_from(bytes.len()).map_err(|_| std::io::Error::other("message too large"))?;
    if len > MAX_MESSAGE {
        return Err(std::io::Error::other("message too large"));
    }
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await
}

pub async fn read_message<R: AsyncRead + Unpin, M: Message + Default>(
    r: &mut R,
) -> std::io::Result<M> {
    let len = r.read_u32().await?;
    if len > MAX_MESSAGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    M::decode(buf.as_slice()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use limen_proto::v1::SessionRequest;

    use super::*;

    #[tokio::test]
    async fn round_trip_and_size_limit() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let req = SessionRequest {
            resource: "web-1".into(),
            principal: "ubuntu".into(),
            database: String::new(),
            group: String::new(),
        };
        write_message(&mut a, &req).await.expect("write");
        let got: SessionRequest = read_message(&mut b).await.expect("read");
        assert_eq!(got, req);

        a.write_all(&(MAX_MESSAGE + 1).to_be_bytes())
            .await
            .expect("write len");
        let err = read_message::<_, SessionRequest>(&mut b)
            .await
            .expect_err("too large");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    fn request_of_encoded_len(len: usize) -> SessionRequest {
        // Field 1 (tag byte) + a two-byte varint length + the string.
        let req = SessionRequest {
            resource: "r".repeat(len - 3),
            ..SessionRequest::default()
        };
        assert_eq!(req.encoded_len(), len, "the fixture's size is exact");
        req
    }

    /// The limit is inclusive on both sides: a message of exactly
    /// `MAX_MESSAGE` bytes goes through, one byte more is refused by the
    /// writer before anything reaches the stream.
    #[tokio::test]
    async fn the_size_limit_holds_to_the_byte_on_both_sides() {
        let max = MAX_MESSAGE as usize;
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let at_limit = request_of_encoded_len(max);
        write_message(&mut a, &at_limit)
            .await
            .expect("at the limit");
        let got: SessionRequest = read_message(&mut b).await.expect("read at the limit");
        assert_eq!(got, at_limit);

        let over = request_of_encoded_len(max + 1);
        write_message(&mut a, &over)
            .await
            .expect_err("one byte over");
        drop(a);
        // Nothing was written for the refused message, not even its length.
        let mut rest = Vec::new();
        b.read_to_end(&mut rest).await.expect("read rest");
        assert!(rest.is_empty(), "wrote {} bytes", rest.len());
    }

    /// A peer that sends less than it announced, or bytes that are not the
    /// message, gets an error rather than a default (empty) request.
    #[tokio::test]
    async fn truncated_or_malformed_messages_are_errors() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(&10u32.to_be_bytes()).await.expect("len");
        a.write_all(b"short").await.expect("body");
        drop(a);
        let err = read_message::<_, SessionRequest>(&mut b)
            .await
            .expect_err("truncated");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

        // A length-delimited field that runs past the end of the message.
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(&2u32.to_be_bytes()).await.expect("len");
        a.write_all(&[0x0a, 0x7f]).await.expect("body");
        let err = read_message::<_, SessionRequest>(&mut b)
            .await
            .expect_err("malformed");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        // A cut-off length prefix is an error too.
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(&[0, 0]).await.expect("half a length");
        drop(a);
        let err = read_message::<_, SessionRequest>(&mut b)
            .await
            .expect_err("half a length");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}

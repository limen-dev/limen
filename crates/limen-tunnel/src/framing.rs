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
}

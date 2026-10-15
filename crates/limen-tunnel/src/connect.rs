//! A tonic connector that dials TCP and does TLS with our own rustls config,
//! so every Limen client uses the same TLS setup.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Shared, swappable client TLS config. Swapped when a component renews its
/// certificate. Existing connections keep their old config.
#[derive(Debug, Clone)]
pub struct SharedClientConfig(Arc<RwLock<Arc<ClientConfig>>>);

impl SharedClientConfig {
    #[must_use]
    pub fn new(config: ClientConfig) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(config))))
    }

    #[must_use]
    pub fn get(&self) -> Arc<ClientConfig> {
        Arc::clone(
            &self
                .0
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    pub fn set(&self, config: ClientConfig) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(config);
    }
}

/// Dial `addr` (`host:port`) and do TLS, checking the server certificate against `server_name`.
///
/// The name is resolved on every call, so a reconnect can reach a replica
/// that DNS started returning since the last one. When it resolves to several
/// addresses they are tried in random order, so clients spread over them,
/// falling through to the next address when one fails.
pub async fn dial(
    addr: &str,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> std::io::Result<TlsStream<TcpStream>> {
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let tcp = connect_in_order(&shuffled(resolve(addr).await?)).await?;
    tcp.set_nodelay(true)?;
    TlsConnector::from(config).connect(name, tcp).await
}

/// How long one address may take to accept before the next one is tried.
/// The last address gets the caller's whole budget.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);

/// Resolve `addr` (`host:port`), honouring test overrides.
async fn resolve(addr: &str) -> std::io::Result<Vec<SocketAddr>> {
    #[cfg(any(test, feature = "test-hooks"))]
    if let Some(addrs) = test_resolution(addr) {
        return Ok(addrs);
    }
    Ok(tokio::net::lookup_host(addr).await?.collect())
}

fn shuffled(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    use rand::seq::SliceRandom as _;
    addrs.shuffle(&mut rand::rng());
    addrs
}

/// Connect to the first of `addrs` that accepts. Returns the last error when
/// none does.
async fn connect_in_order(addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut last = None;
    for (i, addr) in addrs.iter().enumerate() {
        let attempt = TcpStream::connect(addr);
        let result = if i + 1 == addrs.len() {
            attempt.await
        } else {
            tokio::time::timeout(ATTEMPT_TIMEOUT, attempt)
                .await
                .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()))
        };
        match result {
            Ok(tcp) => return Ok(tcp),
            Err(e) => {
                tracing::debug!(%addr, error = %e, "connect failed; trying the next address");
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "the name resolved to no address",
        )
    }))
}

#[cfg(any(test, feature = "test-hooks"))]
static TEST_RESOLUTION: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, Vec<SocketAddr>>>,
> = std::sync::LazyLock::new(std::sync::Mutex::default);

/// Tests only: make `addr` (`host:port`, exactly as dialed) resolve to
/// `addrs` instead of asking DNS. Lets a test stand up several replicas
/// behind one name without a DNS server.
#[cfg(any(test, feature = "test-hooks"))]
pub fn set_test_resolution(addr: &str, addrs: Vec<SocketAddr>) {
    TEST_RESOLUTION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(addr.to_owned(), addrs);
}

#[cfg(any(test, feature = "test-hooks"))]
fn test_resolution(addr: &str) -> Option<Vec<SocketAddr>> {
    TEST_RESOLUTION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(addr)
        .cloned()
}

/// True when a call failed because its connection went away (the server
/// closed it, sent GOAWAY, or refused the stream), not because the server
/// answered. A server closes connections on purpose (maximum connection age,
/// shutdown), so this is a reason to reconnect, not an error.
#[must_use]
pub fn went_away(status: &tonic::Status) -> bool {
    let mut source = std::error::Error::source(status);
    while let Some(e) = source {
        if let Some(e) = e.downcast_ref::<hyper::Error>() {
            return e.is_canceled()
                || e.is_closed()
                || std::error::Error::source(e).is_some_and(graceful_h2);
        }
        source = e.source();
    }
    false
}

/// A GOAWAY without an error, or a stream the server refused before acting
/// on it. h2 is not a direct dependency, so this reads its messages (the
/// reason descriptions are fixed by RFC 9113 names; a test with a real
/// GOAWAY keeps this honest).
fn graceful_h2(e: &(dyn std::error::Error + 'static)) -> bool {
    let text = e.to_string();
    text == "connection error received: not a result of an error"
        || text == "stream error received: refused stream before processing any application logic"
}

/// Run `call`; if it failed because the connection went away, log that at
/// info and run it once more at once (a lazy channel redials, and so
/// re-resolves, on its next use). Only for calls that are safe to repeat.
pub async fn retry_if_went_away<T, F, Fut>(what: &str, mut call: F) -> Result<T, tonic::Status>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, tonic::Status>>,
{
    match call().await {
        Err(status) if went_away(&status) => {
            tracing::info!(call = %what, reason = %status.message(), "connection closed by the server; reconnecting");
            call().await
        }
        result => result,
    }
}

/// `tower::Service<Uri>` for `tonic::transport::Endpoint::connect_with_connector`.
/// It ignores the URI and always dials the configured address.
#[derive(Debug, Clone)]
pub struct TlsConnectorService {
    addr: Arc<str>,
    server_name: Arc<str>,
    config: SharedClientConfig,
}

impl TlsConnectorService {
    #[must_use]
    pub fn new(addr: &str, server_name: &str, config: SharedClientConfig) -> Self {
        Self {
            addr: addr.into(),
            server_name: server_name.into(),
            config,
        }
    }
}

impl tower::Service<Uri> for TlsConnectorService {
    type Response = TokioIo<TlsStream<TcpStream>>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let (addr, name, config) = (
            Arc::clone(&self.addr),
            Arc::clone(&self.server_name),
            self.config.get(),
        );
        Box::pin(async move { dial(&addr, &name, config).await.map(TokioIo::new) })
    }
}

/// A tonic channel over a TLS connection the caller already made (and could
/// inspect, e.g. to check the peer's identity). The channel never redials:
/// once the connection drops, calls on it fail.
pub async fn channel_over(
    stream: TlsStream<TcpStream>,
) -> Result<tonic::transport::Channel, tonic::transport::Error> {
    let slot = Arc::new(std::sync::Mutex::new(Some(TokioIo::new(stream))));
    let connector = tower::service_fn(move |_: Uri| {
        let taken = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        async move { taken.ok_or_else(|| std::io::Error::other("connection already used")) }
    });
    tonic::transport::Endpoint::from_static("http://limen.invalid")
        .connect_with_connector(connector)
        .await
}

/// A lazily connecting tonic channel over our TLS, with HTTP/2 keepalives.
#[must_use]
pub fn channel(
    addr: &str,
    server_name: &str,
    config: SharedClientConfig,
) -> tonic::transport::Channel {
    // The scheme is http because TLS is done by the connector, not by tonic.
    tonic::transport::Endpoint::from_static("http://limen.invalid")
        .connect_timeout(std::time::Duration::from_secs(10))
        .http2_keep_alive_interval(std::time::Duration::from_secs(15))
        .keep_alive_timeout(std::time::Duration::from_secs(45))
        .keep_alive_while_idle(true)
        .connect_with_connector_lazy(TlsConnectorService::new(addr, server_name, config))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Mutex;

    use limen_proto::v1::PingRequest;
    use limen_proto::v1::worker_tunnel_client::WorkerTunnelClient;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn connect_falls_through_to_the_next_address() {
        let live = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let live_addr = live.local_addr().expect("addr");
        // A port nobody listens on: bind, note the port, close.
        let dead_addr = {
            let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            l.local_addr().expect("addr")
        };
        let tcp = connect_in_order(&[dead_addr, live_addr])
            .await
            .expect("falls through");
        assert_eq!(tcp.peer_addr().expect("peer"), live_addr);
        let err = connect_in_order(&[dead_addr])
            .await
            .expect_err("nothing listens");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
        assert!(
            connect_in_order(&[]).await.is_err(),
            "no address is an error"
        );
    }

    #[test]
    fn every_resolved_address_gets_picked_first_sometimes() {
        let addrs: Vec<SocketAddr> = (1..=3)
            .map(|p| SocketAddr::from(([127, 0, 0, 1], p)))
            .collect();
        let mut firsts = std::collections::HashSet::new();
        for _ in 0..200 {
            firsts.insert(shuffled(addrs.clone())[0]);
        }
        assert_eq!(firsts.len(), 3, "load spreads over every address");
    }

    #[tokio::test]
    async fn overridden_names_resolve_to_the_given_addresses() {
        let name = format!("cp-{}.limen.test:3080", std::process::id());
        let addrs = vec![
            SocketAddr::from(([127, 0, 0, 1], 1)),
            SocketAddr::from(([127, 0, 0, 1], 2)),
        ];
        set_test_resolution(&name, addrs.clone());
        let mut got = resolve(&name).await.expect("resolves");
        got.sort();
        assert_eq!(got, addrs);
        let real = resolve("127.0.0.1:9").await.expect("resolves");
        assert_eq!(real, vec![SocketAddr::from(([127, 0, 0, 1], 9))]);
    }

    /// A server that answers the HTTP/2 preface and then sends GOAWAY with
    /// last stream 0 and error code `reason`. With `NO_ERROR` (0) this is
    /// what a client sees when its request crosses a graceful close.
    async fn goaway_server(reason: u8) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut preface = [0u8; 24];
                    if tcp.read_exact(&mut preface).await.is_err() {
                        return;
                    }
                    // SETTINGS (empty), then wait for the client's first HEADERS.
                    let _ = tcp.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await;
                    loop {
                        let mut head = [0u8; 9];
                        if tcp.read_exact(&mut head).await.is_err() {
                            return;
                        }
                        let len = usize::from(head[0]) << 16
                            | usize::from(head[1]) << 8
                            | usize::from(head[2]);
                        let mut payload = vec![0u8; len];
                        if tcp.read_exact(&mut payload).await.is_err() {
                            return;
                        }
                        match head[3] {
                            // SETTINGS without ACK: acknowledge.
                            4 if head[4] & 1 == 0 => {
                                let _ = tcp.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).await;
                            }
                            // HEADERS: refuse it with GOAWAY(last stream 0, reason).
                            1 => {
                                let _ = tcp
                                    .write_all(&[
                                        0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, reason,
                                    ])
                                    .await;
                                let _ = tcp.flush().await;
                                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                return;
                            }
                            _ => {}
                        }
                    }
                });
            }
        });
        addr
    }

    fn plain_channel(addr: SocketAddr) -> tonic::transport::Channel {
        tonic::transport::Endpoint::from_static("http://limen.invalid").connect_with_connector_lazy(
            tower::service_fn(move |_: Uri| async move {
                TcpStream::connect(addr).await.map(TokioIo::new)
            }),
        )
    }

    #[tokio::test]
    async fn a_request_refused_by_goaway_counts_as_the_connection_going_away() {
        let addr = goaway_server(0).await;
        let status = WorkerTunnelClient::new(plain_channel(addr))
            .ping(PingRequest {})
            .await
            .expect_err("refused");
        assert!(
            went_away(&status),
            "GOAWAY must classify as a reconnect: {status:?}"
        );

        // A GOAWAY that reports an error (here PROTOCOL_ERROR) is a failure.
        let addr = goaway_server(1).await;
        let status = WorkerTunnelClient::new(plain_channel(addr))
            .ping(PingRequest {})
            .await
            .expect_err("refused");
        assert!(!went_away(&status), "{status:?}");
    }

    #[test]
    fn answers_from_the_server_do_not_count_as_the_connection_going_away() {
        for status in [
            tonic::Status::unavailable("worker is draining"),
            tonic::Status::internal("boom"),
            tonic::Status::permission_denied("no"),
        ] {
            assert!(!went_away(&status), "{status:?}");
        }
    }

    #[tokio::test]
    async fn a_call_that_crossed_a_graceful_close_is_sent_again_at_once() {
        let calls = Mutex::new(0u32);
        let goaway = goaway_server(0).await;
        let started = std::time::Instant::now();
        let result = retry_if_went_away("ping", || {
            let first = {
                let mut n = calls.lock().expect("lock");
                *n += 1;
                *n == 1
            };
            async move {
                if first {
                    WorkerTunnelClient::new(plain_channel(goaway))
                        .ping(PingRequest {})
                        .await
                        .map(|_| ())
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(*calls.lock().expect("lock"), 2);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "no backoff"
        );

        // A real answer is returned as is, without a second call.
        let calls = Mutex::new(0u32);
        let result: Result<(), _> = retry_if_went_away("ping", || {
            *calls.lock().expect("lock") += 1;
            async { Err(tonic::Status::permission_denied("no")) }
        })
        .await;
        assert_eq!(
            result.expect_err("denied").code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(*calls.lock().expect("lock"), 1);
    }
}

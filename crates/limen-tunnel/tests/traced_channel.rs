//! `TracedChannel` hands the calling span's `traceparent` to the callee, and
//! sends nothing outside an exported span.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use clap::Parser;
use futures::Stream;
use limen_core::telemetry::{LogArgs, current_traceparent};
use limen_proto::v1::worker_tunnel_client::WorkerTunnelClient;
use limen_proto::v1::worker_tunnel_server::{WorkerTunnel, WorkerTunnelServer};
use limen_proto::v1::{PingRequest, PingResponse, TunnelFrame};
use limen_tunnel::connect::TracedChannel;
use tonic::{Request, Response, Status, Streaming};
use tracing::Instrument as _;

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    log: LogArgs,
}

/// Records the `traceparent` header of each Ping.
struct Recorder(Arc<Mutex<Vec<Option<String>>>>);

#[tonic::async_trait]
impl WorkerTunnel for Recorder {
    type OpenSessionStream = Pin<Box<dyn Stream<Item = Result<TunnelFrame, Status>> + Send>>;

    async fn open_session(
        &self,
        _: Request<Streaming<TunnelFrame>>,
    ) -> Result<Response<Self::OpenSessionStream>, Status> {
        Err(Status::unimplemented("not needed"))
    }

    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        let header = request
            .metadata()
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        self.0.lock().expect("lock").push(header);
        Ok(Response::new(PingResponse::default()))
    }
}

async fn serve(seen: Arc<Mutex<Vec<Option<String>>>>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(WorkerTunnelServer::new(Recorder(seen)))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    addr
}

#[tokio::test]
async fn adds_the_callers_traceparent_only_inside_an_exported_span() {
    let cli = Cli::parse_from(["x", "--otlp-endpoint", "http://127.0.0.1:1"]);
    let _guard = cli.log.init("limen-traced-channel-test");

    let seen = Arc::new(Mutex::new(Vec::new()));
    let addr = serve(Arc::clone(&seen)).await;
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut client = WorkerTunnelClient::new(TracedChannel::new(channel));

    // Outside any exported span: no header.
    client.ping(PingRequest {}).await.expect("ping");

    // Inside one: the header carries that span's id.
    let span = limen_core::trace_span!("session");
    let expected = span.in_scope(current_traceparent).expect("traceparent");
    client
        .ping(PingRequest {})
        .instrument(span)
        .await
        .expect("ping");

    let seen = seen.lock().expect("lock");
    assert_eq!(seen.as_slice(), [None, Some(expected)]);
}

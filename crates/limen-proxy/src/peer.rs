//! Proxy peering (ADR-0004). Workers reach the proxies through a load
//! balancer, so a session can land on a proxy that doesn't hold a tunnel to
//! the right worker. That proxy then opens the session through the proxy
//! that does: it calls the same `WorkerTunnel` service on the peer, with the
//! worker ID in metadata, and the peer forwards the stream into its tunnel.
//!
//! Peers authenticate both ways with internal-CA certificates. The client
//! side pins the peer's identity (`proxy` + ID from the registry) rather than
//! a host name, since peer addresses are private and often IPs.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::Stream;
use limen_core::identity::ComponentKind;
use limen_proto::v1::registry_client::RegistryClient;
use limen_proto::v1::worker_tunnel_client::WorkerTunnelClient;
use limen_proto::v1::worker_tunnel_server::{WorkerTunnel, WorkerTunnelServer};
use limen_proto::v1::{ListTunnelsRequest, PeerTunnel, PingRequest, PingResponse, TunnelFrame};
use limen_tunnel::connect::TracedChannel as Channel;
use limen_tunnel::serve::{H2Settings, serve_h2};
use limen_tunnel::{PeerInfo, alpn};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};

use crate::Proxy;
use crate::tunnels::{Load, NoWorker, p2c};

/// Metadata naming the worker a peered session is for.
pub const WORKER_ID: &str = "x-limen-worker-id";

const REGISTRY_CACHE: Duration = Duration::from_secs(5);

// ---- Server side: forward a peer's session into a local tunnel --------------

pub(crate) async fn serve(proxy: &Proxy, tls: TlsStream<TcpStream>, peer: PeerInfo) {
    let Ok(internal_ca) = proxy.credentials().internal_ca() else {
        return;
    };
    let caller = peer
        .leaf()
        .map(|leaf| limen_ca::verify::verify_component(leaf, &internal_ca, false));
    match caller {
        Some(Ok(id)) if id.kind == ComponentKind::Proxy => {
            let routes = tonic::service::Routes::new(WorkerTunnelServer::new(Forwarder {
                proxy: proxy.clone(),
            }))
            .prepare();
            if let Err(e) = serve_h2(tls, peer, routes, H2Settings::default()).await {
                tracing::debug!(error = %e, peer = %id.id, "peer connection ended with error");
            }
        }
        other => {
            tracing::warn!(remote = ?peer.remote_addr, result = ?other.map(|r| r.map(|i| i.kind)), "rejected peer: not a proxy certificate");
        }
    }
}

struct Forwarder {
    proxy: Proxy,
}

type FrameStream = Pin<Box<dyn Stream<Item = Result<TunnelFrame, Status>> + Send>>;

#[tonic::async_trait]
impl WorkerTunnel for Forwarder {
    type OpenSessionStream = FrameStream;

    async fn open_session(
        &self,
        request: Request<Streaming<TunnelFrame>>,
    ) -> Result<Response<FrameStream>, Status> {
        let worker_id = request
            .metadata()
            .get(WORKER_ID)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Status::invalid_argument("missing worker id"))?
            .to_owned();
        // This proxy's view of the worker's load is the freshest: it counts
        // every session through its tunnels, peered ones included.
        let (channel, slot) = self
            .proxy
            .tunnels
            .reserve(&worker_id)
            .map_err(|why| match why {
                NoWorker::Full => {
                    Status::resource_exhausted(format!("no capacity: {worker_id} is full"))
                }
                NoWorker::None => Status::unavailable(format!("no tunnel to {worker_id} here")),
            })?;
        // The worker verifies the grant inside the stream; this proxy only relays.
        let inbound = request.into_inner().map_while(Result::ok);
        let response = match WorkerTunnelClient::new(channel).open_session(inbound).await {
            Ok(response) => response,
            Err(s) => {
                if s.code() == tonic::Code::ResourceExhausted {
                    // Our figure was stale; the peer tries another worker.
                    // Give back this slot first so it isn't counted.
                    drop(slot);
                    self.proxy.tunnels.mark_full(&worker_id);
                } else if limen_tunnel::refusal::is_draining(&s) {
                    // The peer tries another worker (the status, with its
                    // marker, goes back as is); stop choosing this one here.
                    drop(slot);
                    self.proxy.tunnels.remove_worker(&worker_id);
                }
                return Err(s);
            }
        };
        tracing::info!(worker = %worker_id, "relaying a peered session");
        // The slot lives as long as the stream back to the peer.
        let outbound = response.into_inner().map(move |frame| {
            let _ = &slot;
            frame
        });
        Ok(Response::new(Box::pin(outbound)))
    }

    async fn ping(&self, _request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        Err(Status::unimplemented("ping workers directly"))
    }
}

// ---- Client side: find a peer holding a suitable tunnel ---------------------

#[derive(Debug, Default)]
pub(crate) struct PeerState {
    tunnels: Mutex<Option<(Instant, Vec<PeerTunnel>)>>,
    channels: Mutex<HashMap<String, Channel>>,
}

/// A worker reachable through another proxy. Its load is counted by the
/// proxy holding the tunnel, while the session lasts.
pub(crate) struct Remote {
    pub worker_id: String,
    /// From the registry (the worker's certified name), if it has one.
    pub worker_name: Option<String>,
    pub proxy_id: String,
    pub channel: Channel,
}

/// Find a worker whose labels satisfy `accept` and that is not in
/// `exclude`, held by another proxy, chosen by [`p2c`] on the load the
/// holding proxies last reported.
pub(crate) async fn find(
    proxy: &Proxy,
    accept: impl Fn(&std::collections::BTreeMap<String, String>) -> bool,
    exclude: &[String],
) -> Result<Result<Remote, NoWorker>, Status> {
    let tunnels = registry(proxy).await?;
    let candidates: Vec<&PeerTunnel> = tunnels
        .iter()
        .filter(|t| {
            !t.peer_address.is_empty()
                && !exclude.contains(&t.worker_id)
                && accept(
                    &t.worker_labels
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                )
        })
        .collect();
    if candidates.is_empty() {
        return Ok(Err(NoWorker::None));
    }
    let Some(pick) = p2c(&candidates, |t| peer_load(t).ratio(), &mut rand::rng()) else {
        return Ok(Err(NoWorker::Full));
    };
    let channel = peer_channel(proxy, &pick.proxy_id, &pick.peer_address)
        .map_err(|e| Status::internal(e.to_string()))?;
    // Control planes before names send none; the certified label has it too.
    let worker_name = Some(pick.worker_name.as_str())
        .filter(|n| !n.is_empty())
        .or_else(|| {
            pick.worker_labels
                .get(limen_core::names::NAME_LABEL)
                .map(String::as_str)
        })
        .map(str::to_owned);
    Ok(Ok(Remote {
        worker_id: pick.worker_id.clone(),
        worker_name,
        proxy_id: pick.proxy_id.clone(),
        channel,
    }))
}

fn peer_load(t: &PeerTunnel) -> Load {
    Load {
        active: t.active_sessions,
        max: t.max_sessions,
    }
}

async fn registry(proxy: &Proxy) -> Result<Vec<PeerTunnel>, Status> {
    if let Some((at, tunnels)) = proxy
        .peers
        .tunnels
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        && at.elapsed() < REGISTRY_CACHE
    {
        return Ok(tunnels.clone());
    }
    let tunnels = RegistryClient::new(proxy.cp_channel())
        .list_tunnels(ListTunnelsRequest {})
        .await?
        .into_inner()
        .tunnels;
    *proxy
        .peers
        .tunnels
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some((Instant::now(), tunnels.clone()));
    Ok(tunnels)
}

fn peer_channel(proxy: &Proxy, proxy_id: &str, address: &str) -> anyhow::Result<Channel> {
    let mut channels = proxy
        .peers
        .channels
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(ch) = channels.get(proxy_id) {
        return Ok(ch.clone());
    }
    let creds = proxy.credentials();
    let provider = limen_tunnel::tls::provider();
    let verifier = PeerVerifier {
        internal_ca: creds.internal_ca()?,
        expected_id: proxy_id.to_owned(),
        provider: Arc::clone(&provider),
    };
    let identity = creds.tls_identity()?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(identity.certs, identity.key)?;
    config.alpn_protocols = vec![alpn::PEER.to_vec()];
    // The server name is not checked (see PeerVerifier); any valid name will do.
    let channel = limen_tunnel::connect::channel(
        address,
        "peer.limen.invalid",
        limen_tunnel::connect::SharedClientConfig::new(config),
    );
    channels.insert(proxy_id.to_owned(), channel.clone());
    Ok(channel)
}

/// Accepts exactly one peer: a proxy certificate from the internal CA with
/// the expected ID. Host names are not used.
#[derive(Debug)]
struct PeerVerifier {
    internal_ca: CertificateDer<'static>,
    expected_id: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let id = limen_ca::verify::verify_component(end_entity, &self.internal_ca, true)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        if id.kind == ComponentKind::Proxy && id.id == self.expected_id {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "expected proxy {}, got {} {}",
                self.expected_id, id.kind, id.id
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

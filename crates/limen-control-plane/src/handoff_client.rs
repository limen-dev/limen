//! Handing the unshipped part of the audit spool to a peer replica
//! (design §A, ephemeral mode).
//!
//! Every record some consumer has not yet passed is sent, from the lowest
//! consumer offset on: the receiver appends it to its own spool, where all of
//! its sinks process it. Each batch is committed for every consumer only once
//! the peer acks it as durable. A peer that fails mid-stream is dropped and
//! the next one gets everything not yet acked, so a record can arrive twice
//! (sinks deduplicate by `event_id`) but is never dropped.

use std::sync::Arc;
use std::time::Duration;

use limen_audit::spool::{Spool, SpoolError};
use limen_ca::ComponentCertRequest;
use limen_ca::verify::verify_component;
use limen_core::identity::ComponentKind;
use limen_proto::v1::HandoffBatch;
use limen_proto::v1::audit_handoff_client::AuditHandoffClient;
use limen_tunnel::tls::{Identity, client_config};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::ClientConfig;
use rustls_pki_types::CertificateDer;
use tokio::time::Instant;
use tokio_stream::StreamExt as _;

use crate::ca_store::Cas;
use crate::replicas::{self, Replica};
use crate::state::AppState;

/// Records per batch (the receiver's limit).
pub const BATCH_MAX: usize = 1000;
/// Payload bytes per batch; the receiver decodes messages up to 8 MiB.
const BATCH_BYTES: usize = 4 * 1024 * 1024;

/// Longest one step (connect, a peer's ack) may take before the peer is
/// given up on and the next is tried.
const STEP_TIMEOUT: Duration = Duration::from_secs(3);

/// Lifetime of the client certificate issued for one handoff.
const CLIENT_CERT_TTL: Duration = Duration::from_mins(10);

#[derive(Debug, thiserror::Error)]
pub enum HandoffError {
    #[error("no live peer replica to hand {left} audit records to")]
    NoPeers { left: u64 },
    #[error("handoff deadline reached: {sent} audit records handed off, {left} not")]
    Deadline { sent: u64, left: u64 },
    #[error("every peer failed: {sent} audit records handed off, {left} not")]
    AllPeersFailed { sent: u64, left: u64 },
    #[error("audit spool: {0}")]
    Spool(#[from] SpoolError),
    #[error("handoff client certificate: {0}")]
    Tls(String),
    #[error("replica registry: {0}")]
    Db(#[from] sqlx::Error),
}

/// What a handoff client presents and trusts: a control plane certificate
/// of its own, and the internal CA every peer's certificate must chain to.
#[derive(Clone)]
pub struct HandoffTls {
    config: Arc<ClientConfig>,
    internal_ca: CertificateDer<'static>,
}

impl std::fmt::Debug for HandoffTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandoffTls").finish_non_exhaustive()
    }
}

impl HandoffTls {
    /// Issue a short-lived control plane certificate for `id` from the
    /// internal CA (the same CA that issues the server certificate).
    pub async fn issue(cas: &Cas, id: &str, dns_names: &[String]) -> Result<Self, HandoffError> {
        let tls = |e: &dyn std::fmt::Display| HandoffError::Tls(e.to_string());
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| tls(&e))?;
        let csr = CertificateParams::default()
            .serialize_request(&key)
            .map_err(|e| tls(&e))?;
        let issued = cas
            .internal
            .issue_component(ComponentCertRequest {
                csr_der: csr.der().to_vec(),
                kind: ComponentKind::ControlPlane,
                id: id.to_owned(),
                dns_names: dns_names.to_vec(),
                labels: std::collections::BTreeMap::new(),
                ttl: CLIENT_CERT_TTL,
            })
            .await
            .map_err(|e| tls(&e))?;
        let chain = format!("{}{}", issued.pem, cas.internal.cert_pem());
        let identity = Identity::from_pem(&chain, &key.serialize_pem()).map_err(|e| tls(&e))?;
        let internal_ca = cas.internal.cert_der().clone();
        let config = client_config(
            std::slice::from_ref(&internal_ca),
            Some(identity),
            &[limen_tunnel::alpn::H2],
        )
        .map_err(|e| tls(&e))?;
        Ok(Self {
            config: Arc::new(config),
            internal_ca,
        })
    }
}

/// Records some consumer still needs.
fn left(spool: &Spool) -> u64 {
    spool
        .config()
        .consumers
        .iter()
        .map(|c| spool.pending(c))
        .max()
        .unwrap_or(0)
}

/// Hand everything unshipped in this replica's spool to a live peer, peers
/// tried in random order. Returns the records handed off.
pub async fn send_remaining(state: &AppState, deadline: Duration) -> Result<u64, HandoffError> {
    let until = Instant::now() + deadline;
    let spool = &state.pipeline.spool;
    let mut peers =
        tokio::time::timeout_at(until, replicas::live_peers(&state.db, &state.config.id))
            .await
            .map_err(|_| HandoffError::Deadline {
                sent: 0,
                left: left(spool),
            })??;
    shuffle(&mut peers);
    let tls = tokio::time::timeout_at(
        until,
        HandoffTls::issue(&state.cas, &state.config.id, &state.config.dns_names),
    )
    .await
    .map_err(|_| HandoffError::Deadline {
        sent: 0,
        left: left(spool),
    })??;
    send_spool(
        spool,
        &peers,
        &tls,
        until.saturating_duration_since(Instant::now()),
    )
    .await
}

pub fn shuffle<T>(items: &mut [T]) {
    for i in (1..items.len()).rev() {
        let j = usize::try_from(rand::random::<u64>() % (i as u64 + 1)).unwrap_or(0);
        items.swap(i, j);
    }
}

/// Hand every record of `spool` that some consumer has not passed to the
/// first of `peers` (in the order given) that takes it all, moving on when
/// one fails. Consumers are committed batch by batch as peers ack. Bounded
/// by `deadline`. Returns the records acked.
pub async fn send_spool(
    spool: &Spool,
    peers: &[Replica],
    tls: &HandoffTls,
    deadline: Duration,
) -> Result<u64, HandoffError> {
    send_spool_via(spool, peers, tls, deadline)
        .await
        .map(|(sent, _)| sent)
}

/// [`send_spool`], also naming the peer that took the records (`None` when
/// there was nothing to send).
pub async fn send_spool_via(
    spool: &Spool,
    peers: &[Replica],
    tls: &HandoffTls,
    deadline: Duration,
) -> Result<(u64, Option<String>), HandoffError> {
    let until = Instant::now() + deadline;
    let mut sent = 0;
    if spool.read_from(spool.min_offset(), 1)?.is_empty() {
        return Ok((0, None));
    }
    if peers.is_empty() {
        return Err(HandoffError::NoPeers { left: left(spool) });
    }
    for peer in peers {
        if Instant::now() >= until {
            break;
        }
        match send_to(spool, peer, tls, until, &mut sent).await {
            Ok(()) => {
                tracing::info!(peer = %peer.id, sent, "handed the audit spool to a peer");
                return Ok((sent, Some(peer.id.clone())));
            }
            Err(e) => {
                tracing::warn!(peer = %peer.id, error = %e, "audit handoff to a peer failed; trying the next");
            }
        }
    }
    let left = left(spool);
    if Instant::now() >= until {
        Err(HandoffError::Deadline { sent, left })
    } else {
        Err(HandoffError::AllPeersFailed { sent, left })
    }
}

/// `host:port` to dial and the name the peer's certificate must carry.
fn target(url: &str) -> Result<(String, String), String> {
    let url = url::Url::parse(url).map_err(|e| format!("bad ingest URL {url:?}: {e}"))?;
    if url.scheme() != "https" {
        return Err(format!("ingest URL {url} is not https"));
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| format!("ingest URL {url} has no port"))?;
    match url.host() {
        Some(url::Host::Domain(d)) => Ok((format!("{d}:{port}"), d.to_owned())),
        Some(url::Host::Ipv4(ip)) => Ok((format!("{ip}:{port}"), ip.to_string())),
        Some(url::Host::Ipv6(ip)) => Ok((format!("[{ip}]:{port}"), ip.to_string())),
        None => Err(format!("ingest URL {url} has no host")),
    }
}

async fn step<T, E: std::fmt::Display>(
    until: Instant,
    what: &str,
    fut: impl Future<Output = Result<T, E>>,
) -> Result<T, String> {
    // Never more than STEP_TIMEOUT, and leave half of what remains for the
    // next peer.
    let now = Instant::now();
    let cap = STEP_TIMEOUT.min(until.saturating_duration_since(now) / 2);
    let limit = until.min(now + cap);
    match tokio::time::timeout_at(limit, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!("{what}: {e}")),
        Err(_) => Err(format!("{what}: timed out")),
    }
}

/// Connect to `peer` and check it is the control plane the registry names,
/// not merely any holder of a certificate for its host name.
async fn connect(
    peer: &Replica,
    tls: &HandoffTls,
    until: Instant,
) -> Result<tonic::transport::Channel, String> {
    let (addr, name) = target(&peer.ingest_url)?;
    let stream = step(
        until,
        "connecting",
        limen_tunnel::connect::dial(&addr, &name, Arc::clone(&tls.config)),
    )
    .await?;
    let leaf = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or("the peer presented no certificate")?;
    let identity = verify_component(leaf, &tls.internal_ca, true).map_err(|e| e.to_string())?;
    if identity.kind != ComponentKind::ControlPlane || identity.id != peer.id {
        return Err(format!(
            "the peer at {} is {}:{}, not control-plane:{}",
            peer.ingest_url, identity.kind, identity.id, peer.id
        ));
    }
    step(
        until,
        "starting HTTP/2",
        limen_tunnel::connect::channel_over(stream),
    )
    .await
}

/// Stream batches to one peer until the spool has nothing left for anyone.
async fn send_to(
    spool: &Spool,
    peer: &Replica,
    tls: &HandoffTls,
    until: Instant,
    sent: &mut u64,
) -> Result<(), String> {
    let channel = connect(peer, tls, until).await?;
    let mut client = AuditHandoffClient::new(channel).max_decoding_message_size(1024 * 1024);
    let (tx, rx) = tokio::sync::mpsc::channel::<HandoffBatch>(1);
    let Some(first) = batch(spool, spool.min_offset())? else {
        return Ok(());
    };
    // (last index, records) of the batch awaiting its ack.
    let mut pending = (first.last_index, first.events.len() as u64);
    let _ = tx.send(first).await;
    let mut acks = step(
        until,
        "opening the handoff stream",
        client.handoff(tokio_stream::wrappers::ReceiverStream::new(rx)),
    )
    .await?
    .into_inner();
    loop {
        let ack = step(until, "waiting for an ack", async {
            acks.next()
                .await
                .unwrap_or_else(|| Err(tonic::Status::aborted("stream ended without an ack")))
        })
        .await?;
        let (last, count) = pending;
        if ack.durable_upto != last {
            return Err(format!(
                "acked {} for a batch ending at {last}",
                ack.durable_upto
            ));
        }
        // Only now is the batch safe elsewhere.
        spool
            .commit_all(last + 1)
            .map_err(|e| format!("committing the spool: {e}"))?;
        *sent += count;
        metrics::counter!("limen_audit_handoff_records_total", "direction" => "sent")
            .increment(count);
        let Some(next) = batch(spool, last + 1)? else {
            return Ok(());
        };
        pending = (next.last_index, next.events.len() as u64);
        step(until, "sending a batch", async {
            tx.send(next).await.map_err(|_| "the handoff stream closed")
        })
        .await?;
    }
}

fn batch(spool: &Spool, from: u64) -> Result<Option<HandoffBatch>, String> {
    let mut records = spool
        .read_from(from, BATCH_MAX)
        .map_err(|e| format!("reading the spool: {e}"))?;
    // Stay well under the receiver's message limit (one record is at most 1 MiB).
    let mut bytes = 0;
    let fits = records
        .iter()
        .take_while(|(_, r)| {
            bytes += r.len();
            bytes <= BATCH_BYTES
        })
        .count();
    records.truncate(fits.max(1));
    let Some(&(last_index, _)) = records.last() else {
        return Ok(None);
    };
    Ok(Some(HandoffBatch {
        events: records.into_iter().map(|(_, r)| r).collect(),
        last_index,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_keep_the_name_for_verification() {
        assert_eq!(
            target("https://cp-1.internal:8443").expect("dns"),
            ("cp-1.internal:8443".into(), "cp-1.internal".into())
        );
        assert_eq!(
            target("https://[::1]:8443").expect("v6"),
            ("[::1]:8443".into(), "::1".into())
        );
        assert_eq!(
            target("https://10.0.0.5").expect("default port"),
            ("10.0.0.5:443".into(), "10.0.0.5".into())
        );
        assert!(target("http://cp-1:8443").is_err());
    }

    #[test]
    fn shuffle_keeps_every_item() {
        let mut v: Vec<u32> = (0..20).collect();
        shuffle(&mut v);
        v.sort_unstable();
        assert_eq!(v, (0..20).collect::<Vec<_>>());
    }
}

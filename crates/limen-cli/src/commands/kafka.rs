//! `limen kafka connect` (design §5.6, ADR-0037).
//!
//! A Kafka client connects to every broker, at the addresses the cluster
//! advertises. So this command opens one loopback listener for bootstrap and
//! one per broker slot, and every session it opens tells the worker which
//! slot it is and where all of them are: the worker rewrites the advertised
//! addresses to those ports, and a connection to slot *n* is served by the
//! broker of rank *n* (node IDs sorted ascending). Clients use PLAINTEXT to
//! these listeners: the hop is local, and the credential never leaves the
//! worker.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context as _, bail};
use limen_core::broker::{KafkaSlot, MAX_LISTENERS};
use tokio::io::AsyncWriteExt;

use super::redis::{Io, default_principal};
use crate::ui;

/// The default number of broker slots: enough for a typical cluster.
pub const DEFAULT_BROKERS: usize = 8;

fn parse_brokers(text: &str) -> Result<usize, String> {
    let n: usize = text.parse().map_err(|_| "not a number")?;
    if (1..MAX_LISTENERS).contains(&n) {
        Ok(n)
    } else {
        Err(format!("between 1 and {}", MAX_LISTENERS - 1))
    }
}

/// For clap.
pub fn brokers_parser(text: &str) -> Result<usize, String> {
    parse_brokers(text)
}

pub async fn connect(
    proxy: Option<&str>,
    resource: &str,
    user: Option<&str>,
    listen: Option<&str>,
    brokers: usize,
    idle_timeout: Duration,
) -> anyhow::Result<()> {
    let user = match user {
        Some(u) => u.to_owned(),
        None => {
            default_principal(
                proxy,
                resource,
                "kafka",
                "broker user",
                "limen kafka connect",
            )
            .await?
        }
    };
    // The bootstrap listener first, then one per broker slot, all on loopback.
    let mut listeners = Vec::with_capacity(brokers + 1);
    for i in 0..=brokers {
        let addr = if i == 0 {
            listen.unwrap_or("127.0.0.1:0")
        } else {
            "127.0.0.1:0"
        };
        let l = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("listening on {addr}"))?;
        if !l.local_addr()?.ip().is_loopback() {
            bail!("--listen must be a loopback address: anyone who can reach it would act as you");
        }
        listeners.push(l);
    }
    let ports: Vec<u16> = listeners
        .iter()
        .map(|l| l.local_addr().map(|a| a.port()))
        .collect::<Result<_, _>>()?;
    // Fail now, with a clear message, if the login is gone or the proxy is unreachable.
    drop(open(proxy, resource, &user, &KafkaSlot::new(0, ports.clone())).await?);

    ui::success(&format!(
        "Listening for {} as {} ({} broker slot{}).",
        ui::bold(resource),
        ui::bold(&user),
        brokers,
        if brokers == 1 { "" } else { "s" }
    ));
    ui::info(&format!("Run: kcat -b 127.0.0.1:{} -L", ports[0]));
    ui::hint(&format!(
        "Use bootstrap.servers=127.0.0.1:{} with security.protocol=PLAINTEXT; Limen logs in for you. Each connection is its own audited session. Press Ctrl-C to stop.",
        ports[0]
    ));
    ui::hint(&format!(
        "Broker listeners: {}. A cluster with more than {brokers} brokers needs --brokers.",
        ports[1..]
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));

    let proxy: Option<Arc<str>> = proxy.map(Arc::from);
    let resource: Arc<str> = Arc::from(resource);
    let user: Arc<str> = Arc::from(user);
    let ports = Arc::new(ports);
    let active = Arc::new(AtomicUsize::new(0));
    let quiet_since = Arc::new(std::sync::Mutex::new(tokio::time::Instant::now()));
    let mut accepts = Vec::new();
    for (slot, listener) in listeners.into_iter().enumerate() {
        let (proxy, resource, user, ports) = (
            proxy.clone(),
            Arc::clone(&resource),
            Arc::clone(&user),
            Arc::clone(&ports),
        );
        let (active, quiet_since) = (Arc::clone(&active), Arc::clone(&quiet_since));
        accepts.push(tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let _ = stream.set_nodelay(true);
                let (proxy, resource, user, ports) = (
                    proxy.clone(),
                    Arc::clone(&resource),
                    Arc::clone(&user),
                    Arc::clone(&ports),
                );
                let (active, quiet_since) = (Arc::clone(&active), Arc::clone(&quiet_since));
                active.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let slot = KafkaSlot::new(slot, ports.to_vec());
                    session(Box::new(stream), proxy.as_deref(), &resource, &user, &slot).await;
                    *quiet_since
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        tokio::time::Instant::now();
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        }));
    }
    let mut check_idle = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = check_idle.tick() => {
                let quiet = quiet_since.lock().unwrap_or_else(std::sync::PoisonError::into_inner).elapsed();
                if !idle_timeout.is_zero() && active.load(Ordering::SeqCst) == 0 && quiet >= idle_timeout {
                    ui::info("No connections for a while; stopping.");
                    break;
                }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    for a in accepts {
        a.abort();
    }
    Ok(())
}

async fn open(
    proxy: Option<&str>,
    resource: &str,
    user: &str,
    slot: &KafkaSlot,
) -> anyhow::Result<
    impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static + use<>,
> {
    let table = slot.encode();
    super::ssh::open_session_for(proxy, limen_tunnel::alpn::KAFKA, resource, user, &table).await
}

/// One local connection = one session. Kafka has no way to say "refused"
/// before the handshake, so the reason is printed here, and the client sees
/// the connection close.
async fn session(
    mut local: Box<dyn Io>,
    proxy: Option<&str>,
    resource: &str,
    user: &str,
    slot: &KafkaSlot,
) {
    match open(proxy, resource, user, slot).await {
        Ok(mut upstream) => {
            let _ = tokio::io::copy_bidirectional(&mut local, &mut upstream).await;
        }
        Err(e) => {
            ui::error(&e.context("Limen refused the connection"));
            let _ = local.shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_number_of_broker_slots_is_bounded() {
        assert_eq!(parse_brokers("8"), Ok(8));
        assert_eq!(parse_brokers("64"), Ok(64));
        assert!(parse_brokers("0").is_err());
        assert!(parse_brokers("65").is_err());
        assert!(parse_brokers("many").is_err());
    }
}

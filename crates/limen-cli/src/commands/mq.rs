//! `limen mq connect` (design §5.5, ADR-0037).
//!
//! Opens a listener on loopback for AMQP 0-9-1 clients. Each connection it
//! accepts becomes one Limen session: the CLI opens a stream to the proxy with
//! the user's certificate and copies bytes. The client's own login is ignored,
//! and the broker's credential never leaves the worker.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context as _, bail};
use tokio::io::AsyncWriteExt;

use super::redis::{Io, default_principal};
use crate::ui;

pub async fn connect(
    proxy: Option<&str>,
    resource: &str,
    user: Option<&str>,
    vhost: &str,
    listen: Option<&str>,
    idle_timeout: Duration,
) -> anyhow::Result<()> {
    let user = match user {
        Some(u) => u.to_owned(),
        None => {
            default_principal(
                proxy,
                resource,
                "rabbitmq",
                "broker user",
                "limen mq connect",
            )
            .await?
        }
    };
    // Every session of this run carries one group, so the console shows them
    // as one row.
    let group: Arc<str> = Arc::from(uuid::Uuid::new_v4().simple().to_string());
    // Fail now, with a clear message, if the login is gone or the proxy is unreachable.
    drop(open(proxy, resource, &user, &group).await?);

    let addr = listen.unwrap_or("127.0.0.1:0");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("listening on {addr}"))?;
    let local = listener.local_addr()?;
    if !local.ip().is_loopback() {
        bail!("--listen must be a loopback address: anyone who can reach it would act as you");
    }
    ui::success(&format!(
        "Listening for {} as {}.",
        ui::bold(resource),
        ui::bold(&user)
    ));
    ui::info(&format!("Run: {}", amqp_url(local.port(), vhost)));
    ui::hint(
        "Any user name and password work: Limen logs in for you. Each connection is its own audited session. Press Ctrl-C to stop.",
    );

    let proxy: Option<Arc<str>> = proxy.map(Arc::from);
    let resource: Arc<str> = Arc::from(resource);
    let user: Arc<str> = Arc::from(user);
    let active = Arc::new(AtomicUsize::new(0));
    let quiet_since = Arc::new(std::sync::Mutex::new(tokio::time::Instant::now()));
    let mut check_idle = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accepting a connection")?;
                stream.set_nodelay(true)?;
                let (proxy, resource, user, group) = (
                    proxy.clone(),
                    Arc::clone(&resource),
                    Arc::clone(&user),
                    Arc::clone(&group),
                );
                let (active, quiet_since) = (Arc::clone(&active), Arc::clone(&quiet_since));
                active.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    session(Box::new(stream), proxy.as_deref(), &resource, &user, &group).await;
                    *quiet_since.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                        tokio::time::Instant::now();
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
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
    Ok(())
}

/// The URL to give a client. The vhost is the client's own choice; this one is
/// only what the printed line suggests.
fn amqp_url(port: u16, vhost: &str) -> String {
    let path = if vhost == "/" {
        "%2F".to_owned()
    } else {
        vhost.trim_start_matches('/').replace('/', "%2F")
    };
    format!("amqp://limen:limen@127.0.0.1:{port}/{path}")
}

async fn open(
    proxy: Option<&str>,
    resource: &str,
    user: &str,
    group: &str,
) -> anyhow::Result<
    impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static + use<>,
> {
    super::ssh::open_session_in(proxy, limen_tunnel::alpn::MQ, resource, user, "", group).await
}

/// One local connection = one session. AMQP has no way to say "refused"
/// before the handshake, so the reason is printed here, and the client sees
/// the connection close.
async fn session(
    mut local: Box<dyn Io>,
    proxy: Option<&str>,
    resource: &str,
    user: &str,
    group: &str,
) {
    match open(proxy, resource, user, group).await {
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
    fn the_url_carries_no_secret_and_encodes_the_vhost() {
        assert_eq!(amqp_url(5672, "/"), "amqp://limen:limen@127.0.0.1:5672/%2F");
        assert_eq!(
            amqp_url(5672, "orders"),
            "amqp://limen:limen@127.0.0.1:5672/orders"
        );
        assert_eq!(
            amqp_url(1, "/team/a"),
            "amqp://limen:limen@127.0.0.1:1/team%2Fa"
        );
    }
}

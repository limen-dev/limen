//! `limen tcp <resource>`: a local forwarder for a fixed TCP resource.

use std::sync::Arc;

use anyhow::{Context as _, bail};

use crate::ui;

pub async fn connect(
    proxy: Option<&str>,
    resource: &str,
    listen: Option<&str>,
) -> anyhow::Result<()> {
    let address = listen.unwrap_or("127.0.0.1:0");
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("listening on {address}"))?;
    let local = listener.local_addr()?;
    ensure_loopback(local)?;

    ui::success(&format!("Forwarding TCP for {}.", ui::bold(resource)));
    ui::info(&format!("Connect with: nc {} {}", local.ip(), local.port()));
    ui::hint(
        "Each local connection opens an audited Limen session to the configured target. Press Ctrl-C to stop.",
    );

    let proxy: Option<Arc<str>> = proxy.map(Arc::from);
    let resource: Arc<str> = Arc::from(resource);
    let group: Arc<str> = Arc::from(uuid::Uuid::new_v4().simple().to_string());
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (local, _) = accepted.context("accepting a local TCP connection")?;
                let (proxy, resource, group) = (
                    proxy.clone(),
                    Arc::clone(&resource),
                    Arc::clone(&group),
                );
                tokio::spawn(async move {
                    match super::ssh::open_session_in(
                        proxy.as_deref(),
                        limen_tunnel::alpn::TCP,
                        &resource,
                        "access",
                        "",
                        &group,
                    )
                    .await
                    {
                        Ok(mut upstream) => {
                            let mut local = local;
                            if let Err(error) =
                                tokio::io::copy_bidirectional(&mut local, &mut upstream).await
                            {
                                tracing::warn!(%error, resource = %resource, "TCP forwarding session ended with an I/O error");
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, resource = %resource, "TCP forwarding session was refused");
                        }
                    }
                });
            }
            result = tokio::signal::ctrl_c() => {
                result.context("waiting for Ctrl-C")?;
                break;
            }
        }
    }
    Ok(())
}

fn ensure_loopback(address: std::net::SocketAddr) -> anyhow::Result<()> {
    if !address.ip().is_loopback() {
        bail!("--listen must be a loopback address: anyone who can reach it would act as you");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ensure_loopback;

    #[test]
    fn listener_must_be_loopback() {
        assert!(ensure_loopback("127.0.0.1:9000".parse().expect("IPv4")).is_ok());
        assert!(ensure_loopback("[::1]:9000".parse().expect("IPv6")).is_ok());
        assert!(ensure_loopback("0.0.0.0:9000".parse().expect("wildcard")).is_err());
    }
}

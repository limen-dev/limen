//! `limen tcp <resource>`: a local forwarder for a fixed TCP resource.

use std::sync::Arc;

use anyhow::{Context as _, bail};

use crate::ui;

pub async fn connect(
    proxy: Option<&str>,
    resource: &str,
    listen: Option<&str>,
) -> anyhow::Result<()> {
    let listener = bind_loopback(listen.unwrap_or("127.0.0.1:0")).await?;
    let local = listener.local_addr()?;

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

/// Bind a TCP listener on a loopback address only. Every address the name
/// resolves to is checked before binding, so a non-loopback address is never
/// briefly exposed; the bound address is checked again.
pub(crate) async fn bind_loopback(address: &str) -> anyhow::Result<tokio::net::TcpListener> {
    for candidate in tokio::net::lookup_host(address)
        .await
        .with_context(|| format!("resolving {address}"))?
    {
        ensure_loopback(candidate)?;
    }
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("listening on {address}"))?;
    ensure_loopback(listener.local_addr()?)?;
    Ok(listener)
}

fn ensure_loopback(address: std::net::SocketAddr) -> anyhow::Result<()> {
    if !address.ip().is_loopback() {
        bail!("--listen must be a loopback address: anyone who can reach it would act as you");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{bind_loopback, ensure_loopback};

    #[tokio::test]
    async fn bind_loopback_refuses_wildcard_before_binding() {
        // A held port proves the refusal came from the check, not from the
        // bind failing (binding the wildcard on a used port would also fail).
        let held = bind_loopback("127.0.0.1:0").await.expect("loopback binds");
        let port = held.local_addr().expect("addr").port();
        let err = bind_loopback(&format!("0.0.0.0:{port}"))
            .await
            .expect_err("wildcard must be refused");
        assert!(err.to_string().contains("loopback"), "{err:#}");
    }

    #[test]
    fn listener_must_be_loopback() {
        assert!(ensure_loopback("127.0.0.1:9000".parse().expect("IPv4")).is_ok());
        assert!(ensure_loopback("[::1]:9000".parse().expect("IPv6")).is_ok());
        assert!(ensure_loopback("0.0.0.0:9000".parse().expect("wildcard")).is_err());
    }
}

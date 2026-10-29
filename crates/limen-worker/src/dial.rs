//! Connecting to targets (ADR-0042 §5, layer 3).
//!
//! A resource a bot writer built from a profile carries a `delegated` marker.
//! For those, the worker never dials loopback, unspecified, link-local
//! (cloud metadata), multicast, or broadcast addresses, nor the AWS and Azure
//! metadata addresses, and, when the profile bounds them, only names under
//! its `hosts`, addresses inside its `cidrs`, on its `ports`. Every address a
//! name resolves to is checked, and the worker connects to an address it
//! checked, so a name that changes what it resolves to (DNS rebinding) can't
//! get around it. Addresses a target hands back (a Kafka broker, a replica
//! set primary) go through the same check.

use std::io;
use std::net::{IpAddr, SocketAddr};

use limen_policy::delegation::{forbidden_address, host_allowed, in_cidrs, numeric_looking};
use limen_policy::model::Delegated;
use tokio::net::TcpStream;

/// Connect to `address` (`host:port`), refusing what `guard` forbids. With no
/// guard, an ordinary connect.
pub async fn connect(address: &str, guard: Option<&Delegated>) -> io::Result<TcpStream> {
    let Some(guard) = guard else {
        return TcpStream::connect(address).await;
    };
    let mut last = None;
    for addr in allowed(address, guard).await? {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| refused(format!("{address} has no address this resource may use"))))
}

/// The addresses `address` resolves to that `guard` allows, in resolver order.
async fn allowed(address: &str, guard: &Delegated) -> io::Result<Vec<SocketAddr>> {
    let (host, port) =
        split(address).ok_or_else(|| refused(format!("{address:?} is not host:port")))?;
    if !guard.ports.is_empty() && !guard.ports.contains(&port) {
        return Err(refused(format!(
            "port {port} isn't one this resource may use"
        )));
    }
    let literal = host.parse::<IpAddr>().ok();
    if literal.is_none() {
        if numeric_looking(host) {
            return Err(refused(format!(
                "{host:?} looks like an address, not a name"
            )));
        }
        if !guard.hosts.is_empty() && !host_allowed(host, &guard.hosts) {
            return Err(refused(format!(
                "{host:?} isn't a host this resource may use"
            )));
        }
    }
    let resolved: Vec<SocketAddr> = match literal {
        Some(ip) => vec![SocketAddr::new(ip, port)],
        None => tokio::net::lookup_host((host, port)).await?.collect(),
    };
    let ok: Vec<SocketAddr> = resolved
        .iter()
        .copied()
        .filter(|a| permitted(a.ip(), guard))
        .collect();
    if ok.is_empty() {
        let shown: Vec<String> = resolved.iter().map(|a| a.ip().to_string()).collect();
        tracing::warn!(%address, resolved = ?shown, profile = %guard.profile, "refused a delegated target address");
        return Err(refused(format!(
            "{address} resolves only to addresses this resource may not use ({})",
            shown.join(", ")
        )));
    }
    Ok(ok)
}

/// Whether the worker may dial `ip` for a delegated resource.
#[must_use]
pub fn permitted(ip: IpAddr, guard: &Delegated) -> bool {
    !forbidden_address(ip) && (guard.cidrs.is_empty() || in_cidrs(ip, &guard.cidrs))
}

fn split(address: &str) -> Option<(&str, u16)> {
    let (host, port) = match address.strip_prefix('[') {
        Some(rest) => rest.split_once("]:")?,
        None => {
            let (host, port) = address.rsplit_once(':')?;
            if host.contains(':') {
                return None;
            }
            (host, port)
        }
    };
    let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
    (!host.is_empty()).then_some((host, port))
}

fn refused(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(hosts: &[&str], cidrs: &[&str], ports: &[u16]) -> Delegated {
        Delegated {
            profile: "p".into(),
            hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
            cidrs: cidrs.iter().map(|c| (*c).to_owned()).collect(),
            ports: ports.to_vec(),
        }
    }

    #[tokio::test]
    async fn loopback_and_metadata_are_refused_even_without_bounds() {
        let open = guard(&[], &[], &[]);
        for address in [
            "127.0.0.1:5432",
            "[::1]:5432",
            "169.254.169.254:80",
            "[fd00:ec2::254]:80",
            "0.0.0.0:22",
            "localhost:5432",
        ] {
            let err = allowed(address, &open).await.expect_err(address);
            assert_eq!(
                err.kind(),
                io::ErrorKind::PermissionDenied,
                "{address}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn bounds_limit_ports_hosts_and_ranges() {
        let g = guard(&["*.payments.internal"], &["10.20.0.0/16"], &[5432]);
        assert!(allowed("10.20.3.4:5432", &g).await.is_ok());
        for (address, why) in [
            ("10.20.3.4:5433", "port"),
            ("10.30.0.1:5432", "may not use"),
            ("db.other.internal:5432", "isn't a host"),
            ("127.1:5432", "looks like an address"),
            ("orders.payments.internal", "not host:port"),
        ] {
            let err = allowed(address, &g).await.expect_err(address);
            assert!(err.to_string().contains(why), "{address}: {err}");
        }
    }

    #[tokio::test]
    async fn a_name_is_checked_on_what_it_resolves_to() {
        // `localhost` resolves to loopback: whatever the hosts pattern says,
        // the address is refused.
        let g = guard(&["localhost"], &[], &[5432]);
        let err = allowed("localhost:5432", &g).await.expect_err("loopback");
        assert!(err.to_string().contains("resolves only to"), "{err}");
    }

    #[tokio::test]
    async fn no_guard_is_an_ordinary_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("addr").to_string();
        connect(&address, None).await.expect("plain connect works");
        let err = connect(&address, Some(&guard(&[], &[], &[])))
            .await
            .expect_err("guarded");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}

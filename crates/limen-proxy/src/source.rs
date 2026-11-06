//! Who a connection counts against before it has proved anything: the source
//! address, with an IPv6 address standing for its whole /64 (one subscriber
//! has billions of addresses there, so a per-address limit means nothing),
//! and an IPv4-mapped IPv6 address standing for the IPv4 address it carries.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};

/// The key a source address is limited by.
#[must_use]
pub fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        },
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Connections open per source key, so one source cannot hold the whole
/// connection budget.
#[derive(Debug, Default, Clone)]
pub struct SourceCounts {
    open: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl SourceCounts {
    /// A slot for a new connection from `ip`, or `None` when its source
    /// already holds `max`. The slot is given back when the guard drops.
    #[must_use]
    pub fn acquire(&self, ip: IpAddr, max: usize) -> Option<SourceGuard> {
        let key = source_key(ip);
        let mut open = self
            .open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = open.entry(key).or_insert(0);
        if *count >= max {
            return None;
        }
        *count += 1;
        Some(SourceGuard {
            key,
            open: Arc::clone(&self.open),
        })
    }
}

#[derive(Debug)]
pub struct SourceGuard {
    key: IpAddr,
    open: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl Drop for SourceGuard {
    fn drop(&mut self) {
        let mut open = self
            .open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = open.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                open.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn an_ipv6_subscriber_is_one_source() {
        assert_eq!(
            source_key(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd")),
            source_key(ip("2001:db8:1:2::1"))
        );
        assert_ne!(
            source_key(ip("2001:db8:1:2::1")),
            source_key(ip("2001:db8:1:3::1"))
        );
        assert_eq!(source_key(ip("::ffff:10.0.0.1")), ip("10.0.0.1"));
    }

    #[test]
    fn one_source_cannot_hold_more_than_its_share_and_gives_slots_back() {
        let counts = SourceCounts::default();
        let a = counts.acquire(ip("2001:db8:1:2::1"), 2).expect("first");
        let _b = counts
            .acquire(ip("2001:db8:1:2::2"), 2)
            .expect("second, same /64");
        assert!(
            counts.acquire(ip("2001:db8:1:2::3"), 2).is_none(),
            "third is refused"
        );
        assert!(
            counts.acquire(ip("10.0.0.1"), 2).is_some(),
            "others are unaffected"
        );
        drop(a);
        assert!(
            counts.acquire(ip("2001:db8:1:2::3"), 2).is_some(),
            "a slot came back"
        );
    }
}

//! Timing shared by the tunnel registry (control plane) and the proxies
//! that report to it (ADR-0004).

/// How long a reported tunnel stays in the registry without a new report.
/// Peers find a proxy's tunnels only while their lease is live.
pub const TUNNEL_LEASE_SECS: u64 = 45;

/// The longest a proxy may wait between reports in release builds: a third
/// of the lease, so one late or lost report never lets the tunnels expire.
pub const MAX_REPORT_INTERVAL_SECS: u64 = TUNNEL_LEASE_SECS / 3;

const _: () = assert!(MAX_REPORT_INTERVAL_SECS * 3 <= TUNNEL_LEASE_SECS);

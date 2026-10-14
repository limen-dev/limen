//! Worker tunnels held by this proxy.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use limen_tunnel::tunnel::TunnelChannel;
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::Notify;

#[derive(Debug, Clone)]
pub struct Tunnel {
    pub worker_id: String,
    pub tunnel_id: String,
    pub connected_at: OffsetDateTime,
    pub channel: TunnelChannel,
}

#[derive(Debug, Clone, Serialize)]
pub struct TunnelSummary {
    pub worker_id: String,
    pub tunnel_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub connected_at: OffsetDateTime,
}

/// Tunnels by ID. `changed` fires whenever one is added or removed.
#[derive(Debug, Default, Clone)]
pub struct Tunnels {
    inner: Arc<Mutex<BTreeMap<String, Tunnel>>>,
    pub changed: Arc<Notify>,
}

impl Tunnels {
    pub fn insert(&self, tunnel: Tunnel) {
        self.lock().insert(tunnel.tunnel_id.clone(), tunnel);
        self.changed.notify_one();
    }

    pub fn remove(&self, tunnel_id: &str) {
        if self.lock().remove(tunnel_id).is_some() {
            self.changed.notify_one();
        }
    }

    #[must_use]
    pub fn summaries(&self) -> Vec<TunnelSummary> {
        self.lock()
            .values()
            .map(|t| TunnelSummary {
                worker_id: t.worker_id.clone(),
                tunnel_id: t.tunnel_id.clone(),
                connected_at: t.connected_at,
            })
            .collect()
    }

    /// A live tunnel to `worker_id`, if this proxy holds one.
    #[must_use]
    pub fn channel_for(&self, worker_id: &str) -> Option<TunnelChannel> {
        self.lock()
            .values()
            .find(|t| t.worker_id == worker_id && !t.channel.is_closed())
            .map(|t| t.channel.clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Tunnel>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

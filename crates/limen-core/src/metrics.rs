//! Prometheus/OpenMetrics exposition for the admin endpoints (ADR-0011).
//! The Datadog agent (or Prometheus) scrapes `/metrics`.

use std::sync::OnceLock;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

static HANDLE: OnceLock<Option<PrometheusHandle>> = OnceLock::new();

/// Install the global metrics recorder (once) and return a handle to render
/// it. `None` if another recorder was installed first (tests running several
/// components in one process share the first one).
pub fn install() -> Option<PrometheusHandle> {
    HANDLE
        .get_or_init(|| PrometheusBuilder::new().install_recorder().ok())
        .clone()
}

/// The current metrics in the Prometheus text format.
#[must_use]
pub fn render() -> String {
    install().map(|h| h.render()).unwrap_or_default()
}

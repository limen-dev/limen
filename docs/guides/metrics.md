# Metrics, traces and alerts

Every component (control plane, proxy, worker) serves Prometheus/OpenMetrics text at `/metrics` on its admin port (`--admin-listen`, `LIMEN_ADMIN_LISTEN`), next to `/healthz` and `/readyz`. Scrape it with Prometheus or the Datadog Agent's OpenMetrics check.

**The admin port is plain HTTP with no authentication.** Expose it only to your monitoring network. Metrics hold counts, latencies and a few fixed labels; they never carry user names, resource names, statements or tokens.

## Metrics

| Metric | Type | Labels | Component |
|---|---|---|---|
| `limen_sessions_active` | gauge | `kind` | proxy, worker |
| `limen_sessions_total` | counter | `kind` | proxy, worker |
| `limen_logins_total` | counter | `outcome` (`success`, `denied`), `actor` (`bot`) | control plane |
| `limen_proxy_tunnels` | gauge | | proxy |
| `limen_worker_tunnels_up` | gauge | | worker |
| `limen_worker_sessions_active`, `limen_worker_sessions_max`, `limen_worker_draining` | gauge | | worker |
| `limen_worker_sessions_refused_total`, `limen_proxy_sessions_refused_total` | counter | `reason` | worker, proxy |
| `limen_policy_snapshot_age_seconds` | gauge | | proxy, worker |
| `limen_audit_spool_pending` | gauge | `consumer` | all |
| `limen_audit_spool_bytes` | gauge | | all |
| `limen_audit_shipped_total`, `limen_audit_ship_errors_total` | counter | `consumer` | all |
| `limen_audit_ocsf_events_total`, `limen_audit_ocsf_skipped_total` | counter | | control plane |
| `limen_ca_sign_seconds` | summary (quantiles) | `kind` (`x509`, `ssh`) | control plane |
| `limen_ca_sign_errors_total` | counter | `kind` | control plane |
| `limen_api_request_seconds` | histogram | `service` | control plane |
| `limen_control_plane_replicas` | gauge | | control plane |
| `limen_policy_shadow_rules`, `limen_policy_shadow_days_left` | gauge | | control plane |
| `limen_policy_shadow_denies_total` | counter | `role`, `rule` | proxy |
| `limen_policy_shadow_events_dropped_total` | counter | | proxy |
| `limen_recordings_pending` | gauge | | worker |

`limen_policy_shadow_days_left` is the days until the first shadow rule runs out, or `+Inf` with none; alert before it reaches 0, because after that policy changes are refused until the rule is enforced or renewed (ADR-0046). `limen_policy_shadow_events_dropped_total` counts shadow denies whose audit event could not be written; the request is never refused for it.

`limen_audit_ocsf_skipped_total` counts records the [OCSF export](audit-ocsf.md) gave up on because its bucket was failing while it held the audit spool back. They are still in the audit trail; alert on any increase.

Protocol-specific counters (`limen_mongo_*`, `limen_search_*`, `limen_broker_*`, `limen_kube_requests_total`) are described in the guide for each protocol.

## Traces

Set `--otlp-endpoint` (`LIMEN_OTLP_ENDPOINT`) on a component to export traces over OTLP/HTTP to a Datadog Agent or any OpenTelemetry collector. Off by default. A session is one trace across the proxy, the worker and the control plane, and log lines written inside it carry its `trace_id`. The flags, the spans, what is attached and how to try it locally are in the [tracing guide](tracing.md).

## Alerts

- Prometheus: [`deploy/prometheus/alerts.yml`](../../deploy/prometheus/alerts.yml). Covers a growing audit spool, failing audit shipping, a denial spike, disconnected workers, stale policy, CA signing errors and latency, and a component not answering. Set `job` names to match your scrape config. Checked with `promtool check rules`; not run against a live Alertmanager.
- Datadog: the monitors in `deploy/terraform/modules/datadog` (`metrics_namespace` enables the metric ones). Checked with `terraform validate` only; **unverified in a real Datadog account** (issue #63).

Thresholds are starting points. Tune the denial threshold to your user count.

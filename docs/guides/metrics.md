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
| `limen_ca_sign_seconds` | summary (quantiles) | `kind` (`x509`, `ssh`) | control plane |
| `limen_ca_sign_errors_total` | counter | `kind` | control plane |
| `limen_api_request_seconds` | histogram | `service` | control plane |
| `limen_control_plane_replicas` | gauge | | control plane |
| `limen_recordings_pending` | gauge | | worker |

Protocol-specific counters (`limen_mongo_*`, `limen_search_*`, `limen_broker_*`, `limen_kube_requests_total`) are described in the guide for each protocol.

## Traces

Set `--otlp-endpoint` (`LIMEN_OTLP_ENDPOINT`, for example `http://localhost:4318`) on a component to export traces over OTLP/HTTP to a Datadog Agent or any OpenTelemetry collector. `--trace-environment` (`LIMEN_ENVIRONMENT`, shared with the control plane's `--environment`) tags them. Off by default. Spans exported today: `api.request` (control plane), and `session` on the proxy and on the worker, which share a `session` attribute. Only ids and outcomes are attached, never user names, statements or tokens (ADR-0040). Traces are per component for now; linking them into one trace is a follow-up. Verified against Jaeger 1.76 (a real OTLP collector); **unverified** against a Datadog Agent. To check yours: `LIMEN_TEST_OTLP_ENDPOINT=http://localhost:4318 cargo test -p limen-core --test otlp_collector`, then look for service `limen-collector-test`.

## Alerts

- Prometheus: [`deploy/prometheus/alerts.yml`](../../deploy/prometheus/alerts.yml). Covers a growing audit spool, failing audit shipping, a denial spike, disconnected workers, stale policy, CA signing errors and latency, and a component not answering. Set `job` names to match your scrape config. Checked with `promtool check rules`; not run against a live Alertmanager.
- Datadog: the monitors in `deploy/terraform/modules/datadog` (`metrics_namespace` enables the metric ones). Checked with `terraform validate` only; **unverified in a real Datadog account** (issue #63).

Thresholds are starting points. Tune the denial threshold to your user count.

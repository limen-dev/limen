# Observability recipes

Limen exports traces over OTLP/HTTP and serves metrics as OpenMetrics, so any backend that speaks either works. There are no per-vendor integrations. Settings are in the [tracing guide](tracing.md) and [metrics guide](metrics.md).

> **What was tried.** Only the Jaeger recipe has run (Jaeger 1.76 and 2.22, in CI and the `tracing` compose stack). The Tempo, Datadog and OpenTelemetry Collector recipes follow those products' documented receiver settings and are **unverified**. Datadog: issue #63.

## What is exported

- **Traces:** OTLP over HTTP/protobuf to `<endpoint>/v1/traces` (not gRPC). Off until `--otlp-endpoint` (`LIMEN_OTLP_ENDPOINT`) is set on the control plane, proxy and worker.
- **Metrics:** Prometheus/OpenMetrics text at `/metrics` on each component's admin port. Limen doesn't push metrics or send DogStatsD.
- **Logs:** JSON on stdout. A line written inside a trace carries `trace_id`.
- **Only ids and outcomes** leave in a span, never a user name, resource name, claim, token, statement or payload. Only spans made with `trace_span!` are exported.

## TLS and authentication

- Use an `https://` endpoint outside a trusted network. For a private CA, add `--otlp-ca-file` (`LIMEN_OTLP_CA_FILE`); it's added to the system roots.
- **Client certificates aren't supported.** Authenticate with headers: set the standard `OTEL_EXPORTER_OTLP_HEADERS` (such as `Authorization=Bearer ...`) in the component's environment, or put the collector behind a network boundary. Pass the token through your secret store, not the command line.
- A bad endpoint is reported at startup and the component runs without tracing.

Tag spans with `deployment.environment` via `--trace-environment` (`LIMEN_ENVIRONMENT`), and lower `--trace-sample-ratio` if volume costs too much.

## Jaeger

Jaeger v2 accepts OTLP/HTTP on port 4318 with no configuration.

```sh
docker run --rm -p 16686:16686 -p 4318:4318 jaegertracing/jaeger:2.22.0
LIMEN_OTLP_ENDPOINT=http://<jaeger-host>:4318   # on each component; a name they can reach
```

Open `http://localhost:16686`, pick service `limen-proxy`, and open a trace. The dev stack does this for you: `deploy/compose/setup.sh --yes --stacks ssh,tracing`. If the image tag in `deploy/compose/.env` (`JAEGER_IMAGE`) differs, use that one.

## Grafana Tempo

**Unverified.** Enable the OTLP/HTTP receiver on the distributor:

```yaml
distributor:
  receivers:
    otlp:
      protocols:
        http:
          endpoint: 0.0.0.0:4318
```

Point Limen at `http://<tempo>:4318`. On Grafana Cloud, use the OTLP gateway URL and send credentials with `OTEL_EXPORTER_OTLP_HEADERS=Authorization=Basic ...`. In Grafana, search by `service.name` (`limen-proxy`, `limen-worker`, `limen-control-plane`). To jump from a log line to its trace, use `trace_id` as a derived field in the Loki data source.

## Datadog

**Unverified.** Enable the Agent's OTLP receiver and point Limen at it. In a container or Kubernetes the Agent must also expose the port, and APM must be on; see the Agent's documentation.

```yaml
# datadog.yaml
otlp_config:
  receiver:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
```

```sh
LIMEN_OTLP_ENDPOINT=http://<agent-host>:4318   # on each component
```

Traces appear under `limen-proxy`, `limen-worker` and `limen-control-plane`. Limen sets `deployment.environment`; whether the Agent maps it to the `env` tag depends on its OTLP mapping, so check in the UI. For metrics use the Agent's OpenMetrics check against each admin port, not DogStatsD:

```yaml
# conf.d/openmetrics.d/conf.yaml
instances:
  - openmetrics_endpoint: http://<component>:<admin-port>/metrics
    namespace: limen
    metrics: [".*"]
    tags:
      - env:<environment>   # the control plane's --environment: the Terraform monitors filter on it
```

The admin port is plain HTTP with no authentication; keep it on the monitoring network. Monitors are in `deploy/terraform/modules/datadog`: set `metrics_namespace` to the `namespace` above and `environment` to the `env` tag.

## OpenTelemetry Collector

**Unverified.** A collector in the middle adds authentication, batching, sampling and several backends without touching Limen:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
processors:
  batch: {}
exporters:
  otlphttp:
    endpoint: https://tempo.example.com
    headers:
      Authorization: Bearer ${env:TEMPO_TOKEN}
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp]
```

Point Limen at `http://<collector>:4318`. For metrics, add a `prometheus` receiver scraping the admin ports and an exporter for your metrics backend.

## Checking it works

1. Start a session: `limen ssh <user>@<host> -- hostname`.
2. Find service `limen-proxy` in the backend. One session is one trace, with proxy, worker and control-plane spans.
3. If nothing arrives, look for `opentelemetry_sdk` warnings in the component's logs, and check the collector's port is reachable from the component, not just your laptop.
4. To test an endpoint without a deployment: `LIMEN_TEST_OTLP_ENDPOINT=http://localhost:4318 cargo test -p limen-core --test otlp_collector`, then look for service `limen-collector-test`.

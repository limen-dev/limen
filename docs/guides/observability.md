# Observability recipes

Limen exports traces over OTLP/HTTP and serves metrics as OpenMetrics, so it works with any backend that speaks either. It has no per-vendor integration. This page shows how to point it at common backends. The settings are in the [tracing guide](tracing.md) and the metrics in the [metrics guide](metrics.md).

**What was tried.** Only the Jaeger recipe has been run (Jaeger 1.76 and 2.22, in CI and in the `tracing` compose stack). The Tempo, Datadog and OpenTelemetry Collector recipes follow those products' documented receiver settings and are **unverified** against a running instance. Datadog is tracked in issue #63.

## What is exported

- **Traces:** OTLP over HTTP/protobuf to `<endpoint>/v1/traces`. Not gRPC. Off until `--otlp-endpoint` (`LIMEN_OTLP_ENDPOINT`) is set on the control plane, proxy and worker.
- **Metrics:** Prometheus/OpenMetrics text at `/metrics` on each component's admin port. Limen does not push metrics, and it does not send DogStatsD.
- **Logs:** JSON on stdout. A line written inside a trace carries `trace_id`.
- **Only ids and outcomes** leave in a span: never a user name, resource name, claim, token, statement or payload. Only spans made with `trace_span!` are exported.

## TLS and authentication

- Use an `https://` endpoint outside a trusted network. If the collector's certificate is from a private CA, add `--otlp-ca-file` (`LIMEN_OTLP_CA_FILE`); it is added to the system roots.
- **Client certificates are not supported.** Authenticate to the collector with headers: set the standard `OTEL_EXPORTER_OTLP_HEADERS` (for example `Authorization=Bearer ...`) in the component's environment, or put the collector behind a network boundary.
- Keep the token out of the command line and logs; pass it through the secret store your deployment already uses.
- If the endpoint is bad, the component prints why at startup and runs without tracing.

Set `--trace-environment` (`LIMEN_ENVIRONMENT`) to tag spans with `deployment.environment`, and lower `--trace-sample-ratio` if volume is a cost.

## Jaeger

Jaeger v2 accepts OTLP/HTTP on port 4318 with no configuration.

```sh
docker run --rm -p 16686:16686 -p 4318:4318 jaegertracing/jaeger:2.22.0
LIMEN_OTLP_ENDPOINT=http://localhost:4318   # on each component
```

Open `http://localhost:16686`, pick the service `limen-proxy`, and open a trace. The development stack does this for you: `deploy/compose/setup.sh --yes --stacks ssh,tracing`. Use the image tag pinned in `deploy/compose/.env` (`JAEGER_IMAGE`) rather than the tag above if they differ.

## Grafana Tempo

Tempo's distributor takes OTLP/HTTP on 4318 once the receiver is enabled:

```yaml
distributor:
  receivers:
    otlp:
      protocols:
        http:
          endpoint: 0.0.0.0:4318
```

Point Limen at `http://<tempo>:4318`. On Grafana Cloud, use the OTLP gateway URL as the endpoint and send its credentials with `OTEL_EXPORTER_OTLP_HEADERS=Authorization=Basic ...`. In Grafana, search by `service.name` (`limen-proxy`, `limen-worker`, `limen-control-plane`). To jump from a log line to its trace, use the `trace_id` field as a derived field in the Loki data source. Unverified.

## Datadog

Enable the Agent's OTLP receiver and point Limen at it:

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

Traces appear under the services `limen-proxy`, `limen-worker` and `limen-control-plane`, with the `env` from `--trace-environment`. For metrics, use the Agent's OpenMetrics check against each admin port, not DogStatsD:

```yaml
# conf.d/openmetrics.d/conf.yaml
instances:
  - openmetrics_endpoint: http://<component>:<admin-port>/metrics
    namespace: limen
    metrics: [".*"]
```

The admin port is plain HTTP with no authentication; keep it on the monitoring network. Monitors for these metrics are in `deploy/terraform/modules/datadog`. Unverified in a real Datadog account (issue #63).

## OpenTelemetry Collector

A collector in the middle lets you add authentication, batching, sampling and several backends without touching Limen:

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

Point Limen at `http://<collector>:4318`. For metrics, add a `prometheus` receiver scraping the admin ports, and an exporter for your metrics backend. Unverified.

## Checking it works

1. Start a session (`limen ssh <user>@<host> -- hostname`).
2. Find the service `limen-proxy` in the backend. One session is one trace, with proxy, worker and control-plane spans.
3. If nothing arrives, look for `opentelemetry_sdk` warnings in the component's logs, and check that the collector's port is reachable from the component, not only from your laptop.
4. To test an endpoint without a deployment: `LIMEN_TEST_OTLP_ENDPOINT=http://localhost:4318 cargo test -p limen-core --test otlp_collector`, then look for the service `limen-collector-test`.

# Tracing

Limen can export traces over OpenTelemetry (OTLP). One session is one trace: the proxy's `session` span, the worker's `session` span and the control plane's `api.request` span for the session's certificate call sit under the same trace id. A slow `limen ssh` can then be traced to the step that took the time. Decisions and limits: [ADR-0040](../adr/0040-trace-export.md). Metrics and alerts are in the [metrics guide](metrics.md); setup for Jaeger, Tempo, Datadog and a collector is in the [observability recipes](observability.md).

Tracing is **off by default**. Nothing is exported until a component is given a collector.

## Turn it on

Set these on the control plane, proxy and worker (flag or environment variable):

| Flag | Variable | Default | |
|---|---|---|---|
| `--otlp-endpoint` | `LIMEN_OTLP_ENDPOINT` | unset (off) | collector base URL, for example `http://localhost:4318`; spans go to `<base>/v1/traces` |
| `--otlp-ca-file` | `LIMEN_OTLP_CA_FILE` | system roots | extra CA for an `https://` collector on a private CA |
| `--trace-sample-ratio` | `LIMEN_TRACE_SAMPLE_RATIO` | `1` | share of new traces kept, 0 to 1. A trace the caller already sampled is always kept |
| `--trace-environment` | `LIMEN_ENVIRONMENT` | | sets `deployment.environment` |

Every span carries `service.name` (the binary), `service.version` and a random `service.instance.id`, so replicas can be told apart. Authentication to the collector uses the standard `OTEL_EXPORTER_OTLP_HEADERS`; client certificates are not supported. A bad endpoint is printed at startup and tracing stays off; it never stops a service from starting. Export failures appear in the logs as `opentelemetry_sdk` warnings.

## What is in a trace

| Span | Component | Fields |
|---|---|---|
| `session` | proxy | `session` id, `kind` (`ssh`, `db`, `web`, ...); from the handshake to the end of the session |
| `session` | worker | `session` id; includes the grant check and certificate request |
| `api.request` | control plane | `service` (for example `limen.v1.SshCertificates`), HTTP status |

A span is marked as an error for a 5xx, for a gRPC failure the control plane can see in headers, and for a denied session. The reason is never attached.

**Only ids and outcomes are exported.** Never a user name, resource name, claim, token, certificate, statement, query text, path, header or payload. Only spans created with `trace_span!` leave the process; log events and every other span stay in the logs. Review any new `trace_span!` field against this rule.

The trace context travels as a W3C `traceparent` only (no `tracestate`, no baggage): in the tunnel's `SessionOpen` frame from proxy to worker, and in a header on gRPC calls to the control plane. The control plane reads the header on gRPC requests only, since the same port serves browsers.

## Logs and traces

A log line written inside a trace carries its `trace_id` (JSON: a top-level key; text: at the end of the line). Search the id in your log tool to see everything a session logged, and open the same id in the trace UI.

## Try it locally

```sh
deploy/compose/setup.sh --yes --stacks ssh,tracing
```

The `tracing` stack starts Jaeger and points the three components at it. `setup.sh` prints the Jaeger URL (http://localhost:16686 unless `LIMEN_PORT_JAEGER` says otherwise). Sign in, run `limen ssh <user>@web-staging-1 -- hostname` a few times, then pick service `limen-proxy` in Jaeger and open a trace: you should see the proxy, worker and control-plane spans in one timeline.

Steady background calls (policy refresh, pings) show up as their own short `api.request` traces. Lower `--trace-sample-ratio` where they cost too much.

## Datadog and other collectors

Point `--otlp-endpoint` at the Datadog Agent's OTLP receiver or any OpenTelemetry collector. Verified against Jaeger 1.76 and 2.22; **unverified against a Datadog Agent** (needs an account, issue #63). Setup for Jaeger, Tempo, Datadog and a collector, and how to check that spans arrive, is in the [observability recipes](observability.md).

CI runs the exporter's test against a Jaeger service container (the `jaeger` service in `.github/workflows/ci-rust.yml`, whose image must match `JAEGER_IMAGE` in `deploy/compose/.env`).

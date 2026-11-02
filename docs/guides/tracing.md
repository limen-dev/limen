# Tracing

Limen exports traces over OpenTelemetry (OTLP). One session is one trace: the proxy's `session` span, the worker's `session` span and the control plane's `api.request` span for the session's certificate call share a trace id, so a slow `limen ssh` can be traced to the step that took the time. Decisions and limits: [ADR-0040](../adr/0040-trace-export.md). Metrics and alerts: [metrics guide](metrics.md). Backend setup: [observability recipes](observability.md).

Tracing is **off by default**; nothing is exported until a component is given a collector.

## Turn it on

Set these on the control plane, proxy and worker (flag or environment variable):

| Flag | Variable | Default | |
|---|---|---|---|
| `--otlp-endpoint` | `LIMEN_OTLP_ENDPOINT` | unset (off) | collector base URL, such as `http://localhost:4318`; spans go to `<base>/v1/traces` |
| `--otlp-ca-file` | `LIMEN_OTLP_CA_FILE` | system roots | extra CA for an `https://` collector on a private CA |
| `--trace-sample-ratio` | `LIMEN_TRACE_SAMPLE_RATIO` | `1` | share of new traces kept, 0 to 1. A trace the caller already sampled is always kept |
| `--trace-environment` | `LIMEN_ENVIRONMENT` | | sets `deployment.environment` |

Every span carries `service.name` (the binary), `service.version` and a random `service.instance.id` to tell replicas apart. Authenticate to the collector with the standard `OTEL_EXPORTER_OTLP_HEADERS`; client certificates aren't supported. A bad endpoint is printed at startup and tracing stays off; it never stops a service starting. Export failures appear in logs as `opentelemetry_sdk` warnings.

## What is in a trace

| Span | Component | Fields |
|---|---|---|
| `session` | proxy | `session` id, `kind` (`ssh`, `db`, `web`, …); from handshake to session end |
| `session` | worker | `session` id; includes the grant check and certificate request |
| `api.request` | control plane | `service` (such as `limen.v1.SshCertificates`), HTTP status |

A span is an error for a 5xx, a gRPC failure visible in headers, or a denied session. The reason is never attached.

**Only ids and outcomes are exported**, never a user name, resource name, claim, token, certificate, statement, query text, path, header or payload. Only spans created with `trace_span!` leave the process; review any new `trace_span!` field against this rule.

Trace context travels as a W3C `traceparent` only (no `tracestate`, no baggage): in the tunnel's `SessionOpen` frame from proxy to worker, and in a header on gRPC calls to the control plane. The control plane reads it on gRPC requests only, since the same port serves browsers.

## Logs and traces

A log line written inside a trace carries its `trace_id` (JSON: a top-level key; text: at the line's end). Search the id in your log tool to see everything a session logged, and open it in the trace UI.

## Try it locally

```sh
deploy/compose/setup.sh --yes --stacks ssh,tracing
```

The `tracing` stack starts Jaeger and points the three components at it; `setup.sh` prints the URL (http://localhost:16686 unless `LIMEN_PORT_JAEGER` says otherwise). Sign in, run `limen ssh <user>@web-staging-1 -- hostname` a few times, pick service `limen-proxy` in Jaeger and open a trace: proxy, worker and control-plane spans on one timeline.

Steady background calls (policy refresh, pings) show up as their own short `api.request` traces; lower `--trace-sample-ratio` if they cost too much.

## Datadog and other collectors

Point `--otlp-endpoint` at the Datadog Agent's OTLP receiver or any OpenTelemetry collector. Verified against Jaeger 1.76 and 2.22; **unverified against a Datadog Agent** (issue #63). Recipes: [observability](observability.md).

CI runs the exporter test against a Jaeger service container (`jaeger` in `.github/workflows/rust.yml`, whose image must match `JAEGER_IMAGE` in `deploy/compose/.env`).

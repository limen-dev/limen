# ADR-0040: Trace export over OTLP

- Status: Accepted and built (issue #60). Export first, then propagation over the tunnel, as the owner asked. Propagation covers the tunnel and the control plane's gRPC API.
- Date: 2026-10-25

## Context
ADR-0011 chose `tracing` with OpenTelemetry export to a collector or Datadog Agent. Issue #60 asked for a decision on what is exported and on what must never be attached to spans. Traces leave the process for a backend that may sit outside the audit boundary, so what goes into them needs a rule, not a habit.

## Decisions

### 1. Opt-in, OTLP over HTTP/protobuf
`--otlp-endpoint` (`LIMEN_OTLP_ENDPOINT`) is a collector base URL such as `http://localhost:4318`; Limen posts to `<base>/v1/traces`. Unset, nothing is exported and no exporter is built. `--trace-environment` (`LIMEN_ENVIRONMENT`, shared with the control plane's `--environment`) sets `deployment.environment`; `service.name` is the binary name and `service.version` the release. HTTP/protobuf reuses the `reqwest` and `prost` already in the tree, where gRPC would bring a second `tonic`. `service.instance.id` is a random id per process, so replicas can be told apart. `--trace-sample-ratio` (`LIMEN_TRACE_SAMPLE_RATIO`, default 1) keeps that share of new traces; a trace a caller already sampled is always kept, so a session is never half-traced. For an `https://` collector on a private CA, `--otlp-ca-file` (`LIMEN_OTLP_CA_FILE`) adds that CA to the system roots; client-certificate authentication to the collector is not supported (use a network boundary or the collector's own auth through `OTEL_EXPORTER_OTLP_HEADERS`). A failure to build the exporter is printed and tracing stays off: tracing never stops a service from starting. Spans are batched on a background thread and flushed when the process exits cleanly (`TelemetryGuard`).

### 2. Only spans made with `trace_span!` are exported
The OTLP layer is filtered to spans whose target is `limen::trace`. Log events, and every span that is not ours, stay in the log output only. A new field on a log line therefore cannot reach the trace backend; reaching it takes a deliberate `trace_span!` (or `#[instrument(target = "limen::trace", ...)]`).

### 3. What may be attached
Identifiers and outcomes only: session id, resource kind, a fixed service label, status code. **Never** a user name, resource name, claim, token, certificate, statement, query text, request path, header, or payload. The same rule as metric labels (docs/guides/metrics.md). Review any new `trace_span!` field against it.

### 4. First spans
`api.request` (control plane, one per call: `service`, `http.response.status_code`), `session` on the proxy (`session`, `kind`; from the handshake to the end of the session) and `session` on the worker (`session`). A span is marked as an error (`otel.status_code`) for a 5xx or a gRPC failure the control plane can see in headers, and for a denied session; never with the reason, which can name users and resources. gRPC failures that arrive only in trailers are not seen by the `api.request` layer.

### 5. Propagation over the tunnel
The proxy puts the W3C `traceparent` of its `session` span in the tunnel's `SessionOpen` frame (new field `traceparent`, empty when tracing is off, so old and new components interoperate). The worker opens its `session` span as a child, so the two form one trace. Only `traceparent` crosses: no `tracestate`, no baggage. The worker accepts only a well-formed 55-byte version 00 value and ignores anything else; the value decides which trace a span is filed under and nothing else (no authorization, no sampling beyond the parent's flag). The web path uses the same `session` span, so each proxied web request is one trace.

### 6. Propagation to the control plane
`limen_tunnel::connect::TracedChannel` wraps tonic's channel and adds the calling span's `traceparent` header to each gRPC call (nothing when tracing is off or outside an exported span). The proxy, worker, component library and CLI channels are all of this type, so a session's grant and certificate calls show up as `api.request` children of the proxy's `session` span. The control plane reads the header only on gRPC requests (`content-type: application/grpc`): the same port serves browsers and probes, whose headers mean nothing. Unauthenticated gRPC callers (login) can therefore choose which trace an `api.request` span is filed under, and nothing else.

### Known limits
**The control-plane link is not reliable yet.** On the scaled dev stack the control plane's `api.request` span for a session's certificate call shows up in the session's trace for roughly half of the sessions (4 of 6, 5 of 8 in the last runs); the control plane does receive the sampled `traceparent` every time, and the SDK reports no export error, so the spans are lost between creating them and exporting them. Cause not found: adding a log line before the span's creation made all sessions complete, which points at a tracing-subscriber callsite or filter-state interaction rather than at propagation. The proxy-to-worker link has not been seen to fail (every session in every run had both spans).

Log lines are not stamped with `trace_id` (ADR-0011 intended it). JSON logs inside a `session` span carry that span's `session` field, which is the join key to the trace. The steady background calls (policy refresh, pings) are root `api.request` spans; lower `--trace-sample-ratio` where they cost too much.

## Consequences
- Outbound data flow added: spans to the configured collector (threat model, cross-cutting).
- Tested against a stand-in socket that records the POST, and against Jaeger 1.76 (`LIMEN_TEST_OTLP_ENDPOINT`, `otlp_collector` test). Unverified against a Datadog Agent.

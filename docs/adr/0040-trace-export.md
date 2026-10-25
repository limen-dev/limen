# ADR-0040: Trace export over OTLP

- Status: Accepted and built (issue #60). Export first, then propagation over the tunnel, as the owner asked. Propagation to the control plane's gRPC API is not built.
- Date: 2026-10-25

## Context
ADR-0011 chose `tracing` with OpenTelemetry export to a collector or Datadog Agent. Issue #60 asked for a decision on what is exported and on what must never be attached to spans. Traces leave the process for a backend that may sit outside the audit boundary, so what goes into them needs a rule, not a habit.

## Decisions

### 1. Opt-in, OTLP over HTTP/protobuf
`--otlp-endpoint` (`LIMEN_OTLP_ENDPOINT`) is a collector base URL such as `http://localhost:4318`; Limen posts to `<base>/v1/traces`. Unset, nothing is exported and no exporter is built. `--trace-environment` (`LIMEN_ENVIRONMENT`, shared with the control plane's `--environment`) sets `deployment.environment`; `service.name` is the binary name and `service.version` the release. HTTP/protobuf reuses the `reqwest` and `prost` already in the tree, where gRPC would bring a second `tonic`. A failure to build the exporter is printed and tracing stays off: tracing never stops a service from starting. Spans are batched on a background thread and flushed when the process exits cleanly (`TelemetryGuard`).

### 2. Only spans made with `trace_span!` are exported
The OTLP layer is filtered to spans whose target is `limen::trace`. Log events, and every span that is not ours, stay in the log output only. A new field on a log line therefore cannot reach the trace backend; reaching it takes a deliberate `trace_span!` (or `#[instrument(target = "limen::trace", ...)]`).

### 3. What may be attached
Identifiers and outcomes only: session id, resource kind, a fixed service label, status code. **Never** a user name, resource name, claim, token, certificate, statement, query text, request path, header, or payload. The same rule as metric labels (docs/guides/metrics.md). Review any new `trace_span!` field against it.

### 4. First spans
`api.request` (control plane, one per call: `service`, `status`), `session` on the proxy (`session`, `kind`; from the handshake to the end of the session) and `session` on the worker (`session`).

### 5. Propagation over the tunnel
The proxy puts the W3C `traceparent` of its `session` span in the tunnel's `SessionOpen` frame (new field `traceparent`, empty when tracing is off, so old and new components interoperate). The worker opens its `session` span as a child, so the two form one trace. Only `traceparent` crosses: no `tracestate`, no baggage. The worker accepts only a well-formed 55-byte version 00 value and ignores anything else; the value decides which trace a span is filed under and nothing else (no authorization, no sampling beyond the parent's flag). The web path uses the same `session` span, so each proxied web request is one trace.

### Not built: propagation to the control plane
The proxy's and worker's gRPC calls to the control plane (grants, SSH certificates, audit handoff) are not linked to the session trace. The 39 client construction sites would each need a layer over the channel, and the control plane would have to decide whether to honour a header on a port that also accepts unauthenticated browsers. That is a separate change; `api.request` spans stay roots until then.

## Consequences
- Outbound data flow added: spans to the configured collector (threat model, cross-cutting).
- Tested against a stand-in socket that records the POST, and against Jaeger 1.76 (`LIMEN_TEST_OTLP_ENDPOINT`, `otlp_collector` test). Unverified against a Datadog Agent.

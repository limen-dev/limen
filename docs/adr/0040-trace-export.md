# ADR-0040: Trace export over OTLP

- Status: Accepted and built (first step of issue #60). The owner asked to start with OpenTelemetry export; propagation across components is a follow-up.
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
`api.request` (control plane, one per call: `service`, `status`), `session` on the proxy (`session`, `kind`) and `session` on the worker (`session`). The proxy and worker spans share the session id, so a backend can join them by that attribute.

## Not decided here: propagation
Linking the proxy's and worker's spans into one trace needs a W3C `traceparent` carried over gRPC metadata and in the tunnel's open frame. That changes the wire protocol and goes in a follow-up ADR. Until then, traces are per component and joined by session id.

## Consequences
- Outbound data flow added: spans to the configured collector (threat model, cross-cutting).
- Unverified against a real collector or Datadog Agent: tested against a stand-in socket that records the POST.

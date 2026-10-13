# ADR-0011: Control-plane outage semantics and the observability stack

- Status: Proposed (the outage semantics were decided by the owner)
- Date: 2026-10-13

## Context
The brief requires that, when the control plane is down, existing sessions continue and new sessions fail closed unless cached policy is within a configurable grace period. One wrinkle: new SSH sessions need a per-session certificate from the CA, and the CA is only reachable through the control plane.

## Decision: outage semantics
- **Existing sessions** always continue. Audit events spool locally, and the audit failure mode (ADR-0009) still applies if the spool fills.
- **New DB, Redis, and Kube sessions** are allowed when the proxy's and the worker's signed policy snapshot is no older than `policy.grace_period` (default **5 minutes**, 0 disables it) **and** the user's cert is still valid. The workers mint IAM tokens and impersonate on their own, so no control plane round trip is needed.
- **New SSH sessions always fail closed**, because only the control plane can reach the SSH CA. The proxy deliberately does **not** get `kms:Sign` (the owner chose this over proxy-side signing).
- **Logins** fail, since they need OIDC verification and cert signing.
- Each case is covered by an integration test in Phase 7. Some get an earlier unit test (snapshot age checks in Phase 1).

## Decision: observability
- `tracing` everywhere. JSON logs in production, with `env`, `service`, `version`, `instance_id`, and `trace_id` on every line.
- Traces: `tracing-opentelemetry` exporting OTLP to the Datadog agent (or any OTel collector).
- Metrics: the `metrics` facade. The OpenMetrics endpoint on the admin port is the source of truth, and the Datadog agent scrapes it. DogStatsD via `cadence` is optional.
- **Secret hygiene:** `Secret<T>` newtypes with redacted `Debug`/`Display`, no `Serialize` on secrets, plus a test that runs every component's log output through a token-pattern scanner.

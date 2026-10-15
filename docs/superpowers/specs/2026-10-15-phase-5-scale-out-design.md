# Phase 5: Scale-out: design

- Date: 2026-10-15
- Implements: ADR-0020 (to be moved from Proposed to Accepted by this phase), epic #7
- Exit criteria (design.md §13): three control planes on one database serve a session while one is killed and another is rolling-restarted, with no lost audit events and a verifying hash chain. Compose and a Kubernetes StatefulSet example run it.

## What the code does today (checked, not assumed)

| Fact | Where | Consequence |
|---|---|---|
| `--id` exists but defaults to `control-plane`; it is also the S3 manifest writer ID | `config.rs:16`, `pipeline.rs` | Three replicas started with defaults write one manifest chain and corrupt it. Nothing detects this |
| Ingest acks as soon as the event is fsynced to the replica's **local** spool | `services/ingest.rs` | Producers drop the event after the ack, so a replica that dies before its sinks ship loses **acked** events. ADR-0020 says producers keep events until acked, which is true but does not cover this window |
| On shutdown the sink consumers return immediately | `ship.rs` `run_consumer` | A SIGTERM'd replica leaves its spool unshipped until it restarts on the same disk |
| The control plane has no max connection age; proxies and workers keep one connection for life | `server.rs` | A new replica gets no traffic; scale-in drops every connection at once |
| Workers are picked at random; the `draining` ping exists but there is no load signal or session cap | `tunnels.rs:71`, `peer.rs:141` | Uneven load; no per-worker limit |
| The e2e harness runs one control plane in-process | `limen-e2e` | Cannot SIGKILL anything. Real kill tests need separate processes (compose) |
| A running SSH session needs the control plane only at start (policy is a cached signed snapshot) | ADR-0011 | Killing a control plane must not end live sessions. We assert this |

## Scope and order

1. **A. Audit safety** (the risk): replica registry, writer ID safety, drain, handoff, adoption of orphan spools.
2. **B. Harness**: a compose `scale` profile with 3 control planes, 3 proxies, 3 workers, and `demo-phase5.sh`. Built right after A so every later item is proven against it.
3. **C. Balancing and load**: max connection age and re-resolve, least-loaded worker choice, per-worker session cap, worker drain.
4. **D. Ops and docs**: scale metrics, pool-sizing guide, rate-limit statement, CI-sized load test at 500 users, Kubernetes StatefulSet example, ADR-0020 accepted (with the correction below), threat model, docs.

Out of scope: the ECS and EC2 examples (the design table gives them to Phase 13 with the other Terraform/Helm work), and a large manual load run. The epic checklist is updated to say so.

## A. Audit safety

**Replica registry.** New table `control_plane_replicas(id primary key, started_at, heartbeat_at, ingest_url, spool_mode)`. A replica inserts its row at start and heartbeats every 5 s. Start is refused if a row with the same `id` has a heartbeat younger than 3 intervals ("another live replica uses this id"). This one table gives writer-ID safety, peer discovery for handoff, and the replica count for metrics. Rows older than a day are removed by the existing singleton cleanup.

**Writer ID.** `--id` defaults to the hostname (stable `control-plane-0` in a StatefulSet; random in ECS, which is fine for ephemeral mode). Documented as the manifest writer.

**Two spool modes** (`--spool-mode durable|ephemeral`, default `durable`):
- *durable*: on SIGTERM, drain best-effort within the drain timeout, then exit. The spool and chain resume on restart with the same id and volume. No handoff.
- *ephemeral*: on SIGTERM, drain, and anything left after `drain_timeout - handoff_reserve` goes to a peer.

**Shutdown sequence** (both modes): readiness goes false and ingest stops accepting (the load balancer drains us), the API finishes in-flight calls, sink consumers keep running until every consumer reaches zero pending or the deadline, then handoff if needed. This replaces "consumers return immediately".

**Handoff API.** New gRPC `AuditHandoff.Handoff(stream records)` on the control plane port. Authenticated by mTLS: the caller's certificate must be a control plane component **and** have a live row in `control_plane_replicas`; otherwise refused. The receiver appends records to its own spool and acks after fsync; the sender commits its offset only after the ack. Events keep their `event_id`, so the at-least-once duplicates that handoff can cause are removed by the same idempotency key the sinks already use. Handed-off events enter the **receiver's** manifest chain (correct: the chain records what that writer shipped).

**Orphan spools.** A durable-mode replica scaled in for good leaves a volume behind. `limen-control-plane spool-adopt --dir <path>` opens a spool read-only and pushes it to a live peer through the same handoff call. Documented in the runbook.

**Correction to ADR-0020.** An ephemeral replica that is SIGKILLed (OOM, host loss) loses events that producers already had acked and not yet shipped. Bounded by the sink flush interval. Options considered: (1) ack only after a peer also has the record (cost: one extra round trip on every ingest, and a hard dependency on a peer), (2) accept and document, steer people who need zero loss to durable mode. **Decision: (2), with the loss measurable**: producer `seq` gaps (already in the envelope) let the verifier report exactly which events are missing and from whom. The exit test uses durable mode for the SIGKILL case and ephemeral mode for the SIGTERM and rolling-restart case, and the docs say why.

## B. Harness

Compose profile `scale`: `control-plane-0..2` (own named volume each, shared network alias `control-plane` so DNS returns all three), three proxies, three workers, sshd target, SeaweedFS, Postgres. `deploy/compose/demo-phase5.sh`:
1. Start an SSH session through the stack and keep it producing output.
2. `docker kill` (SIGKILL) `control-plane-1` mid-batch; start it again.
3. Rolling-restart `control-plane-0` and `-2` one at a time (SIGTERM).
4. Assert: the session never dropped; a new session succeeds throughout; `limen-control-plane verify` passes the chain for every writer; no `seq` gap for any producer; the event count in S3 equals the count produced.

## C. Balancing and load

- **Connection age.** Control plane gRPC server sets max connection age 5 min ± 10 % jitter with a 30 s grace. Proxies and workers re-resolve DNS on every reconnect and treat GOAWAY as a normal reconnect, not an error. Test: a replica added after start receives connections within one age period.
- **Load report.** Workers include `active_sessions` and `max_sessions` in the ping reply the proxy already sends.
- **Selection.** Power of two choices on `active/max` among eligible workers (policy and labels decide eligibility first, unchanged). Applies to local tunnels and to peer routing.
- **Cap.** `--max-sessions` on the worker (default 200). At the cap the worker is not eligible; if every eligible worker is full the user gets a clear "capacity" error and an audit event, not a hang.
- **Worker drain.** On SIGTERM the worker reports `draining`, accepts no new sessions, waits for open ones up to the drain timeout, then ends the rest with an audit event.

## D. Ops and docs

- Metrics: `limen_sessions_active` and `limen_tunnels_active` (proxy, worker), `limen_audit_spool_pending` (exists), `limen_control_plane_replicas`, API latency histogram. A Grafana row and scale-signal notes in the docs.
- Pool sizing: `max_connections × replicas` against Aurora limits, RDS Proxy recommendation, a worked example for 500 users.
- Rate limits: stay per replica; the docs state the effective limit is `limit × replicas` and why that is acceptable (the limits are abuse guards, not authorization).
- Load test: a Rust driver in `limen-e2e` for CI size (500 users logging in, 100 concurrent sessions) against the compose profile; reports latency and errors. The larger manual run is described in the docs, not claimed.
- Kubernetes: StatefulSet example for the control plane with PVC and `terminationGracePeriodSeconds` greater than the drain timeout, Deployments for proxy and worker, run on kind if available here, otherwise labelled `unverified`.
- Docs: ADR-0020 Accepted with the correction above; threat model (new entry point: handoff; new data store: replica registry); design.md Phase 5 status; a runbook for replacing and adopting a replica.

## Testing

- Unit: spool drain to zero, handoff stream commit-after-ack, duplicate id refusal, p2c selection distribution, session cap.
- Integration (compose services): handoff between two in-process replicas on one database; non-replica caller refused; stale heartbeat allows takeover.
- End to end: `demo-phase5.sh` as above, run for real before any "works" claim. CI-sized load test.
- Everything stays clippy-pedantic clean; sqlx queries use literal SQL.

## Risks

- Spool handoff and shutdown ordering is the delicate part; it gets the most tests and is built first.
- DNS round-robin through compose aliases is a stand-in for a real load balancer. The behavior (re-resolve, GOAWAY) is the same, but I will label anything cloud-LB specific `unverified`.

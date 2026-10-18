# ADR-0020: Scale-out: many control planes, proxies, and workers

- Status: Accepted (Phase 5, 2026-10-16). Proposed 2026-10-14 at the owner's request
- Date: 2026-10-14

## Context
Limen must run as several copies of each component and tolerate copies appearing and disappearing: a Kubernetes StatefulSet or Deployment, several ECS tasks, or an EC2 Auto Scaling group. The design already says the control plane is stateless (state is in PostgreSQL, ADR-0010) and proxies find each other through the registry (ADR-0004), but "stateless" was never tested with more than one replica, and four things are not stateless yet.

## What already works, and what doesn't

| Concern | Today | Needed |
|---|---|---|
| Control plane state | PostgreSQL: policy, components, tunnels, locks, kills, console sessions and login state, nonces. Cleanup uses an advisory lock | **Test it** with 2 to 3 replicas on one database, including a rolling restart |
| Audit spool | **On the replica's local disk.** Events ingested by a replica sit there until its sinks ship them. Its S3 manifest chain belongs to that replica | A replica that disappears with unshipped events loses them. See "Spool" below |
| Policy snapshot signing | Each replica signs with its own rotating certificate key. Proxies and workers verify the chain | Fine. Add a test that a snapshot from any replica is accepted |
| Rate limits | In memory, per replica, so limits multiply by the replica count | Accept and document, or move to the database |
| Load balancing of long-lived connections | A proxy dials one control-plane address and keeps the HTTP/2 connection for its life, so a new replica gets no traffic and a scale-in drops everything | DNS or service-discovery resolution with round-robin, plus a **maximum connection age** on the control plane so connections rebalance |
| Database connections | One pool per replica | Document sizing against Aurora limits; recommend RDS Proxy at scale |
| Proxies | Stateless except tunnels; peering routes to the proxy that holds the worker | Test 3+ proxies; load-aware worker selection |
| Workers | Several per pool, random pick, `draining` ping on shutdown | A per-worker session limit, least-loaded selection, and drain on scale-in |

## Decisions
- **Spool durability.** Two supported ways to run a control plane or proxy, documented as such:
  1. **Durable volume** (StatefulSet with a PVC, ECS with EFS or an EBS volume, EC2 with an attached EBS): the replica restarts and resumes its own spool. Its **writer ID stays stable** (for example `control-plane-0`) so its audit manifest chain continues.
  2. **Ephemeral replicas** (Fargate task storage, an ASG that terminates instances): on SIGTERM the replica stops ingesting, drains its spool to every sink within the drain timeout, and if events remain it **hands them to a peer replica** through the same ingest API (peers are found in the component registry). A replica killed without warning loses only what its producers have not yet had acknowledged, because producers keep events until the control plane acks (ADR-0009). The orchestrator's grace period must exceed the drain timeout, and the Terraform modules set it.
- **Writer IDs are an explicit setting** (`--id`), unique per live replica. The S3 verifier already handles any number of writers; a retired writer's chain simply ends.
- **No leader for hot paths.** Every replica serves the API and ships its own spool. Only periodic cleanup is singleton, through the advisory lock.
- **Scale signals** are exported as metrics: active sessions and tunnels per proxy and worker, spool depth per replica, API latency. The Terraform and Kubernetes examples wire them to target-tracking policies. Workers are scaled by session load, control planes and proxies by CPU and connections.
- **Capacity target:** about 500 users (the original design scale), tested with a load run in CI-sized form and a larger manual one.

## Consequences
- Needs a multi-replica test harness (the e2e deployment can already run several processes), and chaos tests that kill a replica mid-session and mid-batch.
- Needs deployment examples for all three platforms (Kubernetes, ECS, EC2 ASG) in the Terraform and Helm work of the hardening phase, built on the volumes and grace periods above.
- A "handoff" API is new surface: it must be authenticated like ingest and refuse events that don't come from a registered replica.

## Outcome (Phase 5)

Built as decided, with these changes found while building and testing it. The operator view is [Running Limen at scale](../scale-out.md).

- **Correction to "producers keep events until the control plane acks".** True, but the ack comes when the event is fsynced to the replica's *local* disk, not when it is shipped. An `ephemeral` replica killed without warning (SIGKILL, out-of-memory, host loss) therefore loses what it had acknowledged and not yet shipped, up to the sink flush interval (60 seconds for S3 by default). Asking a peer to hold a copy before acking was rejected: one more round trip on every ingest and a hard dependency on a peer. The loss is bounded, documented, and **visible**: the verifier reports each producer's missing sequence numbers. `durable` mode (a volume per replica, the default) loses nothing.
- **A replica registry** (`control_plane_replicas`, heartbeat 5 s, live under 15 s) gives refusal of a duplicate `--id`, peer discovery for handoff, and the replica count. `--id` defaults to the hostname. An ownership token stops a stalled replica from refreshing or deleting the row of the replica that took its id.
- **A replica that cannot reach the database stops writing to S3** after 8 seconds (events wait in its spool) and resumes when the registry answers, so a process that takes over its id never shares its manifest chain; one that loses the id shuts down. Proxies drain their audit spool to the control plane before they exit, as workers do.
- **Handoff** is a streaming `AuditHandoff` call on the normal API port: the caller needs a control plane certificate and a live registry row; the receiver acks after fsync, the sender commits after the ack, and a draining receiver refuses. The shutdown sequence has one clock: in-flight calls and shipping get 80 % of `--drain-timeout`, the handoff the rest.
- **`limen-spool-adopt`** hands a spool left on a volume to a peer. The spool directory is locked while open.
- **Connection balancing** is a maximum connection age with a graceful close (HTTP/2 GOAWAY), plus clients that look the name up again and spread over the addresses it returns. A call is resent after a graceful close only when the request provably was not processed.
- **Worker selection** is power of two choices on active sessions against the worker's cap, with a bounded retry on another worker after a refusal for capacity or drain. Workers report load in the ping reply (additive; older workers report none).
- **Worker drain** defaults to 10 minutes (the existing default, kept). The old `LIMEN_DRAIN_TIMEOUT` still works with a warning.
- **Names** for proxies and workers (added at the owner's request during the phase): approved by the join token, unique among live components, display only. Policy refuses a `worker_selector` on the name label.
- **Rate limits** stay per replica and in memory, and the rate and burst are now settings (defaults unchanged).
- **Scale signals** are exported as metrics (see the guide). The bundled Grafana dashboards read audit data, not metrics, so no panel was added.
- **Not done in this phase:** the ECS and EC2 Auto Scaling examples move to Phase 13 with the other Terraform and Helm work. A Kubernetes example ships in `deploy/kubernetes/`, checked offline only.
- **Known limits:** a recording upload longer than about the connection age plus grace on an old connection is retried from the start; a large handoff backlog may not fit in the last 20 % of the drain time (the remainder stays on `durable` volumes and is lost on `ephemeral` ones); the load test runs in one process.

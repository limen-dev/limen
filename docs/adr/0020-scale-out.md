# ADR-0020: Scale-out: many control planes, proxies, and workers

- Status: Proposed (owner requested 2026-10-14)
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

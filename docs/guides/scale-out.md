# Running Limen at scale

Limen runs as several copies of each component: control planes, proxies and workers. This guide covers what copies share, what each keeps, what happens as copies come and go, and what to watch. Decisions: [ADR-0020](../adr/0020-scale-out.md). Operator steps: [scale-out runbook](../runbooks/scale-out.md).

Try it: `demos/demo-phase5.sh` runs three of each, kills one control plane and rolling-restarts two others during a live SSH session, then checks that no audit event was lost.

## What is shared

| Component | Shared state | Kept per copy |
|---|---|---|
| Control plane | PostgreSQL (policy, components, tunnels, locks, console sessions, replica registry) and the CA | The **audit spool** on local disk, rate limits (in memory), its S3 manifest chain |
| Proxy | Only its tunnels, which workers dial into; peers find each other through the registry | Tunnels, a policy snapshot, an audit spool |
| Worker | Nothing | Session count, a policy snapshot, recordings and an audit spool until uploaded |

No copy leads the hot path. Only periodic cleanup runs on one replica at a time (a database advisory lock).

## Control planes

**Identity.** Each replica needs its own `--id` (`LIMEN_ID`), also the writer name of its audit chain in S3. It defaults to the hostname, which is stable in a Kubernetes StatefulSet (`control-plane-0`). A replica registers in `control_plane_replicas` and heartbeats every 5 seconds.

- Starting a second replica with an id whose heartbeat is fresh (under 15 s) is **refused**. A replica that finds its id taken over shuts down.
- A replica that can't reach the database for more than 8 s **stops writing to S3** (events wait in its spool) until the registry answers. A process taking over the id therefore never shares the manifest chain: the fence is in place before the old row goes stale at 15 s.
- A crashed replica leaves its row for up to 15 s, so a restart with the same id in that window is refused and the orchestrator retries. A failed start gives the id back at once.

**The CA.** CA certificates are in the database. With the file backend, the keys must be on one volume every replica mounts: separate key volumes fail, because a replica whose key doesn't match the stored certificate refuses to start. The first replica to start creates them. With KMS, every replica uses the same key ids.

**The audit spool.** Events from proxies and workers are acknowledged once fsynced to the replica's local disk, then shipped to the sinks (S3, Datadog, the console database). A replica that vanishes with unshipped events loses them if the disk goes too. Choose with `--spool-mode` (`LIMEN_SPOOL_MODE`):

| Mode | Use for | On SIGTERM | If killed without warning |
|---|---|---|---|
| `durable` (default) | StatefulSet with a volume, ECS with EFS or EBS, EC2 with an attached volume | Ships what it can within the drain time, then exits. The spool stays on the volume and the same id resumes it | Nothing lost; the replica resumes its spool on restart |
| `ephemeral` | Fargate task storage, an Auto Scaling group that terminates instances | Ships what it can, then **hands the rest to a live peer** | **Acknowledged but unshipped events are lost**, up to the sink flush interval (S3 batches close after 60 s by default, `LIMEN_AUDIT_S3_FLUSH`; Datadog ships about every second). Producers keep an event only until the acknowledgement |

If you can't accept that window, run `durable`. If you must run `ephemeral`, shorten `LIMEN_AUDIT_S3_FLUSH` (more, smaller S3 objects). The verifier reports lost events as gaps, so a loss is visible, never silent.

**Shutdown.** On SIGTERM a replica stops reporting ready (`/readyz` returns 503; `/healthz` and `/metrics` stay up), closes its API port and refuses new ingest, finishes in-flight calls, ships its spool to every sink, hands any remainder to a peer (ephemeral mode), deregisters, and exits. This must fit in `--drain-timeout` (default 20 s): calls and shipping get 80%, the handoff the last 20%. **Set your orchestrator's grace period above the drain timeout** (Kubernetes `terminationGracePeriodSeconds`, ECS `stopTimeout`) or the process is killed mid-drain.

**Handoff.** A replica sends unshipped records to a live peer with the `AuditHandoff` call on the normal API port. The caller needs a control plane certificate **and** a live registry row; anything else is refused. The peer acknowledges only after the records are on its disk, and only then does the sender forget them. Delivery is at least once, so an interrupted handoff can send a record twice. Events keep their id: the console and verifier count each once, but the S3, JSONL and Datadog sinks keep both lines. Handed-off events ship under the receiver's chain.

**A volume left behind.** If a durable replica is removed for good, its spool stays on the volume. Hand it to a peer with `limen-spool-adopt` (see the runbook).

**Connection age.** A proxy or worker holds one HTTP/2 connection to the control plane. So new replicas get traffic and scale-in doesn't drop everything at once, each control plane closes connections gracefully (GOAWAY) after `--max-connection-age-secs` (default 300 ±10%, 0 to disable), with `--connection-age-grace-secs` (default 30) for calls in flight. Clients reconnect and re-resolve at once, so reach the control plane through a name resolving to every replica (DNS round-robin, or a TCP-mode load balancer). A recording upload longer than about 90% of the age plus grace, on an already old connection, is cut and retried from the start; recordings stay on the worker's disk until an upload succeeds.

## Proxies and workers

**Worker choice.** Policy and worker labels decide which workers may serve a resource. Among them, the proxy picks the less loaded of two random candidates (power of two choices) by active sessions against cap. Workers report load with every ping (every 15 s), and the proxy adds sessions it has opened since. If a worker refuses because it is full or draining, the proxy tries up to two others before telling the user "no capacity". Older workers report no load or cap and are weighed by session count.

**Capacity.** A worker accepts up to `--max-sessions` (default 200, 0 for no limit). When every eligible worker is full, the user gets a clear error and an `auth.denied` event with `reason: capacity`.

**Scale-in.** On SIGTERM a worker stops taking sessions (pings say `draining`), waits for open sessions up to `--drain-timeout-secs` (default **600**), then ends the rest and exits. Ended sessions are recorded as `session.end` with `reason: worker_drain`, after recordings are finished and uploaded. Set the orchestrator's grace period to the drain timeout plus about 20 s, or lower the timeout if you can't wait that long.

A proxy's `--drain-timeout-secs` (default 20) is the time its client connections get. It closes worker tunnels at once (ending their sessions, so workers reconnect through another proxy), then ships its audit spool to the control plane for up to 10 more seconds. Anything unshipped stays in the spool and is lost if the disk goes too (an `emptyDir`), so give a proxy a volume if that matters, and set the grace period to the drain timeout plus about 10 s.

**Names.** Give proxies and workers readable names with `--name` (`LIMEN_NAME`), approved by the join token (exact, or a pattern such as `prod-a-*`). Names appear in the console, audit events and logs; the id stays the identity and policy never decides on a name. See the [enrollment runbook](../runbooks/worker-enrollment.md).

## What to watch

| Metric | Where | Use |
|---|---|---|
| `limen_control_plane_replicas` | control plane | Live replicas; alert below target |
| `limen_api_request_seconds{service}` | control plane | Latency per gRPC service (`http` for browsers and the rest). Scale on CPU and connections |
| `limen_audit_spool_pending{consumer}`, `limen_audit_spool_bytes` | every component | Unshipped events; spool depth |
| `limen_audit_handoff_records_total{direction}` | control plane | Records handed off; near zero except during scale-in |
| `limen_sessions_active`, `limen_proxy_tunnels` | proxy | Sessions and tunnels. Scale proxies on connections |
| `limen_worker_sessions_active`, `limen_worker_sessions_max`, `limen_worker_draining` | worker | **Scale workers on `active / max`** (target about 60%) |
| `limen_worker_sessions_refused_total`, `limen_proxy_sessions_refused_total` | worker, proxy | Refused at the cap; any sustained rate means no room |

The bundled Grafana dashboards read audit data (Athena or Trino), not these metrics. Scrape `/metrics` on each component's admin port with your own Prometheus or agent. A worker target-tracking rule looks like `avg(limen_worker_sessions_active / limen_worker_sessions_max) = 0.6`.

## Logging

The control plane, proxy, worker and `limen-spool-adopt` take the same flags:

| Flag | Variable | Default |
|---|---|---|
| `--log-level` | `LIMEN_LOG_LEVEL` | `info`; a `tracing` filter such as `info,h2=debug`. `RUST_LOG`, when set, wins |
| `--log-format` | `LIMEN_LOG_FORMAT` | `text`; `json` writes one object per line. `--log-json` / `LIMEN_LOG_JSON` still works |

`error` needs an operator, `warn` is handled but unexpected, `info` is lifecycle, `debug` per-request detail, `trace` wire-level. Credentials are wrapped in `limen_core::secret::Secret` and never logged. The `limen` CLI logs to stderr at `warn`.

Conventions: a failed audit write that makes Limen refuse something is `error` (audit fails closed); a refused login is `warn` and a refused session `info`, always with user and reason; a failure in an optional sink (Datadog) is `warn`. Messages are lowercase, say what was refused or lost, and carry `session`, `resource` or `user` where known.

## Sizing

**Database connections.** Each control plane holds up to 16 PostgreSQL connections (`--database-max-connections`, `LIMEN_DATABASE_MAX_CONNECTIONS`, 1–500), so *N* replicas use up to 16 × *N*. Check that against your instance's `max_connections` and leave room for migrations and console queries. A handful of replicas is far below any production instance; with dozens, put RDS Proxy in front.

**Rate limits.** Limits on unauthenticated entry points (logins, enrollment, bot logins) are per client IP, counted **in memory per replica**, so a load balancer spreading a client over *N* replicas allows about *N* times the limit. That's intended: they are abuse guards, not authorization. Defaults: 30 requests a minute, burst 10 (browser sign-ins get double). **A site with many users behind one egress IP should raise them**: at the defaults, 500 users behind one address need about 17 minutes to log in. Set `--unauthenticated-rate-per-minute` and `--unauthenticated-burst` (`LIMEN_UNAUTHENTICATED_RATE_PER_MINUTE`, `LIMEN_UNAUTHENTICATED_BURST`) on the control plane.

**The proxy has its own guard** ahead of everything: at most 50 new connections a second per client IP, burst 200, dropping the rest before the TLS handshake (the client sees a reset). A login or SSH session is one connection each. 500 users logging in over a minute is about 8 a second, well inside it; 500 in the same second are not (200 get in, the rest must retry). Raise `--accept-rate-per-second` and `--accept-burst` (`LIMEN_ACCEPT_RATE_PER_SECOND`, `LIMEN_ACCEPT_BURST`) on the proxy if that's you. It is per proxy.

**Capacity target:** about 500 users, the original design scale.

## Load test

`LIMEN_LOAD_TEST=1 cargo test -p limen-e2e --test scale --release load_users_log_in_and_hold_sessions -- --nocapture`, with the integration-test environment (PostgreSQL, KMS, S3), logs in 500 users 50 at a time, then opens 100 SSH sessions at once and holds each 10 s (`LIMEN_LOAD_USERS`, `LIMEN_LOAD_SESSIONS`, `LIMEN_LOAD_HOLD_SECS`). It fails if more than 1% of logins or sessions fail. Every component runs in one process on one machine with loopback network and database, so it measures this code, not your infrastructure.

Result (2026-10-16, release build on an Apple-silicon laptop, one control plane, one proxy, two workers, per-IP limits lifted):

| Phase | Done | Errors | p50 | p95 | p99 | max |
|---|---|---|---|---|---|---|
| 500 logins, 50 at a time | 500 | 0 | 74 ms | 134 ms | 150 ms | 161 ms |
| 100 SSH sessions at once (connect and first command) | 100 | 0 | 183 ms | 288 ms | 292 ms | 301 ms |

**At default limits the same test fails.** Everything came from one IP, and the proxy's accept guard dropped 290 of 500 logins and all 100 sessions: 50 connections a second with a burst of 200 doesn't admit 500 logins in under a second. That is the guard working as designed, and why `--accept-rate-per-second` and `--accept-burst` exist for shared addresses.

## What is verified

Run on a local Docker stack (`demo-phase5.sh` and the end-to-end tests): three control planes on one database serving a live session while one is killed and two are rolling-restarted, with the audit chain intact for every writer and no gaps; handoff between replicas, including a receiver dying mid-stream; connection rebalancing; load-aware choice, the session cap and worker drain.

**Unverified:** behaviour behind a cloud load balancer (NLB, ALB), Aurora and RDS Proxy limits, a KMS-backed CA with three replicas, `limen-spool-adopt` against a running stack, orchestrator grace behaviour on Kubernetes and ECS (the manifests in `deploy/kubernetes/limen/` were checked offline, not applied), and any run larger than the load test.

# Running Limen at scale

Limen runs as several copies of each component: control planes, proxies, and workers. This guide says what each copy shares, what it keeps to itself, what happens when copies come and go, and what to watch. The decisions are in [ADR-0020](adr/0020-scale-out.md); the steps for an operator are in the [scale-out runbook](runbooks/scale-out.md).

Try it: `deploy/compose/demo-phase5.sh` runs three control planes, three proxies, and three workers, kills one control plane and rolling-restarts two others during a live SSH session, then checks that no audit event was lost.

## What is shared, and what is not

| Component | Shared state | Kept per copy |
|---|---|---|
| Control plane | PostgreSQL (policy, components, tunnels, locks, console sessions, the replica registry) and the CA | The **audit spool** on local disk, its rate limits (in memory), its S3 manifest chain |
| Proxy | Nothing but its tunnels, which workers dial into. Peers find each other through the registry | Tunnels, a policy snapshot, an audit spool |
| Worker | Nothing | Its session count, a policy snapshot, recordings and an audit spool until uploaded |

No copy is a leader for the hot path. Only periodic cleanup runs on one replica at a time (a database advisory lock).

## Control planes

**Identity.** Each replica needs its own `--id` (`LIMEN_ID`), which is also the writer name of its audit chain in S3. It defaults to the hostname, which is stable in a Kubernetes StatefulSet (`control-plane-0`). On start a replica registers in the `control_plane_replicas` table and heartbeats every 5 seconds. **Starting a second replica with an id that has a fresh heartbeat (under 15 seconds) is refused.** If a stalled replica later finds its id taken over, it shuts down rather than share the chain.

**The audit spool.** Events that proxies and workers send are acknowledged once they are on the replica's local disk (fsynced), then shipped to the sinks (S3, Datadog, the console database). A replica that disappears with events not yet shipped loses them if the disk goes with it. Choose how each replica runs (`--spool-mode`, `LIMEN_SPOOL_MODE`):

| Mode | Use it for | On SIGTERM | If killed without warning |
|---|---|---|---|
| `durable` (default) | StatefulSet with a volume, ECS with EFS or EBS, EC2 with an attached volume | Ships what it can within the drain time, then exits. The spool stays on the volume and the same id resumes it | Nothing is lost; the replica resumes its spool when it restarts |
| `ephemeral` | Fargate task storage, an Auto Scaling group that terminates instances | Ships what it can, then **hands the rest to a live peer** (below) | **Events acknowledged but not yet shipped are lost**, up to the sink flush interval (S3 batches close after 60 seconds by default, `LIMEN_AUDIT_S3_FLUSH`; Datadog ships about every second). Producers keep an event only until the acknowledgement |

If you cannot accept that loss window, run `durable`; if you must run `ephemeral`, shorten `LIMEN_AUDIT_S3_FLUSH` (more, smaller S3 objects) to shrink it. The verifier reports lost events as gaps (below), so a loss is visible, never silent.

**Shutdown.** On SIGTERM a replica: stops reporting ready (`/readyz` returns 503, `/healthz` and `/metrics` stay up), closes its API port and refuses new ingest, finishes in-flight calls, ships its spool to every sink, hands any remainder to a peer (ephemeral mode), deregisters, and exits. The whole sequence fits in `--drain-timeout` (default 20 seconds): in-flight calls and shipping get 80 % of it, the handoff the last 20 %. **Set your orchestrator's grace period above the drain timeout** (Kubernetes `terminationGracePeriodSeconds`, ECS `stopTimeout`), or the process is killed mid-drain.

**Handoff.** A replica sends its unshipped records to a live peer with the `AuditHandoff` call on the normal API port. The caller must present a control plane certificate **and** have a live row in the registry; anything else is refused. The peer acknowledges only after the records are on its own disk, and the sender forgets them only then. Events keep their id, so a duplicate (from an interrupted handoff) is dropped by the sinks. Handed-off events are shipped under the receiving replica's chain.

**A volume left behind.** If a durable replica is removed for good, its spool stays on the volume. Hand it to a peer with `limen-spool-adopt` (see the runbook).

**Connection age.** A proxy or worker holds one HTTP/2 connection to the control plane. So that a new replica gets traffic and a scale-in does not drop everything at once, each control plane closes its connections gracefully (GOAWAY) after `--max-connection-age-secs` (default 300, plus or minus 10 %, 0 to disable), with `--connection-age-grace-secs` (default 30) for calls in flight. Clients reconnect at once and look the name up again, so reach the control plane through a name that resolves to every replica (DNS round-robin, or a load balancer in TCP mode). Limit: a recording upload longer than about 90 % of the age plus the grace on a connection that is already old is cut and retried from the start; recordings stay on the worker's disk until an upload succeeds.

## Proxies and workers

**Worker choice.** Policy and worker labels decide which workers may serve a resource. Among those, the proxy picks the less loaded of two random candidates (power of two choices), using each worker's active sessions against its cap. Workers report their load with every ping (every 15 seconds); the proxy adds the sessions it has opened since. If a worker refuses because it is full or draining, the proxy tries up to two others before it tells the user "no capacity". Workers from older versions report no load and no cap, and are weighed by their session count.

**Capacity.** A worker accepts up to `--max-sessions` (default 200, 0 for no limit) at once and refuses more. When every eligible worker is full, the user gets a clear error and an `auth.denied` event with `reason: capacity`.

**Scale-in.** On SIGTERM a worker stops taking sessions (pings say `draining`), waits for open sessions up to `--drain-timeout-secs` (default **600**, the previous default), then ends the rest and exits. Sessions it ends are recorded as `session.end` with `reason: worker_drain`; recordings are finished and uploaded first. Set the orchestrator's grace period to the drain timeout plus about 20 seconds, or lower the timeout if you cannot wait that long (sessions are then ended at the deadline). A proxy's `--drain-timeout-secs` (default 20) works the same way for the proxy.

**Names.** Give proxies and workers readable names with `--name` (`LIMEN_NAME`), approved by the join token (exact or a pattern such as `prod-a-*`). Names show in the console, audit events, and logs; the id stays the identity, and policy never decides on a name. See the [worker enrollment runbook](runbooks/worker-enrollment.md).

## What to watch (scale signals)

| Metric | Where | Use |
|---|---|---|
| `limen_control_plane_replicas` | control plane | Live replicas; alert if it drops below your target |
| `limen_api_request_seconds{method}` | control plane | Latency per gRPC method (`console` for browser requests). Scale control planes on CPU and connections |
| `limen_audit_spool_pending{consumer}`, `limen_audit_spool_bytes` | every component | Events not yet shipped; spool depth per replica |
| `limen_audit_handoff_records_total{direction}` | control plane | Records sent or received in handoffs (should be near zero except during scale-in) |
| `limen_sessions_active`, `limen_proxy_tunnels` | proxy | Sessions and tunnels per proxy. Scale proxies on connections |
| `limen_worker_sessions_active`, `limen_worker_sessions_max`, `limen_worker_draining` | worker | **Scale workers on `limen_worker_sessions_active / limen_worker_sessions_max`** (target about 60 %) |
| `limen_worker_sessions_refused_total`, `limen_proxy_sessions_refused_total` | worker, proxy | Sessions refused at the cap; any sustained rate means you are out of room |

The bundled Grafana dashboards read the audit data (Athena or Trino), not these metrics; scrape `/metrics` on each component's admin port with your own Prometheus or agent. A target-tracking rule for workers looks like `avg(limen_worker_sessions_active / limen_worker_sessions_max) = 0.6`.

## Sizing

**Database connections.** Each control plane holds a pool of up to 16 connections to PostgreSQL (`--database-max-connections`, `LIMEN_DATABASE_MAX_CONNECTIONS`, 1 to 500). With *N* replicas the database sees up to 16 × *N*. Check that against your Aurora instance's `max_connections` (it depends on the instance class) and leave room for migrations and the console's queries. A handful of replicas is far below any production instance. If you run dozens, put RDS Proxy in front of the database.

**Rate limits.** The limits on unauthenticated entry points (logins, enrollment, bot logins) are per client IP and counted **in memory per replica**, so a client that a load balancer spreads over *N* replicas can make about *N* times the limit. That is intended: they are abuse guards, not authorization. The defaults are 30 requests a minute with a burst of 10 (browser sign-ins get twice as much). **A site with many users behind one egress IP should raise them**: at the defaults, 500 users behind one address need about 17 minutes to log in. Set `--unauthenticated-rate-per-minute` and `--unauthenticated-burst` (`LIMEN_UNAUTHENTICATED_RATE_PER_MINUTE`, `LIMEN_UNAUTHENTICATED_BURST`) on the control plane.

**The proxy has its own guard** in front of everything: it accepts at most 50 new connections a second from one client IP, with a burst of 200, and drops the rest before the TLS handshake (the client sees a reset). A login or an SSH session is one connection each. 500 users behind one address logging in over a minute is about 8 a second, well inside it; 500 at the same second are not (200 get in at once, the rest are dropped and must retry). Raise `--accept-rate-per-second` and `--accept-burst` (`LIMEN_ACCEPT_RATE_PER_SECOND`, `LIMEN_ACCEPT_BURST`) on the proxy if that is your case. Like the other limit, it is per proxy.

**Capacity target.** About 500 users (the original design scale). See the load test below.

## Load test

`cargo test -p limen-e2e --test scale --release load_users_log_in_and_hold_sessions -- --nocapture` with `LIMEN_LOAD_TEST=1` and the integration-test environment (PostgreSQL, KMS, S3) logs in 500 users, 50 at a time, then opens 100 SSH sessions at once and holds each for 10 seconds (`LIMEN_LOAD_USERS`, `LIMEN_LOAD_SESSIONS`, `LIMEN_LOAD_HOLD_SECS`). It fails if more than 1 % of logins or sessions fail. It runs every component in one process on one machine, so it measures this code with the network and the database on loopback. It is not a substitute for a run against your own infrastructure.

**Result** (2026-10-16, a release build on an Apple-silicon laptop, one control plane, one proxy, two workers, the per-IP limits lifted as above):

| Phase | Done | Errors | p50 | p95 | p99 | max |
|---|---|---|---|---|---|---|
| 500 logins, 50 at a time | 500 | 0 | 74 ms | 134 ms | 150 ms | 161 ms |
| 100 SSH sessions at once (connect and first command) | 100 | 0 | 183 ms | 288 ms | 292 ms | 301 ms |

**With the limits at their defaults the same test fails.** The first run, before the limits were settable, sent everything from one IP and the proxy's accept guard dropped 290 of the 500 logins and all 100 sessions: 50 connections a second with a burst of 200 does not admit 500 logins in under a second. That is the guard working as designed, and the reason `--accept-rate-per-second` and `--accept-burst` now exist for sites behind a shared address.

## What has and has not been verified

Verified by running it (`demo-phase5.sh` and the end-to-end tests, on a local Docker stack): three control planes on one database serving a live session while one is killed and two are rolling-restarted, with the audit chain intact for every writer and no gaps; handoff between replicas, including a receiver that dies mid-stream; connection rebalancing; load-aware choice, the session cap, and worker drain.

**Unverified against a real service:** behaviour behind a cloud load balancer (NLB, ALB), Aurora and RDS Proxy limits, KMS-backed CA with three replicas, `limen-spool-adopt` against a running stack, orchestrator grace behaviour on Kubernetes and ECS (the example manifests in `deploy/kubernetes/` were checked offline, not applied to a cluster), and any run larger than the load test above.

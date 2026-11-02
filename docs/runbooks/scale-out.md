# Scaling out, replacing, and upgrading copies

Add and remove control planes, proxies and workers without losing audit events or ending sessions. Background: [Running Limen at scale](../guides/scale-out.md).

## Grace periods first

An orchestrator that kills a copy too early defeats the drain. Set its grace period above the drain time:

| Component | Drain setting (default) | Grace at least |
|---|---|---|
| Control plane | `--drain-timeout` (20 s) | drain + 10 s |
| Proxy | `--drain-timeout-secs` (20) | drain + 10 s |
| Worker | `--drain-timeout-secs` (600) | drain + 20 s |

Kubernetes: `terminationGracePeriodSeconds`. ECS: `stopTimeout`. Auto Scaling groups: a lifecycle hook that waits for the process to exit.

## Control planes

**Add.**
1. Give it its own id (`LIMEN_ID`, or the hostname) and the same database, CA and sink settings as the others.
2. Pick the spool mode: `durable` with its own volume (default), or `ephemeral` for disks that vanish. Mixing modes is fine.
3. Start it and check `limen_control_plane_replicas` rose by one. "another live replica uses this id" means the id is taken: pick another, or wait 15 s if the old replica is truly gone.
4. Traffic reaches it within one connection age (about 5 minutes) as proxies and workers reconnect. Nothing needs restarting.

**Remove or replace.**
1. Send SIGTERM. The replica stops being ready, drains its spool to the sinks, hands any remainder to a peer if `ephemeral`, and exits. One at a time: wait for `limen_control_plane_replicas` to recover before the next.
2. Look for `received audit records handed off` on a peer, or (durable) `audit records remain in the spool after the drain deadline; they ship when this replica restarts on the same volume`.
3. If it was killed before draining (out of memory, host loss): a `durable` replica loses nothing and resumes on restart with the same id and volume; an `ephemeral` one loses what it hadn't shipped (up to the sink flush interval). Run [audit verification](audit-verify.md); lost events appear as sequence gaps.

**Adopt a spool left behind.** A durable replica that never returns leaves unshipped events on its volume. With the volume mounted and unused, run this wherever the control plane's environment (database URL, CA settings) is available:

```sh
limen-spool-adopt --dir /path/to/spool --expect-id control-plane-3
```

It refuses if another process holds the spool or `control-plane-3` still has a fresh heartbeat. It registers briefly as `spool-adopt-<random>`, sends every unshipped record to a live replica (acknowledged before it forgets them), and exits 0 only when nothing is left. `--consumers` names any sink the replica ran that the environment doesn't imply. A sink the spool has no record of is treated as having shipped nothing, so its records are resent: duplicates are possible (the console and verifier count each once; S3, JSONL and Datadog keep both lines), loss is not. Verify with the [chain verification](audit-verify.md) afterwards. During rolling upgrades, replicas on older code don't hold the spool lock, so `--expect-id` is the only guard against adopting a spool still in use.

## Proxies and workers

- **Add.** Enroll with a join token ([worker enrollment](worker-enrollment.md)). `--name` gives a readable name; the token must approve it, and names are unique among live proxies and workers. A new worker gets sessions once its tunnels are up.
- **Remove a worker.** SIGTERM: it stops taking sessions, waits for open ones up to its drain timeout, ends the rest (`session.end`, `reason: worker_drain`), uploads recordings, and exits. To end no session at all, wait for `limen_worker_sessions_active` to reach 0 first.
- **Remove a proxy.** SIGTERM: tunnels close at once and workers reconnect through another proxy; open sessions finish up to the drain timeout.
- **Lost data directory.** A component that lost it can't re-enroll under its old name until the old one is revoked (`limen admin revoke`). Autoscaled instances should use unique names (include the instance id) or none.

## Upgrading

Migrations run when a replica starts and are additive, so replicas on the previous version keep running. **A replica restarting on the old version after a newer one has migrated refuses to start.** Don't roll any replica back once one is on the new version; to roll back, roll the whole fleet back first, against a database restored from before the migration.

## Many users behind one address

- Logins fail with "too many requests; slow down": raise `--unauthenticated-rate-per-minute` and `--unauthenticated-burst` on the control plane.
- Connections reset before the TLS handshake (the CLI reports a connection error; the proxy logs "connection rejected by rate limit" at debug): raise `--accept-rate-per-second` and `--accept-burst` on the proxy.

Both limits are per replica; see the guide.

## When something looks wrong

| Symptom | Look at |
|---|---|
| "no capacity" | `limen_worker_sessions_active / limen_worker_sessions_max` on every worker and `limen_worker_sessions_refused_total`. Add workers or raise `--max-sessions` |
| Audit events missing after a replica died | [Chain verification](audit-verify.md): gaps name the producer and missing sequence numbers. Loss is expected only for an `ephemeral` replica killed before shipping |
| "another live replica uses this id" | Two replicas share an id, or the old one died under 15 s ago |
| Spool growing on one replica | [Audit backlog](audit-spool-full.md) |
| New replica gets no traffic | The name proxies dial must resolve to it; wait one connection age |

# Scaling out, replacing, and upgrading copies

How to add and remove control planes, proxies, and workers without losing audit events or ending sessions. Background: [Running Limen at scale](../scale-out.md).

## Before you start: grace periods

An orchestrator that kills a copy too early defeats the drain. Set these above the component's drain time:

| Component | Drain setting (default) | Orchestrator grace should be at least |
|---|---|---|
| Control plane | `--drain-timeout` (20 s) | drain timeout + 10 s |
| Proxy | `--drain-timeout-secs` (20) | drain timeout + 10 s |
| Worker | `--drain-timeout-secs` (600) | drain timeout + 20 s |

Kubernetes: `terminationGracePeriodSeconds`. ECS: `stopTimeout`. Auto Scaling groups: a lifecycle hook that waits for the process to exit.

## Add a control plane

1. Give it its own id (`LIMEN_ID`, or let it use the hostname) and the same database, CA and sink settings as the others.
2. Pick the spool mode: `durable` with a volume of its own (default), or `ephemeral` for disks that vanish. Mixing modes across replicas is fine.
3. Start it. Check `limen_control_plane_replicas` went up by one. A start that is refused with "another live replica uses this id" means the id is taken: choose another, or wait 15 seconds if the old replica is really gone.
4. New traffic reaches it within one connection age (about 5 minutes) as proxies and workers reconnect; nothing needs restarting.

## Remove or replace a control plane

1. Send SIGTERM (scale in, rolling restart). The replica stops being ready, drains its audit spool to the sinks, hands any remainder to a peer if it is `ephemeral`, and exits. Do one at a time and wait for `limen_control_plane_replicas` to recover before the next.
2. Watch the log for `received audit records handed off` on a peer, or `audit records remain in the spool after the drain deadline; they ship when this replica restarts on the same volume` (durable).
3. If the process is killed before it drains (out of memory, host loss): a `durable` replica loses nothing and resumes its spool when it starts again with the same id and volume; an `ephemeral` replica loses what it had not shipped (up to the sink flush interval, see the guide). Run the [audit verification](audit-verify.md): it reports any lost events as sequence gaps.

## Adopt a spool left on a volume

A durable replica that is never coming back leaves unshipped events on its volume. With the volume mounted (nothing else using it), run from a place that has the control plane's environment (database URL, CA settings):

```sh
limen-spool-adopt --dir /path/to/spool --expect-id control-plane-3
```

It refuses if another process holds the spool or if `control-plane-3` still has a fresh heartbeat. It registers briefly as `spool-adopt-<random>`, sends every unshipped record to a live replica (acknowledged before it forgets them), and exits 0 only when nothing is left. Pass `--consumers` to name any sink the replica ran that the environment does not imply. Verify with the [chain verification](audit-verify.md) afterwards.

**Rolling upgrades.** Replicas on older code do not hold the spool lock, so `--expect-id` is the only guard against adopting a spool that is still in use.

## Add or remove proxies and workers

- **Add:** enroll with a join token as usual ([worker enrollment](worker-enrollment.md)). Give each one `--name` if you want readable names; the token must approve it, and a name is unique among live proxies and workers. New workers get sessions as soon as their tunnels are up.
- **Remove a worker:** send SIGTERM. It stops taking sessions, waits for open ones up to its drain timeout, ends the rest (`session.end` with `reason: worker_drain`), uploads its recordings, and exits. To scale in without ending any session, wait for `limen_worker_sessions_active` to reach 0 on that worker first.
- **Remove a proxy:** send SIGTERM. Its tunnels close at once, so workers reconnect through another proxy; open sessions finish up to the drain timeout.
- **A component that lost its data directory** cannot enroll again under its old name until the old one is revoked (`limen admin revoke`); autoscaled instances should use unique names (include the instance id) or none.

## Upgrading

Migrations run when a replica starts and are additive, so replicas on the previous version keep running. **A replica that restarts on the old version after a newer one has migrated refuses to start** (the database has a migration it does not know). During a rolling upgrade, upgrade replicas and do not roll any back once one has started on the new version; if you must roll back, roll the whole fleet back first and expect the old binary to start only against a database restored from before the migration.

## Tuning for many users behind one address

If logins fail with "too many requests; slow down" for people who share an egress IP, raise `--unauthenticated-rate-per-minute` and `--unauthenticated-burst` on the control plane. If connections are reset before the TLS handshake (the CLI reports a connection error, the proxy log has "connection rejected by rate limit" at debug level), raise `--accept-rate-per-second` and `--accept-burst` on the proxy. Both are per replica; see the guide.

## When something looks wrong

| Symptom | Look at |
|---|---|
| Users get "no capacity" | `limen_worker_sessions_active / limen_worker_sessions_max` on every worker, and `limen_worker_sessions_refused_total`. Add workers or raise `--max-sessions` |
| Audit events missing after a replica died | Run the [chain verification](audit-verify.md); gaps name the producer and the missing sequence numbers. See "Remove or replace a control plane" for when loss is expected |
| A replica will not start: "another live replica uses this id" | Two replicas share an id, or the old one died less than 15 seconds ago |
| Spool growing on one replica | [Audit pipeline backlog](audit-spool-full.md) |
| New replica gets no traffic | The name proxies dial must resolve to it; wait one connection age |

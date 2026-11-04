# Control plane outage

What keeps working when every control plane replica is down, what stops, how to tell, and how to recover. The rules are in [ADR-0011](../adr/0011-failure-semantics-and-observability.md); the end-to-end tests that pin them are `crates/limen-e2e/tests/phase2.rs` (SSH) and `outage_new_sessions.rs` (workers, logins, audit).

## What happens

Proxies and workers decide from a signed policy snapshot they fetched earlier. Its age is the time since a control plane last answered. The **grace period** (`LIMEN_POLICY_GRACE_SECS` on a proxy, `LIMEN_POLICY_GRACE` on a worker; default 5 minutes, 0 turns the grace off) is how old it may get before new sessions fail closed.

| | Inside the grace period | After it |
|---|---|---|
| **Sessions already open** | keep working | keep working |
| **New database, Redis, Kubernetes, TCP sessions** | allowed, if the person's certificate is still valid | refused: "access can't be decided right now (policy snapshot is Ns old, beyond the grace period)" |
| **New SSH sessions** | refused: only the control plane can reach the SSH CA ("control plane unreachable") | refused |
| **Logins** (`limen login`, bot logins) | fail with "control plane unreachable" | fail |
| **The console** | unavailable ("the control plane is unreachable") | unavailable |
| **Admin changes** (apply policy, lock a user, create a token, approve a request) | unavailable: they are control plane calls | unavailable |
| **Audit** | events are written to each component's local spool and ship when the control plane returns | the same, until a spool is full (below) |

Two things follow that people forget:

- **A lock or a policy change made before the outage is already in the snapshot**, so it applies. One you try to make *during* the outage can't be made. If you must stop someone now, stop the proxy or worker they connect through.
- **Nobody new can log in.** A person whose certificate expires during the outage (default 1 hour) is out until the control plane is back, however long the grace period is. A longer `--default-cert-ttl` is the lever, with the usual cost of longer-lived credentials.

## Detect

- Metric `limen_policy_snapshot_age_seconds` on each proxy and worker: it climbs steadily instead of staying near the refresh interval. Alert well before the grace period (for example at half of it).
- Users report "control plane unreachable" on `limen login`, or "can't be decided" on a connect. `limen doctor` names the failing step.
- Worker log: `policy refresh failed; using the cached snapshot within the grace period`.

## Do

1. **Bring a control plane back.** Check the replicas' health and logs, and their database (Postgres) and KMS: logins and certificate signing need both. One healthy replica is enough; see [scale-out](scale-out.md).
2. **Don't restart proxies or workers to "refresh" them.** A restart ends the open sessions that go through that component and does not bring the snapshot back: only a control plane does.
3. **Watch the snapshot age fall** to the refresh interval on every proxy and worker. Policy decisions are fresh again from then.
4. If the outage will outlast the grace period and you need new sessions meanwhile, raise `LIMEN_POLICY_GRACE_SECS` and `LIMEN_POLICY_GRACE` and restart. That keeps trusting a snapshot that can't learn about locks or revocations, so do it only knowingly, and put it back afterwards.

## The audit spool

Every component writes audit events to a local spool first and ships them when it can. During an outage the spool grows. If it fills, the default is to fail closed: a new session is closed, because it could not be recorded. In the test, a spool of 1500 bytes stopped new sessions within the grace period while the default size kept running them. Size it for your outage budget with `--audit-spool-max-bytes` (default 512 MiB), and see [audit pipeline backlog / spool full](audit-spool-full.md).

## After recovery

- Spools drain by themselves; watch `limen_audit_spool_pending` return to 0, then [verify the audit chain](audit-verify.md).
- Service certificates renew at half of their lifetime, so an outage shorter than that should not stop components from reconnecting (design §4.2). That is a design property; no test here pins it.
- Look for people who were refused (support tickets, `auth.denied` events) and tell them to retry.

## Not covered by a test

The behavior above is tested for SSH and raw TCP, with a local identity provider and stand-ins for the targets. Database, Redis and Kubernetes sessions share the same proxy and worker snapshot check, and have no outage test of their own. Nothing here has been run against a real AWS KMS outage.

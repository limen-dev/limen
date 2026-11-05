# Upgrading Limen

Move a deployment to a new release without ending sessions or losing audit events. The policy comes from [ADR-0024](../adr/0024-release-strategy.md); the mechanics of replacing copies are in the [scale-out runbook](scale-out.md). Nothing here has been run against a real AWS or Kubernetes deployment; the steps were checked only against the compose stack and by reading the code and workflows (`unverified`).

## Before you start
1. **Read the release notes**, in particular the *Upgrade notes* section. Before 1.0, a minor release may break things, and that section is where it says so.
2. **Take a database backup or snapshot.** Migrations only move forward, so a backup is the only way back (see *Rolling back*). On Aurora, take a cluster snapshot and note its identifier.
3. **Check the audit chain is healthy** with [audit verification](audit-verify.md), so a gap you see later is not one you started with.
4. **Check the drain settings.** The orchestrator's grace period must exceed each component's drain time, or the drain is cut short (table in the [scale-out runbook](scale-out.md#grace-periods-first)).
5. **Verify the release.** `scripts/smoke-release.sh vX.Y.Z` checks the checksums and runs the published images against the demo. The images are pinned by digest in `image-refs.txt`.

## Order
Always **control planes, then proxies, then workers**, then the CLI.

| Step | What | Why |
|---|---|---|
| 1 | Control planes, one at a time | A replica runs the migrations when it starts. Replicas still on the old version keep serving, because migrations are additive |
| 2 | Proxies | They take policy and certificates from the control plane, so the control plane must already speak the new version |
| 3 | Workers | Same reason. A worker's drain can take up to 10 minutes by default (`--drain-timeout-secs`) |
| 4 | The CLI | A CLI of the same minor version works with a deployment of that minor. Users can update on their own schedule |

The design intends a control plane at version N to serve proxies and workers at N and N-1, so a rolling upgrade works (ADR-0024). Nothing tests that across a minor release yet, because there has been no minor release; treat it as `unverified` until the first upgrade between two releases is run.

## Step by step
For each component, upgrade one copy, wait for it to be ready, then the next. Don't start the next while the previous one is draining.

1. **Control plane.** Roll the image to the new tag (Helm: `helm upgrade limen "$CHART" --version "$VERSION" -n limen -f limen-values.yaml -f my-values.yaml`; Terraform: change `image_tag` in the example and apply; Compose: the dev stack is not an upgrade target).
   - Wait for `limen_control_plane_replicas` to recover before the next replica.
   - Look for `received audit records handed off` or, for durable spools, a restart on the same volume ([scale-out](scale-out.md#control-planes)).
2. **Proxies.** Same, one at a time. SIGTERM closes tunnels at once and workers reconnect through another proxy; open sessions finish up to the drain timeout.
3. **Workers.** Same. To end no session at all, wait for `limen_worker_sessions_active` to reach 0 on the worker first.
4. **Check.** `limen doctor` from a CLI, a login, and one session per protocol you use. Run [audit verification](audit-verify.md) again; the chain must verify across the upgrade.

## Rolling back
**There is no rollback of a migration.** A replica that starts on the old version after a newer one has migrated the database refuses to start. So:

- **Before any replica has migrated** (the first control plane is not yet upgraded, or failed before migrating): roll the image back. Nothing else is needed.
- **After one has migrated:** don't roll single replicas back. Roll the *whole* fleet back to the old version, against a database **restored from the backup you took before the upgrade**. Anything written since that backup (sessions, access requests, audit rows in the database) is lost with the restore. Audit events already shipped to S3 or Datadog stay there; the chain will show the gap, and [audit verification](audit-verify.md) tells you where.
- **Proxies and workers** keep no state that a control plane restore invalidates, except what their local directories hold (certificates, the policy snapshot, spools). Check each one after the restore; one that can't reconnect needs the steps in [worker enrollment](worker-enrollment.md). This was not tried.

Prefer a forward fix to a restore whenever the failure is not data loss.

## If it goes wrong
| Symptom | Likely cause |
|---|---|
| A control plane exits at start with a migration/version error | It is older than the database. Upgrade it instead of rolling back, or restore the database |
| Proxies or workers can't connect after step 1 | They are more than one version behind. Upgrade them now; don't roll the control plane back |
| Sessions end during step 2 or 3 | The drain was shorter than the sessions. Raise the grace period for the next copy |
| Audit verification reports a sequence gap | An `ephemeral` spool was lost, or a copy was killed before draining. See [scale-out](scale-out.md#control-planes) |

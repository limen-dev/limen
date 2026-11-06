# Upgrading Limen

One `helm upgrade` or one `terraform apply` upgrades everything in the right order: control planes, then proxies, then workers, then the CLI. You don't stage it by hand. A proxy or worker that is newer than its control plane waits, logs it, and starts only once the control plane has caught up ([ADR-0045](../adr/0045-upgrade-gate.md)). Sessions are not cut off: each copy drains on SIGTERM before it stops ([grace periods](scale-out.md#grace-periods-first)).

**Unverified.** Written from the code, the chart and the Terraform modules; no rollout has been run on a cluster or in AWS. Correct it on the first real upgrade.

## Before you start
1. **Read the release notes.** Before 1.0 a minor release may break things.
2. **Back up the database** (on Aurora, take a cluster snapshot). Migrations run when the first new control plane replica starts and only move forward, so this backup is the only way back.
3. **[Verify the audit chain](audit-verify.md)**, so a gap you see later is not one you started with.

`OLD` and `NEW` below are image tags with the leading `v`, for example `v0.1.0-rc.2`.

## Helm
```sh
CHART=oci://ghcr.io/limen-dev/charts/limen      # from a checkout: deploy/helm/limen, and drop --version
helm upgrade limen "$CHART" --version "${NEW#v}" -n limen -f limen-values.yaml -f my-values.yaml \
  --wait --timeout 40m
```
What happens: the control plane StatefulSet replaces its replicas one at a time. New proxy pods stay unready until the control plane is upgraded, and the old ones keep serving (the rollout never removes a serving proxy first). Workers follow the same way.

- **`--timeout`** must exceed the slowest rollout: replicas times the grace period. Three workers at the default 330 s is about 17 minutes.
- **Don't use `--atomic` or `helm rollback`** once the control plane has migrated; both would put the old version back on a migrated database (see *Rolling back*).
- Every group (`controlPlanes`, `proxies`, `workers` entries) rolls in the same upgrade.

## Terraform (`examples/complete`)
Set `image_tag` in `my.tfvars` to `NEW`, then plan and apply:
```sh
terraform plan  -var-file=my.tfvars -out=upgrade.plan
terraform apply upgrade.plan
```
Read the plan first. It should show new images, task definitions and the worker launch templates, and nothing else. A new resource or a changed database or key means the example changed in this release; read the notes before applying.

What happens: the ECS services (control planes and proxies) are replaced without dropping below the desired count (new tasks start before old ones stop), and `apply` waits for each service to settle. The worker Auto Scaling groups are updated only after that. Their instance refresh keeps running after `apply` returns, so wait for it:
```sh
for asg in $(terraform output -json worker_groups | jq -r '.[].autoscaling_group_name'); do
  aws autoscaling describe-instance-refreshes --auto-scaling-group-name "$asg" \
    --query 'InstanceRefreshes[0].[Status,PercentageComplete]' --output text   # until Successful 100
done
```
`examples/kubernetes` creates only the dependencies (database, KMS, S3, IAM, join tokens). Limen itself is the Helm path above.

## Check it worked
- Every replica, task and pod is ready, and `limen_control_plane_replicas` is back at its count.
- A login and a new session work, and the logs show no startup or migration errors.
- A proxy or worker logging `waiting for the control plane to be upgraded before starting` is normal while the control plane rolls. It is a problem only if the control plane never finishes.
- Workers end the sessions that outlast their drain (`session.end`, `reason: worker_drain`). To end none, wait for `limen_worker_sessions_active` to reach 0 on a worker before it is replaced.

## The CLI, last
An older CLI keeps working against the same minor, so users can update when they like.
```sh
brew update && brew upgrade limen-dev/tap/limen      # first install: brew install limen-dev/tap/limen
limen --version && limen doctor
```
The tap follows the latest release within about an hour, so right after a release `limen --version` may still show the old one; run the two commands again later. Without Homebrew, take the archive for your platform from the release (it ships `SHA256SUMS`; check it) or run `scripts/install-cli.sh` from a checkout. Then [verify the audit chain](audit-verify.md) again; it must verify across the upgrade.

## Pausing between components (optional)
To check each component before the next, keep the single tag on `OLD` and move one component at a time with an override, widening it from `control-plane` to `proxy` to `worker`. At the end set the single tag to `NEW` and drop the overrides; that last step must change nothing.
```sh
helm upgrade limen "$CHART" --version "${NEW#v}" -n limen -f limen-values.yaml -f my-values.yaml \
  --set image.tag=$OLD --set image.componentTags.control-plane=$NEW --wait --timeout 40m
terraform apply -var-file=my.tfvars -var 'image_tags={control-plane="'$NEW'"}'
```

## Rolling back
**A migration cannot be undone.** A replica on the old version refuses to start against a database a newer one has migrated.

- **The control plane failed before any replica migrated** (the first new pod or task never became ready): put the old image back and apply.
- **After a replica migrated:** roll back the whole fleet, not single replicas, against a database **restored from your backup**. Everything written since the backup (sessions, access requests, audit rows in the database) is lost. Events already in S3 or Datadog remain, and audit verification shows where the gap is. Prefer a forward fix when nothing is lost. A release without the wait doesn't have it, so move all components back together.
- **Only proxies or workers failed:** put just that component back with the per-component override. They hold no database state, so the control plane can stay on `NEW`.

## Troubleshooting
| Symptom | Likely cause |
|---|---|
| `helm upgrade --wait` times out | A pod is not ready, or `--timeout` is shorter than replicas times the grace period. `kubectl -n limen get pods`; the rollout carries on |
| A proxy or worker keeps waiting | The control plane has not finished upgrading. Look at its pods or tasks |
| A control plane exits with a migration or version error | It is older than the database. Upgrade it, or restore the database |
| `terraform plan` shows more than the expected changes | The example changed in this release; read the notes |
| `describe-instance-refreshes` stays below 100 | Workers are draining (up to the group's `stop_timeout`, 330 s by default); wait |
| Sessions end during the upgrade | The drain was shorter than the sessions: raise `terminationGracePeriodSeconds` (Helm) or `stop_timeout` (Terraform) |

# Upgrading Limen

One `helm upgrade` or one `terraform apply` upgrades in order: control planes, proxies, workers. Proxies and workers wait for a control plane at least as new as themselves ([ADR-0045](../adr/0045-upgrade-gate.md)), and sessions drain on SIGTERM ([scale-out](scale-out.md#grace-periods-first)).

**Unverified:** not run on a cluster or in AWS.

## Before
- Read the release notes; before 1.0 a minor release may break things.
- **Back up the database** (Aurora: a cluster snapshot). Migrations only move forward.
- [Verify the audit chain](audit-verify.md).

`OLD` and `NEW` are image tags with the `v`, for example `v0.1.0-rc.2`.

## Helm
```sh
CHART=oci://ghcr.io/limen-dev/charts/limen    # from a checkout: deploy/helm/limen, without --version
helm upgrade limen "$CHART" --version "${NEW#v}" -n limen -f limen-values.yaml -f my-values.yaml \
  --wait --timeout 40m
```
`--timeout` must exceed replicas times the grace period (three workers at 330 s: about 17 minutes). **No `--atomic`, no `helm rollback`** once the control plane has migrated.

## Terraform (`examples/complete`)
Set `image_tag = "NEW"` in `my.tfvars`, then:
```sh
terraform plan  -var-file=my.tfvars -out=upgrade.plan    # new images, task definitions, worker launch templates only
terraform apply upgrade.plan
```
Workers wait for the ECS services. Their instance refresh outlives `apply`:
```sh
for asg in $(terraform output -json worker_groups | jq -r '.[].autoscaling_group_name'); do
  aws autoscaling describe-instance-refreshes --auto-scaling-group-name "$asg" \
    --query 'InstanceRefreshes[0].[Status,PercentageComplete]' --output text   # until Successful 100
done
```
`examples/kubernetes` creates only the dependencies; Limen itself is the Helm path.

## Check
Replicas ready, `limen_control_plane_replicas` at its count, a login and a new session work, no startup or migration errors. A proxy or worker logging `waiting for the control plane to be upgraded` is normal until the control plane finishes. Workers end sessions that outlast their drain (`reason: worker_drain`); to end none, wait for `limen_worker_sessions_active` to reach 0.

## CLI, last
```sh
grep "limen-$NEW-<target>.tar.gz" SHA256SUMS | shasum -a 256 -c     # Linux: sha256sum -c
tar -xzf limen-$NEW-<target>.tar.gz && install -m 0755 limen-$NEW-<target>/limen ~/.local/bin/limen
limen --version && limen doctor
```
Then [verify the audit chain](audit-verify.md) again.

## Pause between components (optional)
Keep the single tag on `OLD` and widen an override: `control-plane`, then `proxy`, then `worker`. Finally set the single tag to `NEW` and drop the overrides; that must change nothing.
```sh
helm upgrade ... --set image.tag=$OLD --set image.componentTags.control-plane=$NEW --wait --timeout 40m
terraform apply -var-file=my.tfvars -var 'image_tags={control-plane="'$NEW'"}'
```

## Rolling back
A migration cannot be undone: an old replica refuses to start on a migrated database.
- **Before any control plane replica migrated:** put the old image back.
- **After:** roll back the whole fleet against a database **restored from the backup**. Writes since the backup are lost; events already in S3 or Datadog remain and verification shows the gap. Components without the gate get no protection from it, so move them together.
- **Proxies or workers only:** put just that component back. They hold no database state.

## Troubleshooting
| Symptom | Cause |
|---|---|
| `helm upgrade --wait` times out | A pod is not ready, or `--timeout` is too short. `kubectl -n limen get pods`; the rollout continues |
| A proxy or worker keeps waiting | The control plane has not finished upgrading. Look at its pods or tasks |
| Control plane exits with a migration error | It is older than the database. Upgrade it, or restore |
| `terraform plan` shows more than the list above | The example changed in this release; read the notes |
| Sessions end during the upgrade | Drain shorter than the sessions: raise `terminationGracePeriodSeconds` / `stop_timeout` |

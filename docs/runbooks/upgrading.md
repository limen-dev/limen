# Upgrading Limen

One `helm upgrade` or one `terraform apply` upgrades everything in order. Proxies and workers do not start serving until the control plane is at least their version ([ADR-0045](../adr/0045-upgrade-gate.md)), so the order **control planes, proxies, workers** needs no manual staging. Sessions keep running: every copy drains on SIGTERM ([scale-out](scale-out.md#grace-periods-first)).

**Unverified.** Written from the code, the chart and the Terraform modules; no rollout has been run on a cluster or in AWS. Expect to correct it on the first real upgrade.

## Before you start
- Read the release notes. Before 1.0 a minor release may break things.
- **Back up the database** (on Aurora, a cluster snapshot). Migrations only move forward; the backup is the only way back.
- [Verify the audit chain](audit-verify.md), so a later gap is not one you started with.

## Helm
```sh
CHART=oci://ghcr.io/limen-dev/charts/limen      # from a checkout: deploy/helm/limen, and drop --version
helm upgrade limen "$CHART" --version "$VERSION" -n limen -f limen-values.yaml -f my-values.yaml \
  --wait --timeout 40m
```
`VERSION` is the release without its `v`. The StatefulSet replaces control plane replicas one at a time; new proxy pods stay unready until the control plane is upgraded, and workers follow. `--timeout` must cover the slowest rollout: replicas times the grace period (three workers at 330 s is about 17 minutes). **Do not add `--atomic`** and do not `helm rollback` once the control plane has migrated; see *Rolling back*.

## Terraform (`examples/complete`)
Set `image_tag` in `my.tfvars` to the new release, then:
```sh
terraform plan  -var-file=my.tfvars -out=upgrade.plan     # read it: images and task definitions only
terraform apply upgrade.plan
```
The ECS services wait for a steady state, and the worker groups depend on them, so workers roll after the control planes and proxies are done. The instance refresh of the EC2 worker groups continues after `apply` returns:
```sh
for asg in $(terraform output -json worker_groups | jq -r '.[].autoscaling_group_name'); do
  aws autoscaling describe-instance-refreshes --auto-scaling-group-name "$asg" \
    --query 'InstanceRefreshes[0].[Status,PercentageComplete]' --output text   # until Successful 100
done
```
A plan that shows more than the new image means the example changed in this release; read the notes. `examples/kubernetes` creates only the dependencies (database, KMS, S3, IAM, tokens); Limen itself is the Helm path.

## Check
All replicas ready; `limen_control_plane_replicas` back at its count; a login and a new session work; no migration or startup errors in the logs. A proxy or worker that is still waiting says so: `waiting for the control plane to be upgraded before starting`. That is normal while the control plane rolls, and a problem only if the control plane never finishes. Workers end the sessions that outlast their drain (`session.end`, `reason: worker_drain`); to end none, wait for `limen_worker_sessions_active` to reach 0 first.

## The CLI
Last; an older CLI works against the same minor and users can update when they like.
```sh
grep "limen-$NEW-<target>.tar.gz" SHA256SUMS | shasum -a 256 -c      # sha256sum -c on Linux
tar -xzf limen-$NEW-<target>.tar.gz && install -m 0755 limen-$NEW-<target>/limen ~/.local/bin/limen
limen --version && limen doctor
```
From a checkout, `scripts/install-cli.sh` builds and installs it. Then re-run the [audit verification](audit-verify.md): the chain must verify across the upgrade.

## Pausing between components (optional)
To check each component before the next, pin the others to the old release and move one at a time. Keep the single tag on the old release and add an override, then widen it (`OLD` and `NEW` are image tags with the `v`).
```sh
# Helm: image.tag stays OLD; override per component (control-plane, proxy, worker)
helm upgrade limen "$CHART" --version "$VERSION" -n limen -f limen-values.yaml -f my-values.yaml \
  --set image.tag=$OLD --set image.componentTags.control-plane=$NEW --wait --timeout 40m
# Terraform: image_tag stays OLD
terraform apply -var-file=my.tfvars -var 'image_tags={control-plane="'$NEW'"}'
```
Add `proxy`, then `worker`, the same way. At the end, set the single tag to the new release and drop the overrides; that must change nothing.

## Rolling back
**A migration cannot be undone.** A replica on the old version refuses to start against a database a newer one has migrated.
- **Control plane failed before any replica migrated:** put the old image back and apply.
- **After it migrated:** roll back the *whole* fleet, against a database **restored from the backup**. Everything written since (sessions, requests, audit rows in the database) is lost; events already in S3 or Datadog remain and verification shows the gap. Prefer a forward fix if nothing is lost. A rollback to a release without the gate gets no protection from it, so move all components together. After a restore, a proxy or worker that cannot reconnect needs [re-enrollment](worker-enrollment.md) (not tried).
- **Proxies or workers only:** move that component back to the old image (`image.componentTags` / `image_tags`). They hold no database state.

## Troubleshooting
| Symptom | Likely cause |
|---|---|
| `helm upgrade --wait` times out | A pod is not ready, or `--timeout` is below replicas times the grace period. `kubectl -n limen get pods`; the rollout continues |
| A proxy or worker keeps logging that it waits | The control plane is older than it and has not finished its own upgrade. Check the control plane pods or tasks |
| A control plane exits with a migration/version error | It is older than the database. Upgrade it, or restore the database |
| `terraform plan` shows more than the new image | The example changed in this release; read the notes |
| Sessions end during the upgrade | The drain was shorter than the sessions; raise `terminationGracePeriodSeconds` / `stop_timeout` |

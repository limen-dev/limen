# Upgrading Limen

Move a deployment to a new release without ending sessions or losing audit events. The order is **control planes, then proxies, then workers, then the CLI**, one component at a time, with a check between each. The policy comes from [ADR-0024](../adr/0024-release-strategy.md); the mechanics of replacing copies are in the [scale-out runbook](scale-out.md).

**Unverified.** Nothing here has been run, not on compose, AWS or Kubernetes. It was written from ADR-0024, the scale-out runbook, the deploy guide, `release.yml`, the Helm chart and the Terraform modules. The chart renders the right image per stage (checked with `helm template`) and the example passes `terraform validate`, but no rollout was applied. Expect to correct it on the first real upgrade.

## Why one component at a time
A single `helm upgrade` or `terraform apply` with a new version rolls every component together. The control plane runs the database migration when its first new replica starts, and the design intends a control plane at version N to serve proxies and workers at N-1 (ADR-0024; untested across a minor release, as there has been none). Rolling the control plane first and checking it before touching the rest keeps a failure small, and it is the only order that stays inside that compatibility rule.

The chart and the Terraform example therefore take a **per-component tag** next to the single one:

| | Single tag (everything) | Per-component override |
|---|---|---|
| Helm | `image.tag` | `image.componentTags.control-plane`, `.proxy`, `.worker` |
| Terraform (`examples/complete`) | `image_tag` | `image_tags = { control-plane = "…", proxy = "…", worker = "…" }` |

During the upgrade you keep the single tag on the **old** release and move one component to the new release per stage. At the end you set the single tag to the new release and drop the overrides, which changes nothing in the cluster.

## Before you start
1. **Read the release notes and the changelog.** Before 1.0 a minor release may break things (ADR-0024 says breaking changes must be called out). Release-please marks commits written as `feat!:` or with a `BREAKING CHANGE:` footer.
2. **Back up the database.** Migrations only move forward, so a backup is the only way back (see *Rolling back*). On Aurora, take a cluster snapshot and note its identifier.
3. **Verify the audit chain** with [audit verification](audit-verify.md), so a gap you see later is not one you started with.
4. **Check the drain settings.** Each component's grace period must exceed its drain time or the drain is cut short ([scale-out](scale-out.md#grace-periods-first)). The chart refuses a value that is too small. The ECS and EC2 modules derive the drain from `stop_timeout`.
5. **Verify the release.** `scripts/smoke-release.sh vX.Y.Z` checks the checksums and runs the published images against the demo. The images are pinned by digest in the release's `image-refs.txt`.
6. **Set the variables** used below. `OLD` and `NEW` are image tags with the leading `v`; the chart version has none.
   ```sh
   OLD=v0.1.0-rc.2; NEW=v0.1.0
   ```

## Kubernetes (Helm)

The chart runs the control plane as a StatefulSet (rolling update, one replica at a time, waiting for readiness) and proxies and workers as Deployments (proxies `maxUnavailable: 1`, workers `maxUnavailable: 0, maxSurge: 1`). Every pod drains on SIGTERM for the grace period in `values.yaml` (45 s, 40 s and 330 s by default).

Keep the stage-specific settings in one file so each command stays the same:

```sh
cat > upgrade-values.yaml <<EOF
image:
  tag: $OLD
EOF
CHART=oci://ghcr.io/limen-dev/charts/limen      # from a checkout: CHART=deploy/helm/limen and drop --version
VERSION=${NEW#v}
UPGRADE() { helm upgrade limen "$CHART" --version "$VERSION" -n limen \
  -f limen-values.yaml -f my-values.yaml -f upgrade-values.yaml --wait --timeout 40m; }
```

`--timeout` must cover the slowest rollout: replicas times the grace period (three workers at 330 s is about 17 minutes if every pod drains in full). Do **not** add `--atomic` or run `helm rollback` once the control plane has migrated; see *Rolling back*.

**Preview.** Render the new chart with the first stage and check that only the control plane's image changed:
```sh
helm get manifest limen -n limen > before.yaml
helm template limen "$CHART" --version "$VERSION" -n limen -f limen-values.yaml -f my-values.yaml \
  --set image.tag=$OLD --set image.componentTags.control-plane=$NEW > after.yaml
diff before.yaml after.yaml
```
Expect the `helm.sh/chart` labels to differ everywhere, and the control plane's image line. If a proxy or worker pod spec changes beyond that (a new chart version can do so), those pods roll in the same stage; read the notes for that release.

**Stage 1: control planes.**
```sh
cat >> upgrade-values.yaml <<EOF
  componentTags: { control-plane: $NEW }
EOF
UPGRADE
kubectl -n limen rollout status statefulset/control-plane-core      # one per control plane group
```
Check: every replica ready, `limen_control_plane_replicas` back at its count, a login with the old CLI works, and the logs of `control-plane-core-0` show the migration without errors. Let it run a while (minutes to hours, your call) before stage 2. With several control plane groups, repeat for each (a group is a separate Limen deployment with its own database).

**Stage 2: proxies.** Edit `upgrade-values.yaml` so `componentTags` also has `proxy: $NEW`, then:
```sh
UPGRADE
kubectl -n limen rollout status deployment/proxy-public              # one per proxy group
```
Each proxy closes its tunnels on SIGTERM; workers reconnect through another proxy, and open sessions finish within the drain. Check that `limen ls` and a new session work.

**Stage 3: workers.** Add `worker: $NEW`, then `UPGRADE` and `kubectl -n limen rollout status deployment/worker-prod-db`. A worker drains for up to its `drainTimeoutSecs` (300 s) and then ends the sessions that remain (`session.end`, `reason: worker_drain`). To end none, wait for `limen_worker_sessions_active` to reach 0 on the worker being replaced first (see [scale-out](scale-out.md#proxies-and-workers)).

**Finish: drop the pins.** Replace `upgrade-values.yaml` with an empty file (or delete the `-f`), so the chart runs its own `appVersion`:
```sh
: > upgrade-values.yaml
UPGRADE
helm get values limen -n limen -a | grep -A2 '^image:'
```
This must roll nothing. If a pod restarts, the tags in the last stage and the chart's `appVersion` differ; stop and compare.

## AWS (Terraform: ECS control planes and proxies, EC2 workers)

This is `deploy/terraform/examples/complete`: control planes and proxies are ECS services (`deployment_minimum_healthy_percent = 100`, `maximum_percent = 150`, so old tasks stay until new ones are healthy; `stopTimeout` is the drain), and workers are Auto Scaling groups (rolling instance refresh at 66% healthy). **`terraform apply` returns before ECS or the instance refresh has finished**, so each stage waits explicitly.

Set the single tag to the old release and keep the overrides in a file you edit per stage (not on the command line, so a stage can be re-run):

```sh
cd deploy/terraform/examples/complete
# my.tfvars already holds image_tag = "<OLD>". Add the overrides in their own file:
echo 'image_tags = { control-plane = "'$NEW'" }' > upgrade.tfvars
terraform plan  -var-file=my.tfvars -var-file=upgrade.tfvars -out=stage1.plan
```
Read the plan. It should show only the control plane services' task definitions and services changing (`aws_ecs_task_definition` and `aws_ecs_service` for `control-plane-*`), nothing for proxies, workers, the database, KMS or the load balancers. Anything else means the module or example changed in this release: stop and read the notes. Then:

**Stage 1: control planes.**
```sh
terraform apply stage1.plan
```
The cluster is named after `var.name` and each service `<name>-<key>`. Wait for the rollout, then check:
```sh
NAME=limen-prod                         # your var.name
SERVICES=$(terraform output -json ecs_services | jq -r 'to_entries[] | select(.key|startswith("control-plane")) | .value.name')
aws ecs wait services-stable --cluster "$NAME" --services $SERVICES
```
(`wait` polls for up to 10 minutes; run it again if it times out while tasks are still draining.) Check: every control plane task healthy, `limen_control_plane_replicas` at its count, a login works, no migration error in the log group `/limen/<name>/control-plane-<key>`.

**Stage 2: proxies.** Change `upgrade.tfvars` to `image_tags = { control-plane = "<NEW>", proxy = "<NEW>" }`, then plan, apply and wait the same way, selecting the services whose key starts with `proxy`:
```sh
echo 'image_tags = { control-plane = "'$NEW'", proxy = "'$NEW'" }' > upgrade.tfvars
terraform plan  -var-file=my.tfvars -var-file=upgrade.tfvars -out=stage2.plan   # only proxy services change
terraform apply stage2.plan
SERVICES=$(terraform output -json ecs_services | jq -r 'to_entries[] | select(.key|startswith("proxy")) | .value.name')
aws ecs wait services-stable --cluster "$NAME" --services $SERVICES
```

**Stage 3: workers.** Add `worker = "<NEW>"`, plan and apply. Only the launch templates of the worker groups change, and the Auto Scaling groups start an instance refresh. Wait for each group:
```sh
echo 'image_tags = { control-plane = "'$NEW'", proxy = "'$NEW'", worker = "'$NEW'" }' > upgrade.tfvars
terraform plan  -var-file=my.tfvars -var-file=upgrade.tfvars -out=stage3.plan
terraform apply stage3.plan
for asg in $(terraform output -json worker_groups | jq -r '.[].autoscaling_group_name'); do
  aws autoscaling describe-instance-refreshes --auto-scaling-group-name "$asg" \
    --query 'InstanceRefreshes[0].[Status,PercentageComplete]' --output text
done                                   # repeat until every group says Successful 100
```
Each replaced instance stops its container with the group's `stop_timeout` (330 s default), so a refresh of a large group takes a while. Open sessions end with `reason: worker_drain` only if they outlast the drain.

**Finish: drop the overrides.** Set `image_tag = "<NEW>"` in `my.tfvars`, delete `upgrade.tfvars`, and plan:
```sh
rm upgrade.tfvars
terraform plan -var-file=my.tfvars       # must say: No changes.
```
A plan that still shows changes means the tags differ from the last stage; fix that before anything else.

**The Kubernetes example** (`examples/kubernetes`) creates the dependencies only (database, KMS, S3, IAM, join tokens). Limen itself is the chart above; a release only needs `terraform apply` there if its notes say the dependencies changed.

## The CLI
Last, because an older CLI works against a deployment of the same minor (ADR-0024) and users can update on their own schedule.

1. Download `limen-<NEW>-<target>.tar.gz` and `SHA256SUMS` from the release, check the sum, and put `limen` on the `PATH`:
   ```sh
   grep "limen-$NEW-<target>.tar.gz" SHA256SUMS | shasum -a 256 -c      # or sha256sum -c on Linux
   tar -xzf limen-$NEW-<target>.tar.gz
   install -m 0755 limen-$NEW-<target>/limen ~/.local/bin/limen
   ```
   (From a checkout, `scripts/install-cli.sh` builds and installs it.)
2. `limen --version`, then `limen doctor`. It checks the proxy, CA, network, clock and login in order and says how to fix each failure.

## Finally
Run [audit verification](audit-verify.md) again; the chain must verify across the upgrade. Then delete `upgrade-values.yaml` / `upgrade.tfvars` and the plans, which can contain environment values.

## Rolling back
**There is no rollback of a migration.** A replica that starts on the old version after a newer one has migrated the database refuses to start. So:

- **Stage 1 failed before any replica migrated** (the first new task or pod never became ready): set the control plane tag back to `$OLD` (remove it from `componentTags` / `image_tags`) and apply. Nothing else is needed.
- **After a control plane has migrated:** don't roll single replicas back. Roll the *whole* fleet back to the old version against a database **restored from the backup you took before the upgrade**. Anything written since that backup (sessions, access requests, audit rows in the database) is lost with the restore. Audit events already in S3 or Datadog stay; the chain shows the gap and [audit verification](audit-verify.md) tells you where. Prefer a forward fix whenever the failure is not data loss.
- **Stage 2 or 3 failed** (proxies or workers only): roll that component back by moving its tag back to `$OLD`. They keep no database state, so the control plane can stay on `$NEW`.
- **Helm:** never `--atomic` and never `helm rollback` after stage 1. Both would roll the control plane back onto a migrated database.
- **After a database restore** check each proxy and worker. One that can't reconnect needs the steps in [worker enrollment](worker-enrollment.md). This was not tried.

## If it goes wrong
| Symptom | Likely cause |
|---|---|
| `helm upgrade --wait` times out | A pod is not ready, or the timeout is shorter than replicas times the grace period. `kubectl -n limen get pods`, `describe` the stuck one. The rollout keeps going; re-run `rollout status` |
| A control plane exits at start with a migration/version error | It is older than the database. Upgrade it instead of rolling back, or restore the database |
| Proxies or workers can't connect after stage 1 | `unverified` guess: they are too far behind the control plane (ADR-0024 intends N and N-1 to work). Move them to `$NEW`; don't roll the control plane back |
| `terraform plan` shows more than the stage's component | The example or a module changed in this release. Stop and read the notes |
| `aws ecs wait` times out | Tasks are still draining or failing health checks; look at the service events and the log group, then run it again |
| Sessions end during stage 2 or 3 | The drain was shorter than the sessions. Raise the grace period (`stop_timeout` / `terminationGracePeriodSeconds`) for the next copy |
| Audit verification reports a sequence gap | An `ephemeral` spool was lost, or a copy was killed before draining. See [scale-out](scale-out.md#control-planes) |

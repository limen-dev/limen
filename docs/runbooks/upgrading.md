# Upgrading Limen

Upgrade **control planes, then proxies, then workers, then the CLI**, one component at a time, checking between each ([ADR-0024](../adr/0024-release-strategy.md)). Sessions keep running: every copy drains on SIGTERM ([scale-out](scale-out.md#grace-periods-first)).

**Unverified.** Written from ADR-0024, the chart and the Terraform modules; no rollout has been run. The design intends a control plane at version N to serve proxies and workers at N-1, but no minor release exists yet to test that.

## Before you start
- Read the release notes. Before 1.0 a minor release may break things.
- **Back up the database** (on Aurora, a cluster snapshot). Migrations only move forward; the backup is the only way back.
- [Verify the audit chain](audit-verify.md), so a later gap is not one you started with.
- `OLD=v0.1.0-rc.2; NEW=v0.1.0` (image tags with the `v`).

Both the chart and the Terraform example take one tag for everything, plus a per-component override. Keep the single tag on `$OLD` and move one component per stage. At the end, set the single tag to `$NEW` and drop the overrides; that must change nothing.

## Helm
```sh
CHART=oci://ghcr.io/limen-dev/charts/limen   # from a checkout: deploy/helm/limen, and drop --version
upgrade() { helm upgrade limen "$CHART" --version "${NEW#v}" -n limen --wait --timeout 40m \
  -f limen-values.yaml -f my-values.yaml --set image.tag=$OLD "$@"; }

upgrade --set image.componentTags.control-plane=$NEW
kubectl -n limen rollout status statefulset/control-plane-core       # then check, below

upgrade --set image.componentTags.control-plane=$NEW --set image.componentTags.proxy=$NEW
kubectl -n limen rollout status deployment/proxy-public

upgrade --set image.componentTags.control-plane=$NEW --set image.componentTags.proxy=$NEW \
        --set image.componentTags.worker=$NEW
kubectl -n limen rollout status deployment/worker-prod-db

helm upgrade limen "$CHART" --version "${NEW#v}" -n limen -f limen-values.yaml -f my-values.yaml
```
The last command drops the pins and must roll nothing. Repeat the `rollout status` for every group (one control plane group is one Limen deployment with its own database). `--timeout` must cover replicas times the grace period (three workers at 330 s is about 17 minutes). Never use `--atomic` or `helm rollback` after the first stage; see *Rolling back*.

## Terraform (`examples/complete`: ECS control planes and proxies, EC2 workers)
`apply` returns before ECS or the instance refresh finishes, so each stage waits. `my.tfvars` holds `image_tag = "<OLD>"`.
```sh
NAME=limen-prod                                  # your var.name; the ECS cluster has this name
stage() { terraform plan -var-file=my.tfvars -var "image_tags=$1" -out=stage.plan && terraform apply stage.plan; }
ecs_wait() { aws ecs wait services-stable --cluster "$NAME" --services \
  $(terraform output -json ecs_services | jq -r "to_entries[]|select(.key|startswith(\"$1\"))|.value.name"); }

stage '{control-plane="'$NEW'"}';                                    ecs_wait control-plane
stage '{control-plane="'$NEW'",proxy="'$NEW'"}';                     ecs_wait proxy
stage '{control-plane="'$NEW'",proxy="'$NEW'",worker="'$NEW'"}'
for asg in $(terraform output -json worker_groups | jq -r '.[].autoscaling_group_name'); do
  aws autoscaling describe-instance-refreshes --auto-scaling-group-name "$asg" \
    --query 'InstanceRefreshes[0].[Status,PercentageComplete]' --output text   # until Successful 100
done
```
**Read each plan before applying:** it must change only that component's task definitions and services (ECS) or launch templates (workers). Anything else means the example changed in this release; stop and read the notes. `ecs_wait` polls up to 10 minutes; run it again if it times out. Finish by setting `image_tag = "<NEW>"` in `my.tfvars`: `terraform plan -var-file=my.tfvars` must say *No changes*.

`examples/kubernetes` only creates the dependencies (database, KMS, S3, IAM, tokens); Limen itself is the Helm path.

## Check after each stage
All replicas ready; `limen_control_plane_replicas` back at its count; a login and a new session work; no migration or startup errors in the logs (`control-plane-core-0`, or the log group `/limen/<name>/control-plane-<key>`). Let the control plane run a while before moving on. Workers end the sessions that outlast their drain (`session.end`, `reason: worker_drain`); to end none, wait for `limen_worker_sessions_active` to reach 0 first.

## The CLI
Last; an older CLI works against the same minor and users can update when they like.
```sh
grep "limen-$NEW-<target>.tar.gz" SHA256SUMS | shasum -a 256 -c      # sha256sum -c on Linux
tar -xzf limen-$NEW-<target>.tar.gz && install -m 0755 limen-$NEW-<target>/limen ~/.local/bin/limen
limen --version && limen doctor
```
From a checkout, `scripts/install-cli.sh` builds and installs it. Then re-run the [audit verification](audit-verify.md): the chain must verify across the upgrade.

## Rolling back
**A migration cannot be undone.** A replica on the old version refuses to start against a database a newer one has migrated.
- **Control plane failed before any replica migrated:** remove its override (or put it back on `$OLD`) and apply.
- **After it migrated:** roll back the *whole* fleet, against a database **restored from the backup**. Everything written since (sessions, requests, audit rows in the database) is lost; events already in S3 or Datadog remain and verification shows the gap. Prefer a forward fix if nothing is lost. After a restore, a proxy or worker that cannot reconnect needs [re-enrollment](worker-enrollment.md) (not tried).
- **Proxies or workers failed:** move only that component back to `$OLD`. They hold no database state.

## Troubleshooting
| Symptom | Likely cause |
|---|---|
| `helm upgrade --wait` times out | A pod is not ready, or `--timeout` is below replicas times the grace period. `kubectl -n limen get pods`; the rollout continues |
| Control plane exits with a migration/version error | It is older than the database. Upgrade it, or restore the database |
| Proxies or workers cannot connect after stage 1 | `unverified`: too far behind the control plane. Move them to `$NEW` |
| `terraform plan` shows more than the stage's component | The example changed in this release; read the notes |
| Sessions end during a stage | The drain was shorter than the sessions; raise `terminationGracePeriodSeconds` / `stop_timeout` |

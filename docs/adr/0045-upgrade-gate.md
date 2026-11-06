# ADR-0045: Components wait for an upgraded control plane

- Status: Accepted (owner directed this on 2026-11-06: upgrades should run in one `helm upgrade` or one `terraform apply`)
- Date: 2026-11-06

## Context
ADR-0024 says to upgrade the control plane first, then proxies, then workers, and intends a control plane at N to serve proxies and workers at N-1. Nothing enforced the order. One `helm upgrade` or `terraform apply` rolled every component at once, so a new proxy could start against an old control plane (the pairing nobody supports), and the only safe path was several manual stages.

Helm applies all manifests together and does not wait between kinds, so the chart cannot order a rollout by itself. Hook Jobs that run `kubectl rollout status` were rejected: they need RBAC and a kubectl image in the chart.

## Decision
- **The component enforces the order.** After it has its identity (loaded or freshly enrolled), a proxy or worker asks the control plane for its version (`PolicySync.GetServerVersion`, components only, not rate limited) and does not start serving until the answer is at least its own version. It polls every 2 to 15 seconds and logs each wait. A worker asks through its proxy, like its other calls to the control plane. The gate compares semantic versions, so a release candidate is older than its release and build metadata is ignored.
- **It waits only on a positive answer that the control plane is older.** A control plane from before this call answers `UNIMPLEMENTED`, which counts as older. If the control plane cannot be reached, answers with another error, or sends a version that cannot be read, the component starts as before. Starting must never depend on the control plane being up (ADR-0011): a proxy restarted during an outage still serves from its cached policy within the grace period.
- **There is no bypass.** No flag or environment variable turns the gate off. A fleet rollback moves every component to the old version together, and the old components have no gate.
- **A stop signal ends the wait.** The proxy and worker `main` race startup against the shutdown signal.
- **Deployments allow for the wait.** While it waits a component serves nothing, not even its admin port (that comes up with the listeners). So the chart gives the proxy a `startupProbe` that tolerates 30 minutes before its liveness probe starts, and sets the proxy rollout to `maxUnavailable: 0` so a waiting new pod never replaces a serving old one. The ECS module gives load-balanced proxy services a health check grace period and waits for each service's steady state. The EC2 module takes a `start_after` list (the example passes the ECS service names), so the worker groups are updated only after the ECS services are done. That is a value dependency, not `depends_on` on the module, which would defer the module's data sources (the AMI lookup) to apply time whenever ECS has changes and plan the launch templates as unknown.
- **Per-component tags stay as an option.** `image.componentTags` (Helm) and `image_tags` (Terraform example) let an operator pause between stages. They are no longer needed for a safe upgrade.

## Consequences
- A normal upgrade is one `helm upgrade --wait --timeout …` or one `terraform apply`. The proxies and workers sit in the rollout until the control plane has been upgraded, then proceed.
- **The check is per answering replica.** The registry stores no version per replica, and adding one needs a migration, so it was left out. While the control plane itself rolls, a new proxy can get its answer from a replica that is already upgraded and then talk to one that is not. That window is the length of the control plane's own rollout, instead of the whole fleet's, and the supported pairing (control plane at least as new) holds for the rest. The runbook still says to check after the control plane stage if you split it.
- **Upgrading to the first release with the gate is covered.** Its new proxies and workers ask the old control plane, get `UNIMPLEMENTED`, and wait. Components from before the gate cannot wait, so a rollback to such a release is not protected: roll the whole fleet back, as ADR-0024 says.
- A new proxy or worker that is deliberately newer than its control plane waits forever, loudly. Upgrade the control plane, or run the matching version.
- One more RPC for components, read-only and returning a version string. It adds no state and no secret.
- The gate does not protect the database: migrations still run when a control plane replica starts and still only move forward. Rollback still means restoring a backup (ADR-0024).

## Alternatives
- **Hook Jobs** that roll the components in order: rejected above.
- **An init container** that polls the control plane: needs a shell or a second binary in distroless images, works only on Kubernetes, and cannot read the version without code in the component anyway.
- **Gating on the lowest live replica version:** more exact, needs a registry migration. Possible later.
- **Splitting the ECS module** into control plane and proxy modules so Terraform orders them: changes the resource addresses of existing deployments, which would replace their services.

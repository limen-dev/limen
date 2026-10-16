# Limen on Kubernetes: scale-out example

Three control planes, three proxies, and three workers, laid out as [Running Limen at scale](../../docs/scale-out.md) describes. **Unverified:** these manifests were parsed and checked for obvious mistakes (matching selectors, no duplicate variables) but never applied to a cluster, because none was available. The behaviour they rely on (stable ids, drain, handoff, rebalancing) is exercised by `deploy/compose/demo-phase5.sh` and the end-to-end tests on Docker. Read them as a starting point and test them on a cluster of yours.

| File | What it runs | Why it looks that way |
|---|---|---|
| `control-plane.yaml` | A **StatefulSet** of 3 with a volume each, a headless Service, and a PodDisruptionBudget | The pod name (`control-plane-0`..`2`) is the replica's `LIMEN_ID`, so a restarted pod resumes its own audit spool and chain (`LIMEN_SPOOL_MODE=durable`). The headless Service makes the name resolve to the ready pods only; a draining pod stops being ready first |
| `proxy.yaml` | A **Deployment** of 3 and a `LoadBalancer` Service (an AWS NLB in TCP mode) | Proxies are stateless apart from their tunnels. Each advertises its pod IP for peering on the public port |
| `worker.yaml` | A **Deployment** of 3 | Workers dial out; nothing connects to them. Scale them on sessions per worker, not CPU |

## Before you apply

1. Replace every `REPLACE`: image names, the OIDC issuer and client id, the audit bucket, the KMS key ids, the load balancer's DNS name, and the names in `LIMEN_NAME`.
2. Create what the manifests read: `Secret/limen-database` (key `url`: the PostgreSQL URL), `Secret/limen-proxy-join` and `Secret/limen-worker-join` (key `token`), and `ConfigMap/limen-internal-ca` (key `internal-ca.pem`: the public internal CA certificate). A single-use join token enrolls one pod; for a Deployment that restarts pods, use a **multi-use static token** (see [worker enrollment](../../docs/runbooks/worker-enrollment.md)) or keep each pod's identity on a volume.
3. Use the **KMS** CA backend, as the control plane manifest does. File-backed CA keys need one volume that every replica can write (ReadWriteMany); KMS keys are shared by id and need nothing else.
4. Check the grace periods against the drain times: control plane 45 s over `LIMEN_DRAIN_TIMEOUT` 20 s; proxy 40 s over 20 s; worker 330 s over `LIMEN_DRAIN_TIMEOUT_SECS` 300 s. The kubelet ends a pod that outlasts its grace period, and with it any session or audit event still in flight.

## Scaling

- Control planes and proxies: scale on CPU and connections. Watch `limen_control_plane_replicas`.
- Workers: scale on `limen_worker_sessions_active / limen_worker_sessions_max`, with a target around 0.6, using your metrics pipeline (for example a Prometheus adapter feeding a HorizontalPodAutoscaler). A HorizontalPodAutoscaler is not included because the metric source differs between clusters.
- Scaling a StatefulSet down leaves the volume of the removed pod behind. If it still holds unshipped audit events, hand them to a peer with `limen-spool-adopt` before you delete the volume (see the [runbook](../../docs/runbooks/scale-out.md)).

ECS and EC2 Auto Scaling examples are part of Phase 13, with the Terraform modules.

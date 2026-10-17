`kubectl` through Limen: sign in once, get a short-lived certificate, and work in the clusters policy lets you reach. Everything is audited, and `exec` sessions are recorded. How it works is in [ADR-0033](../adr/0033-kubernetes-access.md).

# Using Kubernetes with Limen

## As a user

```sh
limen login
limen ls                         # clusters show as kind "kubernetes", with the groups you may use
limen kube login eks-staging     # writes a kubeconfig for that cluster
export KUBECONFIG=~/.limen/profiles/<proxy>/kubeconfig-eks-staging.json
kubectl get pods -A
kubectl exec -it deploy/web -- sh        # recorded
kubectl port-forward svc/db 5432:5432    # audited
```

- The kubeconfig holds **no secret**. Its only credential is an exec plugin that runs `limen kube credentials`, which prints the certificate `limen login` gave you. When that expires, `kubectl` says so; run `limen login` again.
- `--kubeconfig FILE` writes somewhere else (to merge into your own, set `KUBECONFIG=a:b`), and `--print` writes to standard output.
- Who you are inside the cluster: `kubectl auth whoami` shows your Limen user name, the groups policy gave you (such as `limen:edit`), and the Limen session ID under `limen-session`. What you may do there is the cluster's RBAC for those groups, so `Forbidden` errors come from the cluster, not from Limen.
- `--as`, `--as-group`, and a token in your kubeconfig are ignored. You are always yourself.

## What gets recorded and audited

| Action | Audit | Recording |
|---|---|---|
| any API request | `kube.request`: user, groups, verb, resource, namespace, name, status, latency (no bodies, no query strings) | no |
| `exec`, `attach` | `session.start` (command, pod) and `session.end` (exit code) | yes: output, resizes, exit status, as asciicast. **Stdin is not recorded**, because it holds passwords. Play it in the console or with `asciinema play` |
| `port-forward` | `session.start` and `session.end` with the ports and bytes each way | no |

`kubectl cp`, `kubectl debug`, and `kubectl run -it` use exec or attach underneath and are recorded the same way. A stream Limen cannot decode is refused rather than let through unrecorded. Locking a user, or killing a session, ends open streams within a second or two.

## As an operator

1. **Policy.** A cluster is a resource, and roles grant Kubernetes **groups** on it:

   ```yaml
   kind: resource
   version: v1
   metadata: { name: eks-staging, labels: { env: staging } }
   spec:
     kubernetes: { cluster_name: staging }
     worker_selector: { pool: staging }
   ---
   kind: role
   version: v1
   metadata: { name: sre }
   spec:
     allow:
       - resources: { kind: [kubernetes], labels: { env: [staging] } }
         kube: { groups: ["limen:edit"] }
   ```

   Groups may not start with `system:`. A user gets every group their roles grant on the cluster.
2. **Cluster.** Apply [`deploy/kube/limen-kube-worker.yaml`](../../deploy/kube/limen-kube-worker.yaml) (a service account that can only impersonate) and bind your groups to roles, as in [`limen-groups.yaml`](../../deploy/kube/limen-groups.yaml).
3. **Worker.** One kube worker per cluster, enrolled like any worker ([runbook](../runbooks/worker-enrollment.md)) with the cluster flags. In a pod, `--kube-cluster` is enough: the API server address, CA, and service account token come from the pod.

   ```sh
   limen-worker --proxy-addr limen.example.com:443 --join-token … \
     --kube-cluster staging                      # must equal kubernetes.cluster_name
   # outside the cluster:
   #   --kube-api-server https://… --kube-ca-file ca.pem --kube-token-file token
   ```

   Run the worker with labels that match `worker_selector`. A worker serves exactly one cluster and refuses grants for another.
4. **Audit.** The worker needs the control plane to be reachable to audit; if the trail is unavailable it answers `503` instead of the cluster's response (fail closed, ADR-0009).

## Limits today

- Verified against **kind** with kubectl 1.35 and Kubernetes 1.37, over WebSocket and SPDY. **Not verified on Amazon EKS** (no AWS account): EKS endpoint access (private endpoints need the worker inside the VPC), and the worker's token and CA on EKS, are the parts that may differ.
- Limen policy picks groups, not verbs or namespaces; use RBAC for those.
- Constrained impersonation (Kubernetes 1.36 and later) is not used yet.
- One request is one tunnel session, which suits `kubectl` but would be heavy for a controller issuing thousands of requests a second. Use a service account in the cluster for those.

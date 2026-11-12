`kubectl` through Limen: sign in once, get a short-lived certificate, and work in the clusters policy lets you reach. Every request is audited and `exec` sessions are recorded. Design: [ADR-0038](../adr/0038-kubernetes-access.md).

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

For every cluster at once, `limen kube config` writes `~/.limen/kubeconfig` with a `limen-<cluster>` context per reachable cluster (through every proxy you use), rewritten on every `limen login`. Add it to kubectl's list once, in your shell profile:

```sh
limen kube config
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}:$HOME/.limen/kubeconfig"
kubectl --context limen-eks-staging get pods
```

It sets no current context, so yours stays in charge; `kubectl config use-context limen-eks-staging` switches. `--print` shows it without writing; `--uninstall` deletes it. `--kubeconfig FILE` writes elsewhere.

- The kubeconfig holds **no secret**. Its only credential is an exec plugin running `limen kube credentials`, which prints the certificate from `limen login`. When it expires, `kubectl` says so; run `limen login`.
- `kubectl auth whoami` shows your Limen user name, the groups policy gave you (such as `limen:edit`) and the session id under `limen-session`. What you may do is the cluster's RBAC for those groups, so `Forbidden` comes from the cluster, not Limen.
- `--as`, `--as-group` and a token in your kubeconfig are ignored. You are always yourself.

## What is recorded and audited

| Action | Audit | Recording |
|---|---|---|
| any API request | `kube.request`: user, groups, verb, resource, namespace, name, status, latency (no bodies, no query strings) | no |
| `exec`, `attach` | `session.start` (command, pod) and `session.end` (exit code) | yes: output, resizes, exit status, as asciicast. **Stdin is not recorded** (it holds passwords). Play it in the console or with `asciinema play` |
| `port-forward` | `session.start` and `session.end` with ports and bytes each way | no |

`kubectl cp`, `debug` and `run -it` use exec or attach underneath and are recorded the same way. A stream Limen can't decode is refused rather than let through unrecorded.

In the console, **Audit trail → Kubernetes** shows each request as kubectl would say it (`get pods default/web 200`), filterable by cluster, verb, namespace, user and refused or failed. Under **Sessions**, one login on one cluster is one `kubectl` session whose page lists every API request (time, verb, resource, namespace, name, status), refused ones marked. It counts as active while the last request is under five minutes old, or until `limen logout` ends it at once (reason "logged out"): the certificate is then refused by proxy and workers, open `watch`, `logs -f` and `exec` streams on it end, and the user's other logins carry on. Exec and attach also get their own recorded session, linked from the request's row.

Locking a user or killing a session ends open streams and long-running responses (`get -w`, `logs -f`) within a second or two. So does a grant reaching its `max_session_ttl`.

## As an operator

1. **Policy.** A cluster is a resource; roles grant Kubernetes **groups** on it.

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

   Neither groups nor user names may start with `system:` (a user called `system:kube-scheduler` would inherit that identity's RBAC); the worker refuses both. A user gets every group their roles grant on the cluster.
2. **Cluster.** Apply [`deploy/kubernetes/access/limen-kube-worker.yaml`](../../deploy/kubernetes/access/limen-kube-worker.yaml) (a service account that can only impersonate) and bind your groups to roles, as in [`limen-groups.yaml`](../../deploy/kubernetes/access/limen-groups.yaml).
3. **Worker.** One per cluster, enrolled like any worker ([runbook](../runbooks/worker-enrollment.md)), with labels matching `worker_selector`. It serves exactly one cluster and refuses grants for another. In a pod, `--kube-cluster` is enough: the API server address, CA and service account token come from the pod.

   ```sh
   limen-worker --proxy-addr limen.example.com:443 --join-token … \
     --kube-cluster staging                      # must equal kubernetes.cluster_name
   # outside the cluster:
   #   --kube-api-server https://… --kube-ca-file ca.pem --kube-token-file token
   ```
4. **Audit.** The worker needs the control plane reachable to audit; if the trail is unavailable it answers `503` instead of the cluster's response (fail closed, ADR-0009). A request that fails on the way to or from the API server (it may already have been applied) is audited with status `502` and an `error` field. The cluster rejecting the worker's own token is a `503`, not a login prompt.

## Limits

- **Verification.** Tested on **kind** (kubectl 1.35, Kubernetes 1.37, WebSocket and SPDY) and on the compose stack's **k3s** 1.35 (read, create, exec, port-forward and RBAC denials, single and scaled). **Unverified on Amazon EKS**: private endpoints need the worker inside the VPC, and the worker's token and CA may differ there.
- Policy picks groups, not verbs or namespaces; use RBAC for those.
- Constrained impersonation (Kubernetes 1.36+) isn't used yet.
- Each request is a session with a one-time grant, and a worker remembers 100,000 grants for a minute: about 1,700 requests a second per worker before it refuses new ones (fail closed). That suits `kubectl` but not a controller issuing thousands of requests a second; give those a service account in the cluster.

## Try it

`demos/demo-phase8.sh --manual` builds a throwaway kind cluster and Postgres (named after `LIMEN_DEMO_CLUSTER`, default `kubernetes-demo8`), runs Limen with the console in front, and prints commands to try: `limen kube login`, `kubectl get/exec/port-forward/logs`, a view-only user and `limen admin lock`. The console is on the same port (`/console/sessions`, `/console/audit`), signing in as `admin@example.com`; write `email group` to the printed `browser-user` file to be someone else. Ctrl-C stops Limen and keeps the cluster.

With the full local stack and a real sign-in, `deploy/compose/setup.sh --stacks kube` starts the dev stack, a k3s cluster `kubernetes-dev`, and a second worker serving it as `eks-staging` (pool `kube`):

```sh
limen --server localhost:3443 login --ca-file deploy/compose/.state/internal-ca.pem   # admin@example.com / password
limen kube login eks-staging --kubeconfig /tmp/eks-staging.json
export KUBECONFIG=/tmp/eks-staging.json
kubectl get pods -A
```

`admin@example.com` is in the `sre` group, which `examples/policy` grants `limen:edit` on `env: staging` Kubernetes resources. Logins last 30 minutes. `deploy/compose/setup.sh down` stops the stack and deletes its data, cluster included. It uses the dev stack's ports (3443, 3444, 3081, 5556 and others `setup.sh` lists) and won't start if another stack holds them.

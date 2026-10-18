# Kubernetes

| Folder | What it is |
|---|---|
| [`limen/`](limen) | Run Limen itself on Kubernetes: three control planes, three proxies, three workers (scale-out example, unverified on a real cluster) |
| [`access/`](access) | Apply these to a cluster Limen should reach: the service account the Limen kube worker uses to impersonate people, and example group bindings |

The local stack that brings up Limen together with a kind cluster is `deploy/compose/setup.sh --stacks kube`.

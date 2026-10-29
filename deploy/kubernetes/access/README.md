# Kubernetes manifests for Limen

- `limen-kube-worker.yaml`: the service account a Limen kube worker runs as. It may impersonate users, the `limen:view`/`edit`/`admin` groups, and the `limen-session` extra, and nothing else.
- `limen-groups.yaml`: example bindings from those groups to the built-in `view`, `edit`, and `cluster-admin` roles. Change them to taste; the group names are the contract with Limen policy (`kube: { groups: [...] }`).

Guide: [docs/guides/kubernetes.md](../../../docs/guides/kubernetes.md). Design: [ADR-0038](../../../docs/adr/0038-kubernetes-access.md).

Try it on kind: `demos/demo-phase8.sh` creates a cluster, applies both files, starts Limen in front of it, and checks `kubectl get`, `exec`, `port-forward`, RBAC, recordings, and locks.

A Helm chart and Terraform for EKS come with Phase 15.

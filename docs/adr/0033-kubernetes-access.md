# ADR-0033: Kubernetes (EKS) access through impersonation

- Status: Proposed (Phase 8 proposal; needs owner approval before any code)
- Date: 2026-10-17

## Context
Phase 8 exit criteria (`docs/design.md` §13): `kubectl get`, `exec`, and `port-forward` work on kind through impersonation, and exec is recorded. Design §5.4 sketches the approach, ADR-0005 routes `/k8s/<cluster>/...` on the single port, and ADR-0018 already ships the `kubernetes` resource kind, the `kube.groups` grant, and a `limen kube login` stub that answers "planned for Phase 8". This ADR settles what the sketch leaves open, so the phase can be built without surprises.

## Decisions

### 1. Impersonation, not per-user cluster credentials
The **kube worker** runs inside the target cluster (or anywhere that can reach its API server, with a kubeconfig) under a service account whose ClusterRole allows only `impersonate` on `users`, `groups`, and `userextras/limen-session`. It forwards each request with `Impersonate-User`, `Impersonate-Group`, and `Impersonate-Extra-limen-session`. Cluster RBAC, bound to the `limen:*` group names, stays the source of truth for what a user may do *inside* the cluster; Limen policy decides only *which groups* a user may assume on *which cluster*.

Alternatives rejected: minting a client certificate the API server trusts (needs control of the cluster CA, which EKS does not give), and EKS access entries or `aws-iam-authenticator` per user (ties Limen to AWS and to long-lived mappings; it remains a documented fallback for operators who do not want the worker).

### 2. Request path
`kubectl` → proxy (`/k8s/<cluster>`, mTLS with the user's Limen certificate) → tunnel → kube worker → API server. The kubeconfig context written by `limen kube login <cluster>` uses an exec credential plugin (`limen kube credentials`, `client.authentication.k8s.io/v1`) that returns the short-lived user certificate and key, and logs in again when expired. No long-lived token is ever written to the kubeconfig.

The proxy checks that policy grants the user *some* group on the cluster and that the cluster's worker is connected, and then relays bytes. The **worker** is the only hop that talks to the API server, and only to the address in the resource definition (no open proxying, as in ADR-0022).

### 3. Header hygiene (fail closed)
The worker deletes every client-supplied `Impersonate-*` header and `Authorization`, and sets its own from the signed grant. Groups come only from the grant, are intersected with the `limen:*` allow-list when the operator configures one, and `system:*` groups (above all `system:masters`) are rejected by policy parsing (already enforced) and again in the worker. A request whose grant is missing, expired, or locked is refused with 403 and audited.

### 4. Streaming: exec, attach, port-forward
kubectl 1.30+ uses WebSocket (`v5.channel.k8s.io`) for exec, attach, and port-forward; older clients and some tools use SPDY/3.1. The worker supports **both**, as a transparent upgrade proxy that understands just enough framing to read the channels. The framing code is our own and small (no new dependency unless the maintenance review in ADR-0012 favors one), and fuzzed.

- **exec and attach** are recorded as asciicast v3 using the same recording pipeline as SSH (ADR-0009): stdout and stderr as output events, stdin as input events, resize messages as resize events. Recordings upload with the usual spool and hash-chain guarantees; a recording that cannot be written ends the stream (audit fails closed).
- **port-forward** is audited (pod, namespace, ports, bytes each way, duration), not recorded.
- Idle and maximum session lifetimes apply, and `lock` or `session kill` closes the upgraded stream, as for SSH.

### 5. Audit
One `kube.request` per API request: user or bot, groups, cluster, verb, resource, namespace, name, subresource, status, latency, and the Limen session ID. Bodies are not recorded by default (Secrets would leak). `kube.exec` and `kube.portforward` events bracket the streams and link to the recording. Watches are one event per watch with duration and event count, not per event.

### 6. Authorization shape
Policy keeps the grant from ADR-0018: `kube: { groups: [...] }`. Resource label matching is unchanged. Phase 8 adds no verb-level policy in Limen; verb, namespace, and resource restrictions are RBAC's job, and we ship example `ClusterRole` and `ClusterRoleBinding` manifests for `limen:view`, `limen:edit`, and `limen:admin` under `deploy/kube/`. Constrained impersonation (Kubernetes 1.36+) is planned hardening, noted in the threat model.

### 7. Worker enrollment
The kube worker enrolls like any worker (ADR-0016, join token) and registers `kubernetes` resources with `cluster_name`. In the cluster it runs from a manifest in `deploy/kube/` (Deployment, ServiceAccount, ClusterRole); locally the demo runs it against kind.

## Out of scope for this phase
Helm chart and Terraform for EKS (Phase 13), the AWS IAM join (Phase 13), EKS access-entry integration, verb-level Limen policy, `kubectl` without the exec plugin (static tokens are intentionally unsupported), and multi-cluster fan-out.

## Verification plan
- **Verified locally:** a `kind` cluster in the compose demo (`deploy/compose/demo-phase8.sh`): `kubectl get` as allowed and denied users, RBAC enforced through groups, forged `Impersonate-*` headers ignored, `exec` (WebSocket and SPDY) recorded and playable, `port-forward` audited, lock ends an open exec.
- **Unverified against real service:** EKS itself (endpoint auth, `eks:*` tokens for the worker, the cluster CA and private endpoints). Everything EKS-specific is labelled `unverified`.
- Unit and integration tests for header stripping, group intersection, both streaming protocols (against a stand-in API server), and recorder fail-closed behavior; a threat-model update for the new worker credential (A6) and the upgrade-proxy entry point.

## Consequences
- The kube worker's service account can act as any user or group it is allowed to impersonate: compromising it is a cluster-level event. The `resourceNames` restriction on `groups` and the `limen-session` extra (visible in the cluster's own audit log) limit and attribute that.
- Two streaming protocols double the test surface; SPDY can be dropped when kubectl 1.30 is the floor everywhere.
- Clients that cannot run an exec plugin cannot use Limen for Kubernetes.

## Open questions for the owner
1. Is a worker **inside** the cluster the only supported topology, or should an out-of-cluster worker with a kubeconfig be first-class too?
2. Should SPDY be in scope for Phase 8, or WebSocket only (kubectl ≥ 1.30) with SPDY as a documented gap?
3. Is "no Limen-side verb or namespace policy" acceptable for this phase?

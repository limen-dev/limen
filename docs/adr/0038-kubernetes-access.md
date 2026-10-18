# ADR-0038: Kubernetes (EKS) access through impersonation

- Status: Accepted and built (Phase 8). The owner asked for the implementation on 2026-10-17 after seeing the proposal; the three open questions below were settled with the defaults proposed.
- Date: 2026-10-17

## Context
Phase 8 exit criteria (`docs/design.md` §13): `kubectl get`, `exec`, and `port-forward` work on kind through impersonation, and exec is recorded. Design §5.4 sketched the approach, ADR-0005 routes `/k8s/<cluster>/...` on the single port, and ADR-0018 already shipped the `kubernetes` resource kind and the `kube.groups` grant.

## Decisions

### 1. Impersonation, not per-user cluster credentials
The **kube worker** runs inside the target cluster (or anywhere that can reach its API server, with a URL, a CA file, and a token file) under a service account whose ClusterRole allows only `impersonate` on `users`, `groups`, and `userextras/limen-session`. It forwards each request with `Impersonate-User`, `Impersonate-Group` (one header per group), and `Impersonate-Extra-limen-session`. Cluster RBAC, bound to the `limen:*` group names, stays the source of truth for what a user may do *inside* the cluster; Limen policy decides only *which groups* a user may assume on *which cluster*.

Rejected: minting a client certificate the API server trusts (needs control of the cluster CA, which EKS does not give), and EKS access entries or `aws-iam-authenticator` per user (ties Limen to AWS and to long-lived mappings; it remains a documented fallback for operators who do not want the worker).

### 2. Request path
`kubectl` → proxy (`/k8s/<cluster>`, mTLS with the user's Limen certificate) → tunnel → kube worker → API server. `limen kube login <cluster>` writes a kubeconfig whose only credential is an exec plugin (`limen kube credentials`, `client.authentication.k8s.io/v1`) that prints the user's short-lived certificate and key. No long-lived token is ever written. If the certificate has expired the plugin fails with "run `limen login`" instead of opening a browser from inside `kubectl` (a change from the proposal: the plugin's stdout belongs to kubectl). The kubeconfig is a separate file, JSON, by default in the profile directory; merging into the user's own is `KUBECONFIG=a:b`.

The proxy checks that policy grants the user *some* group on the cluster and that a worker is connected, signs a grant that **lists all of those groups** (`SessionGrant.groups`), and opens a tunnel session. **One HTTP request is one session**: the proxy speaks HTTP/1.1 to the worker over the session's byte stream. An upgrade turns the stream into raw bytes. The worker is the only hop that talks to the API server, and only to the address it was configured with (no open proxying).

kubectl opens its upgrade connections (`exec`, `attach`, `port-forward`) with **no ALPN**; a connection with none is served as HTTP/1.1 (RFC 7301), which reaches only `/console/` and `/k8s/`.

### 3. Header hygiene (fail closed)
The proxy and then the worker delete every client-supplied identity header (`Authorization`, `Impersonate-*`, `X-Remote-*`, `X-Limen-*`). The worker sets its own from the signed grant, which it re-evaluates against its own policy snapshot, group by group. `system:*` groups are rejected by policy parsing and again by the worker. Paths must be canonical (no `.`/`..`/empty segments, no encoded slash or dot): the audit trail and the API server must read a path the same way, so anything else is a 400. A grant for a cluster the worker was not configured for, a missing grant, a lock, or a kill is a refusal, audited.

### 4. Streaming: exec, attach, port-forward
Both transports are supported, as a pass-through that decodes a copy:
- **WebSocket** `v4`/`v5.channel.k8s.io` (kubectl ≥ 1.30 exec and attach): the worker offers only the binary protocols (never `base64.*`) and strips `Sec-WebSocket-Extensions`, so frames are never compressed.
- **SPDY/3.1**: header blocks are zlib streams with the SPDY/3 dictionary; client header blocks are inflated in order to track stream types.
- **SPDY inside WebSocket** (`SPDY/3.1+portforward.k8s.io`, kubectl ≥ 1.31 port-forward) — found by running kubectl against kind; the proposal had missed it.

After the upgrade the worker checks what the server agreed to. A protocol it cannot decode, a malformed frame, or a recording write failure ends the stream. Output is written to the recording before it reaches the user.

- **exec and attach** are recorded as asciicast v3 with the existing recorder: stdout and stderr as output, resizes, and the exit status from the status channel. **Stdin is not recorded** (as with SSH: it holds passwords). This corrects the proposal. Recordings upload through the usual spool and appear in the console player.
- **port-forward** is audited (pod, namespace, ports, bytes each way, duration), not recorded.
- Lock, kill, and the grant's expiry end a stream within a second; the proxy and the worker both check. The same holds for **streaming responses** (`get -w`, `logs -f`): the worker relays the body through a watchdog that cuts it when the user is locked or the grant ends, and closes the API server connection as soon as the proxy hangs up, even on an idle watch.

### 5. Audit
- `kube.request` per API request, from the worker: user or bot, groups, cluster, verb, API group, resource, namespace, name, subresource, method, path, status, latency, client address. Bodies and query strings are not recorded. Verbs follow the API server's own request classification (`limen-kube::info`). If the audit trail is unavailable the worker answers 503 and drops the response, so reads never reach a user unaudited; a write that was applied is flagged by the missing event and the log.
- Streams add `session.start` and `session.end` (kind `kube`, `login` = `exec`/`attach`/`portforward`, command, exit code, ports, recording SHA-256). The existing console, session list, and recording player work unchanged.
- The proxy audits denials as `auth.denied` (`action: kube`).

(The proposal named separate `kube.exec` and `kube.portforward` events; reusing `session.*` keeps the console, search, and dashboards working without changes.)

### 6. Authorization shape
Policy keeps the grant from ADR-0018: `kube: { groups: [...] }`, plus `Policy::kube_groups` to list what roles grant on a cluster. No verb or namespace policy in Limen; that is RBAC's job. Example ClusterRole and bindings: `deploy/kube/`. Constrained impersonation (Kubernetes 1.36+) is planned hardening.

### 7. Worker configuration
A kube worker enrolls like any worker and is told its cluster: `--kube-cluster` (must equal `kubernetes.cluster_name`), and `--kube-api-server`, `--kube-ca-file`, `--kube-token-file`, which default to the pod's in-cluster values. The token file is re-read about once a minute so projected tokens can rotate. A missing or unreadable token, or a worker not configured for the cluster, is a `503` (an operator problem), never a `403` (which means "you may not"). The connection to the API server accepts TLS 1.2 as well as 1.3, since it is the one hop that is not between Limen components. `http://` API servers are refused.

## Out of scope
Helm and Terraform for EKS (Phase 14), the AWS IAM join (Phase 14), EKS access-entry integration, verb-level Limen policy, long-running-controller workloads (one session per request), merging into an existing kubeconfig, and multi-cluster fan-out.

## Verification
- **Verified** on a real **kind** cluster (Kubernetes 1.37, kubectl 1.35) by `deploy/compose/demo-phase8.sh`: `get`, `auth whoami` (user, groups, and session extra as the cluster sees them), RBAC for `limen:view` and `limen:edit`, forged `--as` ignored, `exec` over WebSocket and SPDY with exit codes and stdin, `attach`, `port-forward` over both transports, recordings uploaded and played, lock ending an open exec.
- Automated: `limen-kube` unit tests (request classification, WebSocket and SPDY decoding, split and malformed input), policy tests, CLI tests, and `limen-e2e/tests/phase8.rs` against a stand-in API server.
- **Unverified against real service:** Amazon EKS (endpoint access, private endpoints, the worker's token and CA there).

## Consequences
- The kube worker's service account can act as any user and any group it may impersonate: compromising it is a cluster-level event. `resourceNames` on `groups` and the `limen-session` extra (visible in the cluster's own audit log) limit and attribute that.
- Three streaming encodings triple the test surface. SPDY can be dropped when kubectl ≥ 1.31 is the floor everywhere.
- Clients that cannot run an exec plugin cannot use Limen for Kubernetes.
- Every request opens a tunnel session and a connection to the API server. That suits people and CI jobs, not controllers.

## Settled open questions
1. An in-cluster worker is the documented topology; an out-of-cluster worker works with the flags above.
2. SPDY is in scope (it is what `kubectl` falls back to, and what older clients use).
3. No Limen-side verb or namespace policy in this phase.

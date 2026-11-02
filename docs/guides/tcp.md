# Raw TCP access

`limen tcp <resource>` opens a loopback listener and forwards each accepted connection to the one address configured on that `tcp` resource. It isn't a general-purpose proxy: the client can't choose a host or port.

```sh
limen tcp cache-admin --listen 127.0.0.1:9000
nc 127.0.0.1 9000
```

Without `--listen` the OS picks a free loopback port and the command prints it. Ctrl-C stops the listener. Each local connection is its own Limen session under your current login. The role needs an explicit `tcp: {}` grant for the resource; deny rules and worker selectors still apply.

```yaml
kind: resource
version: v1
metadata: { name: cache-admin, labels: { env: staging } }
spec:
  tcp: { address: "cache.internal.example:9000" }
  worker_selector: { pool: staging-vpc }
---
kind: role
version: v1
metadata: { name: staging-ops }
spec:
  allow:
    - resources: { kind: [tcp], labels: { env: [staging] } }
      tcp: {}
```

- The worker connects only to `address`. Run a worker that can reach the target and apply a least-privilege network policy to its egress.
- Limen neither inspects nor records raw payloads. It audits the actor, resource, session duration, byte counts and end reason.
- Audit failure prevents new sessions; lock, revoke and session expiry end existing ones.
- A raw TCP stream is opaque, so access is enforced at connection setup, not per command. Use a protocol-aware resource kind when you need operation-level policy.

## Demo

`demos/demo-phase12.sh` exercises TCP against the Compose echo fixture together with browser SSO, web requests, WebSockets and audit checks. It builds the CLI and starts its own Compose project, resetting the project and its volumes first; pass `--keep` to reuse the existing stack.

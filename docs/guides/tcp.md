# Raw TCP access

`limen tcp <resource>` opens a local loopback listener and forwards each
accepted connection to the single address configured for that `tcp` resource.
It does not expose a general-purpose proxy: the client cannot choose a target
host or port.

```sh
limen tcp cache-admin --listen 127.0.0.1:9000
nc 127.0.0.1 9000
```

Omit `--listen` to let the OS choose a free loopback port; the command prints
the address to connect to. Press Ctrl-C to stop the listener. Each local
connection is a separate Limen session authenticated with the current Limen
login. The role needs an explicit `tcp: {}` grant for that resource, and deny
rules and worker selectors still apply.

The worker connects only to `address` in the resource definition. Configure a
worker that can reach the target and apply a least-privilege network policy to
its egress. Limen does not inspect or record raw payloads; it audits the actor,
resource, session duration, byte counts, and end reason. Audit failure prevents
new sessions, and lock, revoke, and session expiry end existing ones.

Example policy:

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

Raw TCP is an opaque stream, so Limen enforces access at connection setup, not
per command or operation. Use a protocol-aware resource kind when operation-
level policy is required.

To exercise TCP against the Compose echo fixture alongside browser SSO, web
requests, WebSockets, and audit checks, run the combined Phase 12 demo:

```sh
demos/demo-phase12.sh
```

It builds the CLI and starts its own Compose project. By default it resets that
project and its volumes before running; pass `--keep` to reuse the existing
stack:

```sh
demos/demo-phase12.sh --keep
```

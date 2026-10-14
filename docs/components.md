# The three server programs

Limen is three programs plus the `limen` CLI. [The design](design.md) has the data paths and failure semantics; this page is the short version of who does what.

| | Control plane | Proxy | Worker |
|---|---|---|---|
| **Binary** | `limen-control-plane` | `limen-proxy` | `limen-worker` |
| **Role** | The brain. It decides and records. | The front door. It enforces and relays. | The hands. It reaches your targets. |
| **Who talks to it** | Only proxies, workers and admin tooling, over mTLS | Users' CLIs and browsers | Only the proxy, through tunnels the worker opens outward |
| **Where it runs** | Central, with a database | Public or edge-facing | Inside your private network, next to the targets |
| **State** | Postgres, the certificate authority, KMS keys, the audit pipeline | Little. It works from the signed policy snapshot. | Little. It has its labels and its certificate. |

## Control plane
- Holds policy, users, locks, session kills and revocations.
- Runs the certificate authority and signs user and component certificates.
- Handles OIDC login (Okta in production, Dex in the dev stack) and the join tokens that enrol components.
- Publishes the **signed policy snapshot**, which also carries locked users, killed sessions and revoked components.
- Receives audit events and recordings and ships them to S3 and Datadog.
- Serves the web console's pages, but only through a proxy.
- **Audit fails closed here:** if it can't write an event, the action doesn't happen.

## Proxy
- The only thing users connect to (port 3443 in the dev stack).
- Checks each connection against the snapshot, and checks again every second while a session runs.
- Relays `/console/*` to the control plane for browsers.
- Routes each session down a tunnel to a worker whose labels match the resource.
- Drops the tunnels of revoked workers and ends sessions that were killed or whose user was locked.
- **SSH fails closed if the control plane is down.**

## Worker
- Opens **outbound** tunnels to the proxy, so your network needs no inbound ports.
- Opens the real connection to the target: SSH today, databases and more later.
- Records the session and ships the recording and events to the control plane.

## Upgrading
Upgrade in this order: control plane, then proxies, then workers ([ADR-0024](adr/0024-release-strategy.md)).

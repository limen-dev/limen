# ADR-0004: Proxy HA through tunnel registry and proxy peering

- Status: Accepted (owner approved 2026-10-13)
- Date: 2026-10-13

## Context
There are at least 2 proxies behind an NLB. A worker's tunnels land on whichever proxies the NLB picks. A user session can land on a proxy that doesn't hold a tunnel to the right worker. Workers sit in other VPCs and can't reach proxy private IPs.

## Options
1. Workers discover every proxy and connect to each one. With Fargate in another VPC this needs per-task public addresses or PrivateLink per task, which doesn't work well.
2. **Tunnel registry plus proxy-to-proxy relay inside the Limen VPC.** (Chosen.)

## Decision
- Proxies report tunnel ownership `(worker_id, proxy_id, tunnel_id, lease_expiry)` to the control plane. It's stored in Aurora, and the lease is renewed every 15 s.
- A proxy that receives a session for a worker it has no tunnel to opens `limen-peer/1` (mTLS, internal CA, proxy role required) to the owning proxy's private address and relays the stream.
- A worker opens 2 tunnels by default, which raises the chance of a local hit. The NLB spreads them.

## Consequences
- \+ Works with a single public NLB and with Fargate.
- − One extra hop for sessions that miss locally. At the target scale that's acceptable.
- − The registry is eventually consistent. On a stale entry the proxy retries once after refreshing from the control plane.
- If the control plane is down, proxies use their cached registry plus their local tunnels. That's best effort during the grace period.

# ADR-0005: Single public port with ALPN and path routing behind an NLB

- Status: Accepted (owner approved 2026-10-13)
- Date: 2026-10-13

## Context
Users need mTLS with client certs, raw TCP-like streams for DB, Redis, and SSH, HTTP/2 for the API, and the Kubernetes API, including upgrades. ALBs terminate TLS and can't pass client certs through for our own validation, and they don't carry arbitrary TCP.

## Decision
- **One public NLB, TCP 443, passthrough** to the proxies. The proxies terminate TLS with rustls and route on the **ALPN** value (see `limen_tunnel::alpn`).
- HTTP (`h2` and `http/1.1`) is then routed by path: `/v1/...` goes to the CLI API (relayed to the control plane), and `/k8s/<cluster>/...` goes to the Kubernetes API. Path routing avoids wildcard certificates for per-cluster SNI.
- The **control plane has no public endpoint**. The proxy relays CLI and worker API calls and forwards the client cert. The control plane checks the client cert again itself.
- **Public cert on the proxy:** an ACM exportable public certificate, or an operator-supplied cert in Secrets Manager. *Unverified: confirm ACM export support in Terraform during Phase 13.* In dev the cert comes from the internal CA, and the CLI uses `--ca-file`.

## Consequences
- \+ One port to open in firewalls, and one DNS name.
- \+ The control plane isn't internet-reachable.
- − The proxy must implement ALPN dispatch itself. rustls exposes the negotiated ALPN after the handshake, so we use one `ServerConfig` with all the protocols.
- − Clients that can't set ALPN (stock `ssh`) go through `limen ssh` / `ProxyCommand`, which sets it.

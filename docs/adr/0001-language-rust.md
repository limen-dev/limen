# ADR-0001: Rust for all components

- Status: Proposed
- Date: 2026-10-13

## Context
The brief makes Rust the default and asks for an ADR if another language would serve a component much better. Candidates for an exception:
- **Kubernetes proxying.** client-go's SPDY and WebSocket handling is the reference implementation.
- **Terraform and Grafana.** These are configuration, not code.

## Decision
Use Rust (edition 2024, toolchain pinned to 1.99.0) for the control plane, proxy, worker, and CLI. No component justifies a second language:
- kube-rs (4.x, actively maintained) covers the client side.
- The proxying itself is HTTP/1.1 upgrade and HTTP/2 passthrough with header rewriting, which hyper handles. We only parse the exec stream framing for recording: SPDY channel frames and the `v5.channel.k8s.io` WebSocket subprotocol.

## Consequences
- One toolchain, one dependency audit (cargo-deny, cargo-audit), and one set of shared types.
- Risk: parsing the SPDY exec protocol in Rust has less prior art than Go. If the Phase 6 exec recording runs into trouble, we revisit this ADR **for the exec-recording sub-component only**.

# Diagrams

| Diagram | Source | Export |
|---|---|---|
| Self-hosted architecture | [`architecture.drawio`](architecture.drawio) | [`architecture.svg`](architecture.svg) |

![Limen self-hosted architecture](architecture.svg)

Solid arrows are connections the caller opens. The dashed arrow is the worker's outbound tunnel: workers need egress to the proxy NLB only, and the proxy then opens sessions over that tunnel. See [design §2](../design.md#2-components) and [§6](../design.md#6-reverse-tunnel-and-ha-routing-adr-0003-adr-0004).

Edit the `.drawio` file with [diagrams.net](https://app.diagrams.net) (or the VS Code extension), then export it as SVG over `architecture.svg` and commit both. Keep the two in step.

A managed-service variant waits until a managed offering is decided.

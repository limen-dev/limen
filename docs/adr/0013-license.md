# ADR-0013: Apache-2.0 license

- Status: Accepted (owner decision, 2026-10-13)

## Decision
Limen is licensed under Apache-2.0. Dependencies must have permissive licenses compatible with it, as enforced by `deny.toml`.

## Consequences
- \+ Adoption-friendly, with an explicit patent grant. Matches most of the Rust ecosystem we depend on.
- − It doesn't prevent closed SaaS forks. The owner accepted that.

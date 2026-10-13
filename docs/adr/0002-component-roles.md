# ADR-0002: Workers terminate protocols; the proxy authorizes and routes

- Status: Accepted (owner approved 2026-10-13)
- Date: 2026-10-13

## Context
Someone has to terminate each resource protocol (SSH, PG, MySQL, RESP, Kubernetes HTTP), in order to:
- get upstream credentials (RDS and ElastiCache IAM tokens, kube impersonation, per-session SSH certs)
- parse statements and commands for audit
- record sessions

IAM auth tokens are SigV4-signed with the caller's AWS credentials. The natural holder of those credentials is the worker, which runs in the target account and VPC under its own IAM role.

## Options
1. **Proxy terminates and records; worker forwards TCP.** The proxy would need AWS credentials for every target account (cross-account role chaining from a public-facing service), and every session's plaintext would pass through the internet-facing tier.
2. **Worker terminates and records; proxy authorizes and routes.** (Chosen.)
3. Split by protocol. Inconsistent, and harder to reason about.

## Decision
Option 2.
- **The proxy** authenticates the user cert, evaluates policy, signs a short-lived **session grant**, emits `session.start` and `session.end`, and routes the stream.
- **The worker** verifies the grant and the forwarded user cert, evaluates policy again from its own snapshot (both must allow), terminates the protocol, emits the fine-grained audit events, and produces the recordings.

## Consequences
- \+ The public edge never sees session plaintext. Proxy compromise doesn't immediately expose DB, SSH, or Redis traffic.
- \+ The AWS credential blast radius is per worker and per target VPC.
- \+ The proxy stays protocol-agnostic and is easy to scale.
- − Workers are heavier, and need disk for the audit spool and recordings.
- − Worker compromise exposes the sessions it serves. Mitigations are in the threat model.
- If the owner prefers proxy-side recording, flip this ADR before Phase 2.

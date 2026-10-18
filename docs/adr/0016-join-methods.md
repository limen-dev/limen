# ADR-0016: How proxies and workers join

- Status: Accepted (Phase 1, 2026-10-14)

## Context
A proxy or worker proves it may join by presenting a secret once, and then gets a certificate (ADR-0006, ADR-0007). The brief asks for single-use, short-lived join tokens. But ECS tasks are ephemeral, and an autoscaled task can't be handed a fresh single-use token by a human each time it starts.

## Decision
Three join methods, in order of preference:

1. **Single-use tokens** (`limen admin token create`). TTL 15 minutes by default, 24 hours at most. Only the SHA-256 hash is stored. They are consumed atomically (`UPDATE … WHERE used_at IS NULL AND expires_at > now() RETURNING`). They are bound to a component kind, labels, and (for proxies) DNS names. Creating and using one is audited. **Default for workers on long-lived hosts.**
2. **AWS IAM join** (planned, Phase 14). The component signs `sts:GetCallerIdentity` and the control plane forwards it to STS and matches the role ARN against an allow list. No secret to distribute. **Intended default for ECS and ASG deployments.**
3. **Static tokens** (`--static-join-token kind:token`). Multi-use, at least 32 characters, compared in constant time, and kind-scoped. A proxy enrolled this way may only request the DNS names in `--proxy-dns-name`, and a worker gets no DNS names. **For the dev stack and for bootstrapping until IAM join exists.** In production they must come from Secrets Manager and be rotated.

The enrolled identity persists in the component's data directory. A restart reuses it instead of enrolling again. Certificates renew at half-life (24-hour TTL by default).

## Consequences
- Until IAM join lands, ECS deployments rely on static tokens. That risk is recorded in the threat model: a leaked static token lets an attacker enroll components of that kind until it's rotated. Enrollments are audited (`worker.enroll`, with `token_type`), and the components table shows every component.
- Revocation: setting `components.revoked_at` blocks renewal and tunnel registration. A CLI command for it is planned for Phase 14.

# ADR-0008: YAML label-based policy, push-applied, signed snapshots

- Status: Accepted (owner approved 2026-10-13)
- Date: 2026-10-13

## Decision
- Document kinds: `role`, `role_mapping`, `resource`, each with `version: v1`. They are parsed strictly (`deny_unknown_fields`) with `serde-saphyr`, chosen because `serde_yaml` is deprecated and `serde_yml` is unsound (RUSTSEC-2025-0068).
- **Evaluation:**
  - deny by default
  - any matching `deny` rule wins
  - an `allow` rule matches when the resource kind matches, **all** selector keys match (values ORed within a key), and the requested principal (login, DB role, kube group, Redis user) is listed in the rule
  - only an explicit `"*"` wildcard is accepted, and `"*"` in an admin role triggers a lint warning
- `Decision::RequiresApproval` is reserved for JIT and approvals. Every enforcement point treats it as deny, and tests assert this.
- **Delivery:** `limen admin apply -f <dir> [--dry-run]` requires the `limen:admin` role. The control plane stores immutable, numbered policy versions in Aurora and emits `policy.change` with the author, version, SHA-256, and a structured diff. Git stays the source of truth, and CI runs `apply`.
- **Snapshots:** the control plane signs `{version, issued_at, documents}` with the internal CA key and streams it to proxies and workers, which persist it to disk. Each worker gets only the resources it serves plus all roles.
- **Extension points (not built in v1):** `lock` (deny a user or role immediately and end their sessions), and approval requests.

## Consequences
- \+ GitOps-friendly. Every change is attributable and auditable inside Limen.
- − Two places to look (Git and the Limen policy history). The `policy.change` event carries the Git commit SHA when CI passes `--source-ref`.

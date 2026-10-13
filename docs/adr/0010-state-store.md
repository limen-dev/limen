# ADR-0010: Aurora PostgreSQL through sqlx, with advisory-lock leader election

- Status: Accepted (owner approved 2026-10-13)
- Date: 2026-10-13

## Decision
- The control plane is stateless. State lives in Aurora PostgreSQL: policy versions, join tokens (SHA-256 hashes only), workers, tunnel leases, login sessions, CA metadata (key ARNs and state, never key material), and audit ingest bookkeeping.
- `sqlx` 0.9 with offline-checked queries (`.sqlx/` committed) and embedded migrations, which run at startup under an advisory lock.
- Leader-only jobs use `pg_try_advisory_lock` per job key on a dedicated connection. Losing the connection releases the lock.
- Local dev uses the compose Postgres. Integration tests use a throwaway database per test.

## Consequences
- \+ No extra coordination service.
- − Aurora is a hard dependency for logins and new SSH sessions (see ADR-0011).
- Scale: the target load (hundreds of logins per hour, tunnel lease renewals every 15 s) is trivial for the smallest Aurora class.

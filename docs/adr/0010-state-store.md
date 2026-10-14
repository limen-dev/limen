# ADR-0010: Aurora PostgreSQL through sqlx, with advisory-lock leader election

- Status: Accepted (owner approved 2026-10-13)
- Date: 2026-10-13

## Decision
- The control plane is stateless. State lives in Aurora PostgreSQL: policy versions, join tokens (SHA-256 hashes only), workers, tunnel leases, login sessions, CA metadata (key ARNs and state, never key material), and audit ingest bookkeeping.
- `sqlx` 0.9 with embedded migrations, which run at startup under sqlx's own advisory lock.
- **Amended in Phase 1:** queries are checked at runtime, not with sqlx's offline macros. Every query is covered by integration tests against a real PostgreSQL in CI, which catches the same mistakes without making every build depend on a prepared `.sqlx/` cache or a live database. SQL strings are static (`&'static str`, `concat!`), so nothing is built from input.
- Leader-only jobs use `pg_try_advisory_lock` per job key on a dedicated connection. Losing the connection releases the lock.
- Local dev uses the compose Postgres. Integration tests use a throwaway database per test.

## Consequences
- \+ No extra coordination service.
- − Aurora is a hard dependency for logins and new SSH sessions (see ADR-0011).
- Scale: the target load (hundreds of logins per hour, tunnel lease renewals every 15 s) is trivial for the smallest Aurora class.

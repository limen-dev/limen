# ADR-0047: IdP-driven offboarding with a stored refresh token

- Status: Accepted (issue #111; the owner chose the refresh-token option and the fail-open default on 2026-11-08, and asked for it to be built). *As built* notes are at the end.
- Date: 2026-11-08

## Context
Onboarding is already driven by the IdP: a person added to a group runs `limen login`, and `role_mapping` turns the group claim into roles. Offboarding is half done. A deactivated user cannot log in again and certificates are short-lived, but an established session lives up to `max_session_ttl` (default 8h) because nothing tells Limen the user is gone.

Issue #111 proposed a periodic userinfo or introspection check with a service credential. That cannot be built IdP-neutrally here: the CLI is a public client that talks to the IdP itself, and the control plane receives only an ID token (ADR-0006). Userinfo needs the user's access token, and RFC 7662 introspection needs a token to introspect. SCIM stays a non-goal (design.md §1); the owner declined it for this step.

## Decision
- **The CLI asks for `offline_access`, when the control plane says so** (`GetAuthConfig` adds the scope only while the check is on, so an IdP that has not enabled refresh tokens is never asked), and sends the refresh token to the control plane at login, in the same request that presents the ID token and the key-bound nonce. An IdP that issues none is not an error: that login simply has no check, and the console says so.
- **The control plane stores it sealed** (AES-256-GCM under `--idp-token-key`, bound to the login id, never logged or audited), one per login ID, deleted when the login ends, is revoked, or expires. It is never returned by any API. Without the key nothing is stored.
- **One job checks logins.** A periodic job (default every 5 minutes, jitter, a bounded batch per tick) takes a database lease so only one replica polls (ADR-0020). For each live login it makes a refresh grant:
  - `invalid_grant` means the user was deactivated or the session revoked at the IdP. **End that login** (the login-revocation path used by `limen logout`; its sessions end with it), audited as `idp.offboard` with the IdP's error as the reason, and check the person's other logins at once.
  - A refreshed ID token whose groups no longer grant a role the login relied on **revokes that login** (`login_revocations`, migration 0013) and ends the sessions that used the role. The user is **not** locked; they can log in again with their remaining access.
  - A rotated refresh token replaces the stored one.
- **Failure to reach the IdP fails open and alerts** (the owner's choice). The job emits `idp.check_failed` and a metric, and keeps sessions. `--idp-check-failure=closed --idp-check-grace=<duration>` ends logins whose last good check is older than the grace window, for deployments that prefer it.
- **Bots and agents are skipped** unless they are tied to a person's account. Bot logins have no refresh token.
- **Login-time claims remain the source of truth** for role mapping; the check only ever removes access.
- **The console records where a user came from** (see "Console"), so an operator can tell a live, checked user from one whose last check failed or who has no refresh token.

## Console
A migration adds to `users`: `source` (`idp_login` for people; bots keep their own table), `issuer`, `idp_status` (`ok`, `unchecked`, `check_failed`, `offboarded`), and `idp_checked_at`. The users page shows these columns and filters by group, role, source, status and lock state with plain GET form parameters (no inline script, because of the CSP). Groups are labelled "as of last login" until a check refreshes them. No SCIM badge: there is no SCIM source.

## Consequences
- \+ Reaction time is the check interval (minutes) with any IdP that issues refresh tokens, including Dex for local tests.
- \+ No per-IdP code.
- − **A new long-lived secret in the database**, which reverses an ADR-0006 default ("no refresh token stored"). It is encrypted, per login, short-lived (bounded by `max_session_ttl`), and the threat model gets a new entry. A database leak plus KMS access yields IdP sessions.
- − The CLI/control-plane login request gains a field (`proto/` change; `buf breaking` must pass, so the field is additive and optional).
- − The IdP may rotate or cap refresh tokens; some IdPs expire them early, which reads as `invalid_grant`. The guide must say so, and the Okta behaviour is unverified until #64.
- − Refreshing keeps IdP sessions alive; the job must not extend a login past `max_session_ttl`.

## Alternatives
- **Per-IdP directory adapters** (Okta Users API, Microsoft Graph): no change to the login flow, but not IdP-neutral, no Dex equivalent, every adapter unverified.
- **SCIM 2.0:** seconds-level and real team data, but a new authenticated entry point and a reversed v1 non-goal. Can follow and fill the same `users` columns.
- **IdP event hooks:** per-IdP integration; same objection.

## As built (2026-11-08)
- **Deactivation ends the login, locks, and lifts the lock itself.** `invalid_grant` ends that login, checks the person's other logins at once, and places a lock as `system:idp-check`, so console and web sessions and logins without a refresh token end too. A refusal can also mean an expired refresh token, so the lock is lifted (audited `user.unlock`) when the person next signs in, because that sign-in is the IdP vouching for them. A lock by anyone else is never lifted that way. (An earlier as-built draft did not lock; it left console sessions and unchecked logins running.)
- **The login keeps its issue-time groups.** Checks compare the groups the login was issued with against the groups now, so a role gained and lost again after login does not end it.
- **Claims last longer than the interval.** A claim covers a whole batch of slow calls, so another replica cannot redeem a rotating token that is still being used.
- **Sealing key, not KMS.** There is no application-level encryption facility yet, so the key is an operator-supplied 32-byte secret (`--idp-token-key`). Wrapping it with KMS is a follow-up.
- **Claims, not leases.** Replicas claim due logins with `FOR UPDATE SKIP LOCKED` and push the next check out first, so no leader is needed and a crash only delays a check.
- **An absent `groups` claim counts as no groups**, since IdPs omit it for a person with none. `--idp-ignore-groups` is the switch for an IdP that drops it from refreshed tokens.
- **No `--no-refresh` flag** on the CLI. Not asking is a one-line change if someone needs it.
- **Tested against Dex v2.46.0.** Dex's memory and SQLite storage deadlock on a refresh grant, so the fixture (`deploy/compose/stacks/dex-refresh.yml`) runs Dex on PostgreSQL with the `mockCallback` connector, and the dev stack's Dex (memory storage, password users) keeps the check off.
- **Console:** the users page shows source, issuer host, groups, and the last check, and filters by group, role, and check state. There is no SCIM badge, because there is no SCIM source; the `source` column is where one would go.

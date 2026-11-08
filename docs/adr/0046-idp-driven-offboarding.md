# ADR-0046: IdP-driven offboarding with a stored refresh token

- Status: Proposed (issue #111; the owner chose the refresh-token option on 2026-11-08)
- Date: 2026-11-08

## Context
Onboarding is already driven by the IdP: a person added to a group runs `limen login`, and `role_mapping` turns the group claim into roles. Offboarding is half done. A deactivated user cannot log in again and certificates are short-lived, but an established session lives up to `max_session_ttl` (default 8h) because nothing tells Limen the user is gone.

Issue #111 proposed a periodic userinfo or introspection check with a service credential. That cannot be built IdP-neutrally here: the CLI is a public client that talks to the IdP itself, and the control plane receives only an ID token (ADR-0006). Userinfo needs the user's access token, and RFC 7662 introspection needs a token to introspect. SCIM stays a non-goal (design.md §1); the owner declined it for this step.

## Decision
- **The CLI asks for `offline_access`** and sends the refresh token to the control plane at login, in the same request that presents the ID token and the key-bound nonce. An IdP that issues none (or a user who passes `--no-refresh`) is not an error: that login simply has no check, and the console says so.
- **The control plane stores it encrypted** (envelope encryption with the existing KMS key, wrapped in `limen_core::secret::Secret`, never logged or audited), one per login ID, deleted when the login ends, is revoked, or expires. It is never returned by any API.
- **One job checks logins.** A periodic job (default every 5 minutes, jitter, a bounded batch per tick) takes a database lease so only one replica polls (ADR-0020). For each live login it makes a refresh grant:
  - `invalid_grant` (or `invalid_token`) means the user was deactivated or the session revoked at the IdP. **Lock the user and end their sessions** through the existing lock and kill paths, audited as `idp.offboard` with the IdP's error as the reason.
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

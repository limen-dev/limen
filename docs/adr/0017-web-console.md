# ADR-0017: Web console

- Status: Accepted (owner decisions, 2026-10-14)

## Context
The brief's "dashboard" meant Grafana over the audit data (ADR-0014). The owner also wants a **web console**: admins see users, sessions, resources, workers, and the control plane's state, and do operational work; ordinary users see the resources they can access.

## Decisions
- **Read-mostly, YAML stays the source of truth.** The console shows users, roles, mappings, resources, workers, and the YAML behind them. It doesn't author policy in forms. Applying policy remains `limen admin apply` (or the equivalent API call from CI). The console can run a **dry run** from uploaded or pasted YAML and show the diff. This keeps GitOps intact and every change attributable.
- **First version covers:** users and their sessions (active and past, with recordings played in the browser), workers and tunnels, join token creation and worker revocation, policy browsing with dry-run diff, and **lock a user / end a session**.
- **Lock and session kill are new features, not UI.** They need: a `locks` table (user, reason, by, at), a check at login and on every session grant, a proxy and worker path that ends open sessions when a lock appears (the policy snapshot carries active locks), and `user.lock` / `session.kill` audit events. The design had only an extension point for this.
- **Server-rendered and built into the control plane.** axum with templates and a small amount of JavaScript, shipped in the same binary and image. No Node build, one artifact to deploy, a small attack surface. Assets are embedded and served with a strict CSP (no inline script, no third-party origins).
- **Who sees what.** Admins (`limen:admin`) see everything. Everyone else sees their own identity, roles, certificate expiry, the resources they can access with the principals allowed on each, and their own session history. A user can't see other users or workers.
- **Login.** The console uses the same OIDC login. The browser flow ends in a cookie session: `HttpOnly`, `Secure`, `SameSite=Lax`, bound to the login ID and expiring with the user's certificate lifetime. State-changing requests carry a CSRF token and require `Origin` to match. The console reuses the CA-issued user certificate only server-side. No private key reaches the browser.
- **Where it's served.** On the proxy's public listener under `/console/` (ALPN `h2`/`http/1.1`), relayed to the control plane like other API calls. The control plane has no public endpoint (ADR-0005).
- **Audit.** Every console action that changes anything is a normal audit event, with the console as the client.

## Timing
**Phase 3.5, right after Phase 3.** It needs the audit pipeline (activity, recordings stored off the worker), so building it earlier would mean redoing its data layer.

## Consequences
- Lock and session kill pull a policy-snapshot extension and a proxy and worker enforcement path into Phase 3.5. They get their own tests, including "kill a live SSH session".
- Browser-facing surface is new: XSS, CSRF, clickjacking, and session fixation join the threat model, with CSP, frame denial, and cookie hardening as mitigations.
- Recording playback in the browser needs an asciicast player. We'll vendor one (asciinema-player, Apache-2.0) after checking its maintenance and advisories, per ADR-0012.

## Amendment: locks and session kill (built, Phase 3.5)
- Tables `user_locks` (one active lock per user, kept after release for history) and `session_kills` (pruned after 2 days).
- The signed policy snapshot carries `locked_users` and `killed_sessions`, read from the database on every snapshot request. Enforcement points: the control plane at login and when it issues SSH certificates (immediate); the proxy when establishing a session and, once a second, over every open session it relays (so a lock or kill bites within about 11 s); the worker when it opens a session.
- Audit: `user.lock`, `user.unlock`, `session.kill`; `session.end` carries the reason (`user locked` / `session killed`).
- CLI: `limen admin lock|unlock|locks|kill-session`. Runbook: `docs/runbooks/lock-user.md`.
- A session killed on a proxy that has lost the control plane is only ended once that proxy gets a snapshot with the kill. Locks that already exist keep being enforced from the cached snapshot.

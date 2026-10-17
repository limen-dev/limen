The web console is for looking around and for the occasional admin action. For daily work, see [the CLI guide](cli.md). Setting it up for your own deployment is in [Turning it on](#turning-it-on) below.

# Using the console

Open **`https://<your proxy>/console/`** (locally `https://localhost:3443/console/`) and choose *Continue with single sign-on*. You sign in with the same identity provider as the CLI. What you see depends on your roles.

| Page | What you can do | Who |
|---|---|---|
| **Overview** | See your identity and roles, what you can reach (with a copy-paste `limen ssh` command), and recent sessions. Admins also get live counts: active sessions, users, locks, workers, policy version | everyone |
| **Resources** | Search and filter by kind. Open a resource to see its labels and, for admins, its target, **which roles grant access**, **which live workers can serve it** (a red *none* means sessions will fail), and its sessions | everyone sees their own; admins see all |
| **Sessions** | Browse live and past sessions. Open one to **replay the recording** (the control plane verifies its hash first) and, as an admin, **end it** with a reason | everyone sees their own; admins see all |
| **Users** | See who has signed in and their roles. **Lock** a user (they are signed out, can't log in, and their open sessions end within seconds) or **unlock** them, always with an audited reason | admins |
| **Bots** | The CI jobs that can log in (from the `bot` documents in policy): what each one matches, its last login and **CI run** (with a link to the run), and its sessions. Lock one from its page, like a person. See [the bots guide](bots.md) | admins |
| **Workers** | See enrolled proxies and workers and their tunnels. See which **join tokens are still outstanding** (who made them, when they expire; never their values), **create single-use join tokens** (shown once) and **revoke** a component | admins |
| **Audit trail** | The last 30 days of events (sign-ins, denials, locks, kills, revokes, token creation, policy changes), filterable by event and user. A user's page shows their recent activity. It is a summary: the complete, signed events live in your audit sinks | admins |
| **Dashboards** | Built-in charts for the last 24 hours, 7 days or 30 days: sessions over time (people and bots apart), sign-ins next to denials, bot sessions by repository, busiest resources and people, session length, why access was denied, and admin actions. Drawn by the console itself, nothing to install | admins |
| **Policy** | Browse roles, mappings, and resources as the YAML behind them, and **check a change**: paste YAML, see the diff, nothing is applied | admins |

A few things worth knowing:
- **Policy stays in Git.** The console shows and checks policy but doesn't edit it. Apply with `limen admin apply`.
- **Everything you change is audited** as you, marked as coming from the console.
- **Switch theme** with the sun/moon buttons at the bottom of the sidebar (it follows your system by default).
- **Browser sign-ins last 8 hours** by default (never longer than the maximum certificate lifetime), or until you sign out or an admin locks you. This is separate from the CLI's short-lived certificate.

`https://<public host>/console/`, served by the proxy and answered by the control plane (ADR-0017). Admins (`limen:admin`) see users, sessions with recordings, workers, and policy. Everyone else sees their own resources and sessions.

## Setting it up

### Turning it on
Register a **confidential** OIDC client for the console in your identity provider:
- Redirect URI: `https://<public host>/console/callback`
- Grant: authorization code with PKCE; scopes `openid email profile groups` (the same groups claim the CLI uses)

Then give the control plane (all replicas):

| Setting | Value |
|---|---|
| `LIMEN_CONSOLE_PUBLIC_URL` | `https://<public host>` (HTTPS only, no path) |
| `LIMEN_CONSOLE_OIDC_CLIENT_ID` | defaults to `limen-console` |
| `LIMEN_CONSOLE_OIDC_CLIENT_SECRET` | from your secret store; never in an image or a log |
| `LIMEN_CONSOLE_SESSION_TTL` | optional; how long a browser sign-in lasts (default `8h`, capped by `LIMEN_MAX_CERT_TTL`) |

Without the public URL the console is off and `/console/*` answers 404.

### Day to day
- **Users**: who has signed in, their roles, lock status. Lock or unlock with a reason.
- **Sessions**: active and past. Open one to play its recording or end it.
- **Workers**: enrollment state, tunnels, certificate expiry. Outstanding join tokens (unused and unexpired; values are never stored). Create single-use join tokens (shown once) and revoke a worker.
- **Dashboards**: built-in charts from the console's own records (30 days). For longer history, or your own panels and alerts, the optional Grafana dashboards in `dashboards/grafana` read the audit store directly.
- **Audit trail**: the last 30 days, filterable. A convenience copy for answering "what just happened"; for investigations use the sinks (S3 or Datadog) and [verify the chain](../runbooks/audit-verify.md).
- **Policy**: what's active, the YAML behind each document, and a dry-run check. Apply changes with `limen admin apply`.

### Troubleshooting (operators)
| Symptom | Likely cause |
|---|---|
| Sign-in loops back to the IdP, or "login state does not match this browser" | The callback was opened in a different browser than the one that started it, or the cookie was blocked. Start again from `/console/` |
| "Sign-in unavailable" | The control plane can't reach the IdP's token endpoint (check `LIMEN_OIDC_INTERNAL_URL`) or the database |
| IdP says `redirect_uri` mismatch | The client's redirect URI must be exactly `<public URL>/console/callback` |
| A recording won't play | "failed its integrity check": the stored file doesn't match the hash recorded at session end (treat as an incident, see [audit hash chain](../runbooks/audit-verify.md)). "unavailable": storage permissions or the object is missing |
| A session shows as "unknown" | No `session.end` arrived for 24 h: its proxy died. The audit trail has the details |
| Blank player | Browser console shows a CSP error: something between the proxy and the browser rewrote the `Content-Security-Policy` header |

Browser sessions end after `LIMEN_CONSOLE_SESSION_TTL` (8 hours by default), when they sign out, or when an admin locks them.

### Resources
The Resources page is the quickest way to see what Limen can reach and whether it is reachable: a red "none" in the Workers column means no enrolled worker has the labels the resource asks for (`worker_selector`), so sessions to it fail. Check the worker's labels on the Workers page and the selector on the resource's page.

# Web console

`https://<public host>/console/`, served by the proxy and answered by the control plane (ADR-0017). Admins (`limen:admin`) see users, sessions with recordings, workers, and policy. Everyone else sees their own resources and sessions.

## Turning it on
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

## Day to day
- **Users**: who has signed in, their roles, lock status. Lock or unlock with a reason.
- **Sessions**: active and past. Open one to play its recording or end it.
- **Workers**: enrollment state, tunnels, certificate expiry. Outstanding join tokens (unused and unexpired; values are never stored). Create single-use join tokens (shown once) and revoke a worker.
- **Dashboards**: built-in charts from the console's own records (30 days). For longer history, or your own panels and alerts, the optional Grafana dashboards in `dashboards/grafana` read the audit store directly.
- **Audit trail**: the last 30 days, filterable. A convenience copy for answering "what just happened"; for investigations use the sinks (S3 or Datadog) and [verify the chain](audit-verify.md).
- **Policy**: what's active, the YAML behind each document, and a dry-run check. Apply changes with `limen admin apply`.

## Troubleshooting
| Symptom | Likely cause |
|---|---|
| Sign-in loops back to the IdP, or "login state does not match this browser" | The callback was opened in a different browser than the one that started it, or the cookie was blocked. Start again from `/console/` |
| "Sign-in unavailable" | The control plane can't reach the IdP's token endpoint (check `LIMEN_OIDC_INTERNAL_URL`) or the database |
| IdP says `redirect_uri` mismatch | The client's redirect URI must be exactly `<public URL>/console/callback` |
| A recording won't play | "failed its integrity check": the stored file doesn't match the hash recorded at session end (treat as an incident, see [audit hash chain](audit-verify.md)). "unavailable": storage permissions or the object is missing |
| A session shows as "unknown" | No `session.end` arrived for 24 h: its proxy died. The audit trail has the details |
| Blank player | Browser console shows a CSP error: something between the proxy and the browser rewrote the `Content-Security-Policy` header |

Browser sessions end after `LIMEN_CONSOLE_SESSION_TTL` (8 hours by default), when they sign out, or when an admin locks them.

## Resources
The Resources page is the quickest way to see what Limen can reach and whether it is reachable: a red "none" in the Workers column means no enrolled worker has the labels the resource asks for (`worker_selector`), so sessions to it fail. Check the worker's labels on the Workers page and the selector on the resource's page.

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
What each page does is in the [console guide](../guides/console.md). For operators: the Dashboards page shows 30 days from the console's own records (longer history, or your own panels and alerts, come from the optional Grafana dashboards in `deploy/grafana`); the Audit trail page is a convenience copy of the last 30 days, so for investigations use the sinks (S3 or Datadog) and [verify the chain](audit-verify.md).

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

## Checking it on phones and in other browsers
Do this after a change to `crates/limen-control-plane/assets/` or `templates/`. `deploy/compose/scripts/console-matrix.mjs` signs in through the identity provider, opens every page (and the first detail page of each list) in each engine and size, and reports sideways scrolling, JavaScript errors, axe-core violations (WCAG 2.1 AA) and touch targets under 32px. Run it in both themes.

```sh
mkdir /tmp/matrix && cd /tmp/matrix && npm init -y && npm i playwright-core axe-core
npx playwright-core install chromium webkit firefox             # once
deploy/compose/setup.sh --yes --stacks tcp,web                   # data for the pages to show
CONSOLE_URL=https://localhost:3443 node <repo>/deploy/compose/scripts/console-matrix.mjs
THEME=light CONSOLE_URL=https://localhost:3443 node <repo>/deploy/compose/scripts/console-matrix.mjs
```

It exits 1 when any page has a problem and 2 when an engine could not start (never 0, since nothing was tested in it). Add `shots` as the second argument to save a screenshot of every page. What it cannot tell you: how a page *feels* (look at the screenshots on a phone profile), anything behind a login you do not have, or a real device. A dev stack running beside another copy needs its own project name, ports and image tag (see the header of `deploy/compose/scripts/lib.sh`).

**Firefox.** Playwright's own Firefox build does not start on every macOS version (it did not on 27.0.1, #151). `deploy/compose/scripts/console-matrix-firefox.mjs` runs the same pages and checks in a regular installed Firefox through Puppeteer (WebDriver BiDi): `npm i puppeteer-core axe-core` in the same directory, then `CONSOLE_URL=https://localhost:3443 node <repo>/deploy/compose/scripts/console-matrix-firefox.mjs` (and `THEME=light`). It has no touch emulation and no screenshots, and it fails a run whose page is not in the requested theme.

## Resources
The Resources page is the quickest way to see what Limen can reach and whether it is reachable: a red "none" in the Workers column means no enrolled worker has the labels the resource asks for (`worker_selector`), so sessions to it fail. Check the worker's labels on the Workers page and the selector on the resource's page.

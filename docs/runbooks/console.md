# Web console

`https://<public host>/console/`, served by the proxy and answered by the control plane (ADR-0017). Admins (`limen:admin`) see users, sessions with recordings, workers and policy; everyone else sees their own resources and sessions. Page by page: [console guide](../guides/console.md).

## Turn it on

Register a **confidential** OIDC client for the console in your identity provider:

- Redirect URI: `https://<public host>/console/callback`
- Grant: authorization code with PKCE; scopes `openid email profile groups` (the same groups claim the CLI uses)

Then set on every control plane replica:

| Setting | Value |
|---|---|
| `LIMEN_CONSOLE_PUBLIC_URL` | `https://<public host>` (HTTPS only, no path) |
| `LIMEN_CONSOLE_OIDC_CLIENT_ID` | defaults to `limen-console` |
| `LIMEN_CONSOLE_OIDC_CLIENT_SECRET` | from your secret store; never in an image or log |
| `LIMEN_CONSOLE_SESSION_TTL` | optional; browser sign-in length (default `8h`, capped by `LIMEN_MAX_CERT_TTL`) |

Without the public URL the console is off and `/console/*` answers 404. Browser sessions end at the TTL, on sign-out, or when an admin locks the user.

## Day to day

The Dashboards page covers 30 days from the console's own records; for longer history or your own panels and alerts, use the optional Grafana dashboards in `deploy/grafana`. The Audit trail page is a convenience copy of the last 30 days: investigate in the sinks (S3 or Datadog) and [verify the chain](audit-verify.md).

The Resources page shows whether something is reachable. A red "none" in the Workers column means no enrolled worker has the labels the resource's `worker_selector` asks for, so sessions to it fail. Compare the worker's labels (Workers page) with the selector (resource page).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Sign-in loops to the IdP, or "login state does not match this browser" | The callback opened in a different browser than the one that started it, or the cookie was blocked. Start again from `/console/` |
| "Sign-in unavailable" | The control plane can't reach the IdP's token endpoint (check `LIMEN_OIDC_INTERNAL_URL`) or the database |
| IdP reports `redirect_uri` mismatch | The redirect URI must be exactly `<public URL>/console/callback` |
| A recording won't play | "failed its integrity check": the stored file doesn't match the hash recorded at session end; treat as an incident ([audit hash chain](audit-verify.md)). "unavailable": storage permissions, or the object is missing |
| A session shows as "unknown" | No `session.end` for 24 h: its proxy died. The audit trail has details |
| Blank player | A CSP error in the browser console: something between proxy and browser rewrote `Content-Security-Policy` |

## Checking phones and other browsers

After changing `crates/limen-control-plane/src/console/assets/` or `templates/`, run `deploy/compose/scripts/console-matrix.mjs`. It signs in through the identity provider, opens every page (and each list's first detail page) in each engine and size, and reports sideways scrolling, JavaScript errors, axe-core violations (WCAG 2.1 AA) and touch targets under 32px. Run it in both themes.

```sh
mkdir /tmp/matrix && cd /tmp/matrix && npm init -y && npm i playwright-core axe-core
npx playwright-core install chromium webkit firefox             # once
deploy/compose/setup.sh --yes --stacks tcp,web                   # data for the pages to show
CONSOLE_URL=https://localhost:3443 node <repo>/deploy/compose/scripts/console-matrix.mjs
THEME=light CONSOLE_URL=https://localhost:3443 node <repo>/deploy/compose/scripts/console-matrix.mjs
```

It exits 1 when any page has a problem and 2 when an engine couldn't start (never 0, since nothing was tested). Pass `shots` as the second argument to save screenshots. It can't judge how a page *feels* (check screenshots on a phone profile), anything behind a login you lack, or real devices. A dev stack beside another copy needs its own project name, ports and image tag (see the header of `deploy/compose/scripts/lib.sh`).

**Firefox.** Playwright's Firefox doesn't start on every macOS version (not on 27.0.1, #151). `console-matrix-firefox.mjs` runs the same checks in an installed Firefox through Puppeteer (WebDriver BiDi): `npm i puppeteer-core axe-core` in the same directory, then `CONSOLE_URL=https://localhost:3443 node <repo>/deploy/compose/scripts/console-matrix-firefox.mjs` (and `THEME=light`). It has no touch emulation or screenshots, and fails a run whose page isn't in the requested theme.

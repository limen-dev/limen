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

After changing `crates/limen-control-plane/assets/` or `templates/`, run `deploy/compose/scripts/console-matrix.mjs`. It signs in through the identity provider, opens every page (and each list's first detail page) in each engine and size, and reports sideways scrolling, JavaScript errors, axe-core violations (WCAG 2.1 AA) and touch targets under 32px. Run it in both themes.

```sh
mkdir /tmp/matrix && cd /tmp/matrix && npm init -y && npm i playwright-core axe-core
npx playwright-core install chromium webkit firefox             # once
deploy/compose/setup.sh --yes --stacks tcp,web                   # data for the pages to show
CONSOLE_URL=https://localhost:3443 node <repo>/deploy/compose/scripts/console-matrix.mjs
THEME=light CONSOLE_URL=https://localhost:3443 node <repo>/deploy/compose/scripts/console-matrix.mjs
```

It exits 1 when any page has a problem and 2 when an engine couldn't start (never 0, since nothing was tested). Pass `shots` as the second argument to save screenshots. It can't judge how a page *feels* (check screenshots on a phone profile), anything behind a login you lack, or real devices. A dev stack beside another copy needs its own project name, ports and image tag (see the header of `deploy/compose/scripts/lib.sh`).

**Firefox.** Playwright's Firefox doesn't start on every macOS version (not on 27.0.1, #151). `console-matrix-firefox.mjs` runs the same checks in an installed Firefox through Puppeteer (WebDriver BiDi): `npm i puppeteer-core axe-core` in the same directory, then `CONSOLE_URL=https://localhost:3443 node <repo>/deploy/compose/scripts/console-matrix-firefox.mjs` (and `THEME=light`). It has no touch emulation or screenshots, and fails a run whose page isn't in the requested theme.

**Without a stack (CI).** `deploy/compose/scripts/console-snapshot-matrix.mjs check` runs the same engines, sizes and both themes over saved pages in `crates/limen-control-plane/tests/console-pages/`, with the repository's own CSS and scripts from `crates/limen-control-plane/assets/`, so it needs no stack and no certificate (it serves plain http on localhost and bypasses no browser warning). `.github/workflows/browser-tests.yml` runs it on pull requests that touch the console assets, templates or fixtures (Chromium and WebKit), and weekly or by hand with Firefox too. It reports sideways scroll, content past the viewport, JavaScript errors, axe-core violations (WCAG 2.1 A and AA) and tap targets under 24px (WCAG 2.5.8; 44px on touch profiles). It does not fail on links inside a line of text or a table cell, or on the bars of a chart, which are counted separately; on phone and tablet profiles (touch screens) the bar is 44px, and a smaller target fails. `DETAIL=1` lists the offenders by selector and size, and `SHOTS=<dir>` saves a screenshot of every page to look at.

```sh
cd /tmp/matrix                                                    # where playwright-core and axe-core are installed
node <repo>/deploy/compose/scripts/console-snapshot-matrix.mjs check <repo>/crates/limen-control-plane/tests/console-pages
BROWSERS=chromium THEMES=light node <repo>/deploy/compose/scripts/console-snapshot-matrix.mjs check <repo>/crates/limen-control-plane/tests/console-pages
```

Firefox falls back to an installed Firefox through Puppeteer (`npm i puppeteer-core`) when Playwright's build doesn't start. **Regenerate the fixtures** after changing a template or adding a page, from a running dev stack with data (`setup.sh --yes --stacks tcp,web`):

```sh
deploy/compose/scripts/console-login.sh admin@example.com /tmp/admin.jar
rm -rf /tmp/console-snap && PAGES_ONLY=1 node <repo>/deploy/compose/scripts/console-snapshot-matrix.mjs snapshot /tmp/console-snap /tmp/admin.jar
rm -rf crates/limen-control-plane/tests/console-pages/console && cp -R /tmp/console-snap/console crates/limen-control-plane/tests/console-pages/
mise exec -- gitleaks dir crates/limen-control-plane/tests/console-pages --redact --no-banner   # dev data only, but check
```

A fixture shows what the stack held when it was captured (dev users, no live sessions), so it covers the markup of 18 pages and nothing that needs a click: forms, lock, kill and token creation are not exercised, and neither are the session detail, recording and watch pages (no live session when captured).

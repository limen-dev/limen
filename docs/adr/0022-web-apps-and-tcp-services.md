# ADR-0022: Identity-aware access to internal web apps and TCP services

- Status: Proposed (owner requested 2026-10-14; this reverses a v1 non-goal in the original brief)
- Date: 2026-10-14

## Context
The original brief listed web app access as a non-goal for v1. The owner now wants it: engineers should reach internal web applications (Grafana, Jenkins, admin UIs, the RabbitMQ and OpenSearch dashboards) and arbitrary TCP services through Limen, with the same login, policy, and audit as everything else. How the browser reaches them was left open.

## Options
1. **Host per app** (`https://grafana.apps.example.com`): a wildcard DNS name and certificate; the proxy routes by `Host`.
2. **Path per app** (`https://limen.example.com/apps/grafana/`): no wildcard needed, but most web apps assume they live at `/`, and rewriting absolute links, cookies, redirects, and WebSocket URLs is fragile. ADR-0005 used paths for Kubernetes only because `kubectl` is path-agnostic.
3. **A local forwarder** (`limen web grafana` opens `localhost:PORT`): works with no DNS, but not a browser-native experience and needs the CLI everywhere.

## Decision
- **Host per app (option 1) for browsers**, served by the proxy on the same port by SNI and `Host`. This needs an operator-supplied **wildcard certificate** (`*.apps.<domain>`): ACM public certificates cannot be exported (ADR-0005 open item), so a wildcard from the operator's CA or ACME DNS-01 is required. Documented in the deploy guides.
- **Option 3 for TCP and for people who can't have a wildcard**: `limen tcp <resource>` is the same local listener the database commands use.
- **Sign-in:** an app request without a Limen session redirects to the console's OIDC login, which sets a session cookie for the app's host through a one-time redirect (never a cookie shared across apps). Bots use their certificate or a short-lived token.
- **Identity to the app:** the worker adds `X-Limen-User`, `X-Limen-Roles`, and a **signed short-lived JWT** (`X-Limen-Identity`, verifiable at a JWKS URL) for apps that can use SSO headers; inbound `X-Limen-*` headers are stripped.
- **Audit:** per request: user or bot, app, method, host, path, status, bytes, and latency. Request and response bodies are not logged. WebSocket upgrades are audited as one session with byte counts. Policy chooses the apps a role may reach and, optionally, allowed methods and path prefixes.
- **The worker is the only hop that reaches the app**, over the reverse tunnel, to the single address in the resource definition. There is no way to ask it for another address (no open proxying, which would be SSRF).

## Consequences
- A new resource kind `web` (`address`, `host`, optional `health_path`) and `tcp` (`address`), with the usual policy grants.
- Cookie and CSRF behaviour of third-party apps is theirs, not ours; guides list known-good apps and pitfalls.
- Large uploads and downloads, HTTP/2, and WebSockets need streaming (no buffering) and tests.
- The console's CSP and cookies are unaffected: app hosts are separate origins.

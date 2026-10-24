# ADR-0022: Identity-aware access to internal web apps and TCP services

- Status: Accepted (owner approved the Phase 12 implementation defaults)
- Date: 2026-10-14

## Context
The original brief listed web app access as a non-goal for v1. The owner now wants it: engineers should reach internal web applications (Grafana, Jenkins, admin UIs, the RabbitMQ and OpenSearch dashboards) and arbitrary TCP services through Limen, with the same login, policy, and audit as everything else. How the browser reaches them was left open.

## Options
1. **Host per app** (`https://grafana.apps.example.com`): a wildcard DNS name and certificate; the proxy routes by `Host`.
2. **Path per app** (`https://limen.example.com/apps/grafana/`): no wildcard needed, but most web apps assume they live at `/`, and rewriting absolute links, cookies, redirects, and WebSocket URLs is fragile. ADR-0005 used paths for Kubernetes only because `kubectl` is path-agnostic.
3. **A local forwarder** (`limen web grafana` opens `localhost:PORT`): works with no DNS, but not a browser-native experience and needs the CLI everywhere.

## Decision
- **Host per app (option 1) for browsers**, served by the proxy on the same port by SNI and `Host`. This needs an operator-supplied **wildcard certificate** (`*.apps.<domain>`): ACM public certificates cannot be exported (ADR-0005 open item), so a wildcard from the operator's CA or ACME DNS-01 is required. Documented in the deploy guides.
- **TCP:** `limen tcp <resource>` opens a local listener for a single configured destination.
- **Sign-in:** an app request without a Limen session redirects to the console's OIDC login, which sets a session cookie for the app's host through a one-time redirect (never a cookie shared across apps). Bots cannot use browser SSO; explicitly granted machine identities may use the TCP CLI.
- **Identity to the app:** when explicitly enabled for a resource, the proxy sets `X-Limen-User`, `X-Limen-Roles`, and a **signed short-lived JWT** (`X-Limen-Identity`, verifiable at the control plane's JWKS URL) for apps that can use SSO headers; inbound `X-Limen-*` headers are stripped.
- **Audit:** per request: user or bot, app, method, host, path, status, bytes, and latency. Request and response bodies are not logged. WebSocket upgrades are audited as one session with byte counts. Policy chooses the apps a role may reach and, optionally, allowed methods and path prefixes.
- **The worker is the only hop that reaches the app**, over the reverse tunnel, to the single address in the resource definition. There is no way to ask it for another address (no open proxying, which would be SSRF).

## Phase 12 implementation

The owner approved the implementation defaults below for Phase 12. Web and TCP resource and grant fields are implemented as described here.

### Web apps

- **Ingress and routing.** Keep the single public listener on TCP 443. Use the wildcard `*.apps.<domain>` certificate and DNS from the existing decision. Route only an exact configured `web.host`, and require the TLS SNI name and HTTP `Host`/`:authority` to agree with it. Reject unknown hosts and mismatches; never derive an upstream address from a request. Keep the proxy as the public HTTP/TLS endpoint and route only to the selected worker over the existing authenticated tunnel.
- **Authentication.** An unauthenticated browser request redirects to the existing console OIDC login, with a one-use, short-lived handoff bound to the user, login, resource, exact app host, and an unpredictable nonce stored in a host-only app-origin cookie. The proxy requires that cookie to redeem the handoff, preventing cross-browser login CSRF. Return only to that configured host, then set a separate `__Host-` app-session cookie (`Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`). Never share the console cookie across app origins. Validate the app session and current `web` grant on every HTTP request; lock, expiry, deny rules, and policy revocation must take effect on the same bounded policy-snapshot interval as other sessions. Browser SSO is a human flow; bots do not get a browser session. Machine access to TCP remains possible only with an explicit policy grant and Limen credentials.
- **TLS client authentication.** The proxy currently permits an absent client certificate at TLS negotiation so unauthenticated login/enrollment routes can work, then authenticates routes individually. Preserve that boundary: an app host may proceed without a client certificate only through successful SSO app-session validation; existing authenticated protocols and API routes must continue to require their expected user or component certificate. Do not weaken their route checks to enable browsers.
- **HTTP and upstream.** Stream request and response bodies; do not buffer them. Support HTTP/1.1 and HTTP/2 from browsers, HTTP/1.1 to the upstream for the first implementation, and WebSocket upgrades as opaque streams. Refuse `CONNECT`, unsupported protocol upgrades, malformed or ambiguously normalized paths, and requests whose routing authority does not match the configured app. Preserve app-owned cookies and authentication, remove the Limen app-session cookie before forwarding, strip client-supplied `X-Limen-*` and forwarding headers, and set trusted forwarding headers. Verify TLS to an HTTPS upstream; plain HTTP is a development-only opt-in guarded like other insecure targets.
- **Identity passed to the app.** The Limen gate, not the app, is the default SSO guarantee. Do not make arbitrary apps trust identity headers by default. If identity propagation is enabled for an explicitly configured app, overwrite all client-supplied identity headers and provide a short-lived signed assertion whose issuer, audience, host, and expiry the app can verify through the documented JWKS endpoint. Publish all active control-plane signing keys from shared state, retaining overlap until each signing certificate expires, so replica selection and rotation do not break verification. This avoids accidentally granting identity to an app that treats spoofable headers as authentication.
- **Policy.** Retain `web: {}` as the resource-level access grant. Optional method and path-prefix restrictions are evaluated on every request after one canonical path parse; ambiguous encodings and alternate interpretations are denied. Deny rules win, and grants remain additive as in ADR-0008. Unknown methods or routes are denied when a grant is restricted rather than silently treated as allowed.
- **Audit.** Emit a `web.request` event before forwarding each request and a `web.response` event with status, byte counts, and latency after the response. Include actor type, resource, method, and a bounded normalized path; omit query values, bodies, cookies, authorization values, and upstream error text. A refusal—including an unauthenticated request that starts OIDC sign-in—emits `auth.denied`. If the request event cannot be durably emitted, do not forward the request; if the outcome event cannot be emitted, close the connection. For WebSockets, audit the upgrade request and final status, then one stream-end event with duration, bytes, and reason. Payloads are never recorded. Project the request/response timeline into the existing console session view, as for search and messaging.

### Raw TCP services

- `limen tcp <resource>` opens a loopback listener using the same local-listener conventions as the database and messaging commands. Each accepted local connection becomes one `tcp` session over a dedicated `limen-tcp/1` ALPN. The client names only the resource; the proxy authorizes it and the worker connects only to that resource's configured `address`.
- Apply the ordinary explicit `tcp: {}` resource grant, deny rules, worker selector, session lifetime, lock, and revoke checks. Do not accept a destination, port, or DNS name from the client, and do not turn the worker into a general-purpose proxy.
- Raw TCP has no request boundaries to inspect. Audit session start/end, actor type, resource, duration, bytes in/out, and end reason; never log payload bytes. A denied connection emits `auth.denied`, and audit failure blocks new connections and ends an active stream according to ADR-0009.

### Scope and exit tests

The phase adds no path rewriting, generic HTTP `CONNECT`, arbitrary destinations, payload inspection, or protocol-specific authorization inside an opaque TCP stream. The demo should use a compose web fixture and a raw TCP fixture and prove: browser SSO and per-host cookie isolation; no access for a user without a grant or a bot using the browser flow; host/SNI mismatch rejection; header spoofing resistance; method/path restrictions; streaming and WebSocket upgrade; audit-before-forward and fail-closed behavior; TCP round-trip, fixed-destination enforcement, denied access, and byte-count audit. Update the threat model, policy/CLI documentation, and a runnable `demos/demo-phase12.sh` with the implementation.

### Implementation invariants

- Browser SSO uses a host- and resource-bound, one-use handoff, additionally bound to a nonce in a host-only app-origin cookie, then a short-lived signed app session in a host-only cookie. Proxies validate the cookie and current policy snapshot on every request; the snapshot refresh interval is the revocation bound.
- Identity propagation is off by default and explicitly enabled per app. When enabled, the proxy strips client-supplied `X-Limen-*` headers and overwrites them with the verified user, roles, and a short-lived signed assertion with a documented JWKS endpoint.
- Upstream TLS is verified by default. Plain HTTP requires an explicit development-only resource setting and a worker started with the matching insecure-target opt-in.
- The browser edge accepts HTTP/1.1 and HTTP/2; the first upstream implementation uses HTTP/1.1 and supports WebSocket upgrades. Request paths are parsed once, normalized conservatively, and denied if ambiguous. Query values and bodies are excluded from audit.
- Bots do not receive browser app sessions. Explicitly granted machine identities may still use `limen tcp`; TCP never accepts a client-selected destination.

## Consequences
- The `web` resource (`address`, `host`, optional TLS and health-check settings, optional identity headers) and `tcp` resource (`address`) use the ordinary deny-first policy evaluation.
- Cookie and CSRF behaviour of third-party apps is theirs, not ours; guides list known-good apps and pitfalls.
- Large uploads and downloads, HTTP/2, and WebSockets use streaming (no buffering) and are covered by tests and the local demo.
- The console's CSP and cookies are unaffected: app hosts are separate origins.

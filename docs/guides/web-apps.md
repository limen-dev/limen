# Internal web apps

Limen publishes each configured web app on its own HTTPS host. The proxy routes
only an exact configured host whose TLS SNI and HTTP `Host`/`:authority` agree;
the worker connects only to the resource's fixed upstream address. Browser
access uses the user's Limen OIDC login and a short-lived, host-only app
session cookie. The Limen cookie is removed before a request reaches the app.

## Configure a web resource

Point the app host at the Limen proxy and configure a certificate whose
hostname covers it. The proxy must trust the certificate and the user's
browser must trust its issuer. Set the public console origin to the externally
visible HTTPS origin; it is used for OIDC redirects and preserves a mapped
public port in local deployments.

```yaml
kind: resource
version: v1
metadata: { name: grafana-staging, labels: { env: staging, team: platform } }
spec:
  web:
    address: "grafana.internal.example:443"
    host: grafana.apps.example.com
    tls_ca_file: /etc/limen/upstream-ca.pem
    tls_server_name: grafana.internal.example # optional if it differs from address host
    health_path: /api/health
    identity_headers: false
  worker_selector: { pool: staging-vpc }
---
kind: role
version: v1
metadata: { name: grafana-users }
spec:
  allow:
    - resources: { kind: [web], names: [grafana-staging] }
      web: { methods: [GET, HEAD], path_prefixes: ["/"] }
```

`address` is the upstream `host:port` reachable from the selected worker. TLS
verification is enabled by default; `tls_ca_file` is required for the trusted
CA bundle, and `tls_server_name` may be set when the certificate name differs
from the address host.
Plain HTTP is for local development only: the resource must set
`insecure_dev: true`, and its worker must be started with the matching
`LIMEN_ALLOW_INSECURE_WEB_TARGETS=true` opt-in. Never enable it for production.

`web: {}` grants access to the resource. Optional `methods` and `path_prefixes`
are checked on every request. An empty list leaves that dimension
unrestricted; deny rules win. Paths with ambiguous encodings or alternate
normalizations are rejected. Requests are streamed, and WebSocket upgrades are
supported over HTTP/1.1. Limen does not support `CONNECT` or arbitrary upstream
destinations.

Apply the policy, sign in with the Limen CLI, and open an authorized app:

```sh
limen admin apply grafana-policy.yaml
limen login
limen ls
limen web open grafana-staging
```

`limen web open --no-browser grafana-staging` prints the HTTPS URL instead.
The command only opens a web resource returned by the authenticated,
policy-filtered resource list. A browser request without an app session starts
OIDC sign-in; bots are refused browser sessions. The user lock, current
resource grant, request method, and path restrictions are checked on each
request, so revocation follows the proxy policy-snapshot refresh bound.

## Identity assertions

The Limen SSO gate is sufficient to protect an app by default; identity
propagation is off unless the resource explicitly sets `identity_headers: true`.
For an app configured to trust Limen, the proxy overwrites client-supplied
`X-Limen-*` and forwarding headers with the verified identity, roles, and a
short-lived signed ES256 JWT in `X-Limen-Identity`. The assertion uses issuer
`urn:limen:control-plane`, the app host as its audience, and a `kid` from the
control plane's shared public key set at `/console/web/jwks.json`. It contains
the keys for all active control-plane signing certificates, including overlap
during certificate rotation. Verify the signature, issuer, audience, and
expiry before trusting it. Do not use identity headers as authentication if
the app cannot verify the signature.

The initial app-host redirect sets a short-lived, host-only browser nonce
cookie. The console carries only its hash into the one-use handoff; the proxy
requires that browser cookie when redeeming the handoff. This prevents a
handoff captured from one browser from logging another browser into that
account.

## Audit and local demo

Allowed requests produce `web.request` before forwarding and a `web.response`
with status, byte counts, and duration. Denials—including unauthenticated
requests that start a sign-in—produce `auth.denied`. Audit excludes query
values, request/response bodies, cookies, and credentials. WebSocket upgrades
produce request and response events and a stream-end event with byte counts.
The handshake's `Origin` must name the app itself (a sibling app on the same
site is refused with `websocket_origin_denied`), and an upgraded stream is
closed when the app session expires (`reason: session_expired`).
The control plane projects request metadata, never payloads or query strings,
into the existing session detail page. If audit cannot be written, Limen does
not forward the request or issue a successful handoff.

Run the local end-to-end demo for browser SSO, app-cookie isolation, identity
assertions, method/path and host/SNI enforcement, streaming, WebSockets, TCP,
and audit:

```sh
demos/demo-phase12.sh
```

The demo uses Dex and local fixtures; it does not verify a production IdP,
certificate authority, or real internal web app.

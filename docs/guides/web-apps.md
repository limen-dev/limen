# Internal web apps

Limen publishes each configured web app on its own HTTPS host. The proxy routes only an exact configured host whose TLS SNI and HTTP `Host`/`:authority` agree, and the worker connects only to the resource's fixed upstream address. Browsers use the user's Limen OIDC login and a short-lived, host-only app session cookie, which is removed before a request reaches the app.

## Configure a web resource

Point the app host at the Limen proxy and configure a certificate covering it. The proxy must trust the certificate and the user's browser must trust its issuer. Set the public console origin to the externally visible HTTPS origin; it's used for OIDC redirects and keeps a mapped public port in local deployments.

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

- `address` is the upstream `host:port` reachable from the selected worker. TLS is verified by default: `tls_ca_file` supplies the trusted CA bundle, and `tls_server_name` covers a certificate name that differs from the address host.
- Plain HTTP is for local development only. The resource must set `insecure_dev: true` and its worker must start with `LIMEN_ALLOW_INSECURE_WEB_TARGETS=true`. Never enable it in production.
- `web: {}` grants access to the resource. Optional `methods` and `path_prefixes` are checked on every request; an empty list leaves that dimension unrestricted, and deny rules win. Paths with ambiguous encodings or alternate normalizations are rejected.
- Requests are streamed and WebSocket upgrades work over HTTP/1.1. `CONNECT` and arbitrary upstream destinations aren't supported.

Apply the policy, sign in and open the app:

```sh
limen admin apply grafana-policy.yaml
limen login
limen ls
limen web open grafana-staging        # --no-browser prints the HTTPS URL instead
```

`limen web open` opens only web resources from your authenticated, policy-filtered list. A browser request without an app session starts OIDC sign-in; bots are refused browser sessions. The user lock, current grant, method and path restrictions are checked on every request, so revocation follows the proxy's policy-snapshot refresh.

## Identity assertions

The Limen SSO gate protects an app by default. Identity propagation is **off** unless the resource sets `identity_headers: true`. For an app configured to trust Limen, the proxy overwrites client-supplied `X-Limen-*` and forwarding headers with the verified identity and roles, plus a short-lived signed ES256 JWT in `X-Limen-Identity`.

- The JWT has issuer `urn:limen:control-plane`, the app host as audience, and a `kid` from the control plane's public key set at `/console/web/jwks.json` (all active signing certificates, including overlap during rotation).
- Verify signature, issuer, audience and expiry before trusting it. Don't use identity headers as authentication if the app can't verify the signature.

The first app-host redirect sets a short-lived, host-only browser nonce cookie. The console carries only its hash into the one-use handoff and the proxy requires the cookie to redeem it, so a handoff captured from one browser can't log another into that account.

## Audit

- Allowed requests produce `web.request` before forwarding and `web.response` with status, byte counts and duration. Denials, including unauthenticated requests that start a sign-in, produce `auth.denied`.
- Audit excludes query values, bodies, cookies and credentials. The session detail page shows request metadata only.
- WebSocket upgrades produce request and response events and a stream-end event with byte counts. The handshake's `Origin` must name the app itself (a sibling app on the same site is refused with `websocket_origin_denied`), and an upgraded stream closes when the app session expires (`reason: session_expired`).
- If audit can't be written, Limen neither forwards the request nor issues a successful handoff.

## Local demo

`demos/demo-phase12.sh` runs browser SSO, app-cookie isolation, identity assertions, method/path and host/SNI enforcement, streaming, WebSockets, TCP and audit end to end. It uses Dex and local fixtures, so a production IdP, certificate authority and real internal web app are **unverified**.

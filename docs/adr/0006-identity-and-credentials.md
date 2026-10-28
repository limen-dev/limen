# ADR-0006: OIDC login with a key-bound nonce, and short-lived X.509 and SSH certificates

- Status: Accepted (owner approved 2026-10-13)
- Date: 2026-10-13

## Context
Engineers log in with Okta (Dex or Keycloak locally). Every downstream credential must be short-lived, and no long-lived user secret may exist. SAML and SCIM are out of scope but must stay possible to add.

## Decision
- **Flows:** Authorization Code with PKCE through a loopback redirect (RFC 8252) by default, and Device Authorization Grant (RFC 8628) with `--device`. The CLI is a public client that talks to the IdP directly, using the `openidconnect` crate.
- **Key binding:**
  - The CLI generates its keys first.
  - It sets `nonce = b64url(SHA-256(x509_pub ‖ ssh_pub ‖ 32 random bytes))`.
  - The control plane accepts the ID token only if its `nonce` matches the presented keys.

  A relaying proxy therefore can't get certs issued for its own keys.
- **Issued credentials:**
  - an X.509 client cert (an OpenSSH user cert was planned here too; see the Phase 2 amendment)
  - both with a 10-minute TTL by default, configurable per role, capped by a cluster `max_cert_ttl`
  - *Amended 2026-10-28:* the default is now **1 hour**, and a deployment sets its own with `--default-cert-ttl` (`LIMEN_DEFAULT_CERT_TTL`), which may not exceed `max_cert_ttl`. A role's `cert_ttl` still overrides it (the shortest across a user's roles wins). Without a stored refresh token, 10 minutes sent people back to the browser for nearly every new connection (each `kubectl` call, each database GUI reconnect), while revocation (logout, locks, kills) already ends access within one policy refresh and a stolen certificate is useless without its private key. An hour also bounds how long a role removed in the IdP survives, since roles are fixed at login. Bots are unchanged (ADR-0019: 15 minutes, at most an hour).
  - roles and the login session ID carried as URI SANs in the X.509 cert (`limen://user/…`, `limen://role/…`, `limen://login/…`, with percent-encoded segments; see `limen_core::identity`), and in the SSH cert's key ID and extensions. *Amended in Phase 1:* URI SANs replace the custom extension planned here. They need no private OID arc, they're understood by every X.509 parser, and they verify offline.
- **Groups → roles** come from `role_mapping` documents (ADR-0008). Groups are read from a configurable claim (default `groups`). For Okta, the custom authorization server needs a groups claim configured; this goes in the Okta setup guide.
- **No refresh token is stored by default.** Users run `limen login` again, which is silent if the IdP session is alive.
- OIDC login lives in the control plane (`oidc.rs`) and the CLI. A placeholder `limen-auth` crate with a one-variant `IdentityProvider` enum was removed unused (#86). If SAML is taken on, add the provider seam with it, in the same change.

## Consequences
- *Amended in Phase 2:* login issues **no** SSH certificate. SSH certificates are per session (ADR-0007, amendment). Login returns the SSH host CA's public key so the CLI can verify workers.
- \+ Stolen certs are worthless after their TTL. Private keys never leave the machine.
- − Each user who connects after the TTL expires has to log in again (a browser round trip, usually silent).
- *Unverified against real service:* Okta's group claim limits (Okta caps the number of groups in a token; large memberships need a filter regex). This is documented in the Okta guide.

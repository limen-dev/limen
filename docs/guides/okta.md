# Signing in with Okta

> **Unverified against a real Okta tenant.** Limen speaks standard OpenID Connect and is tested against Dex (the dev stack's identity provider). The settings Limen needs are from its code; the Okta screens and behaviors below are from Okta's documentation and have not been run. Where Okta might differ, the text says so. If you try this, please tell us what was wrong (issue #64).

Limen needs three things from an identity provider: an **issuer** it can discover, an **ID token with the user's email and groups**, and **client registrations** for the CLI and (optionally) the console. Groups become roles through `role_mapping` policy; nothing else about a person comes from Okta.

## What you will end up with

| In Okta | In Limen |
|---|---|
| Authorization server, e.g. `https://<org>.okta.com/oauth2/default` | `LIMEN_OIDC_ISSUER`, character for character as it appears in the ID token's `iss` |
| A **Native** app (public client, PKCE) for `limen login` | `LIMEN_OIDC_CLIENT_ID` |
| A **Web** app (client secret) for the console, if you turn the console on | `LIMEN_CONSOLE_OIDC_CLIENT_ID` and `LIMEN_CONSOLE_OIDC_CLIENT_SECRET` |
| A `groups` claim in the ID token | `role_mapping` documents (`idp_group: ...`) |

## 1. The authorization server

Use Okta's **default** custom authorization server (Security → API → Authorization Servers), or your own. This guide describes a custom server. The org authorization server (`https://<org>.okta.com`, no `/oauth2/...`) is configured differently for groups and is not covered here. The issuer is on the server's settings page. Open `<issuer>/.well-known/openid-configuration` in a browser and check that its `issuer` field is the same string you will give Limen.

## 2. The groups claim

Limen asks for the scopes `openid email profile groups` (`LIMEN_OIDC_SCOPES`). On the authorization server:

1. **Scopes → Add Scope**: name `groups`. Okta may reject a request for a scope the server doesn't define, so define it, or remove `groups` from `LIMEN_OIDC_SCOPES` and attach the claim to "Any scope" instead.
2. **Claims → Add Claim**: name `groups`, include in **ID Token** (always), value type **Groups**, filter **Matches regex** `.*` to send all, or **Starts with** a prefix such as `limen-` to send only the groups that matter and keep the token small.

Then in the CLI the groups arrive in the ID token and `role_mapping` turns them into roles:

```yaml
kind: role_mapping
version: v1
metadata: { name: okta }
spec:
  - { idp_group: limen-db-readonly, roles: [db-readonly] }
```

Roles are fixed into the certificate at login, so a change to a person's groups applies at their next login.

## 3. The CLI client

Applications → Create App Integration → **OIDC** → **Native Application**.

- Grant types: **Authorization Code** and, for machines without a browser, **Device Authorization**.
- Sign-in redirect URIs: `limen login` uses a loopback address on a random port (`http://127.0.0.1:<port>/callback`, RFC 8252). Okta may require redirect URIs to match exactly; if it does not accept a loopback address without a port, register what it accepts, and if that is impossible use the device flow: `limen login --device` needs no redirect URI. **This is the part most likely to need adjusting.**
- Assignments: assign the people or groups who should be able to sign in.

The Client ID is `LIMEN_OIDC_CLIENT_ID`. There is no secret: it is a public client and Limen uses PKCE.

## 4. The console client (optional)

If you set `LIMEN_CONSOLE_PUBLIC_URL`, register a second app: **Web Application**, grant **Authorization Code**, sign-in redirect URI `https://<public host>/console/callback` exactly. Give its Client ID to `LIMEN_CONSOLE_OIDC_CLIENT_ID` (default `limen-console`) and its secret to `LIMEN_CONSOLE_OIDC_CLIENT_SECRET` from your secret store. See the [console runbook](../runbooks/console.md).

## 5. Limen's side

```sh
LIMEN_OIDC_ISSUER=https://<org>.okta.com/oauth2/default
LIMEN_OIDC_CLIENT_ID=<the native app's client id>
LIMEN_BOOTSTRAP_ADMIN_GROUPS=<an okta group of your admins>   # so the first admin can log in and apply policy
```

`LIMEN_OIDC_USERNAME_CLAIM` is `email` by default: the ID token must carry the user's email, which the `email` scope gives. The [deploy guide](deploy.md) shows where these go on ECS, EC2 and Kubernetes.

## 6. Check it

```sh
limen login            # or: limen login --device
limen status           # your name, roles and when the certificate ends
limen doctor           # if something is off, it says which step
```

If `limen status` shows no roles, the token had no groups claim or no `role_mapping` matches: decode the ID token (it is not secret to you) and look at `groups`. The usual causes are the claim not attached to the ID token, the scope not requested or not defined, or a filter that excludes the group.

## What we have not checked

Everything on the Okta side, on a real tenant: the loopback redirect, the device grant, the groups claim and scope behavior, token lifetime, and a multi-factor sign-in. OneLogin is not covered here (#64).

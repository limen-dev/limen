# Onboarding and offboarding from your IdP

The IdP is the only source of truth for who may use Limen (ADR-0046). Limen has no user lifecycle of its own and needs no offboarding checklist.

*Everything here is tested against a stand-in IdP that issues refresh tokens. It is not verified against Okta, Entra or another real IdP (#64).*

## Onboarding

Add a person to an IdP group that a `role_mapping` document maps to a role. They run `limen login`. Nothing is created in Limen first.

## Offboarding

Deactivate the person, or remove them from the group that grants a role. Within a few minutes (`--idp-check-interval`, 5 minutes by default):

| In the IdP | What Limen does | Audit event |
|---|---|---|
| The person is deactivated, or their IdP session is revoked | Ends their logins: certificates stop working at the next API call and their sessions end. They cannot sign in again, because the IdP refuses them. | `idp.offboard` with `deactivated: true` and the IdP's reason |
| A group that gave them a role is removed | Ends that login only. The person is **not** locked; they can sign in again with the access they still have. | `idp.offboard` with `deactivated: false` and the roles lost |
| The IdP cannot be reached | Keeps sessions and raises `idp.check_failed` once per person per outage (see the failure rule below). | `idp.check_failed` |

An admin lock is still the immediate tool (see [locking a user](../runbooks/lock-user.md)); this removes the need to remember to use it.

## How it works

When the check is on, the control plane tells the CLI to add the `offline_access` scope, so the IdP issues a refresh token; the CLI sends it to the control plane with the ID token. The control plane stores it **sealed** (AES-256-GCM, bound to the login) and uses it to ask the IdP, on a schedule, whether the session is still valid. The token is never returned by any API, logged, or audited, and it is deleted when the login ends, is revoked, or expires.

A login whose IdP issued no refresh token works as before and is simply not checked. The console shows it as "not checked".

## Turning it on

```sh
# 32 random bytes, base64. Keep it in your secret store, like the database password.
LIMEN_IDP_TOKEN_KEY=$(openssl rand -base64 32)
```

Without the key, no refresh token is stored and nothing is checked.

| Flag | Default | Meaning |
|---|---|---|
| `--idp-token-key` | none | Key that seals refresh tokens. Required to turn the check on |
| `--idp-check-interval` | `5m` | How often a login is checked, spread by ±10%. `0s` turns the check off |
| `--idp-check-failure` | `open` | `open`: keep sessions when the IdP cannot be reached and alert. `closed`: end logins not confirmed within the grace period |
| `--idp-check-grace` | `1h` | With `closed`: how long a login may go unconfirmed |
| `--idp-ignore-groups` | off | Do not end logins on group removal. For an IdP that leaves groups out of refreshed ID tokens |

The IdP must allow `offline_access` and issue refresh tokens to the CLI's client (Okta: enable the Refresh Token grant on the native app) and put the groups claim in refreshed ID tokens. **An IdP that omits the claim for a person with no groups looks the same as a person with no groups**, so a refreshed token without `groups` counts as no groups. If your IdP drops the claim from refreshed tokens, every login would end at its first check; set `--idp-ignore-groups` and rely on deactivation only.

If your IdP expires refresh tokens early (idle or absolute lifetimes), an expired token reads as a refusal (`invalid_grant`) and ends the login. Set the refresh token lifetime at least as long as `--max-cert-ttl`.

## What to watch

- Metrics: `limen_idp_checks_total{outcome="ok|refused|roles_lost|failed"}` and `limen_idp_offboards_total`. Alert on `failed` rising: with `open`, it means offboarding has stopped working.
- The console **Users** page shows where each person came from and the last check ("checked", "IdP not reachable since", "ended by the IdP", "not checked"), and filters by group, role and check state.
- Several control plane replicas share the work: each claims logins that are due, so none is checked twice.

## Limits

- Reaction time is the check interval, not instant. For instant, lock the user.
- Roles are still fixed at login; a *new* group applies at the next sign-in.
- Bots and agents are not checked (they hold no refresh token).
- SCIM and IdP event hooks are not built (ADR-0046, alternatives).

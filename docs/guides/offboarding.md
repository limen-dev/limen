# Onboarding and offboarding from your IdP

The IdP is the only source of truth for who may use Limen (ADR-0047). Limen has no user lifecycle of its own and needs no offboarding checklist.

*Tested against Dex v2.46.0 (on PostgreSQL storage) and a stand-in IdP. Not verified against Okta, Entra or another hosted IdP (#64).*

## Onboarding

Add a person to an IdP group that a `role_mapping` document maps to a role. They run `limen login`. Nothing is created in Limen first, and they inherit exactly the roles their groups map to:

- A group you add them to later is picked up at their **next** sign-in (roles are fixed at sign-in).
- A group no mapping names gives nothing. A person with no mapped group at all cannot sign in, unless a request or approval policy lets them *ask* for access (ADR-0025).
- To give everyone a baseline, map a group that everyone is in (most IdPs have one, such as `Everyone` in Okta).

## Offboarding

Deactivate the person, or remove them from the group that grants a role. Within a few minutes (`--idp-check-interval`, 5 minutes by default):

| In the IdP | What Limen does | Audit event |
|---|---|---|
| The person is deactivated, or their IdP session is revoked | Ends that login, **locks the person** (as `system:idp-check`), so console and web sessions and logins without a refresh token end too, and checks their other logins at once. The lock lifts itself, audited as `user.unlock`, when the IdP vouches for them at their next sign-in. An admin's lock is never lifted that way. | `idp.offboard` with `deactivated: true` and the IdP's reason, then `user.lock` |
| A group that gave them a role is removed | Ends that login only. The person is **not** locked; they can sign in again with the access they still have. | `idp.offboard` with `deactivated: false` and the roles lost |
| The IdP cannot be reached | Keeps sessions and raises `idp.check_failed` once per person per outage (see the failure rule below). | `idp.check_failed` |

An admin lock is still the immediate tool (see [locking a user](../runbooks/lock-user.md)); this removes the need to remember to use it.

### Deleting the record

A disabled person's record is kept at first, because their sessions, recordings and audit events name them and a false alarm should be recoverable. After that:

- **Automatically.** Someone the IdP check disabled and who has not signed in again for `--idp-purge-after` (`LIMEN_IDP_PURGE_AFTER`, **90 days** by default, `0s` turns it off) has their user record and stored IdP tokens deleted, audited as `user.delete` by `system:idp-check`. Sessions, recordings and audit events stay. A person an **admin** disabled is never purged automatically. The purge runs hourly, as part of the IdP check, so it needs `--idp-token-key` too.
- **By hand.** On a disabled user's page, **Delete** removes the record, with a reason in the audit trail. Enabled users can't be deleted, and bots are managed on the Bots page. If an admin had disabled them, that lock stays, so they can't come back unnoticed; they are listed under "Disabled, no user record" until an admin enables them.
- **If they come back.** A person deleted after the IdP disabled them simply signs in again if the IdP accepts them, and gets a new record with no history on the Users page (their old sessions and audit events are still there under their name).

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

## Dex

Dex works as the IdP, with one caveat found in testing: with Dex v2.46.0 a refresh grant **never returns** when Dex keeps its state in memory or SQLite (the token update holds the storage lock while the connector reads storage). That also freezes the rest of that Dex. Use PostgreSQL (or another networked) storage, as production Dex deployments do. The development stack's Dex is in memory, so by default the dev stack leaves `--idp-token-key` unset and does not check logins; the opt-in `idp-check` stack turns it on (below). The check's HTTP calls time out after 10 seconds, so a stuck IdP shows up as `idp.check_failed`, not as a stuck control plane.

### Try it on the dev stack

```bash
deploy/compose/setup.sh --stacks idp-check      # adds to any other stacks you pick
mise run install-cli                            # the CLI must send the refresh token
limen --proxy localhost:3443 login --ca-file deploy/compose/.state/internal-ca.pem   # developer@example.com / password
```

The `idp-check` stack moves the stack's Dex, with the same users, onto PostgreSQL (`dex-db`) and sets `LIMEN_IDP_TOKEN_KEY` (a development-only key) and `LIMEN_IDP_CHECK_INTERVAL=15s` on the control plane. Open `https://localhost:3443/console/users`: after one interval the person's *last check* is fresh. Then:

- **Offboard.** Delete the person's refresh token in Dex, which is what a revoked session looks like to the IdP:
  `docker exec limen-dex-db psql -U dex -d dex -c "delete from refresh_token where claims_email='developer@example.com'"`.
  At the next check, Dex answers `invalid_grant`, the login ends, and the person is **disabled** (a lock held by `system:idp-check`; the Users page's *State* filter has "Disabled by the IdP") (`idp.offboard` in the audit trail). Signing in again lifts the lock.
- **Remove the user from Dex's config instead and the check does not offboard.** Dex answers a refresh for a user it no longer has with `500 invalid_request` ("user not found" in its log), not `invalid_grant`, so Limen reads it as the IdP being unreachable: it fails open and raises `idp.check_failed`. Treating every 500 as a deactivation would lock everyone out in a Dex outage, so Limen does not. Okta and the other hosted IdPs answer `invalid_grant` for a deactivated user (unverified until #64).
- **Onboard.** Change a user's `groups` in `deploy/compose/config/dev-users.toml`, run `python3 deploy/compose/scripts/gen-dev-users.py`, and restart Dex (`docker compose restart dex`). The new group applies at that person's next sign-in. A refreshed token from this Dex carries the same `groups`.

Run `docker exec limen-dex-db psql -U dex -d dex -c 'select id, claims_email from refresh_token'` to see the tokens Dex holds.

## What to watch

- Metrics: `limen_idp_checks_total{outcome="ok|refused|roles_lost|failed"}` and `limen_idp_offboards_total`. Alert on `failed` rising: with `open`, it means offboarding has stopped working.
- The console **Users** page shows where each person came from and the last check ("checked", "IdP not reachable since", "ended by the IdP", "not checked"), and filters by group, role and check state.
- Several control plane replicas share the work: each claims logins that are due, so none is checked twice.

## Limits

- **A refresh token is a credential that outlives the sign-in.** Anyone who can read the login request on the way to the control plane (a compromised proxy) or the database and the sealing key can redeem it at the IdP, and, through the device flow, which has no key binding, get Limen certificates until the token expires. Keep refresh token lifetimes short, and see the threat model (TB0, residual risk 11).

- Reaction time is the check interval, not instant. For instant, lock the user.
- Roles are still fixed at login; a *new* group applies at the next sign-in.
- Bots and agents are not checked (they hold no refresh token).
- SCIM and IdP event hooks are not built (ADR-0047, alternatives).

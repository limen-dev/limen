# Pre-provisioning with SCIM

*Built against Okta's published SCIM 2.0 requests; **not verified against a real Okta** (#64). Design: ADR-0048.*

With SCIM on, a person assigned to the Limen app in your IdP appears on Limen's **Users** page before they ever sign in, with the access their groups will give. Deactivating them locks them within seconds, and removing them from a group that gave a role ends the logins that relied on it.

**SCIM grants nothing by itself.** Roles still come from the ID token when the person signs in. SCIM tells Limen who exists, who is disabled, and which pushed groups they are in; a group counts only if a `role_mapping` names it.

## Turn it on

```sh
LIMEN_SCIM_TOKEN=$(openssl rand -base64 36)    # at least 32 characters; keep it in your secret store
```

Start the control plane with `--scim-token` (`LIMEN_SCIM_TOKEN`). Without it `/scim/v2` answers `404`. Proxies relay `/scim/` as they relay `/console/`, so the base URL is `https://<your proxy>/scim/v2`. **Okta needs a publicly trusted certificate on that name**; the development stack's internal CA will not do.

## Set up Okta (only engineering gets in)

1. Add a **SCIM 2.0** app integration (an app with provisioning enabled) with base URL `https://<proxy>/scim/v2`, unique identifier field `userName`, and *HTTP Header* authentication with the token as `Bearer <token>`. Enable **Push New Users**, **Push Profile Updates** and **Push Groups** (Create Users, Update User Attributes, Deactivate Users).
2. **Assign only the engineering group** to the app. Okta pushes the people assigned to it, nobody else. This is the filter that keeps non-engineers out.
3. **Push the group(s)** a `role_mapping` names (for example `limen-engineering`). Push Groups sends members by id; Limen records them as the person's IdP groups.
4. Map the group to a role in policy:

```yaml
kind: role_mapping
version: v1
metadata: { name: okta }
spec:
  - { idp_group: limen-engineering, roles: [engineer] }
```

## What it does

| Okta | Limen |
|---|---|
| A person is assigned to the app | A user appears with source **SCIM**, "never signed in" (`user.provision`). If they had signed in before SCIM was on, nothing changes except that SCIM now knows them |
| They are added to a pushed group | Their groups update; the Users page shows the access they will have ("next sign-in: +engineer"). Roles apply at their sign-in |
| They are removed from a pushed group | Logins that relied on a role the group gave end at once (`user.groups_change`, `idp.offboard`). They are not locked |
| They are deactivated in the app (Okta's Deactivate Users) | They are disabled as `system:scim` (`user.lock`) and their logins end. Signing in does not lift it; reactivating them in Okta does, and only a lock SCIM placed (never an admin's) |
| A user is deleted | The record is deleted through the audited path the console's Delete uses (`user.delete`) |

Ending logins for a group change needs the IdP check's stored logins (`--idp-token-key`); without it a deactivation still locks, but a group removal waits for the person's next sign-in. A lock stops everything immediately either way.

## Limits

- **The token is a powerful secret.** Anyone holding it can create, lock, unlock and delete people (not grant roles). Rotate it like a database password; a wrong token is counted in `limen_scim_requests_total{outcome="unauthorized"}`.
- A SCIM `userName` must match the name in the person's ID token (your `--username-claim`), ignoring case; it cannot be changed through SCIM.
- Only what Okta sends is built: no bulk, sorting, `/Schemas` or `/ResourceTypes`, and only `userName eq` / `displayName eq` filters. Other IdPs differ in their PATCH shapes.
- Bots are not provisioned through SCIM.

# Honeytokens: decoy resources that raise an alarm

A honeytoken is a resource that looks real, is granted by no role and is backed by nothing. Nobody has a reason to use it, so any attempt is worth a look: a stolen credential feeling around, a scanner, or someone browsing where they shouldn't. It needs no baseline and no tuning. Design and decisions: [ADR-0053](../adr/0053-honeytoken-resources.md).

*Tested against local stand-ins (an end-to-end test with a real control plane, proxy and worker, and unit tests). Not run against a SIEM, Datadog or Grafana.*

## Set one up

A decoy is a `resource` document with a `honeytoken` block in place of a protocol section:

```yaml
kind: resource
version: v1
metadata: { name: prod-backup-db, labels: { env: prod } }
spec:
  honeytoken:
    kind: postgres               # what it pretends to be
    principals: [backup_admin]   # the logins `limen ls` shows
    exposed_to: [developer]      # roles whose holders are shown it
    default_database: orders     # database kinds only: see below
```

- It has no address and no worker, so there is nothing to connect to. `kind: web` isn't offered, because a web app is reached by host name.
- `exposed_to` names the roles whose holders see it. A decoy nobody can see catches nothing, so it can't be empty. A role that doesn't exist is neither an error nor a warning (both would reach writers' results and name the decoy to whoever deleted a role); the admin-only policy page marks such a decoy "exposed to missing role".
- For `postgres`, `mysql`, `redshift` and `mongodb` decoys, set `default_database` as you would on a real resource. Without it `limen db connect` and `limen mongo connect` stop on the user's machine ("has no default database") before they reach the proxy, and the attempt is never seen. `principals` are shown sorted and once each, and a `tcp` decoy always shows `access`, as a real resource does.
- Pick a name and labels that fit your estate, like the real ones next to it. The name `prod-backup-db` beside `orders-prod` is believable; `honeypot-1` is not.
- Only people can create decoys. A bot writer can't set `honeytoken`, and can't read a decoy outside its namespace. Keep decoy names outside any writer's name patterns: a writer who picks the same name gets a "duplicate" error that gives it away.
- **Upgrade every control plane, proxy and worker first.** An older component can't read the field, and an older control plane refuses `detect.honeytoken` along with the rest of the proxy's batch.

## What people see

`limen ls` lists the decoy among the real resources, in name order, with the same columns, for the exposed roles only. Listing it is not an alert: that would fire on every `limen ls`.

Using it is. Each of these is refused with the answer a name the person can't reach gets, so the refusal doesn't give the decoy away (`explain` says so even though `limen ls` lists it):

| What they try | Refused as |
|---|---|
| `limen ssh`, `limen db connect`, and the other session commands (SSH, databases, Redis, MongoDB, search, RabbitMQ, Kafka, TCP) | `access denied to <login>@<resource>` |
| `kubectl` against the cluster | `access denied to <cluster>` |
| `limen request <resource>` (and break-glass), which never creates a request | "there is nothing you can request that reaches …" |
| `limen explain <resource>` for themselves | "No role you hold grants access to …, or it does not exist." |

An admin running `limen explain --user` on someone else is not a touch.

## The alert

Each touch writes one `detect.honeytoken` audit event (at the proxy, beside the usual `auth.denied`; the control plane's `request` and `explain` touches write only this):

| Field | Meaning |
|---|---|
| `user` | Who (a person, or `bot:<name>`) |
| `data.resource` | The decoy's name |
| `data.action` | `ssh`, `db`, `redis`, `mongo`, `search`, `mq`, `kafka`, `tcp`, `kube`, `request`, `explain` |
| `data.principal` | The login, role or user they tried, when the action names one |
| `data.roles` | The roles on their certificate (for `request`, the roles their groups map to) |
| `data.client_addr` | Their address, where the proxy sees it (not for `request` and `explain`) |
| `data.bot`, `data.ci` | For a bot: `true`, and the CI run (repository, workflow, commit) |

Where it goes: the S3 trail and Datadog like any event, and the [OCSF export](audit-ocsf.md) as a Base Event with severity High and status Failure. Ready-made rules:

- Grafana: **Limen: honeytoken touched** in `deploy/grafana/alerting/` (any event in 15 minutes).
- Datadog: the `honeytoken` monitor in `deploy/terraform/modules/datadog`.

If writing the event fails, the failure is logged and the refusal is unchanged. The request is refused either way.

## What it doesn't do

- It doesn't lock anyone. Locking on first touch is [#109](https://github.com/limen-dev/limen/issues/109); this event is what that would act on.
- It isn't a baseline or anomaly detector ([#107](https://github.com/limen-dev/limen/issues/107)).
- A person who is shown a decoy and tries it out of curiosity raises the alarm too. Expose decoys to roles where that is rare, and tell people not to use resources they don't recognize.
- The console's resource list never includes decoys; an admin sees them on the policy page as `honeytoken (<kind>)`. A user who opens a decoy's console page gets "no such resource", which is not a touch: a page view is a GET, and a link in a chat would otherwise raise alerts in the clicker's name. `limen policy who-can` treats a decoy's name as unknown.
- Some answers can still tell a decoy from a real resource, each only after the touch has been reported: a malformed Kafka request (or a database request with no database) to a decoy is refused as a denial where an unknown name gets a plain error; `limen explain` says "does not exist" about a name `limen ls` lists; and the CLI's automatic `explain` after a refusal writes a second event.
- Mixed versions: a proxy that can't read the field keeps its last policy and then fails closed, and an older control plane refuses `detect.honeytoken`, so the proxy retries that batch. Upgrade everything before adding a decoy.
- A discovered resource that was approved before a decoy took its name is skipped from then on: pick decoy names that no discovery matcher would produce.

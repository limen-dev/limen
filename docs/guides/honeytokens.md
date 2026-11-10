# Honeytokens: decoy resources that raise an alarm

A honeytoken is a resource that looks real, is granted by no role and is backed by nothing. Nobody has a reason to use it, so any attempt is worth a look: a stolen credential feeling around, a scanner, or someone browsing where they shouldn't. It needs no baseline and no tuning. Design and decisions: [ADR-0050](../adr/0050-honeytoken-resources.md).

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
```

- It has no address and no worker, so there is nothing to connect to. `kind: web` isn't offered, because a web app is reached by host name.
- `exposed_to` names existing roles. A decoy nobody can see catches nothing, so it can't be empty.
- Pick a name and labels that fit your estate, like the real ones next to it. The name `prod-backup-db` beside `orders-prod` is believable; `honeypot-1` is not.
- Only people can create decoys. A bot writer can't set `honeytoken`, and can't read a decoy outside its namespace. Keep decoy names outside any writer's name patterns: a writer who picks the same name gets a "duplicate" error that gives it away.
- **Upgrade every control plane, proxy and worker first.** An older component can't read the field, and an older control plane refuses `detect.honeytoken` along with the rest of the proxy's batch.

## What people see

`limen ls` lists the decoy among the real resources, in name order, with the same columns, for the exposed roles only. Listing it is not an alert: that would fire on every `limen ls`.

Using it is. Each of these is refused with the answer a name the person can't reach gets, so the refusal doesn't give the decoy away:

| What they try | Refused as |
|---|---|
| `limen ssh`, `limen db connect`, and the other session commands (SSH, databases, Redis, MongoDB, search, RabbitMQ, Kafka, TCP) | `access denied to <login>@<resource>` |
| `kubectl` against the cluster | `access denied to <cluster>` |
| `limen request <resource>` (and break-glass), which never creates a request | "there is nothing you can request that reaches …" |
| `limen explain <resource>` for themselves | "No role you hold grants access to …, or it does not exist." |

An admin running `limen explain --user` on someone else is not a touch.

## The alert

Each touch writes one `detect.honeytoken` audit event beside the usual `auth.denied`:

| Field | Meaning |
|---|---|
| `user` | Who (a person, or `bot:<name>`) |
| `data.resource` | The decoy's name |
| `data.action` | `ssh`, `db`, `redis`, `mongo`, `search`, `mq`, `kafka`, `tcp`, `kube`, `request` or `explain` |
| `data.principal` | The login, role or user they tried, when the action names one |
| `data.roles` | The roles on their certificate |
| `data.client_addr` | Their address, where the proxy sees it (not for `request` and `explain`) |
| `data.ci` | For a bot: the CI run (repository, workflow, commit) |

Where it goes: the S3 trail and Datadog like any event, and the [OCSF export](audit-ocsf.md) as a Base Event with severity High and status Failure. Ready-made rules:

- Grafana: **Limen: honeytoken touched** in `deploy/grafana/alerting/` (any event in 15 minutes).
- Datadog: the `honeytoken` monitor in `deploy/terraform/modules/datadog`.

If writing the event fails, the failure is logged and the refusal is unchanged. The request is refused either way.

## What it doesn't do

- It doesn't lock anyone. Locking on first touch is [#109](https://github.com/limen-dev/limen/issues/109); this event is what that would act on.
- It isn't a baseline or anomaly detector ([#107](https://github.com/limen-dev/limen/issues/107)).
- A person who is shown a decoy and tries it out of curiosity raises the alarm too. Expose decoys to roles where that is rare, and tell people not to use resources they don't recognize.
- The console doesn't show decoys at all, to anyone, and `limen policy who-can` treats a decoy's name as unknown.

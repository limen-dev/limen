---
title: Concepts
description: The ideas behind Limen in one page, from certificates to the audit chain.
---
## Credentials are certificates that expire

`limen login` creates a key pair on your machine and signs you in through your identity provider (OIDC: a browser, or a device code). The control plane checks the ID token, maps your IdP groups to roles, and returns an **X.509 client certificate valid for 1 hour by default** (the operator sets the default with `--default-cert-ttl`, a role can shorten it with `cert_ttl`). The nonce in the login binds the certificate to your exact public key, so a proxy in the middle cannot swap in its own.

There is no refresh token on disk by default. When the certificate expires you sign in again, which is cheap while your IdP session is alive. `limen logout` ends the login everywhere, and an admin can lock a user, which ends all of their sessions within about 10 seconds. Details: [design §4](../architecture/design/#4-identity-and-credentials-adr-0006-adr-0007).

## Three programs

| Program | Does |
|---|---|
| **Control plane** | Holds state in PostgreSQL, runs the certificate authority (keys in KMS in production), evaluates policy, and writes the audit trail. |
| **Proxy** | The single public entry point. Authorizes each connection and routes it to the right worker. |
| **Worker** | Runs next to your targets and **dials out** to the proxy, so targets need no inbound ports. It terminates the protocol, records and audits the session, and uses the target's own credentials, which you never see. |

See [the three server programs](../architecture/components/) and the [diagrams](../architecture/diagrams/).

## Policy: labels, roles, deny by default

Policy is YAML in Git. A role says which resources (by kind and labels) it allows and as whom (an SSH login, a database role). IdP groups map to roles. If no rule allows it, it is denied. Policy is pushed to proxies and workers as a signed snapshot that they refresh every 10 seconds, so they keep enforcing when the control plane is briefly down.

Because policy is code you can test it: `limen policy test` fails CI on a policy that opens production, `limen policy diff` shows who gained access (with `--replay`, it also runs recorded sessions through both versions), and `limen explain` says why a request was denied. A new `deny` rule can run in **shadow mode** first, reporting what it would have refused without refusing it, and `limen policy suggest` proposes what to remove, based on real sessions. See [testing and questioning policy](../guides/policy-tooling/) and the [policy reference](../reference/policy/).

## Access you ask for

A *requestable* role grants nothing until someone asks, gives a reason, and an approver agrees. The grant is scoped to one resource, lasts a limited time, and ends the sessions it allowed when it expires or is revoked. You can never approve your own request. See [access requests and break-glass](../guides/access-requests/).

## People, and the machines that act for them

Your identity provider stays the source of truth for who may use Limen. Deactivate a person there and Limen's next check (every 5 minutes by default) ends their logins and locks them; with [SCIM](../guides/scim/) it happens within seconds, and people appear before their first sign-in. See [offboarding](../guides/offboarding/).

CI jobs are first-class principals. A **bot** joins with a GitHub Actions or GitLab CI token (or any OIDC provider), matched on exact claims, and gets the same short-lived certificates under the same policy. The run (repository, workflow, commit) is in every audit event. See [bots](../guides/bots/).

## Everything is audited, and the audit is checkable

Workers and proxies write events to a disk spool first, then deliver them at least once to S3 and Datadog. A session that cannot be audited is not allowed to start, because audit **fails closed**. Each control plane writes its S3 batches with a signed manifest naming the previous manifest's hash, so a missing, reordered, or altered batch shows up when you run:

```sh
limen audit verify
```

Limen also tests its own controls on a schedule and keeps a signed report of the result ([self-test and controls report](../guides/controls-report/)), and can export the trail in OCSF for a SIEM ([OCSF export](../guides/audit-ocsf/)).

SSH sessions are recorded and replayable. Databases, Redis, MongoDB, search, and brokers are audited as commands or requests, and values that are secret by nature (Redis values, message bodies, record values) are redacted or never logged. See [verifying the audit chain](../runbooks/audit-verify/) and [access reviews and evidence](../guides/access-reviews/).

## The console and the CLI

The CLI is for daily work. The web console, served by the proxy and signed in through the same identity provider, is for looking around and the occasional admin action: it opens on what needs you, shows what each resource is doing and how to connect to it, replays sessions, and is where approvers decide requests and reviewers answer access reviews. Your roles decide what you see, and what you change is audited as you. See [using the console](../guides/console/).

## What is and isn't verified

Limen only claims what it can demonstrate. The [status page](../status/) lists what is built, and what has only been tested against a local stand-in.

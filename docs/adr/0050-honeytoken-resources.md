# ADR-0050: Honeytoken resources

- Status: Proposed (issue #108, `needs: design`, part of the detection epic #110). Built at the owner's request with the defaults below; the owner has not yet approved the decisions listed under Open for review, and the status stays Proposed until they do.
- Date: 2026-11-10

## Context
Limen sees every attempt to use a resource, so it can raise an alarm that needs no baseline: a resource that looks real, that no policy grants and that nothing backs. Nobody has a reason to touch it, so any attempt is a stolen credential, a scanner or an insider looking around. Issue #108 asks for exactly this, with an alert (`detect.honeytoken`) carrying the actor's full context, shown only to principals the admin chooses.

## Decision
- **A decoy is a resource document with a `honeytoken` block and no protocol section.** `spec.honeytoken` holds `kind` (what it pretends to be), `principals` (what `limen ls` shows, 1 to 8) and `exposed_to` (roles whose holders are shown it). Labels come from `metadata.labels`. It has no address, no `worker_selector` and can't be `delegated`, so it is backed by nothing. `kind: web` is refused: a web app is reached by host name, so a decoy of it would never be touched. No new document kind, so the management API, Terraform and the console carry it already.
- **Kept apart from real resources.** `Policy` compiles a decoy into its own map, `honeytokens`, never into `resources`. Everything that routes (web host routing), grants (every `*_grants` function, `accessible`, `kube_groups`, `requestable_resources`), bootstraps database roles, discovers or connects reads `resources`, so a decoy is absent from all of it by construction, whatever a wildcard role or a label selector says. Only the code that lists or alerts reads the new map: `Policy::honeytoken(name)` and `Policy::exposed_honeytokens(roles)`. A decoy can't share a name with a resource, and `exposed_to` must name existing roles.
- **No new deny reason.** `Decision` and the trace are unchanged. A deny reason reaches callers (`ssh_certs` formats it into a gRPC status, `explain` returns it), so a `Honeytoken` reason would give the decoy away. Each place a person names a resource asks `policy.honeytoken(name)` instead.
- **Exposure is listing, not an alert.** `ListResources` appends the decoys exposed to the caller's certificate roles, merged in name order, with the same fields as a real resource (kind, labels, principals, no grant expiry). Listing fires nothing: an alert on every `limen ls` by an exposed principal would be noise. The issue's "list" is read as exposure; the alert is on use.
- **What counts as a touch.** Each is refused with the answer an ordinary refusal gets, and reported:
  - a session request through the proxy for any protocol (`establish`): SSH, databases, Redis, MongoDB, search, MQ, Kafka, TCP. The check runs before the principal is resolved, so a malformed probe still counts;
  - a Kubernetes request through the proxy to the cluster;
  - an access request or break-glass request naming it (never creates a grant or a pending request);
  - `limen explain` by the person themselves. An admin explaining someone else's access is not a touch.
- **The refusal reads like any other.** The proxy answers `access denied to <principal>@<resource>`, the same text and `denied` flag as a resource the caller can't reach, and the control plane answers with the "nothing you can request" text and `explain`'s "no role grants it, or it does not exist". A locked user gets the lock message exactly as for any resource. Failing to write the alert is logged, never turned into a different answer.
- **The alert.** A new audit kind, `detect.honeytoken`, written beside the ordinary `auth.denied`. `data`: `resource`, `action` (`ssh`, `db`, `redis`, `mongo`, `search`, `mq`, `kafka`, `tcp`, `kube`, `request`, `explain`), `principal` if one was named, the certificate `roles`, `client_addr` where the component sees it, and for a bot `bot: true` and the CI run (ADR-0019). The user is on the event. Names and principals are clipped to 128 characters. Nothing from the decoy but its name is in the event. The envelope is unchanged (`SCHEMA_VERSION` stays 1; adding a kind never bumped it). Proxies may send it through ingest; workers may not (a worker never sees a decoy request, because the proxy refuses it first).
- **OCSF.** Base Event (class 0), *Other*, severity High, status Failure, with the whole event in `unmapped`, so a SIEM routes it on severity. The exhaustive match made the mapping a compile error until chosen.
- **People write decoys.** A bot writer can neither set `honeytoken` in a resource (refused by the writer guard) nor in a profile template. A writer can't read a decoy: documents outside its namespace read as missing.
- **Out of scope.** Locking on first touch is #109 (auto-lock); `detect.honeytoken` is the event it would trigger on. Baselines and anomaly alerts are #107.

## Threats this design has to survive
- **The decoy is told apart from a real resource.** Same listing shape and order, same refusal text and flag, no distinct deny reason, no decoy in grant paths so no response differs by timing of a rule match. Residual differences are listed under Not verified.
- **A wildcard or label-selector role grants a decoy.** It can't: decoys are not in the map the rules are evaluated against. A table-driven test builds roles that match everything and checks no grant function, listing path or tooling reaches a decoy.
- **A bot or low-privilege caller enumerates decoys or clears the flag.** Writers can't set the field or read decoys. The management API's reads are limited to admins and, within their namespace, writers.
- **A decoy collides with a name a writer may create.** The policy refuses the duplicate, and the error names the resource, so a writer whose namespace pattern covers a decoy's name can learn it exists. Keep decoy names outside writers' namespaces.
- **An attacker triggers alerts to drown real ones.** Only someone shown the decoy (or guessing its name) can, which is the point; the event is a signal to look, and #109 adds action.
- **Forged alerts.** Only a proxy can send the kind through ingest, and a forged one is a false alarm, never an access.
- **A mixed-version rollout.** A component from before this change can't read `honeytoken` (unknown fields are errors), and an older control plane refuses `detect.honeytoken` at ingest with the rest of the proxy's batch. As with shadow mode (ADR-0046), add a decoy only after every control plane, proxy and worker runs this version.

## Consequences
- A resource document with `honeytoken`, a policy map and two accessors, one audit kind, and touch checks at the proxy and the control plane.
- Any code that adds a new way for a person to name a resource has to ask `policy.honeytoken` too; nothing enforces that at compile time (the checks are at the proxy's `establish` and Kubernetes `open`, and in `request_access` and `explain`).
- Dashboards and alert rules: a Grafana alert rule and a Datadog monitor example for `detect.honeytoken`.
- No dependency added.

## Open for review
- Whether `limen ls` should mark nothing (as built: identical to a real resource), or an exposed principal should see a hint that some listed resources are traps.
- Whether a plain `limen ls` of a decoy should itself be a low-severity event. As built it is not.
- Whether to lock the actor on first touch: left to #109.
- Whether the web console's resource page should also alert on a decoy's URL, and show decoys to admins with a marker. As built the console lists only granted resources and so doesn't show decoys at all.
- Whether `limen policy who-can` and `limen policy test` should know about decoys. As built they treat a decoy name as an unknown resource.

## Not verified
- Tested against local stand-ins and the in-repo proxy, worker and control plane only. No SIEM has ingested the OCSF record.
- Timing differences between a decoy and an unknown resource were not measured. A decoy answers from the same code path as a denied resource, but the refusal comes earlier than for a resource that needs a role lookup.
- Mixed-version behavior is documented, not exercised.

## As built
- Tests: eleven policy tests (no role reaches a decoy, validation, round trip and digest, exposure, discovery can't take a decoy's name), the OCSF table and `may_send` tests, and an end-to-end test (`limen-e2e/tests/honeytoken.rs`, run by `demos/demo-honeytoken.sh`) with a real control plane, proxy, worker and SSH target: listing, refusal text equal to an unknown name's, the touch events for connect, request and explain, none for listing, for the real resource, or for an admin explaining for someone else.
- Discovery (ADR-0027) skips a resource whose name is a decoy's and picks another name for a proposal.
- Alert rules: Grafana (`limen-honeytoken-touched`, generated) and a Datadog monitor (`honeytoken`). Neither was evaluated by Grafana or Datadog.
- Not built, as listed under Open for review: a marker for admins in the console, `who-can` and `policy test` support for decoys.

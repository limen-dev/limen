# ADR-0027: Resource discovery

- Status: Accepted and built (Phase 13). The owner asked for the whole phase on 2026-10-25.
- Date: 2026-10-14

## Context
Resources (hosts, databases, clusters) are written by hand in policy YAML. That does not survive autoscaling groups, many AWS accounts, or a team that creates a database a day. Discovery should find them, **without ever granting access by itself**.

## Decision
- **Workers discover, the control plane records.** A worker already runs inside the network, near the targets, with an IAM role. A worker with the right labels runs discovery matchers on an interval (default 5 minutes) with a **describe-only** IAM role, and reports what it found. The control plane never calls customer AWS accounts.
- **Sources, in order:** EC2 instances (SSH), RDS and Aurora (PostgreSQL, MySQL) and Redshift (Phase 6), ElastiCache (Phase 7), EKS clusters (Phase 8). Each lands when its protocol does. Other clouds and Kubernetes services are out of scope for now.
- **A `discovery` document in policy** says what to look for and how to name it:
  ```yaml
  kind: discovery
  version: v1
  metadata: { name: aws-prod }
  spec:
    provider: aws
    accounts: [{ role_arn: "arn:aws:iam::111122223333:role/limen-discovery" }]
    regions: [eu-west-1]
    match:
      - type: ec2
        tags: { limen/managed: ["true"] }
        name_template: "{{ tag.Name }}"
        ssh: { logins: [ec2-user, ubuntu] }
        labels_from_tags: [env, team]       # only these tags become labels
  ```
- **Discovered resources look like static ones to policy.** Roles select them by labels as before, so access stays deny-by-default: discovery makes things *selectable*, nothing more. A discovered resource is marked `discovered` in the console and in audit.
- **Tag injection is the main risk, so changes are quarantined.** Labels come from tags, and anyone who can write an EC2 tag could otherwise steer a resource into a role's selector. Defences: only the listed tag keys become labels; a *new* resource or a *changed label* on a known one is held as **pending** until an admin accepts it in the console (or `limen admin discovery accept`), unless the document opts into `auto_accept` for specific keys; every change emits `resource.discovered` or `resource.relabel`; the policy validator warns when a role selects on a tag-derived label.
- **Lifecycle:** seen, then missing for N cycles marks it *stale* (new sessions are refused, fail closed), then it is removed after a TTL. A resource with open sessions is never removed from under them.
- **Console and CLI:** a "Discovered" tab on Resources (pending, accepted, stale) with accept and reject; `limen admin discovery status`. Dashboard panel: resources by state.
- **Terraform:** not part of Phase 13. The describe-only IAM role is in the scope of the Terraform modules issue (#68, Phase 15); the guide lists the permissions to create it by hand.
- **Testing:** unit tests with recorded API responses and, in compose, a LocalStack stand-in for EC2 `DescribeInstances` (assumption to verify when the phase starts). Everything is labelled **unverified against real AWS** until Phase 15.

## Threats this design has to survive
- **Tag injection / label steering:** see above (allow-listed keys, quarantine, audit, validator warning).
- **A compromised worker reporting fake resources:** a worker may only report within the accounts and regions its matcher names, only the control plane's `discovery` document defines names, and a pending state needs an admin.
- **Over-broad discovery IAM:** the module grants `Describe*` only, scoped per source, with no `iam:PassRole`, no data-plane access.
- **Stale or vanished targets:** fail closed; open sessions are tracked until they end.

## Consequences
- Policy gains a third document kind. Resources gain `source` (`static` or `discovered`) and a state.
- Some environments will prefer to keep manual lists; static resources keep working unchanged.

## As built (Phase 13)
Accepted by the owner's request to build the phase. Differences:

- **Workers report facts; the control plane makes names and labels.** The worker sends the provider id, the address, and only the tags the matcher uses. The control plane applies the `discovery` document (`propose`), so a compromised worker cannot choose a name or a label, and a report outside the document's accounts, regions, tag filter, and matchers is dropped.
- **`ssh.logins` is gone** from the discovery document: logins belong to roles, not resources. `ssh` takes `port` and `address` (`private_ip` or `private_dns`).
- **SSH host keys.** `DescribeInstances` does not return them and workers refuse unpinned hosts, so the worker reads each instance's console output (`ec2:GetConsoleOutput`) and pins the best host key cloud-init printed. An instance with none cannot be accepted.
- **All five sources are built** (EC2, RDS and Aurora, Redshift, ElastiCache replication groups outside cluster mode, EKS), since their protocols all exist. Aurora is found through its cluster endpoint.
- **Calls are signed with the hand-written SigV4** the worker already has, and answers are read with a small bounded XML reader. No AWS SDK crate was added.
- **A change to a name, label, or target waits** while the accepted values stay in force; `auto_accept` names label keys whose changes (never name or target) apply at once, audited. Stale resources are refused; removal waits for open sessions.
- **The stand-in is ours**, not LocalStack: `limen-testkit`'s `fake_aws` answers with the documented response shapes and refuses unsigned or non-read calls. Everything is **unverified against real AWS**.
- **`limen.io/discovered`, `limen.io/source`, `limen.io/region`, `limen.io/account`** labels are set by the control plane from checked facts and win over tags.

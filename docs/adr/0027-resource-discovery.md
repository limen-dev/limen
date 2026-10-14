# ADR-0027: Resource discovery

- Status: Proposed (owner requested 2026-10-14; priority: **must have**)
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
- **Terraform:** a module for the worker's describe-only IAM role (least privilege, per source) in `deploy/terraform/modules/discovery`.
- **Testing:** unit tests with recorded API responses and, in compose, a LocalStack stand-in for EC2 `DescribeInstances` (assumption to verify when the phase starts). Everything is labelled **unverified against real AWS** until Phase 13.

## Threats this design has to survive
- **Tag injection / label steering:** see above (allow-listed keys, quarantine, audit, validator warning).
- **A compromised worker reporting fake resources:** a worker may only report within the accounts and regions its matcher names, only the control plane's `discovery` document defines names, and a pending state needs an admin.
- **Over-broad discovery IAM:** the module grants `Describe*` only, scoped per source, with no `iam:PassRole`, no data-plane access.
- **Stale or vanished targets:** fail closed; open sessions are tracked until they end.

## Consequences
- Policy gains a third document kind. Resources gain `source` (`static` or `discovered`) and a state.
- Some environments will prefer to keep manual lists; static resources keep working unchanged.

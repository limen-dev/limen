# Discovering resources

Hosts, databases, and clusters come and go; writing them by hand does not survive autoscaling. Discovery finds them in your AWS accounts **without ever granting access by itself** ([ADR-0027](../adr/0027-resource-discovery.md)).

> **Unverified against real AWS.** The parsers follow AWS's documented response shapes and are tested against a stand-in (`limen-testkit`'s `fake_aws`) that insists on signed, read-only calls. Nothing here has run against a real account yet; that is tracked in #123.

## How it works

1. A **worker** with `--discovery` runs the `discovery` documents whose `worker_selector` matches its labels, every `interval` (default 5 minutes), with a **describe-only IAM role**. The control plane never calls your accounts.
2. It reports *facts* (an instance id, an address, the few tags the matcher uses). It does not choose names or labels.
3. The **control plane** builds the name and labels from the document and holds the result as **pending**. Pending resources are visible to admins and reachable by nobody.
4. An admin **accepts** it (console: *Resources → Discovered*; CLI: `limen admin discovery accept <key>`). Now it is an ordinary resource: roles select it by labels, and access stays deny-by-default.

## The document

```yaml
kind: discovery
version: v1
metadata: { name: aws-prod }
spec:
  provider: aws
  accounts:                                   # empty = the worker's own account
    - role_arn: arn:aws:iam::111122223333:role/limen-discovery
  regions: [eu-west-1]
  interval: 5m                                # at least 1m
  worker_selector: { pool: prod-vpc }         # who runs it, and who serves what it finds
  auto_accept: [team]                         # label keys whose *changes* need no admin
  stale_after_cycles: 3
  remove_after: 7d
  match:
    - type: ec2
      tags: { limen/managed: ["true"] }       # server-side and client-side filter
      name_template: "{{ tag.Name }}"         # {{ id }} {{ region }} {{ account }} {{ tag.X }}
      labels_from_tags: [env, team]           # ONLY these tags become labels
      labels: { source: aws }
      ssh: { port: 22, address: private_ip }  # or private_dns
    - type: rds            # PostgreSQL and MySQL (Aurora through the cluster endpoint)
    - type: redshift
    - type: elasticache    # replication groups with a primary endpoint (not cluster mode)
    - type: eks
```

Resources also get labels Limen sets from checked facts, never from tags: `limen.io/discovered=true`, `limen.io/source`, `limen.io/region`, `limen.io/account`. They win over any tag.

## Tag injection, the main risk

Anyone who can write an EC2 tag could try to steer a resource into a role's selector. So:

- only the tags in `labels_from_tags` become labels, values must be printable ASCII;
- a **new resource, and any change to an accepted resource's name, labels, or target, waits** as pending while the *accepted* values stay in force; only label keys listed in `auto_accept` change without an admin (never the name or target), and the change is audited either way (`resource.relabel`);
- `limen policy` warns (and `apply` prints) when a role selects on a label that comes from a tag;
- a report can only add things inside the document's accounts, regions, tag filter, and sources; anything else is dropped and counted;
- a worker that the document's `worker_selector` does not name cannot report for it.

## Lifecycle

Seen, then not seen in `stale_after_cycles` **complete** scans marks it **stale**: new sessions are refused (fail closed). A scan that failed partway proves nothing about what is missing, so it counts nothing. Stale for `remove_after` and with no open session, it is removed. If it reappears it returns as it was accepted. If the discovery document is removed from policy, its resources leave policy at once.

## SSH hosts need a host key

`DescribeInstances` does not return host keys, and the worker refuses hosts it cannot verify. For EC2 the worker reads each instance's **console output** (`ec2:GetConsoleOutput`), where cloud-init prints its public host keys, and pins the best one (ed25519, then ECDSA). If the image prints none, the resource shows *host key not known* and **cannot be accepted** until it does. The key therefore comes from the instance's own console log through the AWS API.

## IAM

Create one role per account that your workers can assume (no Terraform module yet; it is part of #68). It only reads:

| Source | Actions |
|---|---|
| ec2 | `ec2:DescribeInstances`, `ec2:GetConsoleOutput` |
| rds | `rds:DescribeDBInstances`, `rds:DescribeDBClusters`, `rds:ListTagsForResource` |
| redshift | `redshift:DescribeClusters` |
| elasticache | `elasticache:DescribeReplicationGroups`, `elasticache:ListTagsForResource` |
| eks | `eks:ListClusters`, `eks:DescribeCluster` |

Grant only the sources your `match` list uses, on resource `*` (describe calls cannot be scoped). No `iam:PassRole`, nothing that reads or writes data. Trust only the roles your workers run as, optionally with an `sts:ExternalId`, and put that role's ARN in `role_arn`.

## Operating

`limen admin discovery status [--state pending|accepted|stale|changed]`, `accept`, `reject`. Events: `resource.discovered`, `resource.relabel`, `resource.review`, `resource.stale`. Metrics: `limen_discovery_scans_total`, `limen_discovered_resources{state}`, `limen_discovered_resources_new_total`. Worker flags: `--discovery`, and `--discovery-endpoint-url` for a stand-in in development.

## Accepting is bound to what you saw

The console sends a digest of the name, kind, labels and target on screen with **Accept**. If a scan changed the proposal in between (for example a tag was edited), the accept is refused with "it changed since you looked" and you check it again. A scope with more than 50 pages of results is reported as failed, not as complete, so nothing in it is marked stale by mistake.

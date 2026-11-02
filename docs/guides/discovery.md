# Discovering resources

Hosts, databases and clusters come and go, and writing them by hand doesn't survive autoscaling. Discovery finds them in your AWS accounts **without ever granting access by itself** ([ADR-0027](../adr/0027-resource-discovery.md)).

> **Unverified against real AWS.** The parsers follow AWS's documented response shapes and are tested against a stand-in (`limen-testkit`'s `fake_aws`) that insists on signed, read-only calls. Tracked in #123.

## How it works

1. A **worker** with `--discovery` runs the `discovery` documents whose `worker_selector` matches its labels, every `interval` (default 5 minutes), using a **describe-only IAM role**. The control plane never calls your accounts.
2. The worker reports *facts* (an instance id, an address, the few tags the matcher uses). It doesn't choose names or labels.
3. The **control plane** builds the name and labels from the document and holds the result as **pending**: visible to admins, reachable by nobody.
4. An admin **accepts** it (console: *Resources → Discovered*; CLI: `limen admin discovery accept <key>`). It's then an ordinary resource: roles select it by labels, and access stays deny-by-default.

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

Limen also sets labels from checked facts, never from tags, and they win over any tag: `limen.io/discovered=true`, `limen.io/source`, `limen.io/region`, `limen.io/account`.

## Tag injection

Anyone who can write an EC2 tag could try to steer a resource into a role's selector. So:

- Only tags in `labels_from_tags` become labels, and values must be printable ASCII.
- A **new resource, and any change to an accepted resource's name, labels or target, waits** as pending while the *accepted* values stay in force. Only label keys in `auto_accept` change without an admin (never the name or target), and the change is audited either way (`resource.relabel`).
- `limen policy` warns (and `apply` prints) when a role selects on a label that comes from a tag.
- A report can only add things inside the document's accounts, regions, tag filter and sources; the rest is dropped and counted.
- A worker the document's `worker_selector` doesn't name can't report for it.

## Lifecycle

A resource seen, then missing from `stale_after_cycles` **complete** scans, becomes **stale**: new sessions are refused (fail closed). A scan that failed partway proves nothing about what's missing, so it counts nothing. Stale for `remove_after` with no open session, it is removed; if it reappears it returns as accepted. Removing the discovery document removes its resources from policy at once.

## SSH hosts need a host key

`DescribeInstances` returns no host keys, and the worker refuses hosts it can't verify. For EC2, the worker reads each instance's **console output** (`ec2:GetConsoleOutput`), where cloud-init prints its public host keys, and pins the best one (ed25519, then ECDSA). If the image prints none, the resource shows *host key not known* and **can't be accepted**.

## IAM

Create one role per account that your workers can assume (no Terraform module yet; part of #68). It only reads:

| Source | Actions |
|---|---|
| ec2 | `ec2:DescribeInstances`, `ec2:GetConsoleOutput` |
| rds | `rds:DescribeDBInstances`, `rds:DescribeDBClusters`, `rds:ListTagsForResource` |
| redshift | `redshift:DescribeClusters` |
| elasticache | `elasticache:DescribeReplicationGroups`, `elasticache:ListTagsForResource` |
| eks | `eks:ListClusters`, `eks:DescribeCluster` |

Grant only the sources your `match` list uses, on resource `*` (describe calls can't be scoped). No `iam:PassRole`, nothing that reads or writes data. Trust only the roles your workers run as, optionally with an `sts:ExternalId`, and put the role's ARN in `role_arn`.

## Operating

- CLI: `limen admin discovery status [--state pending|accepted|stale|changed]`, `accept`, `reject`.
- Events: `resource.discovered`, `resource.relabel`, `resource.review`, `resource.stale`.
- Metrics: `limen_discovery_scans_total`, `limen_discovered_resources{state}`, `limen_discovered_resources_new_total`.
- Worker flags: `--discovery`; `--discovery-endpoint-url` for a stand-in in development.

**Accepting is bound to what you saw.** The console sends a digest of the name, kind, labels and target on screen with **Accept**. If a scan changed the proposal meanwhile (say a tag was edited), the accept is refused with "it changed since you looked". A scope with more than 50 pages of results is reported as failed, not complete, so nothing in it is wrongly marked stale.

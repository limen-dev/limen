# Policy reference

Policy is YAML, applied with `limen admin apply <files or dirs> [--dry-run] [--source-ref <git sha>]`. There are seven document kinds: `role`, `role_mapping`, `resource`, `bot`, `discovery`, and `policy_test`, and the built-in roles below. Parsing is strict: unknown fields, wildcard logins, and `system:` Kubernetes groups are rejected. Every apply creates a numbered version and a `policy.change` audit event with a diff. Working examples are in [`examples/policy/`](../examples/policy/).

The examples are grouped into `shared/` policy and `stacks/<kind>/` files.
Applying the `examples/policy/` directory still recursively applies the full
example policy. To apply one stack's examples, include the shared policy and
that stack's directory, for example:

```sh
limen admin apply examples/policy/shared examples/policy/stacks/redis
```

## Evaluation

Access is **denied by default**. A request names a resource and the principal to use on it (an SSH login, DB role, Kubernetes group, Redis user, or MongoDB role).

1. If any of the user's roles has a `deny` rule that matches the resource (and the principal, if the rule names principals), the request is denied.
2. Otherwise it's allowed if some `allow` rule matches the resource **and** lists the principal.

A selector matches when:
- the resource kind is listed,
- **every** label key matches (any of the listed values; `"*"` means "present with any value", and `"*": ["*"]` matches every resource),
- and `names`, if given, includes the resource.

Roles come from IdP groups **at login** and are fixed into the short-lived certificate. Policy changes to role mappings take effect at the user's next login. Changes to roles and resources take effect immediately.

The certificate lasts the shortest `cert_ttl` among the user's roles. When none sets one, it lasts the control plane's `--default-cert-ttl` (`LIMEN_DEFAULT_CERT_TTL`, **1 hour** unless the operator changes it). Either way it is capped by `--max-cert-ttl` (`LIMEN_MAX_CERT_TTL`, 12 hours by default), and the control plane refuses to start with a default above that cap. A shorter TTL also shortens how long a role removed in the IdP keeps working; to cut someone off at once, lock them.

## `role`

```yaml
kind: role
version: v1
metadata: { name: dev-readonly, description: optional }
spec:
  cert_ttl: 10m            # credential lifetime; the shortest across a user's roles wins (default 1h, set by the control plane's --default-cert-ttl)
  max_session_ttl: 8h      # cap on a single session; the shortest across a user's roles wins
  allow:
    - resources: { kind: [postgres, mysql], labels: { env: [staging] } }
      db: { roles: [limen_read], databases: ["*"] }
    - resources: { kind: [ssh], labels: { env: [staging] }, names: [web-staging-1] }
      ssh: { logins: [ubuntu], port_forwarding: false }
    - resources: { kind: [kubernetes], labels: { env: [staging] } }
      kube: { groups: ["limen:view"] }
    - resources: { kind: [redis], labels: { env: [staging] } }
      redis: { users: [read], keys: ["app:*"], deny_commands: [KEYS] }
    - resources: { kind: [opensearch, elasticsearch], labels: { env: [staging] } }
      search: { roles: [read], indices: ["app-*"] }
    # Planned integrations (nothing serves them yet; see below):
    - resources: { kind: [mongodb], labels: { env: [staging] } }
      mongo: { roles: [read], databases: ["*"] }
    - resources: { kind: [rabbitmq], labels: { env: [staging] } }
      mq: { users: [consumer] }
    - resources: { kind: [kafka], labels: { env: [staging] } }
      kafka: { users: [consumer] }
    - resources: { kind: [web], labels: { env: [staging] } }
      web: {}
  deny:
    - resources: { kind: [ssh], labels: { tier: [bastion] } }   # no principals: denies the resource entirely
  # Optional, see "Requestable roles" below:
  request: { who: [developers], approvers: [sre-leads], max_duration: 2h }
  break_glass: false
  notify_observed: false     # tell people on SSH sessions this role grants that an admin may watch
```

`db.roles` names the database roles people may use. **They must start with `limen_`** (followed by lowercase letters, digits, or underscores): the prefix is reserved for roles Limen creates and manages, and policy validation rejects any other. `db.databases` lists the databases (`"*"` for any).

For Redis, MongoDB, search, RabbitMQ, and Kafka, the `users` and `roles` fields select upstream identities; they do not require a Limen prefix. Use concise names such as `read`, `write`, `consumer`, or `admin`.

## `role_mapping`

```yaml
kind: role_mapping
version: v1
metadata: { name: okta }
spec:
  - { idp_group: okta-payments-eng, roles: [dev-readonly] }
  - { idp_group: limen-admins, roles: ["limen:admin"] }
```

`limen:admin` is built in. It grants the admin API (policy, join tokens, components) and no resource access. **`limen:auditor`** is built in too ([search and the record](guides/audit-search.md)): it can search the audit trail, read events and sessions, play recordings, and read requests, grants, and reviews; it cannot lock, kill, revoke, approve, or apply anything. Map either like any role. The control plane's `--bootstrap-admin-group` also grants it, so the first admin can log in before any policy exists.

## `resource`

```yaml
kind: resource
version: v1
metadata: { name: orders-prod, labels: { env: prod, team: payments } }
spec:
  postgres: { endpoint: "orders.cluster-xyz.eu-west-1.rds.amazonaws.com:5432", region: eu-west-1, iam_auth: true }
  worker_selector: { pool: payments-vpc }   # which workers may serve it
```

`worker_selector` labels must match a worker's labels exactly. Workers get their labels from their join token at enrollment, and the labels are signed into their certificate. An empty selector lets any worker serve the resource.

Exactly one target must be set: `ssh` (`address`, and `host_key`: the target's public host key, which is required to connect, since the worker refuses unpinned hosts), `postgres` / `mysql` / `redshift` (`endpoint`, `iam_auth`, `region`, `default_database`, `password_dir`, `tls_ca_file`, `tls_server_name`, `insecure_dev`, `normalize_literals`, `cluster_identifier`, `workgroup`, `admin_user`, `admin_password_file`, `bootstrap`; see [the databases guide](guides/databases.md)), `redis` (`endpoint`, `region`, `iam_auth`, `cache_name`, `tls`, and `audit` with `log_values` and `redact_keys`), `mongodb` (`endpoint`, `flavor: standard | atlas | documentdb`, `auth: scram | scram_sha1 | x509 | aws`, `default_database`, `auth_source`, `credentials_dir`, `tls_ca_file`, `tls_server_name`, `insecure_dev`, `full_commands`; see [the MongoDB guide](guides/mongodb.md)), `opensearch` / `elasticsearch` (`endpoint`, `region`, `aws`, `serverless`, `tls`, and `audit` with `log_bodies`, `log_query` and `redact_ids`), `kubernetes` (`cluster_name`), `web` (`address`, `host`, optional `tls_ca_file`, `tls_server_name`, `health_path`, `insecure_dev`, and `identity_headers`; see [the web apps guide](guides/web-apps.md)), or `tcp` (`address`; see [the TCP guide](guides/tcp.md)). Names and label keys use lowercase `[a-z0-9._-]`.

### RabbitMQ and Kafka grants

`mq: { users, vhosts, classes, names }` (classes `read`, `write`, `configure`; default `read` and `write` on vhost `/`) and `kafka: { users, classes, topics, groups }` (classes `read`, `write`, `admin`; default `read`) are enforced by the worker on every operation (ADR-0037). Name patterns use `*` only. Each decision is made by one grant: grants don't combine. See [the messaging guide](guides/messaging.md).

### Redis grants

`redis: { users: [...] }` names the target Redis users a role may act as; no Limen prefix is required. Optional limits, enforced by the worker on every command (ADR-0034):

- `keys: [patterns]`: only keys matching a pattern (`*`, `?`). Also refuses `KEYS`, `SCAN`, `RANDOMKEY`, and scripts.
- `deny_commands: [NAME or "NAME SUB"]`: refuse these as well as the built-in deny list. Wins over `allow_commands`.
- `allow_commands: [...]`: open commands from the built-in deny list (`FLUSHALL`, `CONFIG`, `EVAL`, ...). `MONITOR`, `SYNC`, `PSYNC`, `REPLCONF`, `RESET`, and `CLIENT REPLY` can't be opened.
- `databases: [0, 3]`: logical databases `SELECT` may name (default: only 0).

With several roles granting the same user, the session may do whatever any one grant allows. [The Redis guide](guides/redis.md) lists the defaults.

### MongoDB grants

`mongo: { roles: [...], databases: [...] }` names the target MongoDB users a role may act as (names the worker has a credential for in the resource's `credentials_dir`; no Limen prefix is required) and the databases they may use (`*` for all; deny rules apply). `deny_commands: [dropDatabase, drop]` refuses named commands (case-insensitive) on those databases. Enforced by the worker on every command (ADR-0035); the server's own grants for the MongoDB user are the second layer. With several grants covering the same database, a session may do whatever any one of them permits. Role names are `[A-Za-z0-9_.-]` (up to 64), and database names must be valid MongoDB database names. [The MongoDB guide](guides/mongodb.md) has the details.

### Search grants

`search: { roles: [...] }` names the target engine roles (the worker's logins to OpenSearch or Elasticsearch) a role may act as; no Limen prefix is required. Optional limits, enforced by the worker on every request (ADR-0036):

- `classes: [read, write, admin]`: what requests may do. Default: `read` only. The classes are independent (`write` doesn't include `read`), and an API the worker doesn't recognise is `admin`.
- `indices: [patterns]`: the index names and patterns (`*` only; lowercase letters, digits, `.`, `_`, `-`) a request may name. Empty means any index that isn't hidden; a name starting with `.` is covered only by a pattern that starts with `.`. A request that names every index needs a `*` pattern.

With several roles granting the same engine role, the session may do whatever any one grant allows. [The search guide](guides/search.md) lists what each class covers and what the worker reads to find the indices.

### Web app grants

`web: {}` allows access to the selected web resource. Optional `methods` and
`path_prefixes` restrict each request; an empty list leaves that dimension
unrestricted. Deny rules still take precedence. Browser sign-in uses OIDC, and
Limen checks the current policy and user lock on every request.
`limen web open <resource>` opens only an app already returned by the
authorized resource list. See the [web apps guide](guides/web-apps.md).

### Planned integrations

Some kinds are accepted by policy before their integration is implemented, so
policy can be reviewed ahead of time. Web apps and raw TCP are served today
alongside SSH, SQL databases, Redis, Kubernetes, MongoDB, search, RabbitMQ, and
Kafka. Stack-specific examples are organized under [`examples/policy/stacks/`](../examples/policy/stacks/), including deployment variants that remain unverified against their real cloud services.
Aurora (like Redshift for the SQL side), DocumentDB, Atlas, Amazon MQ, and MSK are not separate kinds: they are the same kind with the fields above. Web and TCP grants are access itself (`web: {}` and `tcp: {}`); neither lets a client choose an upstream identity or destination.

## Requestable roles and break-glass

A role with a `request` block grants nothing until someone asks, gives a reason, and an approver agrees; the access then exists for a limited time on **one resource**. See [the access requests guide](guides/access-requests.md).

| Field | Meaning |
|---|---|
| `request.who` | IdP groups that may ask (required) |
| `request.approvers`, `request.approver_users` | IdP groups and named users who may approve (one of them required, unless `break_glass`) |
| `request.approvals_required` | different approvers needed, 1 to 5 (default 1) |
| `request.max_duration` | longest grant (default `2h`, at most `7d`; at most `1h` for break-glass) |
| `request.require_reason` | default `true`; always on for break-glass |
| `request.ticket_pattern` | a regular expression (linear-time, up to 256 characters) the reason must match |
| `break_glass: true` | granted at once, reason required, at most 1 hour, announced and reviewed; takes no approvers |
| `notify_observed: true` | users on SSH sessions this role grants are told an admin may watch ([guide](guides/watching-sessions.md)) |

`limen apply` warns when a group can both request and approve a role, when a requestable role is already held by a group in `request.who`, and when a role selects on a label copied from a cloud tag.

## `discovery`

Finds resources in cloud accounts and holds them for an admin; it grants nothing. See [the discovery guide](guides/discovery.md).

```yaml
kind: discovery
version: v1
metadata: { name: aws-prod }
spec:
  provider: aws
  accounts: [{ role_arn: arn:aws:iam::111122223333:role/limen-discovery }]
  regions: [eu-west-1]
  interval: 5m                  # at least 1m
  worker_selector: { pool: prod-vpc }
  auto_accept: [team]           # label keys whose changes apply without an admin
  stale_after_cycles: 3
  remove_after: 7d
  match:
    - type: ec2                 # ec2 | rds | redshift | elasticache | eks
      tags: { limen/managed: ["true"] }
      name_template: "{{ tag.Name }}"      # {{ id }} {{ region }} {{ account }} {{ tag.X }}
      labels_from_tags: [env, team]        # only these tags become labels
      labels: { source: aws }
      ssh: { port: 22, address: private_ip }
```

## `policy_test`

Cases that run offline through the same decision code as enforcement. The runtime ignores them. See [the policy tooling guide](guides/policy-tooling.md).

```yaml
kind: policy_test
version: v1
metadata: { name: prod-is-locked-down }
spec:
  cases:
    - name: developers cannot ssh to prod as root
      who: { groups: [developers] }       # or: bot: deploy-staging, or roles: [..]
      resource: web-prod
      principal: { login: root }          # login | db_role (+database) | mongo_role (+database) | kube_group | redis_user | search_role | mq_user | kafka_user | web | tcp
      expect: deny                        # allow | request | deny
      via_role: sre                       # optional, with expect: allow
```

## `bot`

Machine identities for CI jobs and automation (ADR-0019, [the guide](guides/bots.md)).

```yaml
kind: bot
version: v1
metadata: { name: deploy-staging, description: optional }
spec:
  join:
    method: github_actions      # github_actions | gitlab | oidc
    issuer: https://...         # optional for github_actions and gitlab; required for oidc
    match:                      # every entry must equal a claim of the token exactly
      repository: acme/infra
      ref: [refs/heads/main, refs/heads/release]   # a list means "any of these"
      environment: staging
  roles: [deployer]
  max_ttl: 15m                  # at most 1h (the default is 15m); logins don't refresh
```

The bot logs in as `bot:<name>`. Rules the validator enforces, so a bot can't be written too broadly:
- `match` is **exact**: no wildcards, anywhere.
- `github_actions` must match `repository` **and** `ref` or `environment`, and never names a pull request ref (`refs/pull/…`) or the `pull_request` and `pull_request_target` events. Independently of the rule, **tokens from pull request runs never match** a GitHub bot, so a rule that names neither can't be used to let them in.
- `gitlab` must match `project_path` and `ref` or `environment`, and a matched `ref` also needs `ref_protected: "true"`.
- `oidc` needs `issuer` and an exact `sub`.
- `roles` must exist, and can't be built-in (`limen:…`). At most one hour of lifetime.
- When a token matches more than one bot the login is refused, so an overlap can't pick a winner.

Default issuers: `https://token.actions.githubusercontent.com` for GitHub Actions and `https://gitlab.com` for GitLab (set `issuer` for GitHub Enterprise Server and self-managed GitLab). Examples: [`examples/policy/stacks/bots/policy.yaml`](../examples/policy/stacks/bots/policy.yaml).

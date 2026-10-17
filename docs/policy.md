# Policy reference

Policy is YAML, applied with `limen admin apply <files or dirs> [--dry-run] [--source-ref <git sha>]`. There are four document kinds. Parsing is strict: unknown fields, wildcard logins, and `system:` Kubernetes groups are rejected. Every apply creates a numbered version and a `policy.change` audit event with a diff. Working examples are in [`examples/policy/`](../examples/policy/).

## Evaluation

Access is **denied by default**. A request names a resource and the principal to use on it (an SSH login, DB role, Kubernetes group, or Redis user).

1. If any of the user's roles has a `deny` rule that matches the resource (and the principal, if the rule names principals), the request is denied.
2. Otherwise it's allowed if some `allow` rule matches the resource **and** lists the principal.

A selector matches when:
- the resource kind is listed,
- **every** label key matches (any of the listed values; `"*"` means "present with any value", and `"*": ["*"]` matches every resource),
- and `names`, if given, includes the resource.

Roles come from IdP groups **at login** and are fixed into the short-lived certificate. Policy changes to role mappings take effect at the user's next login. Changes to roles and resources take effect immediately.

## `role`

```yaml
kind: role
version: v1
metadata: { name: dev-readonly, description: optional }
spec:
  cert_ttl: 10m            # credential lifetime; the shortest across a user's roles wins (default 10m)
  max_session_ttl: 8h      # cap on a single session; the shortest across a user's roles wins
  allow:
    - resources: { kind: [postgres, mysql], labels: { env: [staging] } }
      db: { roles: [limen_readonly], databases: ["*"] }
    - resources: { kind: [ssh], labels: { env: [staging] }, names: [web-staging-1] }
      ssh: { logins: [ubuntu], port_forwarding: false }
    - resources: { kind: [kubernetes], labels: { env: [staging] } }
      kube: { groups: ["limen:view"] }
    - resources: { kind: [redis], labels: { env: [staging] } }
      redis: { users: [limen-ro] }
    # Planned integrations (nothing serves them yet; see below):
    - resources: { kind: [mongodb], labels: { env: [staging] } }
      mongo: { roles: [limen-read], databases: ["*"] }
    - resources: { kind: [opensearch, elasticsearch], labels: { env: [staging] } }
      search: { roles: [limen-read] }
    - resources: { kind: [rabbitmq], labels: { env: [staging] } }
      mq: { users: [limen-consumer] }
    - resources: { kind: [kafka], labels: { env: [staging] } }
      kafka: { users: [limen-consumer] }
    - resources: { kind: [web], labels: { env: [staging] } }
      web: {}
  deny:
    - resources: { kind: [ssh], labels: { tier: [bastion] } }   # no principals: denies the resource entirely
```

`db.roles` names the database roles people may use. **They must start with `limen_`** (followed by lowercase letters, digits, or underscores): the prefix is reserved for roles Limen creates and manages, and policy validation rejects any other. `db.databases` lists the databases (`"*"` for any).

## `role_mapping`

```yaml
kind: role_mapping
version: v1
metadata: { name: okta }
spec:
  - { idp_group: okta-payments-eng, roles: [dev-readonly] }
  - { idp_group: limen-admins, roles: ["limen:admin"] }
```

`limen:admin` is built in. It grants the admin API (policy, join tokens, components) and no resource access. The control plane's `--bootstrap-admin-group` also grants it, so the first admin can log in before any policy exists.

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

Exactly one of `ssh` (`address`, and `host_key`: the target's public host key, which is required to connect, since the worker refuses unpinned hosts), `postgres` / `mysql` / `redshift` (`endpoint`, `iam_auth`, `region`, `default_database`, `password_dir`, `tls_ca_file`, `tls_server_name`, `insecure_dev`, `normalize_literals`, `cluster_identifier`, `workgroup`, `admin_user`, `admin_password_file`, `bootstrap`; see [the databases guide](guides/databases.md)), `redis` (`endpoint`, `region`, `iam_auth`, `cache_name`), or `kubernetes` (`cluster_name`) must be set. Names and label keys use lowercase `[a-z0-9._-]`.

### Planned integrations

These kinds are accepted by policy, listed by `limen ls` and the console, and tested, so the shape of the product is visible and policy can be written ahead of the integrations. SSH and the SQL databases (`postgres`, `mysql`, `redshift`) are served today. **Nothing serves the kinds below yet**: the matching `limen` command says which phase delivers it. Examples: [`examples/policy/planned.yaml`](../examples/policy/planned.yaml). The field names are provisional until each phase confirms its ADR.

| Kind | Resource fields | Grant section | Command (planned) |
|---|---|---|---|
| `mongodb` | `endpoint`, `flavor: standard \| atlas \| documentdb` | `mongo: { roles, databases }` | `limen mongo connect` (Phase 9) |
| `opensearch`, `elasticsearch` | `endpoint`, `region`, `aws` | `search: { roles }` | `limen search connect` (Phase 10) |
| `rabbitmq` | `endpoint`, `region`, `aws` (Amazon MQ) | `mq: { users }` | `limen mq connect` (Phase 11) |
| `kafka` | `endpoint`, `region`, `aws` (MSK) | `kafka: { users }` | `limen kafka connect` (Phase 11) |
| `web` | `address`, `host`, `health_path` | `web: {}` | `limen web open` (Phase 12) |
| `tcp` | `address` | `tcp: {}` | `limen tcp` (Phase 12) |

Aurora (like Redshift for the SQL side), DocumentDB, Atlas, Amazon MQ, and MSK are not separate kinds: they are the same kind with the fields above. `web` and `tcp` have no upstream identity to choose, so their grant is access itself (`web: {}`).

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

Default issuers: `https://token.actions.githubusercontent.com` for GitHub Actions and `https://gitlab.com` for GitLab (set `issuer` for GitHub Enterprise Server and self-managed GitLab). Examples: [`examples/policy/bots.yaml`](../examples/policy/bots.yaml).

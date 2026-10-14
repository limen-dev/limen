# Policy reference

Policy is YAML, applied with `limen admin apply <files or dirs> [--dry-run] [--source-ref <git sha>]`. There are three document kinds. Parsing is strict: unknown fields, wildcard logins, and `system:` Kubernetes groups are rejected. Every apply creates a numbered version and a `policy.change` audit event with a diff. Working examples are in [`examples/policy/`](../examples/policy/).

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
  deny:
    - resources: { kind: [ssh], labels: { tier: [bastion] } }   # no principals: denies the resource entirely
```

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

Exactly one of `ssh` (`address`, and `host_key`: the target's public host key, which is required to connect, since the worker refuses unpinned hosts), `postgres` / `mysql` (`endpoint`, `region`, `iam_auth`, `admin_secret_arn`), `redis` (`endpoint`, `region`, `iam_auth`, `cache_name`), or `kubernetes` (`cluster_name`) must be set. Names and label keys use lowercase `[a-z0-9._-]`.

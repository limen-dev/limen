This guide is for **teams that manage infrastructure with Terraform or OpenTofu**. The provider, [`limen-dev/terraform-provider-limen`](https://github.com/limen-dev/terraform-provider-limen), is a client of the [management API](management-api.md) ([ADR-0042](../adr/0042-management-api.md)). **Unverified:** it isn't released, and it has only run against a stand-in for the control plane, not a real one.

# Terraform and OpenTofu: register what you create

A team's module creates a database and registers it in Limen in the same apply, in its own state. The security team keeps roles and mappings in theirs. The pipeline logs in as a [bot](bots.md) with its CI token: no admin rights, no stored secret.

```hcl
resource "limen_resource" "orders_db" {
  name    = "payments-orders-db"
  profile = "payments-postgres" # written by a person: credentials, worker, IAM, and audit are fixed there
  spec = {
    postgres = { endpoint = "${aws_db_instance.orders.address}:5432" }
  }
  labels = { env = "staging" }
}
```

## 1. A person grants the bot what it may write

```yaml
kind: policy_writer
version: v1
metadata: { name: payments-terraform }
spec:
  bot: payments-terraform           # a bot that matches this repository's main branch
  namespace: payments
  names: ["payments-*"]
  kinds: [resource, policy_test]
  profiles: [payments-postgres]
```

Only people write `policy_writer`, `resource_profile`, and `bot` documents, so a pipeline can't widen its own grant ([policy reference](../policy.md#delegated-writes-resource_profile-and-policy_writer)).

## 2. Configure the provider

```hcl
terraform {
  required_providers {
    limen = { source = "limen-dev/limen", version = "~> 0.1" }
  }
}

provider "limen" {
  address        = "limen.example.com:443"
  ca_file        = "${path.module}/limen-ca.pem"
  default_source = "terraform/payments-prod" # one per state: which configuration owns what it creates
  bot            = { method = "github_actions", name = "payments-terraform" }
}
```

`method` is `github_actions`, `gitlab`, or `oidc` (with a `token_file`). The apply job needs `id-token: write` on GitHub. From a laptop, leave out `bot`: the provider reuses `limen login`.

A pull request run never matches a bot ([ADR-0019](../adr/0019-machine-identities.md)), so plan pull requests with `LIMEN_OFFLINE=true` and plan online on the protected branch.

## What it manages

`limen_resource`, `limen_role`, `limen_role_mapping`, and `limen_policy_test` are resources. Every other kind is a data source. A `spec` has the shape of the YAML spec, so `yamldecode(file("role.yaml"))` works.

- **Plans are dry runs.** Limen checks the grant, validation, profile bounds, and tests, and the plan shows who gains access. A refusal fails the plan.
- **Nothing is overwritten.** Writes carry the etag. A document that Git, the console, or another state owns is never written; the error names the owner.
- **Widening waits for a person.** A bot's change that adds standing access is [held for approval](management-api.md#changes-held-for-approval). Apply names the change, or waits for it with `approval_timeout`.

Provider 0.x needs Terraform 1.5 or OpenTofu 1.6, and a control plane that serves `limen.manage.v1`. Every attribute is in the provider's repository.

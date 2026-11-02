This guide is for **teams that manage infrastructure with Terraform or OpenTofu** and want Limen to follow it. The provider is [`limen-dev/terraform-provider-limen`](https://github.com/limen-dev/terraform-provider-limen); it is a client of the [management API](management-api.md) ([ADR-0042](../adr/0042-management-api.md)). The provider is **not released yet**, and it has only run against a stand-in for the control plane, **not** against a real one.

# Terraform and OpenTofu: register what you create

A team's module creates a database and registers it in Limen **in the same apply, in its own state**, while the security team keeps roles and mappings in theirs. The pipeline logs in as a [bot](bots.md) with its CI token: no admin rights, and no secret stored anywhere.

```hcl
resource "aws_db_instance" "orders" {
  identifier = "payments-orders"
  engine     = "postgres"
  # ...
}

resource "limen_resource" "orders_db" {
  name    = "payments-orders-db"
  profile = "payments-postgres" # written by a person: credentials, worker, IAM, and audit are fixed there
  spec = {
    postgres = { endpoint = "${aws_db_instance.orders.address}:5432" }
  }
  labels = { env = "staging" }
}
```

`terraform plan` asks Limen to check the change and shows who would gain access next to the diff:

```text
Warning: Access changes: resource/payments-orders-db

+ group:payments-eng gains standing access to payments-orders-db as db role app_rw (via role payments-read)
```

## 1. A person grants the pipeline what it may write

In the policy repository, a `policy_writer` names the bot, the namespace, the names it may use, the kinds, and the resource profiles it may complete. Only people write it, so no pipeline can widen its own grant. The bot document it names is written by a person too.

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

Delegated writes are described in the [policy reference](../policy.md#delegated-writes-resource_profile-and-policy_writer).

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

From a laptop, `limen login` is enough: without a `bot` block, the provider reuses the CLI's login, address, and CA. The Terraform Registry and OpenTofu Registry listings come with the first release.

## 3. Run it from CI

The apply job needs `permissions: id-token: write` on GitHub Actions. A pull request run never matches a bot ([ADR-0019](../adr/0019-machine-identities.md)), so plan pull requests offline with `LIMEN_OFFLINE=true` and plan online on the protected branch.

## What it manages

| Resource | What it is |
|---|---|
| `limen_resource` | Something people connect to: a database, SSH host, cluster, or web app. Bots complete a person's resource profile. |
| `limen_role` | Allow and deny rules over resources. |
| `limen_role_mapping` | Which IdP groups get which roles. |
| `limen_policy_test` | Cases stating who must or must not reach what. |

Bots, resource profiles, policy writers, and discovery are **data sources only**. A `spec` has exactly the shape of the document's YAML spec, so `spec = yamldecode(file("role.yaml"))` works.

## How it behaves

- **Plans are dry runs.** Limen checks every change during plan (grant, validation, profile bounds, tests). A refusal fails the plan, not the apply.
- **Nothing is overwritten.** A write carries the document's etag, so a change made between plan and apply is refused. A document that Git, the console, or another state owns is never written; the error names its owner.
- **Approval when access widens.** A bot's change that widens standing access waits for a person ([changes held for approval](management-api.md#changes-held-for-approval)). The plan warns, and apply names the change or waits for it with `approval_timeout`.
- **Safe retries.** Every write has a request id, so a retry never applies twice.

## Authentication

| Method | When |
|---|---|
| Bot, GitHub Actions | `bot = { method = "github_actions" }` |
| Bot, GitLab CI | `bot = { method = "gitlab" }` |
| Bot, any OIDC issuer | `bot = { method = "oidc", token_file = "..." }` |
| Client certificate | `client_certificate = { cert_pem, key_pem }` |
| The Limen CLI's login | Nothing to configure: run `limen login` first |

Bot certificates last at most an hour, and the provider logs in again before one expires when the platform can mint another token.

## Compatibility

Provider 0.x needs a control plane that serves `limen.manage.v1`, and Terraform 1.5 or later, or OpenTofu 1.6 or later.

The provider's own documentation has every attribute: [`limen-dev/terraform-provider-limen`](https://github.com/limen-dev/terraform-provider-limen).

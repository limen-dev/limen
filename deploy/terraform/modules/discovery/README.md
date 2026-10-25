# discovery

The describe-only IAM role Limen workers assume to discover EC2 instances,
RDS and Aurora databases, Redshift clusters, ElastiCache replication groups,
and EKS clusters ([ADR-0027](../../../../docs/adr/0027-resource-discovery.md)).

```hcl
module "limen_discovery" {
  source           = "./modules/discovery"
  worker_role_arns = [aws_iam_role.limen_worker.arn]
  sources          = ["ec2", "rds"]          # least privilege: only what you discover
}
```

Then, in the discovery document:

```yaml
accounts: [{ role_arn: <module.limen_discovery.role_arn> }]
```

The role can only read. It has no `iam:PassRole`, no data-plane access, and
no write action. Each source adds only its own `Describe*` and `List*` calls
(and `ec2:GetConsoleOutput`, where cloud-init prints the instance's SSH host
keys). Create one per account you discover in.

Tested with `terraform validate` only; **not applied against a real account**.

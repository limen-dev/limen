# Terraform modules

| Module | What it creates |
|---|---|
| `audit` | S3 audit store, KMS, Glue and Athena |
| `ocsf` | The OCSF export bucket and KMS key for SIEMs, with write and read policies (ADR-0049) |
| `datadog` | Datadog sink monitors |
| `foundation` | Everything Limen depends on: PostgreSQL (RDS), four KMS signing keys, the audit store, join tokens, secrets, control plane IAM and optional EKS IRSA role. Wraps `terraform-aws-modules` `rds`, `kms`, `secrets-manager`, `iam` |
| `discovery` | The describe-only IAM role workers assume for resource discovery (ADR-0027): trust limited to the worker roles, optional external id, read actions per enabled source. Wraps `terraform-aws-modules` `iam-role` |
| `ecs` | Limen services on Fargate, built on `terraform-aws-modules/ecs` (cluster and service submodules) |
| `ec2` | Limen Auto Scaling groups of Amazon Linux 2023 instances running the container under systemd, built on `terraform-aws-modules/autoscaling` and `security-group` |

Layout of `ecs` and `ec2`: `versions.tf`, `variables.tf`, `locals.tf`, `main.tf`, `outputs.tf` (and `data.tf`, `user-data.sh.tftpl` in `ec2`). Provider and module versions are pinned.

See [docs/guides/deploy.md](../../../docs/guides/deploy.md) for the full deployment (ECS/EC2 and Kubernetes). `examples/complete` applies `foundation`, a VPC, load balancers, `ecs` and `ec2`; `examples/kubernetes` applies `foundation` only, for the Helm chart.

## Running more than one of each

`ecs` takes a `services` map and `ec2` a `groups` map. **Every entry is one more service**, of any component (`control-plane`, `proxy`, `worker`), with its own VPC, subnets, size, image and settings:

```hcl
module "ecs" {
  source = "../../modules/ecs"
  name   = "limen-prod"
  services = {
    proxy-public  = { component = "proxy", image = "...", vpc_id = "vpc-core", subnet_ids = [...], desired_count = 3, target_group_arn = "..." }
    proxy-partner = { component = "proxy", image = "...", vpc_id = "vpc-partner", subnet_ids = [...] }
    worker-prod   = { component = "worker", image = "...", vpc_id = "vpc-prod", subnet_ids = [...], min_count = 3, max_count = 20 }
  }
}
```

Scale an existing service by changing `desired_count` (ECS; with `min_count`/`max_count` a CPU target-tracking policy is added) or `desired_capacity` (EC2; Terraform then ignores the live count so your scaling policies win). Peers reach each other through security group rules; both modules output each service's `security_group_id` and role name. `examples/complete` builds all three components from maps, with workers in separate VPCs; `terraform.tfvars.example` shows the shape.

Services get the internal CA through `internal_ca = { secret_arn }` (a publisher sidecar on control planes, a writer on proxies and workers; see the guide). Secrets are ARNs (`secrets = { LIMEN_JOIN_TOKEN = arn }`), read at start with the task or instance role, so values stay out of state and user data. Attach KMS and S3 policies with `task_role_policy_arns` (ECS) or `role_policy_arns` (EC2).

Each module and example has its own README with the inputs, outputs and community modules it uses, generated from the code by `mise exec -- deploy/terraform/docs.sh` (terraform-docs; CI fails if one is out of date). The chart's values table is generated the same way by helm-docs.

## Limits

- Fargate stops a task at most 120 s after SIGTERM (`stop_timeout`; the module rejects a larger value). Both modules set the drain timeout inside `stop_timeout` (workers 30 s under it, control planes and proxies at most 20 s, [scale-out runbook](../../../docs/runbooks/scale-out.md)); a `LIMEN_DRAIN_*` in `environment` wins. The plan tests (`terraform test`, mocked provider) check both. Use `ec2` for workers that need long drains.
- Neither a Fargate task nor an Auto Scaling instance keeps its disk, so control planes get `spool_mode = "ephemeral"` (`LIMEN_SPOOL_MODE`): on shutdown a replica hands what it has not shipped to a peer. If a task dies before that, the events not yet in S3 (up to `LIMEN_AUDIT_S3_FLUSH`, 60 s by default) are lost, and the audit verifier shows them as gaps. Shorten `LIMEN_AUDIT_S3_FLUSH` in `environment` if that window is too long, or run control planes on Kubernetes with a volume (`durable`). The replica id (`LIMEN_ID`) defaults to the hostname, which is unique per task and instance.
- `ec2` follows the latest Amazon Linux 2023 AMI by default, so a new image replaces the launch template and rolls every instance on the next apply. Set `ami_id` to pin it. Both modules refuse a plan with a proxy or worker and no `internal_ca`.
- The admin port (`/readyz`, `/metrics`) is open to no one until you add `admin_ingress_cidrs` to a service or group.
- Proxies on `ec2` need a TCP load balancer you create; pass its target groups in `target_group_arns`.

**Unverified:** the modules and the example pass `terraform validate` only. They were never planned or applied against AWS.

# Terraform modules

| Module | What it creates |
|---|---|
| `audit` | S3 audit store, KMS, Glue and Athena |
| `datadog` | Datadog sink monitors |
| `foundation` | Everything Limen depends on: PostgreSQL (RDS), four KMS signing keys, the audit store, join tokens, secrets, control plane IAM and optional EKS IRSA role. Wraps `terraform-aws-modules` `rds`, `kms`, `secrets-manager`, `iam` |
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

## Limits

- Fargate stops a task at most 120 s after SIGTERM (`stop_timeout`), shorter than the worker's default 300 s drain; the module rejects a larger value. Use `ec2` for workers, or set `LIMEN_DRAIN_TIMEOUT_SECS` below 120.
- Fargate tasks have no persistent volume, so an unshipped audit spool is lost if a control plane task dies. Control plane replicas also need stable ids (`LIMEN_ID`) that neither ECS nor an Auto Scaling group gives; the Kubernetes StatefulSet does. Test control planes on these runtimes before relying on them.
- Proxies on `ec2` need a TCP load balancer you create; pass its target groups in `target_group_arns`.

**Unverified:** the modules and the example pass `terraform validate` only. They were never planned or applied against AWS.

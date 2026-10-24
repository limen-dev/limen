# Terraform modules

| Module | What it creates |
|---|---|
| `audit` | S3 audit store, KMS, Glue and Athena |
| `datadog` | Datadog sink monitors |
| `ecs` | One Limen component (`control-plane`, `proxy` or `worker`) as a Fargate service: log group, security group, task and execution roles |
| `ec2` | One component as an Auto Scaling group of Amazon Linux 2023 instances running the container under systemd |

`ecs` and `ec2` deploy **one component per call**, so each can sit in its own VPC and subnets with its own name: call the module once per component. Peers reach each other through security group rules; both modules output `security_group_id` for that. `examples/complete` puts the control plane and proxy on ECS in one VPC and the workers on EC2 in another.

Both modules take secrets as Secrets Manager ARNs (`secrets = { LIMEN_JOIN_TOKEN = arn }`), read at start with the task or instance role, so values stay out of Terraform state and user data. Roles accept extra policies (`task_role_policy_arns`) for KMS and S3.

Limits to know about:

- Fargate stops a task at most 120 s after SIGTERM (`stop_timeout`), shorter than the worker's default 300 s drain. Use `ec2` for workers, or lower `LIMEN_DRAIN_TIMEOUT_SECS` below 120.
- Fargate has no persistent volume here. A control plane there runs with the default spool, and an unshipped audit spool is lost if the task dies. Use `ec2` (root volume) when that matters.
- Proxies on `ec2` need a TCP load balancer you create; pass its target group as `target_group_arn`.

**Unverified:** both modules and the example pass `terraform validate` and `tflint` only. They were never applied to AWS.

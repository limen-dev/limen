# Terraform module: ecs

Control planes, proxies and workers as ECS services on Fargate. `services` is a map: each entry is one service, so any number of each component runs from one call. Control planes publish the internal CA to a secret and proxies and workers wait for it (`internal_ca`). Drain timeouts are derived from `stop_timeout`, and control planes run with an `ephemeral` audit spool.

```hcl
module "ecs" {
  source = "github.com/limen-dev/limen//deploy/terraform/modules/ecs?ref=vX.Y.Z"

  name        = "limen"
  internal_ca = { secret_arn = module.foundation.internal_ca_secret_arn }
  services = {
    core = { component = "control-plane", image = "ghcr.io/limen-dev/limen-control-plane:vX.Y.Z", vpc_id = "vpc-...", subnet_ids = ["subnet-..."] }
  }
}
```

Unverified: validated with `terraform validate`, never applied to AWS (#123).

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| terraform | >= 1.6 |
| aws | >= 6.0, < 7.0 |

## Modules

| Name | Source | Version |
| ---- | ------ | ------- |
| cluster | terraform-aws-modules/ecs/aws//modules/cluster | ~> 7.6 |
| service | terraform-aws-modules/ecs/aws//modules/service | ~> 7.6 |

## Resources

| Name | Type |
| ---- | ---- |
| [terraform_data.preflight](https://registry.terraform.io/providers/hashicorp/terraform/latest/docs/resources/data) | resource |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| name | Prefix for the cluster and every service, e.g. "limen-prod". | `string` | n/a | yes |
| services | Limen services to run, keyed by a short name that becomes part of the<br/>resource names: { proxy-a = { component = "proxy", ... }, worker-a = {...} }.<br/>Add as many entries as you need of any component; each has its own VPC,<br/>subnets, size and settings, so proxies and workers can live in different VPCs.<br/>"environment" holds plain LIMEN\_* settings; "secrets" maps a variable name to<br/>a Secrets Manager or SSM parameter ARN, read at task start. | <pre>map(object({<br/>    component                  = string<br/>    image                      = string<br/>    vpc_id                     = string<br/>    subnet_ids                 = list(string)<br/>    assign_public_ip           = optional(bool, false)<br/>    desired_count              = optional(number, 3)<br/>    min_count                  = optional(number)<br/>    max_count                  = optional(number)<br/>    cpu_target_percent         = optional(number, 60)<br/>    cpu                        = optional(number, 512)<br/>    memory                     = optional(number, 1024)<br/>    stop_timeout               = optional(number, 60)<br/>    spool_mode                 = optional(string, "ephemeral")<br/>    environment                = optional(map(string), {})<br/>    secrets                    = optional(map(string), {})<br/>    ingress_cidrs              = optional(list(string), [])<br/>    ingress_security_group_ids = optional(list(string), [])<br/>    admin_ingress_cidrs        = optional(list(string), [])<br/>    target_group_arn           = optional(string)<br/>    task_role_policy_arns      = optional(map(string), {})<br/>    # A proxy task can wait for an upgraded control plane before it serves (ADR-0045), and<br/>    # its load balancer health check fails meanwhile. Ignore that for this long after start<br/>    # (proxies only; a control plane that does not become healthy should be replaced at once).<br/>    health_check_grace_seconds = optional(number, 900)<br/>    # Make `terraform apply` wait until the service has finished its rollout, so what depends<br/>    # on it starts afterwards.<br/>    wait_for_steady_state = optional(bool, true)<br/>  }))</pre> | n/a | yes |
| helper\_images | Images of the two helper containers: the CA publisher (needs a shell and the AWS CLI) and the CA writer (needs a shell). | <pre>object({<br/>    aws_cli = optional(string, "public.ecr.aws/aws-cli/aws-cli:2.38.0")<br/>    shell   = optional(string, "public.ecr.aws/docker/library/busybox:1.37.0")<br/>  })</pre> | `{}` | no |
| internal\_ca | Pass { secret\_arn = ... }: the Secrets Manager secret for the Limen internal CA certificate (the<br/>foundation module creates it). Control plane tasks run a publisher sidecar<br/>that writes the certificate they export into it; proxy and worker tasks<br/>wait for it and write it to the file LIMEN\_CA\_FILE points at. Needed when<br/>any service is a proxy or worker. | <pre>object({<br/>    secret_arn = string<br/>  })</pre> | `null` | no |
| log\_retention\_days | Retention of each service's CloudWatch log group. | `number` | `90` | no |
| tags | Tags added to every resource. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| cluster\_arn | ARN of the ECS cluster. |
| services | Per service key: name, security group (allow it on a peer's ingress), the task role (attach KMS or S3 policies to it) and the plain environment the container gets. |
<!-- END_TF_DOCS -->

# Limen ec2

Control planes, proxies or workers on Auto Scaling groups of EC2 instances running the container under systemd. `groups` is a map: each entry is one group, in its own VPC if you like. Use it where Fargate does not fit, typically workers that need a long drain or a network Fargate cannot join.

```hcl
module "ec2" {
  source = "github.com/limen-dev/limen//deploy/terraform/modules/ec2?ref=vX.Y.Z"

  name        = "limen"
  internal_ca = { secret_arn = module.foundation.internal_ca_secret_arn }
  groups = {
    prod-db = { component = "worker", image = "ghcr.io/limen-dev/limen-worker:vX.Y.Z", vpc_id = "vpc-...", subnet_ids = ["subnet-..."] }
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
| asg | terraform-aws-modules/autoscaling/aws | ~> 9.3 |
| security\_group | terraform-aws-modules/security-group/aws | ~> 6.0 |

## Resources

| Name | Type |
| ---- | ---- |
| [aws_cloudwatch_log_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_iam_role_policy.read_secrets](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.write_logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [terraform_data.preflight](https://registry.terraform.io/providers/hashicorp/terraform/latest/docs/resources/data) | resource |
| [aws_iam_policy_document.read_secrets](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.write_logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |
| [aws_ssm_parameter.ami](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ssm_parameter) | data source |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| groups | Auto Scaling groups of Limen instances, keyed by a short name that becomes<br/>part of the resource names: { proxy-a = { component = "proxy", ... }, worker-a = {...} }.<br/>Add as many entries as you need of any component; each has its own VPC,<br/>subnets and size, so proxies and workers can live in different VPCs.<br/>"environment" holds plain LIMEN\_* settings; "secrets" maps a variable name to<br/>a Secrets Manager secret ARN, read at boot with the instance role. | <pre>map(object({<br/>    component                  = string<br/>    image                      = string<br/>    vpc_id                     = string<br/>    subnet_ids                 = list(string)<br/>    associate_public_ip        = optional(bool, false)<br/>    instance_type              = optional(string, "t4g.small")<br/>    min_size                   = optional(number, 3)<br/>    max_size                   = optional(number, 6)<br/>    desired_capacity           = optional(number, 3)<br/>    volume_size_gb             = optional(number, 30)<br/>    stop_timeout               = optional(number, 330)<br/>    admin_ingress_cidrs        = optional(list(string), [])<br/>    spool_mode                 = optional(string, "ephemeral")<br/>    environment                = optional(map(string), {})<br/>    secrets                    = optional(map(string), {})<br/>    ingress_cidrs              = optional(list(string), [])<br/>    ingress_security_group_ids = optional(list(string), [])<br/>    target_group_arns          = optional(list(string), [])<br/>    role_policy_arns           = optional(map(string), {})<br/>  }))</pre> | n/a | yes |
| name | Prefix for every group and its resources, e.g. "limen-prod". | `string` | n/a | yes |
| ami\_id | Pin the AMI (an arm64 Amazon Linux 2023 image for the default instance types). When set, ami\_ssm\_parameter is not read and a new AWS image changes nothing. | `string` | `null` | no |
| ami\_ssm\_parameter | SSM parameter holding the AMI id, read at every plan: the default follows the latest Amazon Linux 2023, so a new AMI replaces the launch template and rolls every instance on the next apply. Set ami\_id to pin. Must match the instance types' architecture (arm64 default). | `string` | `"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"` | no |
| internal\_ca | Pass { secret\_arn = ... }: the Secrets Manager secret for the Limen internal CA certificate (the<br/>foundation module creates it). Control plane instances publish the<br/>certificate they export into it; proxy and worker instances wait for it<br/>and write it to the file LIMEN\_CA\_FILE points at. | <pre>object({<br/>    secret_arn = string<br/>  })</pre> | `null` | no |
| log\_retention\_days | Retention of each group's CloudWatch log group. | `number` | `90` | no |
| tags | Tags added to every resource. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| groups | Per group key: Auto Scaling group name, security group (allow it on a peer's ingress) the instance role (attach KMS or S3 policies to it) and the plain environment the container gets. |
<!-- END_TF_DOCS -->

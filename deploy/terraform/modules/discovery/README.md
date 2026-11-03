# Limen discovery

The describe-only IAM role workers assume to discover EC2 instances, databases, caches and clusters ([discovery guide](../../../../docs/guides/discovery.md)). Only the listed worker roles can assume it, optionally with an external id. No `iam:PassRole`, no data access, no writes.

```hcl
module "discovery" {
  source = "github.com/limen-dev/limen//deploy/terraform/modules/discovery?ref=vX.Y.Z"

  name             = "limen-discovery"
  worker_role_arns = [module.ec2.groups["prod-db"].role_arn]
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
| role | terraform-aws-modules/iam/aws//modules/iam-role | ~> 6.8 |

## Resources

| Name | Type |
| ---- | ---- |
| [aws_iam_policy.assume](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy_document.assume](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| worker\_role\_arns | The roles the Limen workers that run discovery use (an instance role, an<br/>ECS task role, an IRSA role). Only these may assume the discovery role. | `list(string)` | n/a | yes |
| external\_id | If set, the worker must present this external id when it assumes the role. | `string` | `null` | no |
| max\_session\_seconds | Longest session of the assumed role. Discovery asks for 900 seconds. | `number` | `3600` | no |
| name | Name of the role, e.g. "limen-discovery". Use its ARN as role\_arn in the discovery document. | `string` | `"limen-discovery"` | no |
| sources | Which sources the role may read. Each is describe-only. | `set(string)` | <pre>[<br/>  "ec2",<br/>  "rds",<br/>  "redshift",<br/>  "elasticache",<br/>  "eks"<br/>]</pre> | no |
| tags | Tags added to every resource. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| assume\_policy\_arn | Policy that lets a worker role assume the discovery role. Attach it to the worker roles (role\_policy\_arns of the ec2 module). |
| role\_arn | Put this in the discovery document's role\_arn. |
<!-- END_TF_DOCS -->

# Terraform example: complete

The whole of Limen on AWS: network, PostgreSQL, KMS keys, audit store, secrets, load balancers, and control planes, proxies and workers from maps. Copy `terraform.tfvars.example`, then `terraform apply`. Walk-through: [Deploying Limen on AWS](../../../../docs/guides/deploy.md).

Unverified: validated with `terraform validate`, never applied to AWS (#123).

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| terraform | >= 1.6 |
| aws | >= 6.0, < 7.0 |
| random | >= 3.6, < 4.0 |

## Modules

| Name | Source | Version |
| ---- | ------ | ------- |
| control\_plane\_lb | terraform-aws-modules/alb/aws | ~> 10.5 |
| discovery | ../../modules/discovery | n/a |
| ec2 | ../../modules/ec2 | n/a |
| ecs | ../../modules/ecs | n/a |
| foundation | ../../modules/foundation | n/a |
| proxy\_lb | terraform-aws-modules/alb/aws | ~> 10.5 |
| vpc | terraform-aws-modules/vpc/aws | ~> 6.7 |

## Resources

| Name | Type |
| ---- | ---- |
| [aws_vpc_security_group_ingress_rule.database_from_control_plane](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| image\_registry | Registry and path of the Limen images, e.g. "ghcr.io/your-org". | `string` | n/a | yes |
| image\_tag | Limen release to run, as the image tag with its leading v, for example v0.1.0 (the images are limen-control-plane, limen-proxy and limen-worker). | `string` | n/a | yes |
| oidc | Your identity provider's issuer URL and the client id registered for Limen. | <pre>object({<br/>    issuer    = string<br/>    client_id = string<br/>  })</pre> | n/a | yes |
| proxies | Proxy services on ECS in the core VPC, each behind its own public Network Load Balancer. dns\_name is the public name you will point at the load balancer. | <pre>map(object({<br/>    desired_count = optional(number, 3)<br/>    dns_name      = string<br/>    client_cidrs  = optional(list(string), ["0.0.0.0/0"])<br/>  }))</pre> | n/a | yes |
| workers | Worker groups on EC2, one per network they reach. With discovery = true the group runs resource discovery (modules/discovery creates the describe-only role it assumes). Each lives in an existing VPC (the one of the hosts and databases it connects to) and dials the proxy named by "proxy" (a key of var.proxies). | <pre>map(object({<br/>    vpc_id           = string<br/>    subnet_ids       = list(string)<br/>    proxy            = string<br/>    desired_capacity = optional(number, 3)<br/>    max_sessions     = optional(number, 200)<br/>    discovery        = optional(bool, false)<br/>  }))</pre> | n/a | yes |
| control\_planes | Control plane services on ECS, all in the core VPC. Raise desired\_count to scale, or add entries. | <pre>map(object({<br/>    desired_count = optional(number, 3)<br/>  }))</pre> | <pre>{<br/>  "core": {}<br/>}</pre> | no |
| core\_vpc | The VPC created for the database, control planes and proxies. | <pre>object({<br/>    cidr               = optional(string, "10.40.0.0/16")<br/>    azs                = optional(list(string), ["eu-west-1a", "eu-west-1b", "eu-west-1c"])<br/>    private_subnets    = optional(list(string), ["10.40.0.0/20", "10.40.16.0/20", "10.40.32.0/20"])<br/>    public_subnets     = optional(list(string), ["10.40.100.0/24", "10.40.101.0/24", "10.40.102.0/24"])<br/>    single_nat_gateway = optional(bool, true)<br/>  })</pre> | `{}` | no |
| database | PostgreSQL settings (see modules/foundation). | `any` | `{}` | no |
| discovery\_sources | Sources the discovery role may read. Used when any worker group sets discovery = true. | `set(string)` | <pre>[<br/>  "ec2",<br/>  "rds",<br/>  "redshift",<br/>  "elasticache",<br/>  "eks"<br/>]</pre> | no |
| name | Prefix for every resource. | `string` | `"limen-prod"` | no |
| region | AWS region for everything in this example. | `string` | `"eu-west-1"` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| audit\_bucket | Audit bucket name (LIMEN\_AUDIT\_S3\_BUCKET). |
| database\_endpoint | PostgreSQL address; the control planes reach it through their secret, not this output. |
| discovery\_role\_arn | role\_arn for the discovery document (docs/guides/discovery.md). |
| ecs\_services | Per ECS service: name, security group and task role, to attach more rules or policies. |
| proxy\_dns\_names | Point each proxy's public name (CNAME or alias) at its load balancer. |
| worker\_groups | Per worker group: Auto Scaling group, security group and role. |
<!-- END_TF_DOCS -->

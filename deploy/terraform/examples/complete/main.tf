# A complete Limen deployment in the shape most teams start with: control
# plane and proxy on ECS in a "core" VPC, workers on EC2 in a separate
# "workloads" VPC next to the databases and hosts they reach. Workers only dial
# out to the proxy, so the two VPCs need a route to each other (peering or
# Transit Gateway) or the proxy's load balancer must be reachable from the
# workers' VPC.
#
#   terraform init && terraform apply
#
# Unverified: validated with `terraform validate` only; never applied to AWS.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }
}

variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "name" {
  type    = string
  default = "limen-prod"
}

variable "image_registry" {
  description = "Registry and path of the Limen images, e.g. \"ghcr.io/your-org\"."
  type        = string
}

variable "image_tag" {
  type = string
}

variable "core_vpc_id" {
  type = string
}

variable "core_private_subnet_ids" {
  type = list(string)
}

variable "workloads_vpc_id" {
  type = string
}

variable "workloads_private_subnet_ids" {
  type = list(string)
}

variable "proxy_target_group_arn" {
  description = "Target group (TCP, port 3443) of your Network Load Balancer."
  type        = string
}

variable "proxy_dns_name" {
  description = "Public DNS name of the load balancer, e.g. \"limen.example.com\"."
  type        = string
}

variable "oidc_issuer" {
  type = string
}

variable "oidc_client_id" {
  type = string
}

variable "ca_key_arns" {
  description = "KMS key ARNs for LIMEN_KMS_{INTERNAL_CA,USER_CA,SSH_USER_CA,SSH_HOST_CA}_KEY, in that key order."
  type = object({
    internal_ca = string
    user_ca     = string
    ssh_user_ca = string
    ssh_host_ca = string
  })
}

variable "database_url_secret_arn" {
  description = "Secrets Manager secret holding the PostgreSQL URL."
  type        = string
}

variable "proxy_join_token_secret_arn" {
  type = string
}

variable "worker_join_token_secret_arn" {
  type = string
}

variable "client_cidrs" {
  description = "Networks allowed to reach the proxy."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "limen", Name = var.name }
  }
}

module "audit" {
  source = "../../modules/audit"
  name   = var.name
}

data "aws_iam_policy_document" "control_plane" {
  statement {
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = values(var.ca_key_arns)
  }
  statement {
    actions   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::${module.audit.bucket}", "arn:aws:s3:::${module.audit.bucket}/*"]
  }
}

resource "aws_iam_policy" "control_plane" {
  name_prefix = "${var.name}-control-plane-"
  policy      = data.aws_iam_policy_document.control_plane.json
}

module "control_plane" {
  source    = "../../modules/ecs"
  name      = "${var.name}-control-plane"
  component = "control-plane"
  image     = "${var.image_registry}/limen-control-plane:${var.image_tag}"

  vpc_id     = var.core_vpc_id
  subnet_ids = var.core_private_subnet_ids

  # Spool mode "durable" needs a volume; Fargate tasks have ephemeral storage
  # only, so run the control plane on EC2 (modules/ec2) when audit loss on a
  # crash is not acceptable. See docs/guides/scale-out.md.
  environment = {
    LIMEN_CA_BACKEND          = "kms"
    LIMEN_KMS_INTERNAL_CA_KEY = var.ca_key_arns.internal_ca
    LIMEN_KMS_USER_CA_KEY     = var.ca_key_arns.user_ca
    LIMEN_KMS_SSH_USER_CA_KEY = var.ca_key_arns.ssh_user_ca
    LIMEN_KMS_SSH_HOST_CA_KEY = var.ca_key_arns.ssh_host_ca
    LIMEN_OIDC_ISSUER         = var.oidc_issuer
    LIMEN_OIDC_CLIENT_ID      = var.oidc_client_id
    LIMEN_AUDIT_S3_BUCKET     = module.audit.bucket
    LIMEN_DRAIN_TIMEOUT       = "20s"
  }
  secrets               = { LIMEN_DATABASE_URL = var.database_url_secret_arn }
  task_role_policy_arns = [aws_iam_policy.control_plane.arn]
  ingress_cidrs         = [] # proxies reach it by security group below
}

module "proxy" {
  source    = "../../modules/ecs"
  name      = "${var.name}-proxy"
  component = "proxy"
  image     = "${var.image_registry}/limen-proxy:${var.image_tag}"

  vpc_id     = var.core_vpc_id
  subnet_ids = var.core_private_subnet_ids

  environment = {
    LIMEN_CONTROL_PLANE_ADDR = "control-plane.${var.name}.internal:3080"
    LIMEN_CONTROL_PLANE_NAME = "control-plane"
    LIMEN_DNS_NAMES          = var.proxy_dns_name
    LIMEN_DRAIN_TIMEOUT_SECS = "20"
  }
  secrets          = { LIMEN_JOIN_TOKEN = var.proxy_join_token_secret_arn }
  target_group_arn = var.proxy_target_group_arn
  ingress_cidrs    = var.client_cidrs
}

# Let the proxies reach the control plane's gRPC port.
resource "aws_vpc_security_group_ingress_rule" "control_plane_from_proxy" {
  security_group_id            = module.control_plane.security_group_id
  referenced_security_group_id = module.proxy.security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 3080
  to_port                      = 3080
}

module "worker" {
  source    = "../../modules/ec2"
  name      = "${var.name}-worker"
  component = "worker"
  image     = "${var.image_registry}/limen-worker:${var.image_tag}"

  vpc_id     = var.workloads_vpc_id
  subnet_ids = var.workloads_private_subnet_ids

  environment = {
    LIMEN_PROXY_ADDR         = "${var.proxy_dns_name}:443"
    LIMEN_PROXY_NAME         = var.proxy_dns_name
    LIMEN_MAX_SESSIONS       = "200"
    LIMEN_DRAIN_TIMEOUT_SECS = "300"
  }
  secrets = { LIMEN_JOIN_TOKEN = var.worker_join_token_secret_arn }
}

output "audit_bucket" {
  value = module.audit.bucket
}

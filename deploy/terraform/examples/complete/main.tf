# A complete Limen deployment: control planes and proxies on ECS, workers on
# EC2 in the VPCs of the systems they reach. Every map entry adds a service, so
# the same file scales from one of each to many.
#
#   terraform init && terraform apply -var-file=my.tfvars
#
# Unverified: validated with `terraform validate` only; never applied to AWS.

module "audit" {
  source = "../../modules/audit"
  name   = var.name
}

data "aws_iam_policy_document" "control_plane" {
  statement {
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = values(var.ca_key_arns)
  }
}

resource "aws_iam_policy" "control_plane_kms" {
  name_prefix = "${var.name}-control-plane-kms-"
  policy      = data.aws_iam_policy_document.control_plane.json
}

resource "aws_iam_policy" "audit_writer" {
  name_prefix = "${var.name}-audit-writer-"
  policy      = module.audit.writer_policy_json
}

locals {
  image = { for c in ["control-plane", "proxy", "worker"] : c => "${var.image_registry}/limen-${c}:${var.image_tag}" }

  control_planes = {
    for k, v in var.control_planes : "control-plane-${k}" => {
      component     = "control-plane"
      image         = local.image["control-plane"]
      vpc_id        = v.vpc_id
      subnet_ids    = v.subnet_ids
      desired_count = v.desired_count
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
      secrets = { LIMEN_DATABASE_URL = var.database_url_secret_arn }
      task_role_policy_arns = {
        kms   = aws_iam_policy.control_plane_kms.arn
        audit = aws_iam_policy.audit_writer.arn
      }
    }
  }

  proxies = {
    for k, v in var.proxies : "proxy-${k}" => {
      component        = "proxy"
      image            = local.image["proxy"]
      vpc_id           = v.vpc_id
      subnet_ids       = v.subnet_ids
      desired_count    = v.desired_count
      target_group_arn = v.target_group_arn
      ingress_cidrs    = v.client_cidrs
      environment = {
        LIMEN_CONTROL_PLANE_ADDR = var.control_plane_addr
        LIMEN_CONTROL_PLANE_NAME = "control-plane"
        LIMEN_DNS_NAMES          = v.dns_name
        LIMEN_DRAIN_TIMEOUT_SECS = "20"
      }
      secrets = { LIMEN_JOIN_TOKEN = v.join_token_secret_arn }
    }
  }

  workers = {
    for k, v in var.workers : "worker-${k}" => {
      component        = "worker"
      image            = local.image["worker"]
      vpc_id           = v.vpc_id
      subnet_ids       = v.subnet_ids
      desired_capacity = v.desired_capacity
      min_size         = min(v.desired_capacity, 1)
      max_size         = max(v.desired_capacity * 2, 2)
      environment = {
        LIMEN_PROXY_ADDR         = "${var.proxies[v.proxy].dns_name}:443"
        LIMEN_PROXY_NAME         = var.proxies[v.proxy].dns_name
        LIMEN_MAX_SESSIONS       = tostring(v.max_sessions)
        LIMEN_DRAIN_TIMEOUT_SECS = "300"
      }
      secrets = { LIMEN_JOIN_TOKEN = v.join_token_secret_arn }
    }
  }
}

module "ecs" {
  source   = "../../modules/ecs"
  name     = var.name
  services = merge(local.control_planes, local.proxies)
}

module "ec2" {
  source = "../../modules/ec2"
  name   = var.name
  groups = local.workers
}

# Let each proxy reach every control plane's gRPC port.
resource "aws_vpc_security_group_ingress_rule" "control_plane_from_proxy" {
  for_each = {
    for pair in setproduct(keys(local.control_planes), keys(local.proxies)) :
    "${pair[0]}/${pair[1]}" => pair
  }

  security_group_id            = module.ecs.services[each.value[0]].security_group_id
  referenced_security_group_id = module.ecs.services[each.value[1]].security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 3080
  to_port                      = 3080
}

# The whole Limen solution on AWS: network, PostgreSQL, KMS signing keys, audit
# store, secrets, load balancers, and the control planes, proxies and workers.
# Every map entry in variables.tf adds a service, so the same file scales from
# one of each to many.
#
#   terraform init && terraform apply -var-file=my.tfvars
#
# Unverified: validated with `terraform validate` only; never applied to AWS.

# -------------------------------------------------------------------- network
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 6.7"

  name = var.name
  cidr = var.core_vpc.cidr
  azs  = var.core_vpc.azs

  private_subnets = var.core_vpc.private_subnets
  public_subnets  = var.core_vpc.public_subnets

  # Tasks pull images and call AWS APIs through the NAT gateway.
  enable_nat_gateway = true
  single_nat_gateway = var.core_vpc.single_nat_gateway
}

# ----------------------------------------------- database, keys, audit, secrets
module "foundation" {
  source = "../../modules/foundation"

  name                   = var.name
  vpc_id                 = module.vpc.vpc_id
  database_subnet_ids    = module.vpc.private_subnets
  database_allowed_cidrs = [] # per control plane rules below
  database               = var.database

  proxy_groups    = toset(keys(var.proxies))
  worker_groups   = toset(keys(var.workers))
  proxy_dns_names = [for p in var.proxies : p.dns_name]
  oidc            = var.oidc
  # The first proxy's name is where users reach the console.
  console_public_url = "https://${values(var.proxies)[0].dns_name}"
}

# ------------------------------------------------------------ load balancers
# Control planes sit behind an internal Network Load Balancer that proxies
# dial. Each proxy has its own public one; TLS is end to end, so both are TCP.
module "control_plane_lb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 10.5"

  name               = "${var.name}-cp"
  load_balancer_type = "network"
  internal           = true
  vpc_id             = module.vpc.vpc_id
  subnets            = module.vpc.private_subnets

  # No security group on the NLB: tasks' own groups admit the proxies.
  enable_deletion_protection = false
  create_security_group      = false

  listeners = {
    grpc = {
      port     = 3080
      protocol = "TCP"
      forward  = { target_group_key = "grpc" }
    }
  }
  target_groups = {
    grpc = {
      name_prefix       = "cp-"
      protocol          = "TCP"
      port              = 3080
      target_type       = "ip"
      create_attachment = false
      health_check = {
        protocol = "HTTP"
        port     = "3081"
        path     = "/readyz"
      }
    }
  }
}

module "proxy_lb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 10.5"

  for_each = var.proxies

  name               = "${var.name}-${each.key}"
  load_balancer_type = "network"
  internal           = false
  vpc_id             = module.vpc.vpc_id
  subnets            = module.vpc.public_subnets

  enable_deletion_protection = false
  create_security_group      = false

  listeners = {
    public = {
      port     = 443
      protocol = "TCP"
      forward  = { target_group_key = "proxy" }
    }
  }
  target_groups = {
    proxy = {
      name_prefix       = "px-"
      protocol          = "TCP"
      port              = 3443
      target_type       = "ip"
      create_attachment = false
      health_check = {
        protocol = "HTTP"
        port     = "3444"
        path     = "/readyz"
      }
    }
  }
}

# ------------------------------------------------------------------- services
locals {
  image = { for c in ["control-plane", "proxy", "worker"] : c => "${var.image_registry}/limen-${c}:${var.image_tag}" }

  control_plane_dns = module.control_plane_lb.dns_name

  control_planes = {
    for k, v in var.control_planes : "control-plane-${k}" => {
      component             = "control-plane"
      image                 = local.image["control-plane"]
      vpc_id                = module.vpc.vpc_id
      subnet_ids            = module.vpc.private_subnets
      desired_count         = v.desired_count
      target_group_arn      = module.control_plane_lb.target_groups["grpc"].arn
      environment           = merge(module.foundation.control_plane_environment, { LIMEN_DNS_NAMES = local.control_plane_dns })
      secrets               = module.foundation.control_plane_secrets
      task_role_policy_arns = module.foundation.control_plane_policy_arns
      ingress_cidrs         = [var.core_vpc.cidr]
    }
  }

  proxies = {
    for k, v in var.proxies : "proxy-${k}" => {
      component        = "proxy"
      image            = local.image["proxy"]
      vpc_id           = module.vpc.vpc_id
      subnet_ids       = module.vpc.private_subnets
      desired_count    = v.desired_count
      target_group_arn = module.proxy_lb[k].target_groups["proxy"].arn
      ingress_cidrs    = v.client_cidrs
      environment = {
        LIMEN_CONTROL_PLANE_ADDR = "${local.control_plane_dns}:3080"
        LIMEN_CONTROL_PLANE_NAME = local.control_plane_dns
        LIMEN_DNS_NAMES          = v.dns_name
        LIMEN_DRAIN_TIMEOUT_SECS = "20"
      }
      secrets = { LIMEN_JOIN_TOKEN = module.foundation.join_token_secret_arns["proxy-${k}"] }
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
      environment = merge(
        {
          LIMEN_PROXY_ADDR         = "${var.proxies[v.proxy].dns_name}:443"
          LIMEN_PROXY_NAME         = var.proxies[v.proxy].dns_name
          LIMEN_MAX_SESSIONS       = tostring(v.max_sessions)
          LIMEN_DRAIN_TIMEOUT_SECS = "300"
        },
        v.discovery ? { LIMEN_DISCOVERY = "true" } : {},
      )
      secrets = { LIMEN_JOIN_TOKEN = module.foundation.join_token_secret_arns["worker-${k}"] }
    }
  }
}

module "ecs" {
  source = "../../modules/ecs"

  name        = var.name
  services    = merge(local.control_planes, local.proxies)
  internal_ca = { secret_arn = module.foundation.internal_ca_secret_arn }
}

module "ec2" {
  source = "../../modules/ec2"

  name        = var.name
  groups      = local.workers
  internal_ca = { secret_arn = module.foundation.internal_ca_secret_arn }
}

# ------------------------------------------------- who may talk to whom
# Control plane tasks reach PostgreSQL.
resource "aws_vpc_security_group_ingress_rule" "database_from_control_plane" {
  for_each = local.control_planes

  security_group_id            = module.foundation.database_security_group_id
  referenced_security_group_id = module.ecs.services[each.key].security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

# ------------------------------------------------------------------ discovery
# Workers with discovery = true assume this describe-only role to find EC2
# instances, databases, caches and clusters (ADR-0027, docs/guides/discovery.md).
# Create one per account you discover in; this one covers the account Limen runs in.
module "discovery" {
  source = "../../modules/discovery"

  count = anytrue([for w in var.workers : w.discovery]) ? 1 : 0

  name             = "${var.name}-discovery"
  sources          = var.discovery_sources
  worker_role_arns = [for k, w in var.workers : module.ec2.groups["worker-${k}"].role_arn if w.discovery]
}

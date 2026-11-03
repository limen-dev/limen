output "proxy_dns_names" {
  description = "Point each proxy's public name (CNAME or alias) at its load balancer."
  value       = { for k, lb in module.proxy_lb : var.proxies[k].dns_name => lb.dns_name }
}

output "audit_bucket" {
  description = "Audit bucket name (LIMEN_AUDIT_S3_BUCKET)."
  value       = module.foundation.audit_bucket
}

output "database_endpoint" {
  description = "PostgreSQL address; the control planes reach it through their secret, not this output."
  value       = module.foundation.database_endpoint
}

output "ecs_services" {
  description = "Per ECS service: name, security group and task role, to attach more rules or policies."
  value       = module.ecs.services
}

output "worker_groups" {
  description = "Per worker group: Auto Scaling group, security group and role."
  value       = module.ec2.groups
}

output "discovery_role_arn" {
  description = "role_arn for the discovery document (docs/guides/discovery.md)."
  value       = one(module.discovery[*].role_arn)
}

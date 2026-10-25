output "proxy_dns_names" {
  description = "Point each proxy's public name (CNAME or alias) at its load balancer."
  value       = { for k, lb in module.proxy_lb : var.proxies[k].dns_name => lb.dns_name }
}

output "audit_bucket" {
  value = module.foundation.audit_bucket
}

output "database_endpoint" {
  value = module.foundation.database_endpoint
}

output "ecs_services" {
  value = module.ecs.services
}

output "worker_groups" {
  value = module.ec2.groups
}

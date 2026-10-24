output "audit_bucket" {
  value = module.audit.bucket
}

output "ecs_services" {
  value = module.ecs.services
}

output "worker_groups" {
  value = module.ec2.groups
}

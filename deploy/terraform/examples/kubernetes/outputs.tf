output "helm_values" {
  description = "Values for the chart's controlPlaneDefaults."
  value       = module.foundation.helm_values
}

output "kubernetes_secrets" {
  description = "Secret values for kubectl (see docs/guides/deploy.md)."
  sensitive   = true
  value       = module.foundation.kubernetes_secrets
}

output "control_plane_role_arn" {
  value = module.foundation.control_plane_irsa_role_arn
}

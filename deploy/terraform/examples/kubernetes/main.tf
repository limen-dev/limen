# Everything the Helm chart needs that is not Kubernetes: PostgreSQL, the four
# KMS signing keys, the audit store, join tokens, and an IAM role for the
# control plane's service account. It does not create the EKS cluster.
#
#   terraform apply -var-file=my.tfvars
#   terraform output -raw helm_values > limen-values.yaml
#
# then follow docs/guides/deploy.md ("On Kubernetes"). Unverified: validated
# only; never applied to AWS.

module "foundation" {
  source = "../../modules/foundation"

  name                   = var.name
  vpc_id                 = var.vpc_id
  database_subnet_ids    = var.database_subnet_ids
  database_allowed_cidrs = var.node_cidrs
  database               = var.database

  proxy_groups    = toset(keys(var.proxies))
  worker_groups   = var.worker_groups
  proxy_dns_names = [for p in var.proxies : p.dns_name]
  oidc            = var.oidc

  console_public_url    = "https://${values(var.proxies)[0].dns_name}"
  eks_oidc_provider_arn = var.eks_oidc_provider_arn
  eks_oidc_provider_url = var.eks_oidc_provider_url
  kubernetes_namespace  = var.kubernetes_namespace
}

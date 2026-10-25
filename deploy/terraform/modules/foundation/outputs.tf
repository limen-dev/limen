output "control_plane_environment" {
  description = "Plain LIMEN_* settings for every control plane (ECS and EC2 modules: services.<key>.environment)."
  value = merge(
    {
      LIMEN_CA_BACKEND          = "kms"
      LIMEN_KMS_INTERNAL_CA_KEY = module.ca_key["internal_ca"].key_arn
      LIMEN_KMS_USER_CA_KEY     = module.ca_key["user_ca"].key_arn
      LIMEN_KMS_SSH_USER_CA_KEY = module.ca_key["ssh_user_ca"].key_arn
      LIMEN_KMS_SSH_HOST_CA_KEY = module.ca_key["ssh_host_ca"].key_arn
      LIMEN_OIDC_ISSUER         = var.oidc.issuer
      LIMEN_OIDC_CLIENT_ID      = var.oidc.client_id
      LIMEN_AUDIT_S3_BUCKET     = module.audit.bucket
      LIMEN_ENVIRONMENT         = var.name
    },
    length(var.proxy_dns_names) > 0 ? { LIMEN_PROXY_DNS_NAMES = join(",", var.proxy_dns_names) } : {},
    var.console_public_url == null ? {} : { LIMEN_CONSOLE_PUBLIC_URL = var.console_public_url },
  )
}

output "control_plane_secrets" {
  description = "Secret ARNs for every control plane, as environment variable name => ARN."
  value = merge(
    { LIMEN_DATABASE_URL = module.database_url.secret_arn },
    length(local.join_tokens) > 0 ? { LIMEN_STATIC_JOIN_TOKENS = module.static_join_tokens[0].secret_arn } : {},
  )
}

output "internal_ca_secret_arn" {
  description = "Secret the control plane publishes its internal CA certificate to; pass it as internal_ca = { secret_arn = ... } to the ecs and ec2 modules."
  value       = module.internal_ca.secret_arn
}

output "join_token_secret_arns" {
  description = "Per group (\"proxy-<key>\", \"worker-<key>\"): the secret that holds its LIMEN_JOIN_TOKEN."
  value       = { for k, s in module.join_token : k => s.secret_arn }
}

output "control_plane_policy_arns" {
  description = "Policies for the control plane's role: KMS signing and audit writes."
  value = {
    kms   = aws_iam_policy.control_plane_kms.arn
    audit = aws_iam_policy.audit_writer.arn
  }
}

output "control_plane_irsa_role_arn" {
  description = "Role for the control plane's Kubernetes service account (set eks_oidc_provider_arn)."
  value       = local.eks ? module.control_plane_irsa[0].arn : null
}

output "database_security_group_id" {
  description = "Allow the control plane's security group on port 5432 with aws_vpc_security_group_ingress_rule."
  value       = aws_security_group.database.id
}

output "database_endpoint" {
  value = module.database.db_instance_address
}

output "audit_bucket" {
  value = module.audit.bucket
}

output "ca_key_arns" {
  value = { for k, v in module.ca_key : k => v.key_arn }
}

output "helm_values" {
  description = "Values for deploy/helm/limen's controlPlaneDefaults. Save with: terraform output -raw helm_values > limen-values.yaml"
  value = yamlencode({
    controlPlaneDefaults = {
      oidc          = { issuer = var.oidc.issuer, clientId = var.oidc.client_id }
      auditS3Bucket = module.audit.bucket
      kms = {
        internalCaKey = module.ca_key["internal_ca"].key_arn
        userCaKey     = module.ca_key["user_ca"].key_arn
        sshUserCaKey  = module.ca_key["ssh_user_ca"].key_arn
        sshHostCaKey  = module.ca_key["ssh_host_ca"].key_arn
      }
      serviceAccount = {
        create      = true
        annotations = local.eks ? { "eks.amazonaws.com/role-arn" = module.control_plane_irsa[0].arn } : {}
      }
      extraEnv = concat(
        length(var.proxy_dns_names) > 0 ? [{ name = "LIMEN_PROXY_DNS_NAMES", value = join(",", var.proxy_dns_names) }] : [],
        var.console_public_url == null ? [] : [{ name = "LIMEN_CONSOLE_PUBLIC_URL", value = var.console_public_url }],
        length(local.join_tokens) > 0 ? [{ name = "LIMEN_STATIC_JOIN_TOKENS", valueFrom = { secretKeyRef = { name = "limen-static-join-tokens", key = "tokens" } } }] : [],
      )
    }
  })
}

output "kubernetes_secrets" {
  description = "Values for the Kubernetes Secrets the chart reads: database URL, the control plane's static tokens, and one token per proxy and worker group."
  sensitive   = true
  value = {
    database_url       = module.database_url.secret_string
    static_join_tokens = local.static_join_tokens
    join_tokens        = { for k, p in random_password.join_token : k => p.result }
  }
}

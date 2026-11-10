variable "name" {
  description = "Prefix for every resource, e.g. \"limen-prod\"."
  type        = string
}

variable "name_prefix" {
  description = "Prefix of the display names proxies and workers ask for (LIMEN_NAME), approved by every static join token as the pattern \"<prefix>-*\". The Helm chart's namePrefix takes the same value from helm_values. Defaults to name. Lowercase letters, digits and hyphens."
  type        = string
  default     = null

  validation {
    condition     = var.name_prefix == null || can(regex("^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$", var.name_prefix))
    error_message = "name_prefix must be 1 to 42 characters of a-z, 0-9 and -, not starting or ending with -."
  }
}

variable "vpc_id" {
  description = "VPC for the database."
  type        = string
}

variable "database_subnet_ids" {
  description = "Private subnets (at least two zones) for the database."
  type        = list(string)
}

variable "database_allowed_cidrs" {
  description = "CIDRs allowed to reach PostgreSQL, normally the control plane's subnets. Add per-service rules with the database_security_group_id output."
  type        = list(string)
  default     = []
}

variable "database" {
  description = "PostgreSQL settings. Deletion protection and a final snapshot are on by default."
  type = object({
    engine_version         = optional(string, "17")
    instance_class         = optional(string, "db.t4g.medium")
    allocated_storage_gb   = optional(number, 50)
    max_allocated_storage  = optional(number, 200)
    multi_az               = optional(bool, true)
    backup_retention_days  = optional(number, 14)
    deletion_protection    = optional(bool, true)
    skip_final_snapshot    = optional(bool, false)
    database_name          = optional(string, "limen")
    username               = optional(string, "limen")
    performance_insights   = optional(bool, true)
    apply_immediately      = optional(bool, false)
    parameter_group_family = optional(string, "postgres17")
    major_engine_version   = optional(string, "17")
  })
  default = {}
}

variable "proxy_groups" {
  description = "Keys of the proxy groups you will run. Each gets its own join token, labelled group=<key>."
  type        = set(string)
  default     = []
}

variable "worker_groups" {
  description = "Keys of the worker groups you will run. Each gets its own join token, labelled group=<key>."
  type        = set(string)
  default     = []
}

variable "proxy_dns_names" {
  description = "DNS names proxies may put in their certificates (LIMEN_PROXY_DNS_NAMES): every proxy's public name."
  type        = list(string)
  default     = []
}

variable "oidc" {
  description = "Your identity provider's issuer URL and the Limen client id. The IdP itself is not created here."
  type = object({
    issuer    = string
    client_id = string
  })
}

variable "console_public_url" {
  description = "Public URL users reach the proxy at, e.g. \"https://limen.example.com\". Turns on the web console."
  type        = string
  default     = null
}

variable "audit" {
  description = "Settings passed to the audit module (S3 Object Lock, retention, the optional OCSF export for SIEMs)."
  type = object({
    retention_days   = optional(number, 400)
    object_lock_days = optional(number, 0)
    ocsf = optional(object({
      enabled        = optional(bool, false)
      bucket_name    = optional(string)
      retention_days = optional(number, 90)
      kms_key_arn    = optional(string)
    }), {})
  })
  default = {}
}

variable "eks_oidc_provider_arn" {
  description = "OIDC provider ARN of your EKS cluster. When set, an IAM role for the control plane's Kubernetes service account is created (IRSA)."
  type        = string
  default     = null
}

variable "eks_oidc_provider_url" {
  description = "Issuer URL of the EKS OIDC provider without https://. Required with eks_oidc_provider_arn."
  type        = string
  default     = null
}

variable "kubernetes_namespace" {
  description = "Namespace the Helm release runs in (for the IRSA trust policy)."
  type        = string
  default     = "limen"
}

variable "tags" {
  description = "Tags added to every resource."
  type        = map(string)
  default     = {}
}

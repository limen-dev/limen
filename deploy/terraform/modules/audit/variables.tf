variable "name" {
  description = "Prefix for every resource name, e.g. \"limen-prod\"."
  type        = string
}

variable "bucket_name" {
  description = "Audit bucket name. Defaults to \"<name>-audit-<account id>\"."
  type        = string
  default     = null
}

variable "retention_days" {
  description = "Days to keep audit events, manifests, and recordings. 0 keeps them forever."
  type        = number
  default     = 400
}

variable "object_lock_days" {
  description = <<-EOT
    Object Lock retention in compliance mode, in days. 0 disables Object Lock.
    Object Lock can only be turned on when the bucket is created, and nobody,
    including the account root, can delete a locked object early.
  EOT
  type        = number
  default     = 0
}

variable "deny_version_deletion" {
  description = "Deny s3:DeleteObjectVersion on the audit bucket to every principal. Lifecycle expiry still applies."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "Existing KMS key for the bucket. A new key is created when null."
  type        = string
  default     = null
}

variable "ocsf" {
  description = <<-EOT
    The OCSF export of the audit trail for SIEMs (ADR-0049): a bucket and KMS
    key of their own, off by default. `kms_key_arn` is an existing key for the
    bucket (a new one is created when null); it must not be the audit key, which
    also protects recordings. `retention_days` 0 keeps objects forever: the
    audit bucket is the record, this copy is for the SIEM.
  EOT
  type = object({
    enabled        = optional(bool, false)
    bucket_name    = optional(string)
    retention_days = optional(number, 90)
    kms_key_arn    = optional(string)
  })
  default = {}
}

variable "athena_bytes_scanned_cutoff" {
  description = "Per-query scan limit for the Athena workgroup, in bytes."
  type        = number
  default     = 10737418240 # 10 GiB
}

variable "athena_results_days" {
  description = "Days to keep Athena query results."
  type        = number
  default     = 7
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}

variable "verifier_trusted_principal_arns" {
  description = <<-EOT
    IAM principals allowed to assume the verifier role: the control plane's task
    or instance role. The control plane assumes it to give auditors short-lived,
    read-only access for `limen audit verify`. Leave empty to create no role and
    attach verifier_policy_json yourself.
  EOT
  type        = list(string)
  default     = []
}

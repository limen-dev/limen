variable "name" {
  description = "Prefix for every resource name, e.g. \"limen-prod\"."
  type        = string
}

variable "bucket_name" {
  description = "OCSF bucket name. Defaults to \"<name>-ocsf-<account id>\"."
  type        = string
  default     = null
}

variable "retention_days" {
  description = "Days to keep OCSF objects. The audit bucket is the record; this copy is for the SIEM. 0 keeps them forever."
  type        = number
  default     = 90
}

variable "kms_key_arn" {
  description = "Existing KMS key for the bucket. It must not be the audit key, which also protects recordings. A new key is created when null."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}

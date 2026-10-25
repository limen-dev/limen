variable "name" {
  description = "Name of the role, e.g. \"limen-discovery\". Use this name in the discovery document's role_arn."
  type        = string
  default     = "limen-discovery"
}

variable "worker_role_arns" {
  description = <<-EOT
    The roles the Limen workers that run discovery use (an instance profile, an
    ECS task role, an IRSA role). Only these may assume the discovery role.
    In the same account the worker role can also be given the policy directly.
  EOT
  type        = list(string)
}

variable "sources" {
  description = "Which sources the role may read. Each is describe-only."
  type        = set(string)
  default     = ["ec2", "rds", "redshift", "elasticache", "eks"]

  validation {
    condition     = length(setsubtract(var.sources, ["ec2", "rds", "redshift", "elasticache", "eks"])) == 0
    error_message = "sources may only hold ec2, rds, redshift, elasticache, and eks."
  }
}

variable "external_id" {
  description = "If set, the worker must present this external id when it assumes the role."
  type        = string
  default     = null
}

variable "max_session_seconds" {
  description = "Longest session of the assumed role. Discovery asks for 900 seconds."
  type        = number
  default     = 3600
}

variable "tags" {
  type    = map(string)
  default = {}
}

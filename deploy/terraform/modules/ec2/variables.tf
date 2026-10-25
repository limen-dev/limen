variable "name" {
  description = "Prefix for every group and its resources, e.g. \"limen-prod\"."
  type        = string
}

variable "groups" {
  description = <<-EOT
    Auto Scaling groups of Limen instances, keyed by a short name that becomes
    part of the resource names: { proxy-a = { component = "proxy", ... }, worker-a = {...} }.
    Add as many entries as you need of any component; each has its own VPC,
    subnets and size, so proxies and workers can live in different VPCs.
    "environment" holds plain LIMEN_* settings; "secrets" maps a variable name to
    a Secrets Manager secret ARN, read at boot with the instance role.
  EOT
  type = map(object({
    component                  = string
    image                      = string
    vpc_id                     = string
    subnet_ids                 = list(string)
    associate_public_ip        = optional(bool, false)
    instance_type              = optional(string, "t4g.small")
    min_size                   = optional(number, 3)
    max_size                   = optional(number, 6)
    desired_capacity           = optional(number, 3)
    volume_size_gb             = optional(number, 30)
    stop_timeout               = optional(number, 330)
    environment                = optional(map(string), {})
    secrets                    = optional(map(string), {})
    ingress_cidrs              = optional(list(string), [])
    ingress_security_group_ids = optional(list(string), [])
    target_group_arns          = optional(list(string), [])
    role_policy_arns           = optional(map(string), {})
  }))

  validation {
    condition     = alltrue([for g in var.groups : contains(["control-plane", "proxy", "worker"], g.component)])
    error_message = "component must be control-plane, proxy or worker."
  }
  validation {
    condition     = alltrue([for g in var.groups : g.min_size <= g.desired_capacity && g.desired_capacity <= g.max_size])
    error_message = "Require min_size <= desired_capacity <= max_size."
  }
}

variable "ami_ssm_parameter" {
  description = "SSM parameter holding the AMI id. Must match the instance types' architecture (arm64 default)."
  type        = string
  default     = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

variable "internal_ca" {
  description = <<-EOT
    Pass { secret_arn = ... }: the Secrets Manager secret for the Limen internal CA certificate (the
    foundation module creates it). Control plane instances publish the
    certificate they export into it; proxy and worker instances wait for it
    and write it to the file LIMEN_CA_FILE points at.
  EOT
  type = object({
    secret_arn = string
  })
  default = null
}

variable "log_retention_days" {
  description = "Retention of each group's CloudWatch log group."
  type        = number
  default     = 90
}

variable "tags" {
  description = "Tags added to every resource."
  type        = map(string)
  default     = {}
}

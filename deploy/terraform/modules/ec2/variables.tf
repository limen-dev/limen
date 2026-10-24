variable "name" {
  description = "Prefix for every resource name, e.g. \"limen-prod-proxy\"."
  type        = string
}

variable "component" {
  description = "Which Limen component this deployment runs."
  type        = string
  validation {
    condition     = contains(["control-plane", "proxy", "worker"], var.component)
    error_message = "component must be control-plane, proxy or worker."
  }
}

variable "image" {
  description = "Container image reference, e.g. \"ghcr.io/your-org/limen-proxy:0.1.0\"."
  type        = string
}

variable "vpc_id" {
  description = "VPC of this component. Each component can use its own VPC."
  type        = string
}

variable "subnet_ids" {
  description = "Subnets for the instances."
  type        = list(string)
}

variable "environment" {
  description = "Plain environment variables (LIMEN_*), merged over the component defaults."
  type        = map(string)
  default     = {}
}

variable "secrets" {
  description = "Environment variables read from Secrets Manager at boot: name => secret ARN. Values never appear in user data or Terraform state."
  type        = map(string)
  default     = {}
}

variable "ingress_cidrs" {
  description = "CIDRs allowed to reach the public port (proxy) or the gRPC port (control plane). Workers accept no inbound traffic."
  type        = list(string)
  default     = []
}

variable "ingress_security_group_ids" {
  description = "Security groups allowed to reach the same port, e.g. a load balancer's."
  type        = list(string)
  default     = []
}

variable "target_group_arn" {
  description = "Load balancer target group for the public port (proxy only)."
  type        = string
  default     = null
}

variable "task_role_policy_arns" {
  description = "Managed policies for the instance role, e.g. KMS and S3 access for the control plane."
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "instance_type" {
  type    = string
  default = "t4g.small"
}

variable "ami_ssm_parameter" {
  description = "SSM parameter holding the AMI id. Must match instance_type's architecture (arm64 default)."
  type        = string
  default     = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

variable "min_size" {
  type    = number
  default = 3
}

variable "max_size" {
  type    = number
  default = 6
}

variable "desired_capacity" {
  type    = number
  default = 3
}

variable "stop_timeout" {
  description = "Seconds Docker waits after SIGTERM; set it above Limen's drain timeout."
  type        = number
  default     = 330
}

variable "associate_public_ip" {
  type    = bool
  default = false
}

variable "volume_size_gb" {
  description = "Root volume size. The control plane keeps its audit spool here."
  type        = number
  default     = 30
}

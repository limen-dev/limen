variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "name" {
  description = "Prefix for every resource."
  type        = string
  default     = "limen-prod"
}

variable "vpc_id" {
  description = "VPC of your EKS cluster. The database goes here."
  type        = string
}

variable "database_subnet_ids" {
  description = "Private subnets of that VPC, in at least two zones."
  type        = list(string)
}

variable "node_cidrs" {
  description = "CIDRs of the EKS nodes or pods that may reach PostgreSQL (the control plane runs there)."
  type        = list(string)
}

variable "oidc" {
  description = "Your identity provider's issuer URL and the client id registered for Limen."
  type = object({
    issuer    = string
    client_id = string
  })
}

variable "eks_oidc_provider_arn" {
  description = "OIDC provider ARN of the cluster (IRSA)."
  type        = string
}

variable "eks_oidc_provider_url" {
  description = "Issuer URL of that provider, without https://."
  type        = string
}

variable "kubernetes_namespace" {
  type    = string
  default = "limen"
}

variable "proxies" {
  description = "Proxy groups you will run, keyed as in the chart's `proxies`, with the public DNS name of each."
  type        = map(object({ dns_name = string }))
}

variable "worker_groups" {
  description = "Keys of the worker groups you will run, as in the chart's `workers`."
  type        = set(string)
}

variable "database" {
  description = "PostgreSQL settings (see modules/foundation)."
  type        = any
  default     = {}
}

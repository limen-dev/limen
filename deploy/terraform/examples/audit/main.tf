# The Phase 3 audit store and its monitors on their own. The full deployment
# (examples/complete, Phase 15) uses the same modules.
#
#   terraform init && terraform apply -var environment=prod
#
# Credentials come from the usual AWS and Datadog provider environment
# variables (AWS_PROFILE, DD_API_KEY, DD_APP_KEY).

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
    datadog = {
      source  = "DataDog/datadog"
      version = ">= 4.0, < 5.0"
    }
  }
}

variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "environment" {
  type    = string
  default = "prod"
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "limen", Environment = var.environment }
  }
}

provider "datadog" {}

module "audit" {
  source           = "../../modules/audit"
  name             = "limen-${var.environment}"
  retention_days   = 400
  object_lock_days = 365
}

module "monitors" {
  source      = "../../modules/datadog"
  environment = var.environment
  notify      = ["@security-oncall"]
}

output "control_plane_flags" {
  description = "Flags for the control plane."
  value       = "--audit-s3-bucket ${module.audit.bucket} --audit-s3-kms-key ${module.audit.kms_key_arn} --environment ${var.environment}"
}

output "audit" {
  value = module.audit
}

# The OCSF export for SIEMs (ADR-0049): a projection of the audit trail in a
# bucket and under a KMS key of its own, off unless `ocsf.enabled`. Whoever
# reads the SIEM feed gets this bucket and nothing of the audit bucket, which
# holds session recordings. Built on the community s3-bucket and kms modules.
#
# Unverified against real AWS: written against the module docs and checked
# with `terraform validate`; the local stand-in is SeaweedFS.

locals {
  ocsf_enabled    = var.ocsf.enabled
  ocsf_create_key = local.ocsf_enabled && var.ocsf.kms_key_arn == null
  ocsf_bucket     = coalesce(var.ocsf.bucket_name, "${var.name}-ocsf-${data.aws_caller_identity.current.account_id}")
  ocsf_kms_arn    = !local.ocsf_enabled ? null : (var.ocsf.kms_key_arn != null ? var.ocsf.kms_key_arn : module.ocsf_kms.key_arn)
}

# The audit key also protects recordings: sharing it would let the SIEM reader
# decrypt them. Applying fails rather than allowing that.
resource "terraform_data" "ocsf_key_guard" {
  count = local.ocsf_enabled ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.ocsf.kms_key_arn != local.kms_arn
      error_message = "ocsf.kms_key_arn is the audit key. It also protects session recordings: the SIEM reader would be able to decrypt them. Use a key of its own (leave it null)."
    }
  }
}

module "ocsf_kms" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 4.2"

  create = local.ocsf_create_key

  description             = "${var.name} OCSF export for SIEMs"
  aliases                 = ["${var.name}-ocsf"]
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = var.tags
}

module "ocsf_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"

  create_bucket = local.ocsf_enabled

  bucket = local.ocsf_bucket

  control_object_ownership = true
  object_ownership         = "BucketOwnerEnforced"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = local.ocsf_kms_arn
      }
      bucket_key_enabled = true
    }
  }

  # TLS only, KMS only, and only this bucket's key: a writer with
  # kms:GenerateDataKey on another key (such as the audit key) cannot write an
  # object that key would decrypt.
  attach_deny_insecure_transport_policy    = true
  attach_deny_unencrypted_object_uploads   = false
  attach_deny_incorrect_encryption_headers = true
  attach_deny_incorrect_kms_key_sse        = true
  allowed_kms_key_arn                      = local.ocsf_kms_arn

  lifecycle_rule = concat(
    var.ocsf.retention_days > 0 ? [{
      id         = "retention"
      enabled    = true
      filter     = {}
      expiration = { days = var.ocsf.retention_days }
    }] : [],
    [{
      id                                     = "abort-incomplete-uploads"
      enabled                                = true
      filter                                 = {}
      abort_incomplete_multipart_upload_days = 2
    }],
  )

  tags = var.tags
}

# The control plane: write OCSF objects. It can't read or delete them.
data "aws_iam_policy_document" "ocsf_writer" {
  count = local.ocsf_enabled ? 1 : 0

  statement {
    sid       = "Append"
    actions   = ["s3:PutObject"]
    resources = ["${module.ocsf_bucket.s3_bucket_arn}/*"]
  }
  statement {
    sid       = "Encrypt"
    actions   = ["kms:GenerateDataKey"]
    resources = [local.ocsf_kms_arn]
  }
}

# The SIEM's collector (Splunk, Sentinel, Chronicle, a Security Lake
# ingester): read this bucket and decrypt with this key, and nothing else.
data "aws_iam_policy_document" "ocsf_reader" {
  count = local.ocsf_enabled ? 1 : 0

  statement {
    sid       = "Read"
    actions   = ["s3:GetObject"]
    resources = ["${module.ocsf_bucket.s3_bucket_arn}/*"]
  }
  statement {
    sid       = "List"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [module.ocsf_bucket.s3_bucket_arn]
  }
  statement {
    sid       = "Decrypt"
    actions   = ["kms:Decrypt"]
    resources = [local.ocsf_kms_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.region}.amazonaws.com"]
    }
  }
}

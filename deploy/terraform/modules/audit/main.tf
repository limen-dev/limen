# The audit store (ADR-0009, ADR-0014): an S3 bucket the control plane
# appends signed, hash-chained batches and recordings to; a Glue table over it
# with partition projection; and an Athena workgroup for Grafana.
#
# Unverified against real AWS: written against the provider docs and checked
# with `terraform validate`; the local stand-ins are SeaweedFS and Trino.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  bucket  = coalesce(var.bucket_name, "${var.name}-audit-${data.aws_caller_identity.current.account_id}")
  kms_arn = var.kms_key_arn != null ? var.kms_key_arn : aws_kms_key.audit[0].arn
}

resource "aws_kms_key" "audit" {
  count                   = var.kms_key_arn == null ? 1 : 0
  description             = "${var.name} audit events and recordings"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = var.tags
}

resource "aws_kms_alias" "audit" {
  count         = var.kms_key_arn == null ? 1 : 0
  name          = "alias/${var.name}-audit"
  target_key_id = aws_kms_key.audit[0].key_id
}

resource "aws_s3_bucket" "audit" {
  bucket              = local.bucket
  object_lock_enabled = var.object_lock_days > 0
  tags                = var.tags
}

resource "aws_s3_bucket_ownership_controls" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Overwrites keep the previous version, so a replaced batch is still found
# (and `limen-audit-verify` reports the hash mismatch).
resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  count  = var.object_lock_days > 0 ? 1 : 0
  bucket = aws_s3_bucket.audit.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.object_lock_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.audit]
}

resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  dynamic "rule" {
    for_each = var.retention_days > 0 ? [1] : []
    content {
      id     = "retention"
      status = "Enabled"
      filter {}
      expiration {
        days = var.retention_days
      }
      noncurrent_version_expiration {
        noncurrent_days = var.retention_days
      }
    }
  }

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 2
    }
  }

  depends_on = [aws_s3_bucket_versioning.audit]
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyOtherEncryption"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  dynamic "statement" {
    for_each = var.deny_version_deletion ? [1] : []
    content {
      sid       = "AppendOnly"
      effect    = "Deny"
      actions   = ["s3:DeleteObjectVersion", "s3:PutBucketVersioning", "s3:PutBucketObjectLockConfiguration"]
      resources = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
      principals {
        type        = "*"
        identifiers = ["*"]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = data.aws_iam_policy_document.bucket.json
  # Last, so the append-only statement doesn't block configuring the bucket.
  depends_on = [
    aws_s3_bucket_public_access_block.audit,
    aws_s3_bucket_versioning.audit,
    aws_s3_bucket_object_lock_configuration.audit,
  ]
}

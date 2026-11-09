# The OCSF export bucket (ADR-0047): a projection of the audit trail for
# SIEMs, in a bucket and under a KMS key of its own. Whoever reads the SIEM feed
# gets this bucket and nothing of the audit bucket, which holds session
# recordings.
#
# Unverified against real AWS: written against the provider docs and checked
# with `terraform validate`; the local stand-in is SeaweedFS.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  bucket  = coalesce(var.bucket_name, "${var.name}-ocsf-${data.aws_caller_identity.current.account_id}")
  kms_arn = var.kms_key_arn != null ? var.kms_key_arn : aws_kms_key.ocsf[0].arn
}

resource "aws_kms_key" "ocsf" {
  count                   = var.kms_key_arn == null ? 1 : 0
  description             = "${var.name} OCSF export for SIEMs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = var.tags
}

resource "aws_kms_alias" "ocsf" {
  count         = var.kms_key_arn == null ? 1 : 0
  name          = "alias/${var.name}-ocsf"
  target_key_id = aws_kms_key.ocsf[0].key_id
}

resource "aws_s3_bucket" "ocsf" {
  bucket = local.bucket
  tags   = var.tags

  lifecycle {
    precondition {
      condition     = var.audit_kms_key_arn == null || var.audit_kms_key_arn != local.kms_arn
      error_message = "kms_key_arn is the audit key. It also protects session recordings: the SIEM reader would be able to decrypt them. Use a key of its own (leave kms_key_arn null)."
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "ocsf" {
  bucket = aws_s3_bucket.ocsf.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "ocsf" {
  bucket                  = aws_s3_bucket.ocsf.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ocsf" {
  bucket = aws_s3_bucket.ocsf.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "ocsf" {
  bucket = aws_s3_bucket.ocsf.id

  dynamic "rule" {
    for_each = var.retention_days > 0 ? [1] : []
    content {
      id     = "retention"
      status = "Enabled"
      filter {}
      expiration {
        days = var.retention_days
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
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.ocsf.arn, "${aws_s3_bucket.ocsf.arn}/*"]
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
    resources = ["${aws_s3_bucket.ocsf.arn}/*"]
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

  # Only this bucket's key: a writer with kms:GenerateDataKey on another key
  # (such as the audit key) cannot write an object that key would decrypt.
  statement {
    sid       = "DenyOtherKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.ocsf.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [local.kms_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "ocsf" {
  bucket = aws_s3_bucket.ocsf.id
  policy = data.aws_iam_policy_document.bucket.json
  depends_on = [
    aws_s3_bucket_public_access_block.ocsf,
  ]
}

# The control plane: write OCSF objects. It can't read or delete them.
data "aws_iam_policy_document" "writer" {
  statement {
    sid       = "Append"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.ocsf.arn}/*"]
  }
  statement {
    sid       = "Encrypt"
    actions   = ["kms:GenerateDataKey"]
    resources = [local.kms_arn]
  }
}

# The SIEM's collector (Splunk, Sentinel, Chronicle, a Security Lake
# ingester): read this bucket and decrypt with this key, and nothing else.
data "aws_iam_policy_document" "reader" {
  statement {
    sid       = "Read"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.ocsf.arn}/*"]
  }
  statement {
    sid       = "List"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [aws_s3_bucket.ocsf.arn]
  }
  statement {
    sid       = "Decrypt"
    actions   = ["kms:Decrypt"]
    resources = [local.kms_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.region}.amazonaws.com"]
    }
  }
}

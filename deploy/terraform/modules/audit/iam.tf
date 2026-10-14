# Least-privilege policies for the three roles that touch the audit store.
# The module outputs them as JSON; attach them to your task or instance roles.

locals {
  bucket_arn  = aws_s3_bucket.audit.arn
  results_arn = aws_s3_bucket.athena_results.arn
}

# The control plane: append batches, manifests, and recordings, and read its
# own manifests back to find the chain head after a restart. It can't delete.
data "aws_iam_policy_document" "writer" {
  statement {
    sid       = "Append"
    actions   = ["s3:PutObject"]
    resources = ["${local.bucket_arn}/events/*", "${local.bucket_arn}/manifests/*", "${local.bucket_arn}/recordings/*"]
  }
  statement {
    sid       = "ReadManifestsAndRecordings"
    actions   = ["s3:GetObject"]
    resources = ["${local.bucket_arn}/manifests/*", "${local.bucket_arn}/recordings/*"]
  }
  statement {
    sid       = "ListManifests"
    actions   = ["s3:ListBucket"]
    resources = [local.bucket_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["manifests/*"]
    }
  }
  statement {
    sid       = "Encrypt"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [local.kms_arn]
  }
}

# Grafana: run Athena queries in the workgroup over the events table.
data "aws_iam_policy_document" "reader" {
  statement {
    sid = "Athena"
    actions = [
      "athena:GetWorkGroup", "athena:StartQueryExecution", "athena:StopQueryExecution",
      "athena:GetQueryExecution", "athena:GetQueryResults", "athena:ListQueryExecutions",
    ]
    resources = [aws_athena_workgroup.audit.arn]
  }
  statement {
    sid     = "AthenaCatalogs"
    actions = ["athena:ListDataCatalogs", "athena:ListDatabases", "athena:ListTableMetadata", "athena:GetTableMetadata", "athena:ListWorkGroups"]
    resources = [
      "arn:${data.aws_partition.current.partition}:athena:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:datacatalog/AwsDataCatalog",
      "arn:${data.aws_partition.current.partition}:athena:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:workgroup/*",
    ]
  }
  statement {
    sid     = "Glue"
    actions = ["glue:GetDatabase", "glue:GetDatabases", "glue:GetTable", "glue:GetTables", "glue:GetPartition", "glue:GetPartitions"]
    resources = [
      "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:catalog",
      "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:database/${aws_glue_catalog_database.audit.name}",
      "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:table/${aws_glue_catalog_database.audit.name}/*",
    ]
  }
  statement {
    sid       = "ReadEvents"
    actions   = ["s3:GetObject"]
    resources = ["${local.bucket_arn}/events/*"]
  }
  statement {
    sid       = "ListEvents"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [local.bucket_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["events/*", ""]
    }
  }
  statement {
    sid       = "Results"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
    resources = [local.results_arn, "${local.results_arn}/*"]
  }
  statement {
    sid       = "Decrypt"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [local.kms_arn]
  }
}

# Auditors running limen-audit-verify: read everything, change nothing.
data "aws_iam_policy_document" "verifier" {
  statement {
    sid       = "Read"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${local.bucket_arn}/*"]
  }
  statement {
    sid       = "List"
    actions   = ["s3:ListBucket", "s3:ListBucketVersions"]
    resources = [local.bucket_arn]
  }
  statement {
    sid       = "Decrypt"
    actions   = ["kms:Decrypt"]
    resources = [local.kms_arn]
  }
}

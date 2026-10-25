# The role Limen workers assume to look for EC2 instances, databases, caches,
# and clusters (ADR-0027). It can only read: describe and list calls, plus
# ec2:GetConsoleOutput (cloud-init prints an instance's SSH host keys there,
# and Limen refuses hosts it cannot verify). It has no iam:PassRole, no data
# plane access, and no write action of any kind.

data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "WorkersAssumeIt"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = var.worker_role_arns
    }
    dynamic "condition" {
      for_each = var.external_id == null ? [] : [var.external_id]
      content {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [condition.value]
      }
    }
  }
}

locals {
  actions = {
    ec2 = [
      "ec2:DescribeInstances",
      "ec2:GetConsoleOutput",
    ]
    rds = [
      "rds:DescribeDBInstances",
      "rds:DescribeDBClusters",
      "rds:ListTagsForResource",
    ]
    redshift = [
      "redshift:DescribeClusters",
    ]
    elasticache = [
      "elasticache:DescribeReplicationGroups",
      "elasticache:ListTagsForResource",
    ]
    eks = [
      "eks:ListClusters",
      "eks:DescribeCluster",
    ]
  }
  allowed = flatten([for s in var.sources : local.actions[s]])
}

data "aws_iam_policy_document" "read" {
  statement {
    sid       = "DescribeOnly"
    effect    = "Allow"
    actions   = local.allowed
    resources = ["*"]
  }
}

resource "aws_iam_role" "discovery" {
  name                 = var.name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = var.max_session_seconds
  tags                 = var.tags
}

resource "aws_iam_role_policy" "read" {
  name   = "${var.name}-read"
  role   = aws_iam_role.discovery.id
  policy = data.aws_iam_policy_document.read.json
}

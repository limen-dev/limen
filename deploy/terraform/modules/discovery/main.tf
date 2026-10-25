module "role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role"
  version = "~> 6.8"

  name                 = var.name
  use_name_prefix      = false
  description          = "Limen workers assume this role to discover resources (describe only)"
  max_session_duration = var.max_session_seconds

  trust_policy_permissions = {
    workers = {
      sid     = "WorkersAssumeIt"
      actions = ["sts:AssumeRole"]
      principals = [{
        type        = "AWS"
        identifiers = var.worker_role_arns
      }]
      condition = var.external_id == null ? [] : [{
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [var.external_id]
      }]
    }
  }

  create_inline_policy = true
  inline_policy_permissions = {
    describe = {
      sid       = "DescribeOnly"
      actions   = local.allowed
      resources = ["*"] # describe calls do not support resource scoping
    }
  }

  tags = var.tags
}

# Needed when a worker runs in another account than the role. In the same
# account the trust policy alone is enough; attaching this is harmless.
data "aws_iam_policy_document" "assume" {
  statement {
    actions   = ["sts:AssumeRole"]
    resources = [module.role.arn]
  }
}

resource "aws_iam_policy" "assume" {
  name_prefix = "${var.name}-assume-"
  description = "Lets a Limen worker assume ${var.name}"
  policy      = data.aws_iam_policy_document.assume.json
  tags        = var.tags
}

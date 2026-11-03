# ---------------------------------------------------------------- audit store
module "audit" {
  source = "../audit"

  name             = var.name
  retention_days   = var.audit.retention_days
  object_lock_days = var.audit.object_lock_days
}

# --------------------------------------------------------------- CA signing keys
module "ca_key" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 4.2"

  for_each = local.ca_keys

  description              = "Limen ${var.name}: ${each.value}"
  aliases                  = ["limen/${var.name}/${replace(each.key, "_", "-")}"]
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  # Asymmetric keys cannot rotate automatically (ADR-0007 covers CA rotation).
  enable_key_rotation     = false
  deletion_window_in_days = 30

  tags = var.tags
}

# -------------------------------------------------------------------- database
resource "random_password" "database" {
  length  = 32
  special = false # the password goes into a URL
}

module "database" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 7.2"

  identifier = var.name

  engine                = "postgres"
  engine_version        = var.database.engine_version
  family                = var.database.parameter_group_family
  major_engine_version  = var.database.major_engine_version
  instance_class        = var.database.instance_class
  allocated_storage     = var.database.allocated_storage_gb
  max_allocated_storage = var.database.max_allocated_storage
  storage_encrypted     = true

  db_name             = var.database.database_name
  username            = var.database.username
  password_wo         = random_password.database.result
  password_wo_version = 1
  # The URL secret below carries the password, so RDS does not manage it.
  manage_master_user_password = false
  port                        = 5432

  multi_az               = var.database.multi_az
  create_db_subnet_group = true
  subnet_ids             = var.database_subnet_ids
  vpc_security_group_ids = [aws_security_group.database.id]

  backup_retention_period      = var.database.backup_retention_days
  deletion_protection          = var.database.deletion_protection
  skip_final_snapshot          = var.database.skip_final_snapshot
  performance_insights_enabled = var.database.performance_insights
  apply_immediately            = var.database.apply_immediately

  parameters = [
    # Limen's client requires TLS (mTLS everywhere, design §5).
    { name = "rds.force_ssl", value = "1" },
  ]

  tags = var.tags
}

resource "aws_security_group" "database" {
  name_prefix = "${var.name}-db-"
  description = "Limen PostgreSQL"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-db" })

  lifecycle { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "database_cidr" {
  for_each = toset(var.database_allowed_cidrs)

  security_group_id = aws_security_group.database.id
  ip_protocol       = "tcp"
  from_port         = 5432
  to_port           = 5432
  cidr_ipv4         = each.value
}

# --------------------------------------------------------------------- secrets
resource "random_password" "join_token" {
  for_each = local.join_tokens

  length  = 48 # static tokens must be at least 32 characters
  special = false
}

module "database_url" {
  source  = "terraform-aws-modules/secrets-manager/aws"
  version = "~> 2.2"

  name                    = "${var.name}/database-url"
  description             = "Limen PostgreSQL URL (LIMEN_DATABASE_URL)"
  recovery_window_in_days = 7
  secret_string           = "postgres://${var.database.username}:${random_password.database.result}@${module.database.db_instance_address}:${module.database.db_instance_port}/${var.database.database_name}?sslmode=require"

  tags = var.tags
}

module "static_join_tokens" {
  source  = "terraform-aws-modules/secrets-manager/aws"
  version = "~> 2.2"

  count = length(local.join_tokens) > 0 ? 1 : 0

  name                    = "${var.name}/static-join-tokens"
  description             = "Limen LIMEN_STATIC_JOIN_TOKENS for the control plane"
  recovery_window_in_days = 7
  secret_string           = local.static_join_tokens

  tags = var.tags
}

# The control plane creates the internal CA certificate, so nobody can write it
# in advance. The control plane's CA publisher stores it here (public
# certificate, not a secret); proxies and workers read it before they enroll.
module "internal_ca" {
  source  = "terraform-aws-modules/secrets-manager/aws"
  version = "~> 2.2"

  name                    = "${var.name}/internal-ca"
  description             = "Limen internal CA certificate (published by the control plane)"
  recovery_window_in_days = 7
  secret_string           = "pending"
  ignore_secret_changes   = true

  tags = var.tags
}

module "join_token" {
  source  = "terraform-aws-modules/secrets-manager/aws"
  version = "~> 2.2"

  for_each = local.join_tokens

  name                    = "${var.name}/join-token/${each.key}"
  description             = "Join token of the ${each.key} group (LIMEN_JOIN_TOKEN)"
  recovery_window_in_days = 7
  secret_string           = random_password.join_token[each.key].result

  tags = var.tags
}

# ------------------------------------------------------- control plane access
data "aws_iam_policy_document" "control_plane" {
  statement {
    sid       = "SignWithCaKeys"
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = [for k in module.ca_key : k.key_arn]
  }
}

resource "aws_iam_policy" "control_plane_kms" {
  name_prefix = "${var.name}-control-plane-kms-"
  policy      = data.aws_iam_policy_document.control_plane.json
  tags        = var.tags
}

resource "aws_iam_policy" "audit_writer" {
  name_prefix = "${var.name}-audit-writer-"
  policy      = module.audit.writer_policy_json
  tags        = var.tags
}

# IRSA: the control plane's Kubernetes service account assumes this role.
module "control_plane_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role"
  version = "~> 6.8"

  count = local.eks ? 1 : 0

  name            = "${var.name}-control-plane"
  use_name_prefix = false

  trust_policy_permissions = {
    irsa = {
      actions = ["sts:AssumeRoleWithWebIdentity"]
      principals = [{
        type        = "Federated"
        identifiers = [var.eks_oidc_provider_arn]
      }]
      condition = [
        {
          test     = "StringLike"
          variable = "${var.eks_oidc_provider_url}:sub"
          values   = ["system:serviceaccount:${var.kubernetes_namespace}:control-plane-*"]
        },
        {
          test     = "StringEquals"
          variable = "${var.eks_oidc_provider_url}:aud"
          values   = ["sts.amazonaws.com"]
        },
      ]
    }
  }

  policies = {
    kms   = aws_iam_policy.control_plane_kms.arn
    audit = aws_iam_policy.audit_writer.arn
  }

  tags = var.tags
}

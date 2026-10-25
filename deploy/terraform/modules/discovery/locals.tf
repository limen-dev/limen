locals {
  # The role can only read: describe and list calls, plus ec2:GetConsoleOutput
  # (cloud-init prints an instance's SSH host keys there, and Limen refuses hosts
  # it cannot verify). No iam:PassRole, no data plane, no write action (ADR-0027).
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

  allowed = sort(distinct(flatten([for s in var.sources : local.actions[s]])))
}

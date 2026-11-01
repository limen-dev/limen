# Plans the module with a mocked AWS provider: no account and no credentials.
# `terraform validate` cannot see a lookup that fails only for a particular
# group (a worker has no service port), so each component runs through here.
mock_provider "aws" {
  # A mocked policy document has no JSON; the IAM policies that embed it need some.
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
  mock_data "aws_ssm_parameter" {
    defaults = {
      value = "ami-0123456789abcdef0"
    }
  }
  mock_data "aws_region" {
    defaults = {
      region = "us-east-1"
    }
  }
}

variables {
  name = "limen-test"
  internal_ca = {
    secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:limen-ca-AbCdEf"
  }
  groups = {
    cp = {
      component         = "control-plane"
      image             = "example.com/limen-control-plane:1"
      vpc_id            = "vpc-0123456789abcdef0"
      subnet_ids        = ["subnet-0123456789abcdef0"]
      ingress_cidrs     = ["10.0.0.0/16"]
      target_group_arns = ["arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/cp/0123456789abcdef"]
    }
    px = {
      component     = "proxy"
      image         = "example.com/limen-proxy:1"
      vpc_id        = "vpc-0123456789abcdef0"
      subnet_ids    = ["subnet-0123456789abcdef0"]
      ingress_cidrs = ["0.0.0.0/0"]
    }
    wk = {
      component  = "worker"
      image      = "example.com/limen-worker:1"
      vpc_id     = "vpc-0fedcba9876543210"
      subnet_ids = ["subnet-0fedcba9876543210"]
    }
  }
}

run "plans_every_component" {
  command = plan
}

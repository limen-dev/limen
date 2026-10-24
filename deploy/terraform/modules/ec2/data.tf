data "aws_region" "current" {}

data "aws_ssm_parameter" "ami" {
  name = var.ami_ssm_parameter
}

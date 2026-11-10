# Plans the module with a mocked AWS provider: no account and no credentials.
# The OCSF export is off by default and, when on, must not share the audit key.
mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
  mock_resource "aws_kms_key" {
    defaults = {
      arn = "arn:aws:kms:eu-west-1:123456789012:key/22222222-2222-2222-2222-222222222222"
    }
  }
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }
  mock_data "aws_region" {
    defaults = {
      region = "eu-west-1"
    }
  }
}

variables {
  name = "limen-test"
}

run "ocsf_is_off_by_default" {
  command = plan

  assert {
    condition     = output.ocsf_bucket == null && output.ocsf_writer_policy_json == null
    error_message = "the OCSF export must not exist unless ocsf.enabled"
  }
}

run "ocsf_on_creates_a_bucket_and_key_of_its_own" {
  command = apply

  variables {
    ocsf = { enabled = true }
  }

  assert {
    condition     = output.ocsf_bucket != null && output.ocsf_kms_key_arn != null && output.ocsf_reader_policy_json != null
    error_message = "ocsf.enabled must create the bucket, key and policies"
  }
}

run "ocsf_refuses_the_audit_key" {
  command = plan

  variables {
    kms_key_arn = "arn:aws:kms:eu-west-1:123456789012:key/11111111-1111-1111-1111-111111111111"
    ocsf = {
      enabled     = true
      kms_key_arn = "arn:aws:kms:eu-west-1:123456789012:key/11111111-1111-1111-1111-111111111111"
    }
  }

  expect_failures = [terraform_data.ocsf_key_guard]
}

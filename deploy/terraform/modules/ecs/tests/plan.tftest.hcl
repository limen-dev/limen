# Plans the module with a mocked AWS provider: no account and no credentials.
# `terraform validate` cannot see a lookup that fails only for a particular
# service (a worker has no service port), so each component runs through here.
mock_provider "aws" {
  # A mocked policy document has no JSON; the IAM policies that embed it need some.
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  name = "limen-test"
  internal_ca = {
    secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:limen-ca-AbCdEf"
  }
  services = {
    cp = {
      component        = "control-plane"
      image            = "example.com/limen-control-plane:1"
      vpc_id           = "vpc-0123456789abcdef0"
      subnet_ids       = ["subnet-0123456789abcdef0"]
      ingress_cidrs    = ["10.0.0.0/16"]
      target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/cp/0123456789abcdef"
    }
    px = {
      component        = "proxy"
      image            = "example.com/limen-proxy:1"
      vpc_id           = "vpc-0123456789abcdef0"
      subnet_ids       = ["subnet-0123456789abcdef0"]
      ingress_cidrs    = ["0.0.0.0/0"]
      target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/px/0123456789abcdef"
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

  assert {
    condition     = length(output.services) == 3
    error_message = "expected one service per entry"
  }
}

# Drain finishes inside the stop timeout and control planes keep an ephemeral spool
# (docs/runbooks/scale-out.md); anything the caller sets in `environment` wins.
run "drain_and_spool_defaults" {
  command = plan

  assert {
    condition     = output.services["cp"].environment.LIMEN_DRAIN_TIMEOUT == "20s"
    error_message = "a control plane drains for 20 s by default"
  }
  assert {
    condition     = output.services["cp"].environment.LIMEN_SPOOL_MODE == "ephemeral"
    error_message = "a control plane on this runtime has no disk that survives it"
  }
  assert {
    condition     = output.services["px"].environment.LIMEN_DRAIN_TIMEOUT_SECS == "20"
    error_message = "a proxy drains for 20 s by default"
  }
  assert {
    condition     = output.services["wk"].environment.LIMEN_DRAIN_TIMEOUT_SECS == "30"
    error_message = "a worker drains 30 s inside its stop timeout"
  }
  assert {
    condition     = !contains(keys(output.services["wk"].environment), "LIMEN_SPOOL_MODE") && !contains(keys(output.services["px"].environment), "LIMEN_SPOOL_MODE")
    error_message = "only control planes have a spool mode"
  }
}

run "drain_and_spool_overrides" {
  command = plan

  variables {
    services = {
      cp = {
        component  = "control-plane"
        image      = "example.com/limen-control-plane:1"
        vpc_id     = "vpc-0123456789abcdef0"
        subnet_ids = ["subnet-0123456789abcdef0"]
        spool_mode = "durable"

      }
      wk = {
        component    = "worker"
        image        = "example.com/limen-worker:1"
        vpc_id       = "vpc-0fedcba9876543210"
        subnet_ids   = ["subnet-0fedcba9876543210"]
        stop_timeout = 100
        environment  = { LIMEN_DRAIN_TIMEOUT_SECS = "5" }
      }
    }
  }

  assert {
    condition     = output.services["cp"].environment.LIMEN_SPOOL_MODE == "durable"
    error_message = "spool_mode is not passed through"
  }
  assert {
    condition     = output.services["wk"].environment.LIMEN_DRAIN_TIMEOUT_SECS == "5"
    error_message = "an environment entry must beat the derived drain timeout"
  }
}

run "drain_follows_the_stop_timeout" {
  command = plan

  variables {
    services = {
      wk = {
        component    = "worker"
        image        = "example.com/limen-worker:1"
        vpc_id       = "vpc-0fedcba9876543210"
        subnet_ids   = ["subnet-0fedcba9876543210"]
        stop_timeout = 100
      }
    }
  }

  assert {
    condition     = output.services["wk"].environment.LIMEN_DRAIN_TIMEOUT_SECS == "70"
    error_message = "a worker drains 30 s inside its stop timeout"
  }
}

# A proxy or worker cannot trust the control plane without the CA, so the plan stops.
run "refuses_proxies_and_workers_without_the_internal_ca" {
  command = plan

  variables {
    internal_ca = null
  }

  expect_failures = [terraform_data.preflight]
}

run "plans_a_control_plane_alone_without_the_internal_ca" {
  command = plan

  variables {
    internal_ca = null
    services = {
      cp = {
        component  = "control-plane"
        image      = "example.com/limen-control-plane:1"
        vpc_id     = "vpc-0123456789abcdef0"
        subnet_ids = ["subnet-0123456789abcdef0"]
      }
    }
  }

  assert {
    condition     = length(output.services) == 1
    error_message = "a control plane needs no internal_ca to plan"
  }
}

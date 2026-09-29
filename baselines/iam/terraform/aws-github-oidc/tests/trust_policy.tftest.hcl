# Runs offline: `terraform test` with a mocked AWS provider, no credentials.

mock_provider "aws" {
  mock_resource "aws_iam_openid_connect_provider" {
    defaults = {
      arn = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
    }
  }
}

variables {
  role_name        = "gha-deploy-prod"
  allowed_subjects = ["repo:my-org/my-repo:environment:production"]
}

run "trust_is_exact_subject_and_audience" {
  # apply against the mock provider: the provider ARN is only known after apply.
  command = apply

  assert {
    condition     = jsondecode(aws_iam_role.github.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == ["repo:my-org/my-repo:environment:production"]
    error_message = "sub condition must be the exact configured subject list"
  }

  assert {
    condition     = jsondecode(aws_iam_role.github.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    error_message = "aud condition must pin sts.amazonaws.com"
  }

  assert {
    condition     = aws_iam_role.github.max_session_duration == 3600
    error_message = "default session must stay at one hour"
  }

  assert {
    condition     = !can(jsondecode(aws_iam_role.github.assume_role_policy).Statement[0].Condition.StringLike)
    error_message = "trust policy must not use StringLike"
  }
}

run "immutable_subject_format_is_accepted" {
  command = plan

  variables {
    allowed_subjects = ["repo:my-org@123456/my-repo@456789:environment:production"]
  }
}

run "wildcard_subject_is_rejected" {
  command = plan

  variables {
    allowed_subjects = ["repo:my-org/*"]
  }

  expect_failures = [var.allowed_subjects]
}

run "bare_org_subject_is_rejected" {
  command = plan

  variables {
    allowed_subjects = ["repo:my-org"]
  }

  expect_failures = [var.allowed_subjects]
}

run "repo_only_subject_is_rejected" {
  command = plan

  variables {
    allowed_subjects = ["repo:my-org/my-repo"]
  }

  expect_failures = [var.allowed_subjects]
}

run "reusable_workflow_subject_is_accepted" {
  command = plan

  variables {
    allowed_subjects = ["job_workflow_ref:my-org/platform/.github/workflows/deploy.yml@refs/heads/main"]
  }
}

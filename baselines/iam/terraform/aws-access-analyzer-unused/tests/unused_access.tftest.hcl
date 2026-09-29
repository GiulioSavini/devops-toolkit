# Runs offline with a mocked AWS provider, no credentials.

mock_provider "aws" {}

variables {
  analyzer_name = "unused-access-90d"
}

run "organization_scope_by_default" {
  command = plan

  assert {
    condition     = aws_accessanalyzer_analyzer.unused.type == "ORGANIZATION_UNUSED_ACCESS"
    error_message = "default scope must analyse the whole organization"
  }

  assert {
    condition     = aws_accessanalyzer_analyzer.unused.configuration[0].unused_access[0].unused_access_age == 90
    error_message = "default unused access age must be 90 days"
  }

  assert {
    condition     = length(aws_accessanalyzer_analyzer.unused.configuration[0].unused_access[0].analysis_rule) == 0
    error_message = "no exclusions were configured, so no analysis_rule block must be emitted"
  }
}

run "account_scope_maps_to_account_type" {
  command = plan

  variables {
    scope = "ACCOUNT"
  }

  assert {
    condition     = aws_accessanalyzer_analyzer.unused.type == "ACCOUNT_UNUSED_ACCESS"
    error_message = "ACCOUNT scope must produce ACCOUNT_UNUSED_ACCESS"
  }
}

run "exclusions_are_rendered" {
  command = plan

  variables {
    excluded_account_ids   = ["111122223333"]
    excluded_resource_tags = [{ "access-analyzer-exempt" = "break-glass" }]
  }

  assert {
    condition     = length(aws_accessanalyzer_analyzer.unused.configuration[0].unused_access[0].analysis_rule[0].exclusion) == 2
    error_message = "both the account and the tag exclusion must be emitted"
  }

  assert {
    condition     = aws_accessanalyzer_analyzer.unused.configuration[0].unused_access[0].analysis_rule[0].exclusion[0].account_ids == tolist(["111122223333"])
    error_message = "excluded account IDs must pass through unchanged"
  }
}

run "age_above_the_api_maximum_is_rejected" {
  command = plan

  variables {
    unused_access_age = 400
  }

  expect_failures = [var.unused_access_age]
}

run "unknown_scope_is_rejected" {
  command = plan

  variables {
    scope = "ORGANISATION"
  }

  expect_failures = [var.scope]
}

run "malformed_excluded_account_id_is_rejected" {
  command = plan

  variables {
    excluded_account_ids = ["my-sandbox-account"]
  }

  expect_failures = [var.excluded_account_ids]
}

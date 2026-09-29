# Runs offline with a mocked google provider.

mock_provider "google" {}

variables {
  project_id         = "my-project"
  project_number     = "123456789012"
  github_owner_id    = "1342004"
  service_account_id = "gha-deploy"
  subjects           = ["repo:my-org/my-repo:environment:production"]
}

run "provider_is_restricted_to_owner_id" {
  command = plan

  assert {
    condition     = google_iam_workload_identity_pool_provider.github.attribute_condition == "assertion.repository_owner_id == '1342004'"
    error_message = "attribute_condition must pin the numeric owner ID"
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.github.oidc[0].issuer_uri == "https://token.actions.githubusercontent.com"
    error_message = "issuer must be GitHub's OIDC issuer"
  }
}

run "binding_is_per_subject" {
  command = plan

  assert {
    condition     = google_service_account_iam_member.github["repo:my-org/my-repo:environment:production"].member == "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/subject/repo:my-org/my-repo:environment:production"
    error_message = "member must be a single principal:// subject, not a principalSet"
  }
}

run "owner_name_instead_of_id_is_rejected" {
  command = plan

  variables {
    github_owner_id = "my-org"
  }

  expect_failures = [var.github_owner_id]
}

run "wildcard_subject_is_rejected" {
  command = plan

  variables {
    subjects = ["repo:my-org/*"]
  }

  expect_failures = [var.subjects]
}

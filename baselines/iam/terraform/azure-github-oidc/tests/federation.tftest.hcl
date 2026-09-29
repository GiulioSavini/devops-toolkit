# Runs offline with a mocked azurerm provider.

mock_provider "azurerm" {}

variables {
  name                = "id-gha-deploy-prod"
  resource_group_name = "rg-identity"
  location            = "westeurope"
  subjects            = { prod = "repo:my-org/my-repo:environment:production" }
}

run "credential_pins_issuer_audience_subject" {
  command = plan

  assert {
    condition     = azurerm_federated_identity_credential.github["prod"].issuer == "https://token.actions.githubusercontent.com"
    error_message = "issuer must be GitHub's OIDC issuer"
  }

  assert {
    condition     = azurerm_federated_identity_credential.github["prod"].audience == tolist(["api://AzureADTokenExchange"])
    error_message = "audience must be api://AzureADTokenExchange"
  }

  assert {
    condition     = azurerm_federated_identity_credential.github["prod"].subject == "repo:my-org/my-repo:environment:production"
    error_message = "subject must be passed through unchanged"
  }
}

run "wildcard_subject_is_rejected" {
  command = plan

  variables {
    subjects = { any = "repo:my-org/my-repo:*" }
  }

  expect_failures = [var.subjects]
}

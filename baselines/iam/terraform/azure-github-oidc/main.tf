locals {
  github_issuer = "https://token.actions.githubusercontent.com"
  # Audience that azure/login requests by default.
  entra_audience = "api://AzureADTokenExchange"
}

resource "azurerm_user_assigned_identity" "github" {
  name                = var.name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

resource "azurerm_federated_identity_credential" "github" {
  for_each = var.subjects

  name                      = each.key
  user_assigned_identity_id = azurerm_user_assigned_identity.github.id
  issuer                    = local.github_issuer
  audience                  = [local.entra_audience]
  subject                   = each.value
}

resource "azurerm_role_assignment" "github" {
  for_each = { for ra in var.role_assignments : "${ra.role_definition_name}|${ra.scope}" => ra }

  scope                = each.value.scope
  role_definition_name = each.value.role_definition_name
  principal_id         = azurerm_user_assigned_identity.github.principal_id
  principal_type       = "ServicePrincipal"
}

output "client_id" {
  description = "Pass to azure/login as client-id (with tenant-id and subscription-id)."
  value       = azurerm_user_assigned_identity.github.client_id
}

output "principal_id" {
  description = "Object ID of the identity, for additional role assignments."
  value       = azurerm_user_assigned_identity.github.principal_id
}

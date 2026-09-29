# Azure: azurerm backend on a storage account container.
#
# Locking is not optional and not configurable here: the backend takes a blob
# lease on the state blob for the duration of an operation. If a run is killed
# mid-apply the lease survives until it expires, and the fix is
# `terraform force-unlock <lock-id>` — never deleting the blob.
#
# `use_azuread_auth = true` authenticates the *backend* with the caller's Entra
# ID identity (az login, or the workload identity federated in CI) instead of a
# storage account access key. An access key is a bearer credential for the
# whole account that cannot be scoped or audited per principal; with AAD auth
# the identity needs "Storage Blob Data Contributor" on the container and every
# state read shows up in the storage account's audit log with a name on it.
#
# Container prerequisites: blob versioning plus a delete-retention policy,
# infrastructure encryption on the account, `allowBlobPublicAccess = false`,
# a private endpoint or a network rule set, and a resource lock so nobody
# deletes the resource group that holds the state of everything else.
terraform {
  required_version = ">= 1.11.0, < 2.0.0"

  backend "azurerm" {
    resource_group_name  = "rg-tfstate-prod"
    storage_account_name = "stexampleorgtfstate"
    container_name       = "tfstate"
    key                  = "env/prod/terraform.tfstate"

    use_azuread_auth = true
    subscription_id  = "00000000-0000-0000-0000-000000000000"
    tenant_id        = "11111111-1111-1111-1111-111111111111"
  }
}

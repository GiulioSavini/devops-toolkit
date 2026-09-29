variable "name" {
  description = "Name of the user-assigned managed identity used by the workflow."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group that holds the identity."
  type        = string
}

variable "location" {
  description = "Azure region of the identity."
  type        = string
}

variable "subjects" {
  description = <<-EOT
    Map of credential name => exact GitHub `sub` claim. Entra ID matches the
    subject literally (no wildcards), and an identity holds at most 20
    federated credentials. Example:
      { prod = "repo:my-org/my-repo:environment:production" }
  EOT
  type        = map(string)

  validation {
    condition     = length(var.subjects) > 0 && length(var.subjects) <= 20
    error_message = "Between 1 and 20 federated credentials per identity."
  }

  validation {
    condition     = alltrue([for s in values(var.subjects) : !can(regex("[*?]", s))])
    error_message = "Entra ID compares the subject literally; a '*' would never match and signals a misunderstanding."
  }
}

variable "role_assignments" {
  description = "Role assignments for the identity: list of { scope, role_definition_name }."
  type = list(object({
    scope                = string
    role_definition_name = string
  }))
  default = []
}

variable "tags" {
  description = "Tags applied to the identity."
  type        = map(string)
  default     = {}
}

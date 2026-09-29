variable "project_id" {
  description = "Project that hosts the workload identity pool and the service account."
  type        = string
}

variable "project_number" {
  description = "Numeric project number (principal identifiers use the number, not the ID)."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.project_number))
    error_message = "project_number must be numeric."
  }
}

variable "pool_id" {
  description = "Workload identity pool ID."
  type        = string
  default     = "github"
}

variable "github_owner_id" {
  description = "Numeric GitHub organization/user ID (repository_owner_id claim). IDs are never reassigned; names can be re-registered after deletion."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.github_owner_id))
    error_message = "Use the numeric owner ID, not the organization name."
  }
}

variable "service_account_id" {
  description = "Account ID (the part before @) of the service account the workflow impersonates."
  type        = string
}

variable "subjects" {
  description = "Exact GitHub `sub` values allowed to impersonate the service account, e.g. repo:my-org/my-repo:environment:production. google.subject is limited to 127 bytes."
  type        = list(string)

  validation {
    condition     = length(var.subjects) > 0 && alltrue([for s in var.subjects : !can(regex("[*?]", s)) && length(s) <= 127])
    error_message = "Subjects must be exact (no wildcards) and at most 127 characters."
  }
}

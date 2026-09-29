variable "create_oidc_provider" {
  description = "Create the token.actions.githubusercontent.com provider. Set false if it already exists in the account (only one per account is allowed)."
  type        = bool
  default     = true
}

variable "role_name" {
  description = "Name of the IAM role GitHub Actions will assume."
  type        = string
}

variable "allowed_subjects" {
  description = <<-EOT
    Exact `sub` claim values allowed to assume the role. Prefer environment
    subjects (repo:ORG/REPO:environment:production) so that GitHub environment
    protection rules gate access. Repositories created after 2026-07-15, or
    that opted in, use the immutable format repo:ORG@ORG_ID/REPO@REPO_ID:...
  EOT
  type        = list(string)

  validation {
    condition     = length(var.allowed_subjects) > 0
    error_message = "At least one subject is required."
  }

  validation {
    condition     = alltrue([for s in var.allowed_subjects : !can(regex("[*?]", s))])
    error_message = "Wildcards are not allowed in allowed_subjects: a '*' in the sub condition lets other repositories, branches or pull requests assume the role."
  }

  validation {
    condition     = alltrue([for s in var.allowed_subjects : can(regex("^[a-z_]+:.+", s))])
    error_message = "Each subject must look like CLAIM:VALUE..., e.g. repo:my-org/my-repo:environment:production."
  }

  validation {
    # An owner-only or repo-only subject (no ref, environment or workflow
    # context) trusts every workflow in that scope, including pull requests.
    condition     = alltrue([for s in var.allowed_subjects : !can(regex("^(repo|repository_owner|repository_owner_id):[^:]+$", s))])
    error_message = "Subjects scoped only to an owner or a repository are too broad; add a ref, environment or job_workflow_ref."
  }
}

variable "policy_arns" {
  description = "Managed policy ARNs attached to the role."
  type        = list(string)
  default     = []
}

variable "permissions_boundary_arn" {
  description = "Optional permissions boundary for the role."
  type        = string
  default     = null
}

variable "max_session_duration" {
  description = "Maximum session length in seconds. Keep it close to the longest job."
  type        = number
  default     = 3600

  validation {
    condition     = var.max_session_duration >= 900 && var.max_session_duration <= 43200
    error_message = "IAM accepts 900 to 43200 seconds."
  }
}

variable "tags" {
  description = "Tags applied to created resources."
  type        = map(string)
  default     = {}
}

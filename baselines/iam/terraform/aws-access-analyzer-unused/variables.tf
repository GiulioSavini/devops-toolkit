variable "analyzer_name" {
  description = "Name of the unused-access analyzer."
  type        = string
  default     = "unused-access"
}

variable "scope" {
  description = <<-EOT
    ACCOUNT analyses this account only. ORGANIZATION analyses every account in
    the organization and must be created in the delegated administrator account
    (or the management account), not in a member account.
  EOT
  type        = string
  default     = "ORGANIZATION"

  validation {
    condition     = contains(["ACCOUNT", "ORGANIZATION"], var.scope)
    error_message = "scope must be ACCOUNT or ORGANIZATION."
  }
}

variable "unused_access_age" {
  description = <<-EOT
    Days of non-use after which a permission, role, user or key is reported.
    AWS accepts 1 to 365. 90 is the usual first target; going below 45 produces
    findings for anything with a quarterly or seasonal usage pattern.
  EOT
  type        = number
  default     = 90

  validation {
    condition     = var.unused_access_age >= 1 && var.unused_access_age <= 365
    error_message = "IAM Access Analyzer accepts an unused access age of 1 to 365 days."
  }
}

variable "excluded_account_ids" {
  description = "Account IDs whose IAM entities are not analysed (e.g. a sandbox OU). Every exclusion is a blind spot: list them in the ticket that asked for them."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.excluded_account_ids : can(regex("^[0-9]{12}$", a))])
    error_message = "Account IDs are 12 digits."
  }
}

variable "excluded_resource_tags" {
  description = "IAM entities carrying any of these tag sets are not analysed, e.g. [{ \"access-analyzer-exempt\" = \"break-glass\" }]."
  type        = list(map(string))
  default     = []
}

variable "tags" {
  description = "Tags applied to the analyzer."
  type        = map(string)
  default     = {}
}

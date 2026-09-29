variable "bucket_name" {
  description = "Name of the backup bucket. Object Lock cannot be enabled on an existing bucket that was created without it, so this bucket is created for the purpose."
  type        = string
}

variable "retention_mode" {
  description = <<-EOT
    Object Lock mode for the default retention rule.

    GOVERNANCE: an object version cannot be deleted or overwritten, except by a
    principal holding s3:BypassGovernanceRetention. This is the mode to start
    with, and the bucket policy in this module denies the bypass permission to
    everyone except the named break-glass role.

    COMPLIANCE: nobody can shorten the retention or delete the version. Not the
    account root, not AWS Support, not you. Storage is billed for the whole
    retention period whatever happens. A wrong retention_days in COMPLIANCE mode
    cannot be undone — it can only be waited out.
  EOT
  type        = string
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.retention_mode)
    error_message = "retention_mode must be GOVERNANCE or COMPLIANCE (exact case)."
  }
}

variable "retention_days" {
  description = "Default retention applied to every new object version. Must be at least as long as the recovery window you promise, and — for ransomware — longer than the time you expect to take to notice an intrusion."
  type        = number
  default     = 30

  validation {
    condition     = var.retention_days >= 1 && var.retention_days <= 36500
    error_message = "retention_days must be between 1 and 36500. A retention of 0 is not a retention: it locks nothing."
  }
}

variable "noncurrent_version_expiration_days" {
  description = "When noncurrent object versions are expired by the lifecycle rule. MUST be greater than retention_days, or the lifecycle rule tries to delete versions that Object Lock still protects."
  type        = number
  default     = 90

  validation {
    condition     = var.noncurrent_version_expiration_days >= 2
    error_message = "noncurrent_version_expiration_days must be at least 2 days."
  }
}

variable "bypass_governance_role_arns" {
  description = "The only principals allowed to hold s3:BypassGovernanceRetention. Keep this to a break-glass role whose use is alerted on; with GOVERNANCE mode, anyone with the bypass can delete a backup, so this list is the real control."
  type        = list(string)
  default     = []
}

variable "kms_key_arn" {
  description = "CMK for SSE-KMS. Null falls back to SSE-S3 (AES256), which is still encryption at rest but with a key you neither hold nor can revoke. The key must NOT be scheduled for deletion while backups exist: destroying it destroys them."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to the bucket."
  type        = map(string)
  default     = {}
}

# A cross-check that belongs in the module and not in a review comment: a
# lifecycle rule that expires versions sooner than Object Lock protects them
# produces a bucket whose rules contradict each other, and the expiry silently
# fails for every locked version.
check "lifecycle_outlives_retention" {
  assert {
    condition     = var.noncurrent_version_expiration_days > var.retention_days
    error_message = "noncurrent_version_expiration_days (${var.noncurrent_version_expiration_days}) must be greater than retention_days (${var.retention_days}): the lifecycle rule would try to delete versions Object Lock still protects."
  }
}

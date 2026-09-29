# `terraform test` with a mocked AWS provider: no credentials, no bucket, no
# cost, and the assertions run against the real plan. Run by tests/backup.sh.
#
# The rejection cases matter as much as the positive ones: a module that accepts
# retention_days = 0 or a lower-case "compliance" produces a bucket that locks
# nothing, and nothing in the plan output says so.

mock_provider "aws" {}

variables {
  bucket_name = "example-org-backups"
}

run "defaults_are_governance_30_days_and_versioned" {
  command = plan

  assert {
    condition     = aws_s3_bucket.backups.object_lock_enabled == true
    error_message = "Object Lock must be enabled on the bucket resource: it cannot be enabled on an existing bucket afterwards."
  }

  assert {
    condition     = aws_s3_bucket_versioning.backups.versioning_configuration[0].status == "Enabled"
    error_message = "Object Lock requires versioning; without it there are no versions to protect."
  }

  assert {
    condition     = aws_s3_bucket_object_lock_configuration.backups.rule[0].default_retention[0].mode == "GOVERNANCE"
    error_message = "The default mode must be GOVERNANCE, so an operator mistake is recoverable by a named break-glass role."
  }

  assert {
    condition     = aws_s3_bucket_object_lock_configuration.backups.rule[0].default_retention[0].days == 30
    error_message = "The default retention must be 30 days."
  }

  assert {
    condition = (
      aws_s3_bucket_public_access_block.backups.block_public_acls &&
      aws_s3_bucket_public_access_block.backups.block_public_policy &&
      aws_s3_bucket_public_access_block.backups.ignore_public_acls &&
      aws_s3_bucket_public_access_block.backups.restrict_public_buckets
    )
    error_message = "All four public-access vectors must be blocked on a backup bucket."
  }

  assert {
    # `rule` is a SET of objects in the provider schema, so it has no
    # addressable index; a nested anytrue() is how you assert on it.
    condition = anytrue([
      for r in aws_s3_bucket_server_side_encryption_configuration.backups.rule :
      anytrue([for d in r.apply_server_side_encryption_by_default : d.sse_algorithm == "AES256"])
    ])
    error_message = "With no CMK the bucket must still be encrypted with SSE-S3."
  }

  assert {
    condition = anytrue([
      for r in aws_s3_bucket_server_side_encryption_configuration.backups.rule : r.bucket_key_enabled == true
    ])
    error_message = "bucket_key_enabled must be on: a repository is millions of objects, and one KMS call per object is what makes people turn encryption off."
  }
}

run "kms_key_switches_the_algorithm" {
  command = plan

  variables {
    kms_key_arn = "arn:aws:kms:eu-west-1:111122223333:key/11111111-2222-3333-4444-555555555555"
  }

  assert {
    condition = anytrue([
      for r in aws_s3_bucket_server_side_encryption_configuration.backups.rule :
      anytrue([for d in r.apply_server_side_encryption_by_default : d.sse_algorithm == "aws:kms"])
    ])
    error_message = "A CMK must select aws:kms, not AES256."
  }

  assert {
    condition = anytrue([
      for r in aws_s3_bucket_server_side_encryption_configuration.backups.rule :
      anytrue([for d in r.apply_server_side_encryption_by_default : d.kms_master_key_id != null])
    ])
    error_message = "The CMK ARN must reach the bucket configuration."
  }
}

run "lifecycle_expires_noncurrent_versions_and_aborts_stale_uploads" {
  command = plan

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.backups.rule[0].noncurrent_version_expiration[0].noncurrent_days == 90
    error_message = "Noncurrent versions must expire, or the bucket grows forever."
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.backups.rule[0].abort_incomplete_multipart_upload[0].days_after_initiation == 7
    error_message = "Incomplete multipart uploads are invisible and billed; they must be aborted."
  }
}

run "bucket_policy_denies_bypass_insecure_transport_and_unlocking" {
  command = plan

  assert {
    condition     = length([for s in jsondecode(aws_s3_bucket_policy.backups.policy).Statement : s if s.Sid == "DenyGovernanceBypassExceptBreakGlass"]) == 1
    error_message = "GOVERNANCE mode without a deny on s3:BypassGovernanceRetention is not a control: anyone with the permission can delete a backup."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(aws_s3_bucket_policy.backups.policy).Statement :
      s.Condition.ArnNotLike["aws:PrincipalArn"] == ["arn:aws:iam::000000000000:role/nobody"]
      if s.Sid == "DenyGovernanceBypassExceptBreakGlass"
    ])
    error_message = "With no break-glass role configured, the bypass must be denied to every principal."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(aws_s3_bucket_policy.backups.policy).Statement :
      s.Condition.Bool["aws:SecureTransport"] == "false"
      if s.Sid == "DenyInsecureTransport"
    ])
    error_message = "The bucket policy must deny plain HTTP: the repository password travels with the request."
  }

  assert {
    condition     = length([for s in jsondecode(aws_s3_bucket_policy.backups.policy).Statement : s if s.Sid == "DenyDisablingVersioningAndLock"]) == 1
    error_message = "Disabling versioning would take Object Lock with it; it must be denied."
  }
}

run "break_glass_role_is_the_only_bypass" {
  command = plan

  variables {
    bypass_governance_role_arns = ["arn:aws:iam::111122223333:role/OrgBreakGlass"]
  }

  assert {
    condition = alltrue([
      for s in jsondecode(aws_s3_bucket_policy.backups.policy).Statement :
      s.Condition.ArnNotLike["aws:PrincipalArn"] == ["arn:aws:iam::111122223333:role/OrgBreakGlass"]
      if s.Sid == "DenyGovernanceBypassExceptBreakGlass"
    ])
    error_message = "The configured break-glass role must be the exception in the bypass deny."
  }
}

run "compliance_mode_is_accepted_but_must_be_explicit" {
  command = plan

  variables {
    retention_mode = "COMPLIANCE"
    retention_days = 14
  }

  assert {
    condition     = aws_s3_bucket_object_lock_configuration.backups.rule[0].default_retention[0].mode == "COMPLIANCE"
    error_message = "COMPLIANCE mode must be selectable for the cases that require it."
  }
}

run "lower_case_mode_is_rejected" {
  command = plan

  variables {
    retention_mode = "governance"
  }

  expect_failures = [var.retention_mode]
}

run "zero_retention_is_rejected" {
  command = plan

  variables {
    retention_days = 0
  }

  expect_failures = [var.retention_days]
}

run "lifecycle_shorter_than_retention_is_rejected" {
  command = plan

  variables {
    retention_days                     = 120
    noncurrent_version_expiration_days = 90
  }

  # The `check` block in variables.tf: a lifecycle rule that expires versions
  # sooner than Object Lock protects them is a bucket whose own rules contradict
  # each other.
  expect_failures = [check.lifecycle_outlives_retention]
}

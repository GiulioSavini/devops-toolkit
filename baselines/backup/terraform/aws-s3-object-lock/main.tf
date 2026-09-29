# An S3 bucket that a compromised backup client cannot destroy: versioning plus
# Object Lock means a `restic forget --prune` run by an attacker with the
# repository password removes references, and the object versions survive it.
#
# What this module is really defending against: ransomware and a stolen backup
# credential. Encryption at rest defends against a stolen disk; Object Lock
# defends against a legitimate credential being used to delete the only copy.
#
# Object Lock CANNOT be enabled on a bucket that was created without it, so this
# bucket is created here with object_lock_enabled = true on the bucket resource.
# Enabling it later is a bucket migration, not a setting change.

resource "aws_s3_bucket" "backups" {
  bucket = var.bucket_name
  tags   = var.tags

  # Immutable after creation. This is the one argument that cannot be added to an
  # existing bucket.
  object_lock_enabled = true
}

# Object Lock requires versioning, and versioning is what makes a delete a
# tombstone rather than a loss.
resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    default_retention {
      mode = var.retention_mode
      days = var.retention_days
    }
  }

  # The default retention only applies to versions written AFTER this
  # configuration exists, so it must be created before the first backup runs.
  depends_on = [aws_s3_bucket_versioning.backups]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    # One data key per object is one KMS call per object. A backup repository is
    # millions of small objects; without this the KMS bill and the request rate
    # are the reason someone turns encryption off.
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "backups" {
  bucket                  = aws_s3_bucket.backups.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_expiration_days
    }

    # Incomplete multipart uploads are invisible in the object listing and are
    # billed. A backup repository writes large objects; a killed run leaves parts
    # behind, and without this rule they accumulate forever.
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.backups]
}

locals {
  # An S3 bucket ARN is region- and account-independent, so it can be built from
  # the name instead of read back from the resource. That is what makes the whole
  # policy known at plan time and therefore assertable in `terraform test` with a
  # mocked provider — a policy built from a mocked resource attribute is unknown
  # during plan and cannot be asserted on at all.
  bucket_arn = "arn:aws:s3:::${var.bucket_name}"

  # An empty allow list denies the bypass to every principal, which is the safe
  # default: a placeholder ARN that matches nothing.
  bypass_principals = length(var.bypass_governance_role_arns) > 0 ? var.bypass_governance_role_arns : ["arn:aws:iam::000000000000:role/nobody"]

  # Built with jsonencode rather than aws_iam_policy_document so the exact policy
  # is visible in plan output and assertable in `terraform test`.
  bucket_policy = {
    Version = "2012-10-17"
    Statement = [
      # Object Lock in GOVERNANCE mode is only as strong as the list of
      # principals that may bypass it. Denying the bypass to everyone except a
      # named role is what turns "governance" into an actual control.
      {
        Sid       = "DenyGovernanceBypassExceptBreakGlass"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:BypassGovernanceRetention"
        Resource  = "${local.bucket_arn}/*"
        Condition = {
          ArnNotLike = { "aws:PrincipalArn" = local.bypass_principals }
        }
      },
      # Transport security. Without this, a client can be argued into plain HTTP
      # and the repository password travels with it.
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      # Deleting the versioning configuration would take Object Lock with it.
      {
        Sid       = "DenyDisablingVersioningAndLock"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:PutBucketVersioning", "s3:PutBucketObjectLockConfiguration"]
        Resource  = local.bucket_arn
        Condition = {
          ArnNotLike = { "aws:PrincipalArn" = local.bypass_principals }
        }
      },
    ]
  }
}

resource "aws_s3_bucket_policy" "backups" {
  bucket = aws_s3_bucket.backups.id
  policy = jsonencode(local.bucket_policy)

  # The public access block must exist first, or `block_public_policy` can reject
  # a policy that is being applied in the same run.
  depends_on = [aws_s3_bucket_public_access_block.backups]
}

# AWS: S3 backend with native locking.
#
# `use_lockfile = true` makes Terraform acquire the lock with a conditional
# PutObject (If-None-Match) on "<key>.tflock" in the same bucket. It shipped in
# Terraform 1.10 and became generally available in 1.11, which is also where
# the DynamoDB locking arguments were deprecated. There is no table to
# provision, no separate IAM statement, no write-capacity to size.
#
# Migrating from DynamoDB: set `use_lockfile = true` while keeping
# `dynamodb_table`, so both locks must be acquired. Run that way until every
# copy of the configuration (laptops, runners, that one Jenkins job) has the
# new setting, then delete `dynamodb_table`. Removing the table first while an
# older config is still in use gives you two writers that cannot see each
# other's lock.
#
# Bucket prerequisites, none of which the backend block creates for you:
#   * versioning enabled — this is the only undo for a corrupted state write,
#     and the backend does not keep backups of its own
#   * a lifecycle rule expiring noncurrent versions: with versioning on, every
#     lock acquire/release adds object versions of the .tflock, which
#     accumulate forever otherwise
#   * SSE-KMS with a CMK, and a bucket policy denying unencrypted transport
#     (aws:SecureTransport = false)
#   * Block Public Access at the account level; state is the most sensitive
#     file in the repository's blast radius — it contains resource attributes
#     and, for several providers, secrets in plaintext
#   * `terraform init -backend=false` skips this block entirely, which is how
#     `validate` runs in CI with no credentials and no bucket (tests/terraform.sh)
terraform {
  required_version = ">= 1.11.0, < 2.0.0"

  backend "s3" {
    bucket = "example-org-tfstate"
    key    = "env/prod/terraform.tfstate"
    region = "eu-west-1"

    use_lockfile = true
    encrypt      = true
    kms_key_id   = "arn:aws:kms:eu-west-1:111122223333:key/11111111-2222-3333-4444-555555555555"

    # Refuse to read or write state in someone else's account, e.g. after a
    # copy-paste of this block into a different environment.
    expected_bucket_owner = "111122223333"
  }
}

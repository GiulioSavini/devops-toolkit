# S3 native locking (Terraform >= 1.10, `use_lockfile`) replaces the old
# DynamoDB-table locking pattern: no separate table to provision, IAM policy,
# or throttling limits to size. Terraform acquires the lock with a
# conditional (If-None-Match) PutObject on "<key>.tflock" next to the state
# object, and both need to be reachable by whoever/whatever runs plan/apply.
#
# DynamoDB locking (`dynamodb_table`) still works and, if already set, both
# mechanisms are honored simultaneously — but it is on a deprecation path,
# do not wire it into new backends.
#
# `-backend=false` (used by `terraform init` in CI/tests/terraform.sh) skips
# this block entirely, so `terraform validate` never needs real AWS
# credentials or a real bucket to exist.
terraform {
  backend "s3" {
    bucket       = "example-org-tfstate"
    key          = "devops-toolkit/example/terraform.tfstate"
    region       = "eu-west-1"
    use_lockfile = true
    encrypt      = true # SSE-S3 by default; set kms_key_id for SSE-KMS
  }
}

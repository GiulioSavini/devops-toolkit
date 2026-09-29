terraform {
  # Floor, not a pin: 1.11 is where S3 native state locking (`use_lockfile`,
  # see backend.tf) became generally available and the DynamoDB locking
  # arguments were deprecated. Ceiling stops a 2.x with breaking changes from
  # being picked up by a runner that happens to have it installed.
  required_version = ">= 1.11.0, < 2.0.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # Pessimistic constraint on the major: allows 6.x bug fixes and new
      # resources, refuses 7.0. The exact build that runs is decided by
      # .terraform.lock.hcl, not by this line.
      version = "~> 6.0"
    }
  }
}

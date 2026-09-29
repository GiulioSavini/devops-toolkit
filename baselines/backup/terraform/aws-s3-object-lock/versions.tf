terraform {
  # Floor: 1.9 is where the `terraform test` `run` blocks and variable
  # validation used by tests/ are stable. The upper bound stops a 2.x with
  # breaking changes from being picked up by whatever runner has it installed.
  required_version = ">= 1.9.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

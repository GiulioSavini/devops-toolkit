terraform {
  # A module's floor should be the oldest version it actually works on, not
  # the newest the caller happens to run: raising it here breaks every
  # consumer. The root module (example/root) is where the stricter floor and
  # the upper bound belong.
  required_version = ">= 1.9.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

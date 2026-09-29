# No `assume_role` / `assume_role_with_web_identity` block here on purpose.
# In CI, aws-actions/configure-aws-credentials (or the GitLab OIDC
# equivalent) exchanges the platform's OIDC token for short-lived AWS
# credentials *before* Terraform runs and exports them as
# AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN. The AWS
# provider picks those up from the standard credential chain with zero
# provider configuration, and the same config still works unchanged for a
# human running `terraform plan` locally with `aws sso login` credentials.
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy = "terraform"
      Repo      = "devops-toolkit-example"
    }
  }
}

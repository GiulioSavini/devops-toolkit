locals {
  issuer_host = "token.actions.githubusercontent.com"

  oidc_provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn

  # Built with jsonencode rather than aws_iam_policy_document so the exact
  # policy is visible in plan output and assertable in `terraform test`.
  trust_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "GitHubActionsOIDC"
        Effect    = "Allow"
        Action    = "sts:AssumeRoleWithWebIdentity"
        Principal = { Federated = local.oidc_provider_arn }
        Condition = {
          StringEquals = {
            "${local.issuer_host}:aud" = "sts.amazonaws.com"
            # StringEquals, never StringLike: exact subjects only.
            "${local.issuer_host}:sub" = var.allowed_subjects
          }
        }
      }
    ]
  }
}

# AWS validates GitHub's JWKS endpoint against its own trusted CA library, so
# no thumbprint is needed; thumbprint_list is optional in provider v6.
resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url            = "https://${local.issuer_host}"
  client_id_list = ["sts.amazonaws.com"]
  tags           = var.tags
}

data "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 0 : 1

  url = "https://${local.issuer_host}"
}

resource "aws_iam_role" "github" {
  name                 = var.role_name
  assume_role_policy   = jsonencode(local.trust_policy)
  max_session_duration = var.max_session_duration
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.tags
}

resource "aws_iam_role_policy_attachment" "github" {
  for_each = toset(var.policy_arns)

  role       = aws_iam_role.github.name
  policy_arn = each.value
}

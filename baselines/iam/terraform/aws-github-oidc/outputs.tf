output "role_arn" {
  description = "Pass to aws-actions/configure-aws-credentials as role-to-assume."
  value       = aws_iam_role.github.arn
}

output "trust_policy_json" {
  description = "Rendered trust policy, for review."
  value       = jsonencode(local.trust_policy)
}

output "analyzer_arn" {
  description = "ARN of the unused-access analyzer."
  value       = aws_accessanalyzer_analyzer.unused.arn
}

output "analyzer_type" {
  description = "Resolved analyzer type, e.g. ORGANIZATION_UNUSED_ACCESS."
  value       = aws_accessanalyzer_analyzer.unused.type
}

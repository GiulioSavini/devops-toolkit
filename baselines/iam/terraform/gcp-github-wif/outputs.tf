output "workload_identity_provider" {
  description = "Pass to google-github-actions/auth as workload_identity_provider."
  value       = "projects/${var.project_number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.github.workload_identity_pool_id}/providers/${google_iam_workload_identity_pool_provider.github.workload_identity_pool_provider_id}"
}

output "service_account_email" {
  description = "Pass to google-github-actions/auth as service_account."
  value       = google_service_account.github.email
}

output "bucket_name" {
  description = "Name of the backup bucket."
  value       = aws_s3_bucket.backups.id
}

output "bucket_arn" {
  description = "ARN of the backup bucket."
  value       = aws_s3_bucket.backups.arn
}

output "restic_repository" {
  description = "Value for RESTIC_REPOSITORY, with the per-host path still to be appended."
  value       = "s3:s3.amazonaws.com/${aws_s3_bucket.backups.id}"
}

output "object_lock_retention" {
  description = "The default retention actually configured, as mode/days."
  value       = "${var.retention_mode}/${var.retention_days}"
}

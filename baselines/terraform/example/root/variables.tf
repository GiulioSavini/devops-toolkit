variable "aws_region" {
  description = "AWS region for the provider and the resources it manages."
  type        = string
  default     = "eu-west-1"
}

variable "bucket_name" {
  description = "Name of the example S3 bucket."
  type        = string
  default     = "example-org-app-data"
}

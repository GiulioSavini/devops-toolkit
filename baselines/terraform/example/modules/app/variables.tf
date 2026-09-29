variable "bucket_name" {
  description = "Name of the S3 bucket used by this example app."
  type        = string
}

variable "tags" {
  description = "Tags applied to every resource this module creates."
  type        = map(string)
  default     = {}
}

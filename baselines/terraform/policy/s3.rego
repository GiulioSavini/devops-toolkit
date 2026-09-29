# Policy-as-code gate for the example module. Run two ways:
#   conftest verify -p policy                 unit-tests the rules themselves
#                                              (s3_test.rego), no .tf needed.
#   conftest test -p policy example/modules/app/main.tf
#                                              runs the rules against real
#                                              Terraform source (conftest's
#                                              built-in HCL parser turns each
#                                              resource block into the
#                                              `resource.<type>.<name>[]`
#                                              shape matched below).
package main

import rego.v1

# --- S3 buckets must not allow public access -------------------------------

deny contains msg if {
	some name
	block := input.resource.aws_s3_bucket_public_access_block[name][_]
	not all_public_access_blocked(block)
	msg := sprintf(
		"aws_s3_bucket_public_access_block.%s must block all four public-access vectors (block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets)",
		[name],
	)
}

all_public_access_blocked(block) if {
	block.block_public_acls == true
	block.block_public_policy == true
	block.ignore_public_acls == true
	block.restrict_public_buckets == true
}

# --- every bucket needs a matching public_access_block ----------------------

deny contains msg if {
	some name
	input.resource.aws_s3_bucket[name]
	not input.resource.aws_s3_bucket_public_access_block[name]
	msg := sprintf(
		"aws_s3_bucket.%s has no matching aws_s3_bucket_public_access_block.%s — buckets default to private, but nothing here pins that",
		[name, name],
	)
}

# --- server-side encryption must be configured, and not disabled -----------

deny contains msg if {
	some name
	input.resource.aws_s3_bucket[name]
	not input.resource.aws_s3_bucket_server_side_encryption_configuration[name]
	msg := sprintf(
		"aws_s3_bucket.%s has no aws_s3_bucket_server_side_encryption_configuration.%s — state and objects would be stored unencrypted at rest",
		[name, name],
	)
}

deny contains msg if {
	some name
	cfg := input.resource.aws_s3_bucket_server_side_encryption_configuration[name][_]
	rule := cfg.rule[_]
	default_sse := rule.apply_server_side_encryption_by_default[_]
	algo := default_sse.sse_algorithm
	not algo in {"aws:kms", "AES256"}
	msg := sprintf(
		"aws_s3_bucket_server_side_encryption_configuration.%s uses sse_algorithm %q, must be aws:kms or AES256",
		[name, algo],
	)
}

# --- versioning must be enabled (state recovery, ransomware/accidental-delete) --

deny contains msg if {
	some name
	input.resource.aws_s3_bucket[name]
	not input.resource.aws_s3_bucket_versioning[name]
	msg := sprintf(
		"aws_s3_bucket.%s has no aws_s3_bucket_versioning.%s configured",
		[name, name],
	)
}

deny contains msg if {
	some name
	v := input.resource.aws_s3_bucket_versioning[name][_]
	status := v.versioning_configuration[_].status
	status != "Enabled"
	msg := sprintf(
		"aws_s3_bucket_versioning.%s status is %q, must be \"Enabled\"",
		[name, status],
	)
}

package main

import rego.v1

good_input := {"resource": {
	"aws_s3_bucket": {"this": [{"bucket": "example"}]},
	"aws_s3_bucket_public_access_block": {"this": [{
		"block_public_acls": true,
		"block_public_policy": true,
		"ignore_public_acls": true,
		"restrict_public_buckets": true,
	}]},
	"aws_s3_bucket_server_side_encryption_configuration": {"this": [{"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}]},
	"aws_s3_bucket_versioning": {"this": [{"versioning_configuration": [{"status": "Enabled"}]}]},
}}

test_compliant_bucket_has_no_denials if {
	count(deny) == 0 with input as good_input
}

test_public_access_block_missing_flag_is_denied if {
	bad := object.union(good_input, {"resource": object.union(good_input.resource, {
		"aws_s3_bucket_public_access_block": {"this": [{
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": true,
			"restrict_public_buckets": false, # <- violation
		}]},
	})})

	some msg in deny with input as bad
	contains(msg, "must block all four public-access vectors")
}

test_missing_public_access_block_resource_is_denied if {
	bad := {"resource": {"aws_s3_bucket": good_input.resource.aws_s3_bucket}}
	some msg in deny with input as bad
	contains(msg, "no matching aws_s3_bucket_public_access_block")
}

test_missing_encryption_is_denied if {
	bad := object.remove(good_input.resource, ["aws_s3_bucket_server_side_encryption_configuration"])
	some msg in deny with input as {"resource": bad}
	contains(msg, "no aws_s3_bucket_server_side_encryption_configuration")
}

test_weak_sse_algorithm_is_denied if {
	bad := object.union(good_input, {"resource": object.union(good_input.resource, {
		"aws_s3_bucket_server_side_encryption_configuration": {"this": [{"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "none"}]}]}]},
	})})

	some msg in deny with input as bad
	contains(msg, "must be aws:kms or AES256")
}

test_versioning_disabled_is_denied if {
	bad := object.union(good_input, {"resource": object.union(good_input.resource, {
		"aws_s3_bucket_versioning": {"this": [{"versioning_configuration": [{"status": "Suspended"}]}]},
	})})

	some msg in deny with input as bad
	contains(msg, "must be \"Enabled\"")
}

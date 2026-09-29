# OpenTofu: state and plan encryption on top of an S3 backend.
#
# This is the one capability with no Terraform equivalent. Terraform's
# `encrypt = true` is *server-side* encryption: S3 decrypts the object for
# anyone with s3:GetObject, so any principal that can read the bucket reads
# your state in plaintext, and so can anyone who ends up with a copy of the
# file. OpenTofu's `encryption` block encrypts the state *before* it leaves the
# process (AES-GCM with a data key from a KMS-held key), so the bucket only
# ever holds ciphertext and the S3 read permission alone is not enough.
#
# Available since OpenTofu 1.7. Validate this file with `tofu validate`:
# `terraform validate` rejects the encryption block outright, which is the
# clearest possible signal that this is not portable between the two tools.
#
# Rollout order matters, and getting it wrong locks you out of your own state:
#   1. add the block with `enforced = false` and a `fallback` method of
#      `unencrypted` — reads accept plaintext, writes produce ciphertext
#   2. run a plan/apply (or `tofu state push`) once per workspace so every
#      state object is rewritten encrypted
#   3. remove the fallback and set `enforced = true`, which makes a plaintext
#      state a hard error instead of a silent downgrade
# Reverse the order to decrypt. Keep the key's ARN in the config and the key
# itself undeletable — a destroyed KMS key is a destroyed state file, and the
# recovery path is rebuilding state by hand with `tofu import`.
terraform {
  required_version = ">= 1.7.0"

  encryption {
    key_provider "aws_kms" "state" {
      kms_key_id = "arn:aws:kms:eu-west-1:111122223333:key/11111111-2222-3333-4444-555555555555"
      region     = "eu-west-1"
      key_spec   = "AES_256"
    }

    method "aes_gcm" "state" {
      keys = key_provider.aws_kms.state
    }

    state {
      method   = method.aes_gcm.state
      enforced = true
    }

    # The plan file is not a lesser secret: it contains the same attribute
    # values as the state, plus everything about to change. CI artifacts
    # outlive the job that made them.
    plan {
      method   = method.aes_gcm.state
      enforced = true
    }
  }

  backend "s3" {
    bucket       = "example-org-tfstate"
    key          = "env/prod/terraform.tfstate"
    region       = "eu-west-1"
    use_lockfile = true # OpenTofu's s3 backend implements this too
    encrypt      = true # server-side encryption as well: defence in depth
  }
}

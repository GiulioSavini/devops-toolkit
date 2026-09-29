# GCP: GCS backend.
#
# Locking is built in and not configurable: the backend writes a
# "<prefix>/default.tflock" object with an x-goog-if-generation-match: 0
# precondition, which is the same conditional-write trick the S3 backend now
# uses. Nothing to provision.
#
# Encryption: objects are encrypted with Google-managed keys by default. Set
# `kms_encryption_key` to hold the key yourself — that is the version that
# survives the "prove the data is unreadable without a key we control" audit
# question. `encryption_key` (customer-supplied, raw base64 AES-256) exists
# too, but then the key material has to live somewhere in the runner
# environment, which is usually a worse trade than KMS.
#
# Bucket prerequisites: object versioning, uniform bucket-level access,
# public access prevention enforced, and a lifecycle rule capping noncurrent
# versions. Grant the CI identity roles/storage.objectAdmin on the bucket
# only — not project-level storage admin.
terraform {
  required_version = ">= 1.11.0, < 2.0.0"

  backend "gcs" {
    bucket = "example-org-tfstate"
    prefix = "env/prod"

    kms_encryption_key = "projects/example-org/locations/europe-west1/keyRings/tfstate/cryptoKeys/state"
  }
}

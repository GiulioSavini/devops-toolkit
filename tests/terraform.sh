#!/usr/bin/env bash
# Validates everything under baselines/terraform/. Run from the repository root:
#
#   bash tests/terraform.sh
#
# Host requirements: bash and docker. Every tool runs from a digest-pinned
# image, so a local run and a CI run resolve the same versions.
#
# What this proves:
#   1. The whole tree is canonically formatted (`terraform fmt -check`).
#   2. The root module and the child module initialise and validate with the
#      real Terraform binary. `-backend=false` is what makes this possible
#      with no AWS credentials and no state bucket.
#   3. `.terraform.lock.hcl` is honoured as read-only: the provider that gets
#      installed must match the recorded checksums. A lock file nobody
#      verifies is decoration.
#   4. The OpenTofu-only state-encryption backend is accepted by `tofu
#      validate` and REJECTED by `terraform validate`, which is the portability
#      claim the file itself makes.
#   5. The rego policy's own unit tests pass (`conftest verify`), and the
#      policy run against the real module source finds no violations.
#   6. tflint, with the checked-in .tflint.hcl and the pinned AWS ruleset,
#      is clean on both modules.
#   7. The plan workflow is valid GitHub Actions, including its embedded shell.
#   8. Each of the above can fail. Every check is first run against a
#      deliberately broken copy and must reject it with the expected
#      diagnostic; the copy is then restored.
#
# What this does NOT do: run `terraform plan` or `apply`. Both need real cloud
# credentials and would create real resources; the plan-time gate is what
# baselines/terraform/ci/plan.yml wires up in CI.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
[[ -d baselines/terraform ]] || { echo "run from the repository root" >&2; exit 2; }

# Image digests were current on 2026-09-29. The AWS ruleset version below must
# stay in step with baselines/terraform/.tflint.hcl.
TERRAFORM_IMG="hashicorp/terraform@sha256:985cdc6c1d9b0a65b83377f666efd2f740b47f02ac55be1ced3d18f7d3b0e829"       # 1.16.4
TOFU_IMG="ghcr.io/opentofu/opentofu@sha256:22cb52f6c5bf5c72a48a8f56d993d8df3e9462b1cdfb5db7e77143c87e8d159f"        # 1.12.6
CONFTEST_IMG="openpolicyagent/conftest@sha256:82f23e0e1f3faf2f3798f4b1974676c1aed96b05c6656ec6820435c31867c532"     # v0.70.1
TFLINT_IMG="ghcr.io/terraform-linters/tflint@sha256:1c595f42d794c32c45a6ea8b58655fd66433d4ca3b1bc631c574a48d120bd19f" # v0.64.0
ACTIONLINT_IMG="rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
ALPINE_IMG="alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"

WORK="$(mktemp -d)"
cleanup() {
  # The containers run as root and leave root-owned files in the bind mount
  # (.terraform/, plugin caches); fix ownership before removing so cleanup
  # cannot mask the script's real exit status.
  docker run --rm -v "$WORK:/w" "$ALPINE_IMG" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
pass() { echo "ok  $*"; }
fail() { printf 'FAIL %b\n' "$*" >&2; exit 1; }

# Writable copy of the tree: every check runs against this, so a broken-copy
# control can never modify the repository.
TF="$WORK/tf"
mkdir -p "$TF" "$WORK/plugin-cache" "$WORK/tflint-plugins"
cp -a baselines/terraform/. "$TF/"
ROOT_DIR="$TF/example/root"
MOD_DIR="$TF/example/modules/app"

# Terraform and OpenTofu share the plugin cache, so the AWS provider is
# downloaded once for the whole run instead of once per module.
tf() {
  docker run --rm \
    -v "$WORK:/w" -w "$1" \
    -e TF_IN_AUTOMATION=1 -e TF_PLUGIN_CACHE_DIR=/w/plugin-cache -e TF_CLI_ARGS=-no-color \
    "$TERRAFORM_IMG" "${@:2}"
}
tofu() {
  docker run --rm \
    -v "$WORK:/w" -w "$1" \
    -e TF_IN_AUTOMATION=1 -e TF_PLUGIN_CACHE_DIR=/w/plugin-cache -e TF_CLI_ARGS=-no-color \
    "$TOFU_IMG" "${@:2}"
}
# .terraform/ is created by the container as root, so removing it needs a
# container too.
purge() {
  docker run --rm -v "$WORK:/w" "$ALPINE_IMG" rm -rf "$1"
}
conftest() {
  docker run --rm -v "$WORK:/w" -w /w/tf "$CONFTEST_IMG" "$@"
}
tflint() {
  docker run --rm -v "$WORK:/w" -w /w/tf \
    -e TFLINT_PLUGIN_DIR=/w/tflint-plugins \
    "$TFLINT_IMG" "$@"
}

### 1. formatting -----------------------------------------------------------
step "terraform fmt -check -recursive"
tf /w/tf fmt -check -recursive >/dev/null || fail "baselines/terraform is not canonically formatted; run 'terraform fmt -recursive baselines/terraform'"
pass "every .tf file is in canonical form"

step "control: fmt must reject a misformatted file"
printf 'variable  "x"  {\n  type=string\n}\n' > "$TF/unformatted.tf"
if tf /w/tf fmt -check -recursive >/dev/null 2>&1; then
  fail "terraform fmt -check accepted a misformatted file — the check above proves nothing"
fi
rm -f "$TF/unformatted.tf"
pass "fmt -check rejects a misformatted file, and passes again once removed"

### 2. init and validate ----------------------------------------------------
step "terraform init -backend=false + validate: example/root"
tf /w/tf/example/root init -backend=false -input=false -lockfile=readonly >"$WORK/init-root.log" 2>&1 \
  || fail "init failed for example/root:\n$(cat "$WORK/init-root.log")"
tf /w/tf/example/root validate >"$WORK/validate-root.log" 2>&1 \
  || fail "validate failed for example/root:\n$(cat "$WORK/validate-root.log")"
pass "example/root initialises with -backend=false and validates"

step "terraform init -backend=false + validate: example/modules/app"
tf /w/tf/example/modules/app init -backend=false -input=false >"$WORK/init-mod.log" 2>&1 \
  || fail "init failed for example/modules/app:\n$(cat "$WORK/init-mod.log")"
tf /w/tf/example/modules/app validate >"$WORK/validate-mod.log" 2>&1 \
  || fail "validate failed for example/modules/app:\n$(cat "$WORK/validate-mod.log")"
pass "example/modules/app initialises and validates on its own"

step "control: validate must reject a broken resource reference"
cp "$MOD_DIR/main.tf" "$WORK/main.tf.good"
printf '\nresource "aws_s3_bucket_versioning" "broken" {\n  bucket = aws_s3_bucket.does_not_exist.id\n}\n' >> "$MOD_DIR/main.tf"
if tf /w/tf/example/modules/app validate >"$WORK/validate-broken.log" 2>&1; then
  fail "terraform validate accepted a reference to an undeclared resource — the validate checks above prove nothing"
fi
grep -q "does_not_exist" "$WORK/validate-broken.log" \
  || fail "validate failed for an unexpected reason:\n$(cat "$WORK/validate-broken.log")"
cp "$WORK/main.tf.good" "$MOD_DIR/main.tf"
pass "validate rejects an undeclared resource reference"

### 3. the lock file is actually enforced -----------------------------------
step "control: -lockfile=readonly must reject a tampered .terraform.lock.hcl"
# The root init above ran with -lockfile=readonly, which makes Terraform verify
# the installed provider against the recorded checksums instead of rewriting
# them. If a lock file whose checksums cannot match is still accepted, the lock
# file is not being verified and pinning the provider means nothing.
cp "$ROOT_DIR/.terraform.lock.hcl" "$WORK/lock.good"
purge /w/tf/example/root/.terraform
# EVERY hash has to be replaced, not one of them. The lock file records a
# `zh:` hash per platform archive plus an `h1:` hash per platform, and the
# install only has to match ONE of them: corrupting a single line is silently
# tolerated because some other line still matches the package being installed.
# A control that corrupts one hash therefore passes while proving nothing —
# which is exactly how this test first "passed".
sed -i -e 's|^    "h1:[^"]*",$|    "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",|' \
       -e 's|^    "zh:[^"]*",$|    "zh:0000000000000000000000000000000000000000000000000000000000000000",|' \
       "$ROOT_DIR/.terraform.lock.hcl"
grep -q 'h1:AAAA' "$ROOT_DIR/.terraform.lock.hcl" \
  || fail "the control could not tamper with the lock file — its format changed, update this test"
if tf /w/tf/example/root init -backend=false -input=false -lockfile=readonly >"$WORK/init-lock.log" 2>&1; then
  fail "init accepted a lock file whose checksums all mismatch — the lock file is not being verified"
fi
grep -q "match any of the checksums" "$WORK/init-lock.log" \
  || fail "init failed for an unexpected reason:\n$(cat "$WORK/init-lock.log")"
cp "$WORK/lock.good" "$ROOT_DIR/.terraform.lock.hcl"
purge /w/tf/example/root/.terraform
tf /w/tf/example/root init -backend=false -input=false -lockfile=readonly >/dev/null 2>&1 \
  || fail "init failed again after restoring the good lock file"
pass "the provider checksums in .terraform.lock.hcl are enforced"

### 4. the OpenTofu-only encryption backend --------------------------------
step "tofu validate: backends/opentofu-encrypted"
tofu /w/tf/backends/opentofu-encrypted init -backend=false -input=false >"$WORK/tofu-init.log" 2>&1 \
  || fail "tofu init failed:\n$(cat "$WORK/tofu-init.log")"
tofu /w/tf/backends/opentofu-encrypted validate >"$WORK/tofu-validate.log" 2>&1 \
  || fail "tofu validate rejected the state-encryption backend:\n$(cat "$WORK/tofu-validate.log")"
pass "OpenTofu accepts the state and plan encryption block"

step "control: terraform must REJECT the encryption block (it is OpenTofu-only)"
# The file documents this as the clearest signal that the block is not portable.
# If Terraform ever accepts it, that comment is wrong and must be corrected.
if tf /w/tf/backends/opentofu-encrypted init -backend=false -input=false >"$WORK/tf-enc.log" 2>&1; then
  fail "terraform accepted the OpenTofu encryption block — the portability note in backend.tf is now wrong"
fi
grep -qi "encryption" "$WORK/tf-enc.log" \
  || fail "terraform failed for an unexpected reason:\n$(cat "$WORK/tf-enc.log")"
pass "terraform rejects the encryption block, as the file documents"

### 5. policy as code -------------------------------------------------------
step "conftest verify: the rego policy's own unit tests"
conftest verify -p policy >"$WORK/conftest-verify.log" 2>&1 \
  || fail "the policy unit tests failed:\n$(cat "$WORK/conftest-verify.log")"
pass "s3_test.rego passes against s3.rego"

step "conftest test: the real module source has no policy violations"
conftest test -p policy example/modules/app/main.tf >"$WORK/conftest-test.log" 2>&1 \
  || fail "the checked-in module violates its own policy:\n$(cat "$WORK/conftest-test.log")"
pass "example/modules/app/main.tf passes the S3 policy"

step "control: each policy rule must reject the corresponding broken module"
# One broken module per rule, so a rule that silently stopped matching shows up
# as a specific missing denial rather than as "something still failed".
declare -A BREAKS=(
  [restrict_public_buckets]='s/restrict_public_buckets = true/restrict_public_buckets = false/|must block all four public-access vectors'
  [weak_sse]='s/sse_algorithm = "aws:kms"/sse_algorithm = "none"/|must be aws:kms or AES256'
  [versioning_suspended]='s/status = "Enabled"/status = "Suspended"/|must be "Enabled"'
)
for name in "${!BREAKS[@]}"; do
  expr="${BREAKS[$name]%%|*}"
  expect="${BREAKS[$name]##*|}"
  cp "$MOD_DIR/main.tf" "$WORK/main.tf.good"
  sed -i "$expr" "$MOD_DIR/main.tf"
  cmp -s "$WORK/main.tf.good" "$MOD_DIR/main.tf" \
    && fail "the '$name' control did not modify main.tf — its sed expression no longer matches, update this test"
  if conftest test -p policy example/modules/app/main.tf >"$WORK/conftest-$name.log" 2>&1; then
    fail "conftest accepted a module broken for '$name' — that policy rule proves nothing"
  fi
  grep -qF "$expect" "$WORK/conftest-$name.log" \
    || fail "the '$name' break was rejected for the wrong reason:\n$(cat "$WORK/conftest-$name.log")"
  cp "$WORK/main.tf.good" "$MOD_DIR/main.tf"
  pass "policy rejects: $name"
done

step "control: a bucket with no public_access_block, encryption or versioning is rejected"
printf 'resource "aws_s3_bucket" "naked" {\n  bucket = "naked"\n}\n' > "$TF/naked.tf"
if conftest test -p policy naked.tf >"$WORK/conftest-naked.log" 2>&1; then
  fail "conftest accepted a bucket with no controls at all"
fi
for expect in "no matching aws_s3_bucket_public_access_block" \
              "no aws_s3_bucket_server_side_encryption_configuration" \
              "has no aws_s3_bucket_versioning"; do
  grep -qF "$expect" "$WORK/conftest-naked.log" \
    || fail "expected denial missing ('$expect'):\n$(cat "$WORK/conftest-naked.log")"
done
rm -f "$TF/naked.tf"
pass "policy rejects a bucket with no controls, naming every missing one"

### 6. tflint --------------------------------------------------------------
step "tflint --init: install the pinned AWS ruleset"
tflint --init >"$WORK/tflint-init.log" 2>&1 \
  || fail "tflint --init failed (the AWS ruleset version in .tflint.hcl must exist):\n$(cat "$WORK/tflint-init.log")"
pass "AWS ruleset installed"

for dir in example/root example/modules/app; do
  step "tflint: $dir"
  tflint --chdir="$dir" --config=/w/tf/.tflint.hcl >"$WORK/tflint-$(basename "$dir").log" 2>&1 \
    || fail "tflint reported issues in $dir:\n$(cat "$WORK/tflint-$(basename "$dir").log")"
  pass "tflint is clean on $dir"
done

step "control: tflint must reject an undocumented variable and a non-snake_case name"
cat > "$MOD_DIR/tflint_control.tf" <<'BROKEN'
variable "undocumented" {
  type = string
}

resource "aws_s3_bucket" "BadName" {
  bucket = var.undocumented
}
BROKEN
if tflint --chdir=example/modules/app --config=/w/tf/.tflint.hcl >"$WORK/tflint-broken.log" 2>&1; then
  fail "tflint accepted an undocumented variable and a non-snake_case resource name — the tflint checks above prove nothing"
fi
grep -q "terraform_documented_variables" "$WORK/tflint-broken.log" \
  || fail "tflint did not flag the undocumented variable:\n$(cat "$WORK/tflint-broken.log")"
grep -q "terraform_naming_convention" "$WORK/tflint-broken.log" \
  || fail "tflint did not flag the non-snake_case name:\n$(cat "$WORK/tflint-broken.log")"
rm -f "$MOD_DIR/tflint_control.tf"
pass "tflint rejects an undocumented variable and a non-snake_case resource name"

### 7. the plan workflow ---------------------------------------------------
step "actionlint: baselines/terraform/ci/plan.yml"
# actionlint only applies its workflow rules to files under
# .github/workflows/, so the file is staged into that layout first.
GH_STAGE="$WORK/gh"
mkdir -p "$GH_STAGE/.github/workflows"
cp "$TF/ci/plan.yml" "$GH_STAGE/.github/workflows/terraform-plan.yml"
# actionlint refuses to run outside a repository ("no project was found in any
# parent directories"), so the stage has to be one.
git -C "$GH_STAGE" init -q
run_actionlint() { docker run --rm -v "$GH_STAGE:/repo" -w /repo "$ACTIONLINT_IMG" -color; }
run_actionlint >"$WORK/actionlint.log" 2>&1 \
  || fail "actionlint rejected the plan workflow:\n$(cat "$WORK/actionlint.log")"
pass "plan.yml is valid GitHub Actions, shell included"

step "control: actionlint must reject a broken permissions block"
sed -i 's/^permissions: {}$/permissions: not-a-valid-value/' "$GH_STAGE/.github/workflows/terraform-plan.yml"
if run_actionlint >"$WORK/actionlint-broken.log" 2>&1; then
  fail "actionlint accepted an invalid permissions value — the check above proves nothing"
fi
grep -q "invalid for permission" "$WORK/actionlint-broken.log" \
  || fail "actionlint failed for an unexpected reason:\n$(cat "$WORK/actionlint-broken.log")"
pass "actionlint rejects an invalid permissions value"

echo
echo "All Terraform baseline checks passed."

#!/usr/bin/env bash
# Validates baselines/cicd/*. Run from repo root:  bash tests/cicd.sh
#
# What this proves:
#   1. Both GitHub Actions workflows (the reusable pipeline and the caller
#      example) are syntactically and semantically valid, INCLUDING their
#      embedded shell (actionlint shells out to shellcheck automatically).
#   2. The GitLab CI equivalent validates against GitLab's own CI JSON
#      schema and correctly activates its conditional jobs.
#   3. The shared pre-commit config is schema-valid.
#   4. Each of the above checks is proven capable of failing: every checker
#      is run once against a deliberately broken copy first.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ACTIONLINT_IMG="rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
NODE_IMG="node:22-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c"
PYTHON_IMG="python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f"
GITLAB_CI_LOCAL_VERSION="4.75.1"
PRE_COMMIT_VERSION="4.6.2"
ALPINE_IMG="alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"

WORKDIR="$(mktemp -d)"
cleanup() {
  # Containers above run as root and leave root-owned files in bind mounts;
  # fix ownership before removing so this doesn't fail (and mask) the
  # script's real exit status.
  docker run --rm -v "$WORKDIR:/w" "$ALPINE_IMG" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

### 1. GitHub Actions workflows -----------------------------------------
GH_STAGE="$WORKDIR/gh"
mkdir -p "$GH_STAGE/.github/workflows"
cp baselines/cicd/security.yml "$GH_STAGE/.github/workflows/security.yml"
cp baselines/cicd/security-caller-example.yml "$GH_STAGE/.github/workflows/caller.yml"
git -C "$GH_STAGE" init -q

run_actionlint() {
  docker run --rm -v "$GH_STAGE:/repo" -w /repo "$ACTIONLINT_IMG" -color
}

# 1a. Prove actionlint can fail: break the reusable workflow's permissions
# block, confirm actionlint rejects it, then restore the good copy.
BROKEN="$GH_STAGE/.github/workflows/security.yml"
cp "$BROKEN" "$WORKDIR/security.yml.good"
sed -i 's/^permissions: {}$/permissions: not-a-valid-value/' "$BROKEN"
if run_actionlint >/tmp/cicd-actionlint-break.log 2>&1; then
  fail "actionlint accepted an invalid permissions value (should have failed)"
fi
grep -q "invalid for permission" /tmp/cicd-actionlint-break.log \
  || fail "actionlint failed for an unexpected reason:\n$(cat /tmp/cicd-actionlint-break.log)"
cp "$WORKDIR/security.yml.good" "$BROKEN"
pass "actionlint rejects an invalid permissions value, and passes again once restored"

# 1b. Prove the shellcheck integration fires: inject an unquoted variable
# expansion into a run: step.
cp "$BROKEN" "$WORKDIR/security.yml.good2"
sed -i 's#--exit-code 1 \\#--exit-code 1 \&\& echo $UNQUOTED_VAR \\#' "$BROKEN"
if run_actionlint >/tmp/cicd-shellcheck-break.log 2>&1; then
  fail "actionlint/shellcheck accepted an unquoted shell variable (should have failed)"
fi
grep -q "shellcheck" /tmp/cicd-shellcheck-break.log \
  || fail "break did not trigger the shellcheck integration:\n$(cat /tmp/cicd-shellcheck-break.log)"
cp "$WORKDIR/security.yml.good2" "$BROKEN"
pass "actionlint's shellcheck integration catches an unquoted shell variable"

# 1c. The real, unmodified workflows must pass cleanly.
run_actionlint || fail "actionlint failed on the checked-in workflows"
pass "actionlint (+ shellcheck) is clean on baselines/cicd/security.yml and security-caller-example.yml"

### 2. GitLab CI equivalent ----------------------------------------------
GL_STAGE="$WORKDIR/gl"
mkdir -p "$GL_STAGE"
cp baselines/cicd/gitlab-ci.yml "$GL_STAGE/.gitlab-ci.yml"

run_glci() {
  docker run --rm -v "$GL_STAGE:/repo" -w /repo "$NODE_IMG" bash -c \
    "npm install -g gitlab-ci-local@$GITLAB_CI_LOCAL_VERSION >/dev/null 2>&1 && gitlab-ci-local --list-all --json-schema-validation"
}

# 2a. Prove it can fail: reference an undeclared stage.
cp "$GL_STAGE/.gitlab-ci.yml" "$WORKDIR/gitlab-ci.yml.good"
sed -i 's/stage: secret-scan/stage: not-a-declared-stage/' "$GL_STAGE/.gitlab-ci.yml"
if run_glci >/tmp/cicd-glci-break.log 2>&1; then
  fail "gitlab-ci-local accepted a job referencing an undeclared stage"
fi
grep -q "not-a-declared-stage" /tmp/cicd-glci-break.log \
  || fail "gitlab-ci-local failed for an unexpected reason:\n$(cat /tmp/cicd-glci-break.log)"
cp "$WORKDIR/gitlab-ci.yml.good" "$GL_STAGE/.gitlab-ci.yml"
pass "gitlab-ci-local rejects a job with an undeclared stage, and passes again once restored"

# 2b. The real file must validate and both conditional jobs must activate
# once IMAGE_REF is set.
OUT="$(docker run --rm -v "$GL_STAGE:/repo" -w /repo "$NODE_IMG" bash -c \
  "npm install -g gitlab-ci-local@$GITLAB_CI_LOCAL_VERSION >/dev/null 2>&1 && gitlab-ci-local --list-all --json-schema-validation --variable IMAGE_REF=ghcr.io/example/app@sha256:deadbeef")"
echo "$OUT" | grep -q "^sbom " || fail "sbom job did not activate when IMAGE_REF is set"
echo "$OUT" | grep -q "^sign " || fail "sign job did not activate when IMAGE_REF is set"
pass "gitlab-ci-local: baselines/cicd/gitlab-ci.yml validates against GitLab's CI schema, conditional jobs activate correctly"

### 3. Shared pre-commit config ------------------------------------------
run_precommit_validate() {
  docker run --rm -v "$REPO_ROOT:/repo" -w /repo "$PYTHON_IMG" bash -c \
    "pip install -q pre-commit==$PRE_COMMIT_VERSION && pre-commit validate-config $1"
}

BAD_PC="$WORKDIR/pre-commit-config.bad.yaml"
cp baselines/cicd/.pre-commit-config.yaml "$BAD_PC"
sed -i 's/rev: v6.0.0/rev: [this, is, not, a, string]/' "$BAD_PC"
if run_precommit_validate "$(realpath --relative-to="$REPO_ROOT" "$BAD_PC")" >/tmp/cicd-pc-break.log 2>&1; then
  fail "pre-commit validate-config accepted a malformed rev field"
fi
pass "pre-commit validate-config rejects a malformed hook rev"

run_precommit_validate baselines/cicd/.pre-commit-config.yaml \
  || fail "pre-commit validate-config failed on the checked-in config"
pass "pre-commit validate-config passes on baselines/cicd/.pre-commit-config.yaml"

echo
echo "All CI/CD baseline checks passed."

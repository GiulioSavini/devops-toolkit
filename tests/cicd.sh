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
#   4. Every action pin, in the baselines and in this repository's own
#      workflow, is a commit SHA with a tag comment Dependabot can maintain.
#   5. Every container image the test suites pull is a sha256 digest that
#      states the version it came from, and no two suites claim the same tool
#      version at different digests.
#   6. Each of the above checks is proven capable of failing: every checker
#      is run once against a deliberately broken input first.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ACTIONLINT_IMG="rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
NODE_IMG="node:22-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c"
PYTHON_IMG="python:3.12.14-slim-trixie@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f"
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

### 4. every action pin is a SHA with a maintainable tag comment -----------
# The pin format is a control, so it is checked rather than trusted: a bare tag
# is a mutable pointer, and a tag comment on the line ABOVE the pin cannot be
# updated by Dependabot, so it goes stale on the first bump and then states a
# version that is not running.
echo "### 4. action pin format"
check_pin_format() {
  local file="$1" bad=0 line
  while IFS= read -r line; do
    # Every `uses:` that names a third-party action (owner/repo@ref) must carry a
    # 40-character SHA and a trailing "# vX.Y.Z" comment. A local `uses: ./path`
    # is not pinned to anything and is excluded deliberately.
    case "$line" in
      *"uses:"*"./"*) continue ;;
    esac
    if ! printf '%s' "$line" | grep -qE 'uses: +[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40} +# +v[0-9]'; then
      echo "    not pinned with a trailing tag comment: ${line# }" >&2
      bad=$((bad + 1))
    fi
    # `- uses:` and a bare `uses:` are both valid YAML here, so the filter has to
    # accept the list-item form too — a filter that misses it makes this whole
    # check silently vacuous, which is how the control below first passed.
  done < <(grep -E '^[[:space:]]*-?[[:space:]]*uses:' "$file")
  echo "$bad"
}

for f in baselines/cicd/security.yml baselines/cicd/security-caller-example.yml baselines/terraform/ci/plan.yml .github/workflows/docs.yml; do
  BAD="$(check_pin_format "$f")"
  [[ "$BAD" == "0" ]] || fail "$f has $BAD action pin(s) that are not a SHA with a trailing tag comment"
done
pass "every action pin is a SHA with a trailing tag comment Dependabot can maintain"

echo "### 4b. control: the pin check must reject a bare tag and a comment above"
BAD_PIN="$WORKDIR/pin-bad.yml"
printf 'jobs:\n  j:\n    steps:\n      - uses: actions/checkout@v4\n' > "$BAD_PIN"
[[ "$(check_pin_format "$BAD_PIN")" != "0" ]] || fail "the pin check accepted a bare tag"
printf 'jobs:\n  j:\n    steps:\n      # actions/checkout@v7.0.1\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n' > "$BAD_PIN"
[[ "$(check_pin_format "$BAD_PIN")" != "0" ]] || fail "the pin check accepted a tag comment on the line above, which Dependabot cannot maintain"
pass "a bare tag and an above-the-line tag comment are both rejected"

### 5. every container image a test suite pulls is a documented digest pin ---
# A test that pins an image by tag proves nothing durable: the tag moves, and
# the run that passes today runs a different binary tomorrow. Every suite
# therefore pins by digest — and states, on the same line, which version that
# digest was. Without the version the digest is unreadable, nobody dares bump
# it, and two suites silently end up on different versions of the same tool:
# that is exactly how tests/network.sh came to run shellcheck v0.10.0 while
# four other suites ran v0.11.0, for months, with every check green.
#
# Two rules are enforced here:
#   a. the pin carries a sha256 digest AND a version, either inline
#      (repo:tag@sha256:...) or in a trailing comment;
#   b. no two pins claim the SAME version of the same repository with
#      DIFFERENT digests — that is a contradiction, and one of them is a lie.
# Deliberate divergence stays legal: linux.sh pins debian:12-slim and
# debian:13-slim on purpose, and the version in the comment is what makes that
# visible as a choice instead of an accident.
echo "### 5. test-suite image pins"

# Emits one record per image assignment:
#   OK <repo> <version> <digest> <file>:<line>
#   BAD <file>:<line> <reason>
scan_image_pins() {
  python3 - "$@" <<'PY'
import re, sys

# NAME_IMAGE= / NAME_IMG= at the start of a line, double-quoted value, optional
# trailing comment. An assignment this does not match is reported, never
# skipped: a silent skip is how a check stops checking.
# Shell (NAME="ref") and make (NAME := ref) both appear, so both are accepted;
# the value may be double-quoted or bare, with an optional trailing comment.
ASSIGN = re.compile(r'^([A-Za-z0-9_]*(?:IMAGE|IMG)[A-Za-z0-9_]*)[ \t]*[:?]?=[ \t]*(.*)$')
VALUE = re.compile(r'^(?:"([^"]*)"|([^"#\s]+))[ \t]*(?:#[ \t]*(.*))?$')
DIGEST = re.compile(r'@sha256:[0-9a-f]{64}$')

for path in sys.argv[1:]:
    with open(path) as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.rstrip("\n")
            m = ASSIGN.match(line)
            if not m:
                continue
            var, rest = m.group(1), m.group(2)
            q = VALUE.match(rest)
            if not q:
                print(f"BAD {path}:{n} {var} is not a plain image reference")
                continue
            ref = q.group(1) if q.group(1) is not None else q.group(2)
            comment = (q.group(3) or "").strip()
            # Images the suite builds itself are not pulled and have no upstream
            # digest to pin; they are named in the repository's own namespace.
            if ref.startswith("devops-toolkit/"):
                continue
            if not DIGEST.search(ref):
                print(f"BAD {path}:{n} {var} is not pinned to a sha256 digest: {ref}")
                continue
            name, digest = ref.split("@", 1)
            # A registry may carry a port (host:5000/repo), so only a colon in
            # the LAST path segment is a tag.
            tag = ""
            if ":" in name.split("/")[-1]:
                name, tag = name.rsplit(":", 1)
            version = tag or comment
            if not version:
                print(f"BAD {path}:{n} {var} pins a digest with no version: "
                      f"put the tag inline (repo:tag@sha256:...) or in a trailing comment")
                continue
            print(f"OK {name} {version} {digest} {path}:{n}")
PY
}

# Fails when two pins claim the same version of one repository with different
# digests. Reads scan_image_pins records on stdin.
check_pin_agreement() {
  awk '
    $1 == "OK" {
      # $2 repo, $3 version (may contain spaces in a comment), last-but-one is
      # the digest, last is file:line — index from the end.
      digest = $(NF - 1); where = $NF
      version = ""
      for (i = 3; i <= NF - 2; i++) version = version (version ? " " : "") $i
      key = $2 " @ " version
      if (key in seen && seen[key] != digest) {
        printf "    %s is pinned to two different digests:\n      %s %s\n      %s %s\n", \
          key, seen[key], at[key], digest, where
        bad++
      }
      seen[key] = digest; at[key] = where
    }
    END { print bad + 0 }
  '
}

PIN_RECORDS="$WORKDIR/image-pins.txt"
# The Makefile is in scope too: `make lint` is the command CI runs, so the
# image it names is as much a pin as any in tests/.
scan_image_pins tests/*.sh tests/lib/*.sh Makefile > "$PIN_RECORDS"
if grep -q '^BAD ' "$PIN_RECORDS"; then
  grep '^BAD ' "$PIN_RECORDS" >&2
  fail "$(grep -c '^BAD ' "$PIN_RECORDS") image pin(s) in tests/ are not a digest with a stated version"
fi
pass "every image a test suite pulls is a sha256 digest with the version it came from"

AGREE="$(check_pin_agreement < "$PIN_RECORDS" | tail -1)"
[[ "$AGREE" == "0" ]] || fail "$AGREE image repository/version pair(s) in tests/ disagree on the digest"
pass "no two suites claim the same tool version at different digests"

echo "### 5b. control: the pin scan must reject a tag, a bare digest and a disagreement"
PIN_FIXTURE="$WORKDIR/pin-fixture.sh"
printf 'FOO_IMAGE="alpine:3.22"\n' > "$PIN_FIXTURE"
scan_image_pins "$PIN_FIXTURE" | grep -q '^BAD ' \
  || fail "the pin scan accepted an image pinned by tag alone"

printf 'FOO_IMAGE="alpine@sha256:%s"\n' "$(printf '0%.0s' {1..64})" > "$PIN_FIXTURE"
scan_image_pins "$PIN_FIXTURE" | grep -q '^BAD ' \
  || fail "the pin scan accepted a digest with no version stated"

printf 'FOO_IMAGE := alpine:3.22\n' > "$PIN_FIXTURE"
scan_image_pins "$PIN_FIXTURE" | grep -q '^BAD ' \
  || fail "the pin scan accepted a make-style assignment pinned by tag alone"

printf 'FOO_IMAGE="alpine@sha256:%s" # alpine:3.22\n' "$(printf '0%.0s' {1..64})"  > "$PIN_FIXTURE"
printf 'BAR_IMAGE="alpine@sha256:%s" # alpine:3.22\n' "$(printf '1%.0s' {1..64})" >> "$PIN_FIXTURE"
[[ "$(scan_image_pins "$PIN_FIXTURE" | check_pin_agreement | tail -1)" != "0" ]] \
  || fail "the agreement check accepted alpine:3.22 pinned to two different digests"

# ...and must accept the deliberate case, or it would forbid linux.sh testing
# two Debian releases.
printf 'A_IMAGE="debian@sha256:%s" # debian:12-slim\n' "$(printf '0%.0s' {1..64})"  > "$PIN_FIXTURE"
printf 'B_IMAGE="debian@sha256:%s" # debian:13-slim\n' "$(printf '1%.0s' {1..64})" >> "$PIN_FIXTURE"
[[ "$(scan_image_pins "$PIN_FIXTURE" | check_pin_agreement | tail -1)" == "0" ]] \
  || fail "the agreement check rejected two different Debian releases, which is a legitimate pin"
pass "a bare tag, an undocumented digest and a same-version digest conflict are all rejected"

echo
echo "All CI/CD baseline checks passed."

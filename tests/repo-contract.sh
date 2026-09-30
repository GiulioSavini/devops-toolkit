#!/usr/bin/env bash
# Validates the repository's own contract. Run from the repository root:
#
#   bash tests/repo-contract.sh
#
# Host requirements: bash. No container, because nothing here runs a third-party
# tool — every check reads files this repository owns.
#
# What this proves:
#   1. Every guide carries the five metadata rows a reader in the middle of an
#      incident needs: Applies to, Baseline files, Validated by, Lockout risk,
#      Last reviewed.
#   2. `Validated by` names at least one file under tests/ that exists. A guide
#      that claims validation by a script nobody wrote is the worst failure
#      this repository can ship, because the claim is the product.
#   3. `Last reviewed` is a YYYY-MM date, so "reviewed" is a fact with a date
#      rather than a word.
#   4. Every repository-relative link in the guides, README.md, CONTRIBUTING.md
#      and CONTROLS.md resolves to a file or directory that exists.
#   5. Every guide appears in the README table. CONTRIBUTING.md asks for this;
#      until now nothing checked it.
#   6. Every tests/*.sh is reachable from a make target, so a suite cannot be
#      added and then never run.
#   7. Each check above is proven capable of failing: it is run once against a
#      deliberately broken copy of the tree first.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
pass() { echo "ok  $*"; }
fail() { printf 'FAIL %b\n' "$*" >&2; exit 1; }

REQUIRED_ROWS=("Applies to" "Baseline files" "Validated by" "Lockout risk" "Last reviewed")

# --- the checks, each taking the tree to inspect --------------------------
# Every one prints a line per violation and nothing when the tree is clean, so
# a control asserts on output rather than on an exit status it could mistake
# for a missing file.

check_metadata_rows() {
  local root="$1" guide row
  for guide in "$root"/guides/*.md; do
    for row in "${REQUIRED_ROWS[@]}"; do
      grep -q "^| $row " "$guide" \
        || echo "${guide#$root/}: metadata table has no '$row' row"
    done
  done
}

check_validated_by() {
  local root="$1" guide line found target
  for guide in "$root"/guides/*.md; do
    line="$(grep -m1 '^| Validated by ' "$guide" || true)"
    if [[ -z "$line" ]]; then
      echo "${guide#$root/}: no 'Validated by' row to check"
      continue
    fi
    found=0
    # Every (../tests/x.sh) target on the row, without assuming there is one:
    # kubernetes-hardening.md names two suites on purpose.
    while read -r target; do
      [[ -n "$target" ]] || continue
      if [[ -f "$root/${target#../}" ]]; then
        found=1
      else
        echo "${guide#$root/}: 'Validated by' names ${target#../}, which does not exist"
      fi
    done < <(grep -oE '\(\.\./tests/[A-Za-z0-9._/-]+\)' <<<"$line" | tr -d '()')
    [[ "$found" == 1 ]] \
      || echo "${guide#$root/}: 'Validated by' names no existing file under tests/"
  done
}

check_last_reviewed() {
  local root="$1" guide value
  for guide in "$root"/guides/*.md; do
    value="$(sed -n 's/^| Last reviewed | *\([^|]*[^| ]\) *|.*/\1/p' "$guide" | head -1)"
    [[ "$value" =~ ^[0-9]{4}-(0[1-9]|1[0-2])$ ]] \
      || echo "${guide#$root/}: 'Last reviewed' is '$value', not a YYYY-MM date"
  done
}

check_relative_links() {
  local root="$1" file link target
  while IFS= read -r file; do
    # Markdown link targets that point inside the repository: no scheme, no
    # anchor-only link, no mailto.
    while read -r link; do
      [[ -n "$link" ]] || continue
      target="${link%%#*}"
      [[ -n "$target" ]] || continue
      case "$target" in
        http*|mailto:*|'') continue ;;
      esac
      # Resolve relative to the file's own directory, the way a reader's
      # browser does.
      ( cd "$(dirname "$file")" && [[ -e "$target" ]] ) \
        || echo "${file#$root/}: link target '$target' does not exist"
    done < <(grep -oE '\]\([^)]+\)' "$file" | sed -E 's/^\]\(//; s/\)$//')
  done < <(find "$root/guides" -name '*.md'; ls "$root"/README.md "$root"/CONTRIBUTING.md "$root"/CONTROLS.md 2>/dev/null)
}

check_readme_lists_every_guide() {
  local root="$1" guide name
  for guide in "$root"/guides/*.md; do
    name="guides/$(basename "$guide")"
    grep -qF "($name)" "$root/README.md" \
      || echo "$name is not linked from the README table"
  done
}

check_every_suite_runs() {
  local root="$1" suite base
  for suite in "$root"/tests/*.sh; do
    base="tests/$(basename "$suite")"
    # `make test` globs tests/*.sh and filters out the end-to-end suite, which
    # `make e2e` names explicitly. Anything else would be dead code.
    if [[ "$base" == "tests/kubernetes-e2e.sh" ]]; then
      grep -qF "bash tests/kubernetes-e2e.sh" "$root/Makefile" \
        || echo "$base is not run by any make target"
      continue
    fi
    grep -qE '^TESTS :=.*wildcard tests/\*\.sh' "$root/Makefile" \
      || echo "$base: the Makefile no longer globs tests/*.sh, so this suite may not run"
  done
}

run_all_checks() {
  local root="$1"
  check_metadata_rows "$root"
  check_validated_by "$root"
  check_last_reviewed "$root"
  check_relative_links "$root"
  check_readme_lists_every_guide "$root"
  check_every_suite_runs "$root"
}

### 1. the repository as it stands ----------------------------------------
step "the repository satisfies its own contract"
VIOLATIONS="$(run_all_checks "$ROOT_DIR")"
[[ -z "$VIOLATIONS" ]] || fail "the repository violates its own contract:\n$VIOLATIONS"

# An empty result is also what checking nothing produces, so assert the scan
# saw the tree it was pointed at.
GUIDE_COUNT="$(find guides -maxdepth 1 -name '*.md' | wc -l)"
[[ "$GUIDE_COUNT" -ge 14 ]] \
  || fail "only $GUIDE_COUNT guides were found under guides/ — either the tree moved or this scan is reading nothing"
LINK_COUNT="$(grep -ohE '\]\([^)]+\)' guides/*.md README.md CONTRIBUTING.md CONTROLS.md | wc -l)"
[[ "$LINK_COUNT" -ge 100 ]] \
  || fail "only $LINK_COUNT markdown links were found — the link scan is reading almost nothing"
pass "$GUIDE_COUNT guides, $LINK_COUNT links: metadata complete, targets resolve, every guide is in the README, every suite runs"

### 2. controls: each check must fail on a broken copy ---------------------
# A fresh copy per control, so one broken fixture cannot mask the next.
fixture() {
  local dir="$WORK/fixture-$1"
  rm -rf "$dir"; mkdir -p "$dir"
  mkdir -p "$dir/tests"
  cp -a tests/*.sh "$dir/tests/"
  # Everything the checks read, including the files the guides link to: an
  # incomplete fixture makes a control report violations it invented.
  cp -a guides baselines .github README.md CONTRIBUTING.md CONTROLS.md \
        SECURITY.md LICENSE Makefile "$dir/"
  echo "$dir"
}

# Runs one check against a fixture and asserts the expected line is in its
# output. The output is captured first: piping a multi-line producer straight
# into `grep -q` makes grep exit on the first match, which kills the producer
# with SIGPIPE and fails the pipeline under `set -o pipefail` — the control then
# reports the opposite of what happened, which is how this control first failed
# on a violation it had correctly found.
expect_violation() {
  local expected="$1"; shift
  local out
  out="$("$@")"
  grep -qF -- "$expected" <<<"$out" \
    || fail "expected a violation containing:\n  $expected\ngot:\n${out:-(nothing)}"
}

step "control: a guide missing a metadata row must be reported"
F="$(fixture rows)"
sed -i '/^| Lockout risk /d' "$F/guides/docker-security.md"
expect_violation "guides/docker-security.md: metadata table has no 'Lockout risk' row" \
  check_metadata_rows "$F"
pass "a missing metadata row is reported"

step "control: a 'Validated by' row naming a script that does not exist must be reported"
F="$(fixture validated)"
sed -i 's#^| Validated by |.*#| Validated by | [`tests/nope.sh`](../tests/nope.sh) |#' "$F/guides/docker-security.md"
expect_violation "names tests/nope.sh, which does not exist" check_validated_by "$F"
expect_violation "names no existing file under tests/" check_validated_by "$F"
pass "a 'Validated by' row pointing at a missing script is reported twice: the bad target, and the guide left with no validation at all"

step "control: a 'Last reviewed' value that is not YYYY-MM must be reported"
F="$(fixture reviewed)"
sed -i 's#^| Last reviewed |.*#| Last reviewed | recently |#' "$F/guides/docker-security.md"
expect_violation "'Last reviewed' is 'recently', not a YYYY-MM date" check_last_reviewed "$F"
pass "a 'Last reviewed' value that is not a date is reported"

step "control: a link to a file that does not exist must be reported"
F="$(fixture links)"
printf '\nSee [the missing one](../baselines/does-not-exist/config.conf).\n' >> "$F/guides/docker-security.md"
expect_violation "link target '../baselines/does-not-exist/config.conf' does not exist" \
  check_relative_links "$F"
pass "a link to a file that does not exist is reported"

step "control: a guide absent from the README table must be reported"
F="$(fixture readme)"
sed -i '\|(guides/docker-security.md)|d' "$F/README.md"
expect_violation "guides/docker-security.md is not linked from the README table" \
  check_readme_lists_every_guide "$F"
pass "a guide missing from the README table is reported"

step "control: a Makefile that stops globbing tests/*.sh must be reported"
F="$(fixture make)"
sed -i 's|^TESTS := .*|TESTS := tests/linux.sh|' "$F/Makefile"
expect_violation "the Makefile no longer globs tests/*.sh" check_every_suite_runs "$F"
pass "a Makefile that stops globbing tests/*.sh is reported"

echo
echo "All repository contract checks passed."

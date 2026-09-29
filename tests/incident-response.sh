#!/usr/bin/env bash
# Validates baselines/incident-response/. Run from the repository root:
#
#   bash tests/incident-response.sh
#
# Host requirements: bash and docker. Everything runs inside one digest-pinned
# container, because the collector reads /proc, /sys and the process table and
# writes evidence to a separate filesystem — none of which can be exercised by
# reading the script.
#
# What this proves:
#   1. ir-collect.sh passes shellcheck.
#   2. Its refusals work: no -o, a non-existent OUTDIR, a non-numeric -t, and
#      OUTDIR on the same filesystem as / are each rejected with exit 2 and the
#      documented message. The last one is the important refusal: writing
#      evidence onto the suspect filesystem overwrites unallocated blocks.
#   3. -F overrides the same-filesystem refusal, as documented.
#   4. The dry-run plan is in RFC 3227 order of volatility, with clock state
#      first. The control re-runs the same ordering check against a deliberately
#      reordered copy, which must be rejected.
#   5. A real collection on a real (container) host produces every artifact in
#      the plan, a collection-order.tsv with one row per artifact in plan order,
#      a chain-of-custody stub naming the case, and a manifest.
#   6. The manifest actually detects tampering: `sha256sum -c` passes on the
#      collected set and FAILS after one byte is appended to one artifact. A
#      manifest that cannot fail is a checksum nobody can rely on in a handover.
#   7. The per-artifact timeout works: a copy with a deliberately hung artifact
#      records exit status 124 and keeps collecting, instead of stalling the
#      whole collection.
#   8. The checklist and the collector do not contradict each other: both must
#      say isolate rather than power off, because a checklist that says reboot
#      makes the collector pointless.
#
# What this does NOT do: acquire memory (avml needs a real kernel without
# lockdown and is not shipped here), nor validate the parts of the plan whose
# tools are absent from a minimal container — the collector is designed to
# record a missing tool and continue, and this test asserts exactly that
# behaviour rather than pretending every artifact has content.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
BASE="baselines/incident-response"
[[ -d "$BASE" ]] || { echo "run from the repository root" >&2; exit 2; }

# Digests were current on 2026-09-29; the tag each belonged to is in the comment.
DEBIAN_IMAGE="debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a"          # debian:13-slim
SHELLCHECK_IMAGE="koalaman/shellcheck@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d" # koalaman/shellcheck:v0.11.0

WORK="$(mktemp -d)"
cleanup() {
  # The container runs as root and leaves root-owned evidence in the bind mount;
  # fix ownership before removing so cleanup cannot mask the real exit status.
  docker run --rm -v "$WORK:/w" "$DEBIAN_IMAGE" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
pass() { echo "ok  $*"; }
fail() { printf 'FAIL %b\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker is required: this suite runs the collector, it cannot be skipped into passing"
docker info >/dev/null 2>&1 || fail "cannot reach a docker daemon (docker info failed)"

COLLECTOR="$BASE/bin/ir-collect.sh"

# Runs a command in the container. The repository is mounted read-only so no
# check can modify it; /evidence is a tmpfs, which is both a separate
# filesystem (what the collector requires) and gone when the container exits.
in_container() {
  docker run --rm \
    -v "$ROOT:/repo:ro" -v "$WORK:/w" \
    --tmpfs /evidence:rw,size=64m \
    -w /repo "$DEBIAN_IMAGE" bash -c "$1"
}

### 1. shellcheck ----------------------------------------------------------
step "shellcheck: $COLLECTOR"
docker run --rm -v "$ROOT:/repo:ro" -w /repo "$SHELLCHECK_IMAGE" "$COLLECTOR"
pass "no shellcheck findings"

step "control: shellcheck must reject an unquoted expansion"
mkdir -p "$WORK/broken"
{ cat "$COLLECTOR"; printf '\nrm -rf $case_dir\n'; } > "$WORK/broken/ir-collect.sh"
if docker run --rm -v "$WORK:/w:ro" -w /w "$SHELLCHECK_IMAGE" broken/ir-collect.sh >/dev/null 2>&1; then
  fail "shellcheck accepted an unquoted variable in rm -rf — the check above proves nothing"
fi
pass "shellcheck rejects an unquoted expansion"

### 2. refusals ------------------------------------------------------------
step "the documented refusals"
# Each case: description | command | expected fragment of the error
while IFS='|' read -r what cmd expect; do
  [[ -n "$what" ]] || continue
  out="$(in_container "$cmd" 2>&1 || true)"
  rc_out="$(in_container "$cmd >/dev/null 2>&1; echo \$?")"
  [[ "$rc_out" == "2" ]] || fail "$what: expected exit 2, got $rc_out ($out)"
  # `--` matters: the expected fragment can start with a dash (-o, -t).
  printf '%s' "$out" | grep -qF -- "$expect" \
    || fail "$what: exit status was right but the message was not ('$expect' missing from: $out)"
  pass "refused: $what"
done <<'CASES'
no -o|bash baselines/incident-response/bin/ir-collect.sh|-o OUTDIR is required
OUTDIR does not exist|bash baselines/incident-response/bin/ir-collect.sh -o /evidence/nope|OUTDIR does not exist
non-numeric -t|bash baselines/incident-response/bin/ir-collect.sh -o /evidence -t abc|-t must be a whole number
OUTDIR on the root filesystem|mkdir -p /tmp/ev && bash baselines/incident-response/bin/ir-collect.sh -o /tmp/ev|same filesystem as /
CASES

step "-F overrides the same-filesystem refusal"
OUT="$(in_container 'mkdir -p /tmp/ev && bash baselines/incident-response/bin/ir-collect.sh -o /tmp/ev -F -n')"
printf '%s' "$OUT" | grep -q 'dry run, nothing written' \
  || fail "-F did not proceed past the filesystem check: $OUT"
pass "-F proceeds, as documented"

### 3. the plan is in order of volatility ---------------------------------
step "dry run: the plan is in RFC 3227 order of volatility"
in_container 'bash baselines/incident-response/bin/ir-collect.sh -o /evidence -n' > "$WORK/plan.txt"
grep -q '^case: ' "$WORK/plan.txt" || fail "dry run printed no case id:\n$(cat "$WORK/plan.txt")"

# The numeric prefixes encode the order; asserting they ascend is asserting the
# collection order, and the first artifact must be the clock (every later
# timestamp is only interpretable against the host's own notion of time).
plan_prefixes() { grep '^artifact:' "$1" | awk '{print $2}' | cut -d- -f1; }
check_order() {
  local file="$1" prev=-1 p
  while read -r p; do
    [[ "$p" =~ ^[0-9]+$ ]] || { echo "NONNUMERIC:$p"; return 0; }
    if (( 10#$p < prev )); then echo "OUTOFORDER:$p<$prev"; return 0; fi
    prev="$((10#$p))"
  done < <(plan_prefixes "$file")
  echo ORDERED
}
FIRST="$(grep '^artifact:' "$WORK/plan.txt" | head -1 | awk '{print $2}')"
[[ "$FIRST" == "00-clock.txt" ]] || fail "the first artifact is '$FIRST', not the clock"
VERDICT="$(check_order "$WORK/plan.txt")"
[[ "$VERDICT" == ORDERED ]] || fail "the plan is not in order of volatility: $VERDICT"
pass "clock first, then ascending order of volatility ($(grep -c '^artifact:' "$WORK/plan.txt") artifacts)"

step "control: the ordering check must reject a reordered plan"
# Swap the clock and the process table in a copy: same artifacts, wrong order.
sed -e 's/^artifact:   00-clock.txt$/artifact:   ZZ-MARK/' "$WORK/plan.txt" \
  | sed -e 's/^artifact:   10-processes.txt$/artifact:   00-clock.txt/' \
  | sed -e 's/^artifact:   ZZ-MARK$/artifact:   10-processes.txt/' > "$WORK/plan-bad.txt"
VERDICT_BAD="$(check_order "$WORK/plan-bad.txt")"
[[ "$VERDICT_BAD" != ORDERED ]] || fail "the ordering check accepted a reordered plan — it proves nothing"
pass "reordered plan rejected ($VERDICT_BAD)"

### 4. a real collection ---------------------------------------------------
step "a real collection on a live (container) host"
in_container '
  set -e
  apt-get -qq update >/dev/null 2>&1
  apt-get -qq install -y procps iproute2 coreutils >/dev/null 2>&1
  case_dir="$(bash baselines/incident-response/bin/ir-collect.sh -o /evidence -c ir-test-case -t 20)"
  cp -a "$case_dir" /w/case
  echo "$case_dir" > /w/case_dir.txt
' >/dev/null
CASE="$WORK/case"
[[ -d "$CASE" ]] || fail "no case directory was produced"
pass "collected into $(cat "$WORK/case_dir.txt")"

step "every artifact in the plan was collected"
MISSING=0
while read -r a; do
  [[ -f "$CASE/$a" ]] || { echo "    missing: $a"; MISSING=$((MISSING+1)); }
done < <(grep '^artifact:' "$WORK/plan.txt" | awk '{print $2}')
[[ "$MISSING" -eq 0 ]] || fail "$MISSING artifact(s) from the plan were not written"
pass "$(grep -c '^artifact:' "$WORK/plan.txt") artifacts present"

step "collection-order.tsv records every artifact, in the order collected"
[[ -f "$CASE/collection-order.tsv" ]] || fail "no collection-order.tsv"
head -1 "$CASE/collection-order.tsv" | grep -q $'^utc\tartifact\texit_status$' \
  || fail "collection-order.tsv has no header row"
LOGGED="$(tail -n +2 "$CASE/collection-order.tsv" | cut -f2)"
PLANNED="$(grep '^artifact:' "$WORK/plan.txt" | awk '{print $2}')"
[[ "$LOGGED" == "$PLANNED" ]] || fail "the collection order does not match the plan:\nlogged:\n$LOGGED\nplanned:\n$PLANNED"
pass "order log matches the plan exactly"

step "the chain-of-custody stub names the case and the verification command"
CUSTODY="$CASE/chain-of-custody.md"
[[ -f "$CUSTODY" ]] || fail "no chain-of-custody.md was written"
grep -q 'ir-test-case' "$CUSTODY" || fail "the custody stub does not name the case"
grep -q 'sha256sum -c manifest.sha256' "$CUSTODY" \
  || fail "the custody stub does not say how to verify the manifest"
grep -q 'FILL IN' "$CUSTODY" || fail "the custody stub has no handler field to fill in"
pass "custody stub written, with the verification command and a handler field"

### 5. the manifest must be able to fail ----------------------------------
step "manifest verifies on the collected set"
in_container 'cd /w/case && sha256sum -c --quiet manifest.sha256' >/dev/null \
  || fail "sha256sum -c failed on an untouched evidence set"
pass "sha256sum -c passes"

step "control: the manifest must DETECT a tampered artifact"
# The copied evidence is root-owned (the collector ran as root in the
# container), so the tampering has to happen in the container too.
in_container 'printf "tampered\n" >> /w/case/10-processes.txt'
if in_container 'cd /w/case && sha256sum -c --quiet manifest.sha256' >/dev/null 2>&1; then
  fail "sha256sum -c passed after an artifact was modified — the manifest proves nothing"
fi
pass "a one-line change to one artifact fails verification"

### 6. the per-artifact timeout -------------------------------------------
step "control: a hung artifact times out (124) and collection continues"
# A copy of the collector with one deliberately hung artifact appended to the
# plan. The real collector must record 124 for it and still finish the rest.
mkdir -p "$WORK/hang"
sed 's#^  "70-persistence-paths.txt|.*#  "69-hang.txt|sleep 30"\n&#' "$COLLECTOR" > "$WORK/hang/ir-collect.sh"
grep -q '69-hang.txt' "$WORK/hang/ir-collect.sh" \
  || fail "the control could not inject a hung artifact — the plan's shape changed, update this test"
HANG_OUT="$(docker run --rm -v "$WORK:/w" --tmpfs /evidence:rw,size=64m -w /w "$DEBIAN_IMAGE" \
  bash -c 'bash hang/ir-collect.sh -o /evidence -c ir-hang -t 2 >/dev/null 2>/w/hang.stderr; cp -a /evidence/ir-hang /w/hangcase' ; echo rc=$?)"
[[ "$HANG_OUT" == "rc=0" ]] || fail "the collection aborted on a hung artifact instead of timing it out ($HANG_OUT)"
grep -q 'timed out after 2s: 69-hang.txt' "$WORK/hang.stderr" \
  || fail "no timeout was reported on stderr:\n$(cat "$WORK/hang.stderr")"
awk -F'\t' '$2=="69-hang.txt" && $3==124 {found=1} END {exit !found}' "$WORK/hangcase/collection-order.tsv" \
  || fail "exit status 124 was not recorded for the hung artifact:\n$(cat "$WORK/hangcase/collection-order.tsv")"
[[ -f "$WORK/hangcase/70-persistence-paths.txt" ]] \
  || fail "collection stopped at the hung artifact instead of continuing"
pass "hung artifact recorded as 124, later artifacts still collected"

### 7. the documents agree with the tool ----------------------------------
step "the first-hour checklist and the collector do not contradict each other"
CHECKLIST="$BASE/checklists/first-hour.md"
grep -qi 'do \*\*not\*\* reboot\|do not reboot' "$CHECKLIST" \
  || fail "the checklist does not tell the responder to avoid rebooting, but ir-collect.sh depends on a live host"
grep -qi 'isolate' "$CHECKLIST" \
  || fail "the checklist does not mention isolation, which is the containment action the collector assumes"
grep -qi 'snapshot' "$CHECKLIST" \
  || fail "the checklist does not mention disk snapshots"
for t in templates/chain-of-custody.md templates/post-mortem.md templates/comms.md; do
  [[ -s "$BASE/$t" ]] || fail "missing template: $t"
done
grep -q 'sha256sum -c' "$BASE/templates/chain-of-custody.md" \
  || fail "the custody template does not name the verification command the tool writes into its stub"
pass "checklist, templates and collector agree"

echo
echo "All incident-response checks passed."

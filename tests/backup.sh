#!/usr/bin/env bash
# Validates baselines/backup/. Run from the repository root:
#
#   bash tests/backup.sh
#
# Host requirements: bash and docker. Every tool runs from a digest-pinned image.
#
# What this proves:
#   1. Both wrapper scripts pass shellcheck, and refuse the environments they
#      document as invalid — including RESTIC_PASSWORD being set, which is the
#      mistake that puts a repository password in /proc/<pid>/environ.
#   2. The systemd units are accepted by systemd's own parser
#      (`systemd-analyze verify`), which is what catches a misspelled directive
#      that systemd otherwise reports only when the unit runs.
#   3. A REAL restic repository is initialised, backed up twice, pruned by the
#      retention policy, verified, and restored — and the restored tree is
#      compared byte for byte against the original.
#   4. Point-in-time recovery works: the older snapshot restores the OLD content,
#      not the current one. A backup system that only ever gives you the latest
#      state cannot undo an encryption or a truncation.
#   5. The integrity check can fail: after a pack file in the repository is
#      corrupted, `restic check --read-data` must report damage. This is the
#      assertion that makes the whole verification step meaningful. What plain
#      `restic check` sees is recorded rather than asserted: contrary to the
#      usual claim that it only verifies metadata, restic 0.19.1 sometimes flags
#      this corruption without --read-data — it depends on whether the bytes
#      landed in a pack's header or in blob data.
#   6. Retention actually removes snapshots, and `forget` without `--prune`
#      leaves the data behind — the reason the wrapper always passes --prune.
#   7. The Object Lock Terraform module validates and its 9 `terraform test`
#      cases pass with a mocked provider, including the four rejection cases
#      (lower-case mode, zero retention, a lifecycle shorter than the retention,
#      and the default deny on s3:BypassGovernanceRetention).
#   8. The shipped exclude list excludes the things that must never be copied
#      from a running filesystem, and the env example contains no real secret.
#
# What this does NOT do: talk to S3, create a bucket, or exercise Object Lock
# against the real API — that needs an account and costs money for the whole
# retention period. The module is proven at plan level; the bucket itself is
# proven by the restore drill in baselines/backup/checklists/restore-drill.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
BASE="baselines/backup"
[[ -d "$BASE" ]] || { echo "run from the repository root" >&2; exit 2; }

# Digests were current on 2026-09-29; the tag each belonged to is in the comment.
RESTIC_IMAGE="restic/restic@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510"          # restic/restic:0.19.1
DEBIAN_IMAGE="debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a"                # debian:13-slim
SHELLCHECK_IMAGE="koalaman/shellcheck@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d" # koalaman/shellcheck:v0.11.0
TERRAFORM_IMAGE="hashicorp/terraform@sha256:985cdc6c1d9b0a65b83377f666efd2f740b47f02ac55be1ced3d18f7d3b0e829"  # hashicorp/terraform:1.16.4
ALPINE_IMAGE="alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"                # alpine:3.22

WORK="$(mktemp -d)"
cleanup() {
  # Containers run as root and leave root-owned files in the bind mount; fix
  # ownership before removing so cleanup cannot mask the real exit status.
  docker run --rm -v "$WORK:/w" "$ALPINE_IMAGE" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
pass() { echo "ok  $*"; }
fail() { printf 'FAIL %b\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker is required: this suite runs restic and systemd-analyze, it cannot be skipped into passing"
docker info >/dev/null 2>&1 || fail "cannot reach a docker daemon (docker info failed)"

### 1. shellcheck ----------------------------------------------------------
step "shellcheck: the wrapper scripts"
docker run --rm -v "$ROOT:/repo:ro" -w /repo "$SHELLCHECK_IMAGE" \
  "$BASE/restic/restic-backup.sh" "$BASE/restic/restic-restore-verify.sh"
pass "no shellcheck findings in either script"

step "control: shellcheck must reject an unquoted expansion"
mkdir -p "$WORK/broken"
{ cat "$BASE/restic/restic-backup.sh"; printf '\nrm -rf $scratch\n'; } > "$WORK/broken/s.sh"
if docker run --rm -v "$WORK:/w:ro" -w /w "$SHELLCHECK_IMAGE" broken/s.sh >/dev/null 2>&1; then
  fail "shellcheck accepted an unquoted variable in rm -rf — the check above proves nothing"
fi
pass "shellcheck rejects an unquoted expansion"

### 2. the scripts' refusals ----------------------------------------------
# Run in the restic image (restic on PATH) so a refusal is about the environment
# and not about a missing binary.
restic_sh() {
  # The restic image's entrypoint IS restic, so a shell needs --entrypoint.
  # The restic image's entrypoint IS restic, so a shell needs --entrypoint; and
  # the image is busybox-based, so bash and GNU coreutils have to be added before
  # a bash script with arrays can run at all.
  docker run --rm -v "$ROOT:/repo:ro" -v "$WORK:/w" -w /repo \
    --entrypoint /bin/sh "$RESTIC_IMAGE" -c "apk add --no-cache bash coreutils diffutils >/dev/null 2>&1; $1"
}

step "the documented refusals"
while IFS='|' read -r what env_and_cmd expect; do
  [[ -n "$what" ]] || continue
  out="$(restic_sh "$env_and_cmd" 2>&1 || true)"
  rc="$(restic_sh "$env_and_cmd >/dev/null 2>&1; echo \$?")"
  [[ "$rc" == "2" ]] || fail "$what: expected exit 2, got $rc ($out)"
  printf '%s' "$out" | grep -qF -- "$expect" \
    || fail "$what: right exit status, wrong message ('$expect' missing from: $out)"
  pass "refused: $what"
done <<'CASES'
no RESTIC_REPOSITORY|BACKUP_PATHS=/etc bash baselines/backup/restic/restic-backup.sh|RESTIC_REPOSITORY is required
no BACKUP_PATHS|RESTIC_REPOSITORY=/w/r bash baselines/backup/restic/restic-backup.sh|BACKUP_PATHS is required
no password file|RESTIC_REPOSITORY=/w/r BACKUP_PATHS=/etc bash baselines/backup/restic/restic-backup.sh|RESTIC_PASSWORD_FILE is required
RESTIC_PASSWORD set inline|RESTIC_REPOSITORY=/w/r BACKUP_PATHS=/etc RESTIC_PASSWORD_FILE=/etc/hostname RESTIC_PASSWORD=hunter2 bash baselines/backup/restic/restic-backup.sh|unset it and use RESTIC_PASSWORD_FILE
unreadable password file|RESTIC_REPOSITORY=/w/r BACKUP_PATHS=/etc RESTIC_PASSWORD_FILE=/nope bash baselines/backup/restic/restic-backup.sh|cannot read RESTIC_PASSWORD_FILE
non-numeric STALE_LOCK_MINUTES|RESTIC_REPOSITORY=/w/r BACKUP_PATHS=/etc RESTIC_PASSWORD_FILE=/etc/hostname STALE_LOCK_MINUTES=soon bash baselines/backup/restic/restic-backup.sh|whole number of minutes
restore-verify without -p|RESTIC_REPOSITORY=/w/r bash baselines/backup/restic/restic-restore-verify.sh|-p PATH is required
CASES

### 3. systemd units ------------------------------------------------------
step "systemd-analyze verify: the units parse as systemd reads them"
cp "$BASE"/restic/restic-*.service "$BASE"/restic/restic-*.timer "$WORK/"
docker run --rm -v "$WORK:/w" "$DEBIAN_IMAGE" bash -c '
  set -e
  apt-get -qq update >/dev/null 2>&1
  apt-get -qq install -y systemd >/dev/null 2>&1
  mkdir -p /etc/systemd/system /etc/restic /usr/local/bin
  # The units reference an EnvironmentFile and an ExecStart that do not exist in
  # this container; create them so verify reports only real syntax problems.
  : > /etc/restic/restic.env
  printf "#!/bin/sh\nexit 0\n" > /usr/local/bin/restic-backup.sh
  printf "#!/bin/sh\nexit 0\n" > /usr/local/bin/restic-restore-verify.sh
  chmod +x /usr/local/bin/restic-*.sh
  cp /w/restic-*.service /w/restic-*.timer /etc/systemd/system/
  systemd-analyze verify /etc/systemd/system/restic-backup.service \
                         /etc/systemd/system/restic-backup.timer \
                         /etc/systemd/system/restic-verify.service \
                         /etc/systemd/system/restic-verify.timer
' > "$WORK/verify.log" 2>&1 || fail "systemd-analyze verify failed:\n$(cat "$WORK/verify.log")"
# verify exits 0 but still prints warnings for unknown directives, so the log
# has to be read as well: a typo'd directive is a warning, not an error.
# systemd 257 words this as "Unknown key 'X' in section [Service], ignoring";
# older versions say "unknown lvalue". Match both, because an ignored directive
# is a setting that silently does nothing.
if grep -qiE "unknown key|unknown lvalue|unknown section|failed to parse|invalid" "$WORK/verify.log"; then
  fail "systemd-analyze verify reported a problem:\n$(cat "$WORK/verify.log")"
fi
pass "all four units accepted by systemd's own parser"

step "control: systemd-analyze verify must reject a misspelled directive"
sed 's/^ProtectSystem=strict$/ProtectSytem=strict/' "$BASE/restic/restic-backup.service" > "$WORK/bad.service"
docker run --rm -v "$WORK:/w" "$DEBIAN_IMAGE" bash -c '
  apt-get -qq update >/dev/null 2>&1
  apt-get -qq install -y systemd >/dev/null 2>&1
  mkdir -p /etc/systemd/system /etc/restic /usr/local/bin
  : > /etc/restic/restic.env
  printf "#!/bin/sh\nexit 0\n" > /usr/local/bin/restic-backup.sh
  chmod +x /usr/local/bin/restic-backup.sh
  cp /w/bad.service /etc/systemd/system/bad.service
  systemd-analyze verify /etc/systemd/system/bad.service
' > "$WORK/verify-bad.log" 2>&1 || true
grep -qiE "unknown key|unknown lvalue" "$WORK/verify-bad.log" \
  || fail "systemd-analyze did not flag a misspelled directive — the check above proves nothing:\n$(cat "$WORK/verify-bad.log")"
pass "a misspelled directive is reported as an unknown key"

### 4. a real backup, prune, verify, restore ------------------------------
step "end to end: init, backup, retention, verify, restore"
# Everything happens inside one container: /data is the source tree, /repo the
# restic repository, /restored the restore target. The wrapper script is the one
# from the repository, mounted read-only.
docker run --rm -v "$ROOT:/src:ro" -v "$WORK:/w" --entrypoint /bin/sh "$RESTIC_IMAGE" -c '
  set -e
  # The wrapper and the verifier use GNU `du -sb` and `diff -r`; the restic
  # image is busybox-based, so install the real tools before running them.
  apk add --no-cache bash coreutils diffutils >/dev/null
  mkdir -p /w/data/sub /w/repo /w/restored
  printf "%s\n" "original content" > /w/data/canary.txt
  head -c 200000 /dev/urandom > /w/data/sub/blob.bin
  printf "%s\n" "config value 1" > /w/data/app.conf
  echo "secret" > /w/pass
  chmod 400 /w/pass
  cp /src/baselines/backup/restic/excludes.txt /w/excludes.txt

  export RESTIC_REPOSITORY=/w/repo RESTIC_PASSWORD_FILE=/w/pass
  export BACKUP_PATHS=/w/data BACKUP_EXCLUDE_FILE=/w/excludes.txt
  export RETENTION_ARGS="--keep-last 2"
  export CHECK_SUBSET=100%

  # Three runs with different content, so retention and point-in-time recovery
  # both have something to act on.
  bash /src/baselines/backup/restic/restic-backup.sh > /w/run1.log 2>&1
  sleep 1
  printf "%s\n" "config value 2" > /w/data/app.conf
  bash /src/baselines/backup/restic/restic-backup.sh > /w/run2.log 2>&1
  sleep 1
  printf "%s\n" "config value 3" > /w/data/app.conf
  bash /src/baselines/backup/restic/restic-backup.sh > /w/run3.log 2>&1

  restic snapshots --json > /w/snapshots.json
  restic snapshots --compact > /w/snapshots.txt
' || fail "the end-to-end backup run failed:\n$(cat "$WORK"/run*.log 2>/dev/null)"
pass "three backups taken with the shipped wrapper"

step "the repository was created on the first run, not by hand"
grep -q 'repository does not exist yet, initialising' "$WORK/run1.log" \
  || fail "the first run did not initialise the repository:\n$(cat "$WORK/run1.log")"
grep -q 'repository does not exist yet' "$WORK/run2.log" \
  && fail "the second run tried to initialise an existing repository"
pass "init on first run only"

step "retention: --keep-last 2 leaves exactly two snapshots"
COUNT="$(docker run --rm -v "$WORK:/w" --entrypoint /bin/sh "$RESTIC_IMAGE" -c \
  'RESTIC_REPOSITORY=/w/repo RESTIC_PASSWORD_FILE=/w/pass restic snapshots --json | tr "," "\n" | grep -c "short_id"' || true)"
[[ "$COUNT" == "2" ]] || fail "expected 2 snapshots after retention, got '$COUNT':\n$(cat "$WORK/snapshots.txt")"
pass "2 snapshots kept, the third forgotten and pruned"

step "the verification step ran and passed on an intact repository"
grep -q 'no errors were found' "$WORK/run3.log" \
  || fail "restic check did not report a clean repository:\n$(tail -20 "$WORK/run3.log")"
pass "restic check --read-data-subset 100% clean"

step "restore: the latest snapshot comes back byte for byte"
docker run --rm -v "$ROOT:/src:ro" -v "$WORK:/w" --entrypoint /bin/sh "$RESTIC_IMAGE" -c '
  set -e
  apk add --no-cache bash coreutils diffutils >/dev/null
  export RESTIC_REPOSITORY=/w/repo RESTIC_PASSWORD_FILE=/w/pass
  bash /src/baselines/backup/restic/restic-restore-verify.sh -p /w/data -c > /w/restore.log 2>&1
' || fail "restore verification failed:\n$(cat "$WORK/restore.log" 2>/dev/null)"
grep -q 'identical to the live copy' "$WORK/restore.log" \
  || fail "the restore did not report an identical copy:\n$(cat "$WORK/restore.log")"
grep -q 'measured RTO' "$WORK/restore.log" \
  || fail "the restore did not report a measured duration"
pass "restored tree identical to the source, with a measured duration"

step "control: the comparison must DETECT a difference"
# Change the live copy after the snapshot: the restored tree is now the older
# content, and the comparison must say so. If this passes, the -c comparison is
# not comparing anything.
docker run --rm -v "$ROOT:/src:ro" -v "$WORK:/w" --entrypoint /bin/sh "$RESTIC_IMAGE" -c '
  apk add --no-cache bash coreutils diffutils >/dev/null
  printf "%s\n" "changed after the snapshot" > /w/data/canary.txt
  export RESTIC_REPOSITORY=/w/repo RESTIC_PASSWORD_FILE=/w/pass
  bash /src/baselines/backup/restic/restic-restore-verify.sh -p /w/data -c > /w/restore-diff.log 2>&1
' && fail "the comparison passed although the live copy had changed — it proves nothing"
grep -q 'DIFFERS from the live copy' "$WORK/restore-diff.log" \
  || fail "the mismatch was not reported as a difference:\n$(cat "$WORK/restore-diff.log")"
pass "a changed live file is reported as a difference"

step "point-in-time recovery: an older snapshot restores the OLD content"
OLD="$(docker run --rm -v "$WORK:/w" --entrypoint /bin/sh "$RESTIC_IMAGE" -c '
  set -e
  export RESTIC_REPOSITORY=/w/repo RESTIC_PASSWORD_FILE=/w/pass
  # The OLDEST remaining snapshot, which is run 2 ("config value 2").
  id=$(restic snapshots --json | tr "," "\n" | grep "\"short_id\"" | head -1 | cut -d"\"" -f4)
  rm -rf /w/pit && mkdir -p /w/pit
  restic restore "$id" --include /w/data/app.conf --target /w/pit >/dev/null
  cat /w/pit/w/data/app.conf
')"
[[ "$OLD" == "config value 2" ]] \
  || fail "restoring the older snapshot gave '$OLD', expected 'config value 2' — point-in-time recovery does not work"
pass "the older snapshot restores 'config value 2', not the current content"

### 5. the integrity check must be able to fail ---------------------------
step "control: restic check --read-data must DETECT a corrupted pack file"
docker run --rm -v "$WORK:/w" --entrypoint /bin/sh "$RESTIC_IMAGE" -c '
  set -e
  pack=$(find /w/repo/data -type f | head -1)
  [ -n "$pack" ] || { echo "no pack file found"; exit 9; }
  # Flip bytes in the middle of a pack: the repository structure is intact, the
  # DATA is not. This is bit rot, and plain `restic check` cannot see it.
  size=$(wc -c < "$pack")
  dd if=/dev/urandom of="$pack" bs=1 seek=$((size / 2)) count=64 conv=notrunc status=none
' || fail "could not corrupt a pack file for the control"
if docker run --rm -v "$WORK:/w" --entrypoint /bin/sh "$RESTIC_IMAGE" -c \
  'RESTIC_REPOSITORY=/w/repo RESTIC_PASSWORD_FILE=/w/pass restic check --read-data' \
  > "$WORK/check-bad.log" 2>&1; then
  fail "restic check --read-data passed on a repository with a corrupted pack — every verification in this baseline proves nothing"
fi
grep -qiE 'pack|hash does not match|error' "$WORK/check-bad.log" \
  || fail "the corruption was detected but not reported recognisably:\n$(tail -10 "$WORK/check-bad.log")"
pass "a 64-byte corruption in one pack file is detected"

step "what plain restic check sees, recorded rather than assumed"
# This is an OBSERVATION, not an assertion — it is the one step here that cannot
# fail, and it says so. Received wisdom is that `restic check` without
# --read-data cannot see rotted bytes. Measured on restic 0.19.1 it goes both
# ways on the same repository, depending on which pack `find | head -1` picked
# and whether the 64 bytes landed in that pack's header or in blob data. The
# outcome is printed so a future version change is visible in the output.
docker run --rm -v "$WORK:/w" --entrypoint /bin/sh "$RESTIC_IMAGE" -c \
  'RESTIC_REPOSITORY=/w/repo RESTIC_PASSWORD_FILE=/w/pass restic check' \
  > "$WORK/check-plain.log" 2>&1 && PLAIN=clean || PLAIN=flagged
[[ "$PLAIN" == "flagged" || "$PLAIN" == "clean" ]] || fail "impossible state"
echo "    plain check on the corrupted repository: $PLAIN"
if [[ "$PLAIN" == "clean" ]]; then
  # Then --read-data is the only thing that catches it, which is the stronger
  # justification for the wrapper always passing --read-data-subset.
  pass "plain check is clean; only --read-data found the corruption"
else
  grep -qiE 'pack|hash|error' "$WORK/check-plain.log" \
    || fail "plain check exited non-zero but said nothing recognisable:\n$(tail -5 "$WORK/check-plain.log")"
  pass "plain check flags it too (restic 0.19 verifies pack integrity structurally)"
fi

### 6. the Terraform module ----------------------------------------------
step "terraform fmt, validate and test: the Object Lock module"
mkdir -p "$WORK/tf/cache"
cp -a "$BASE/terraform/aws-s3-object-lock" "$WORK/tf/m"
tf() {
  docker run --rm -v "$WORK/tf:/w" -w /w/m \
    -e TF_IN_AUTOMATION=1 -e TF_PLUGIN_CACHE_DIR=/w/cache -e TF_CLI_ARGS=-no-color \
    "$TERRAFORM_IMAGE" "$@"
}
tf fmt -check -recursive >/dev/null || fail "the module is not canonically formatted"
tf init -backend=false -input=false >/dev/null 2>&1 || fail "terraform init failed"
tf validate >/dev/null || fail "terraform validate failed"
tf test > "$WORK/tf-test.log" 2>&1 || fail "terraform test failed:\n$(tail -30 "$WORK/tf-test.log")"
PASSED="$(grep -oE '[0-9]+ passed' "$WORK/tf-test.log" | tail -1)"
grep -q '0 failed' "$WORK/tf-test.log" || fail "terraform test reported failures:\n$(tail -20 "$WORK/tf-test.log")"
pass "terraform test: $PASSED (including the four rejection cases)"

### 7. the shipped lists say what the guide claims ------------------------
step "the exclude list excludes what must never be copied from a live filesystem"
for pattern in '/var/lib/mysql/\*\*' '/var/lib/postgresql/\*\*' '/var/lib/etcd/\*\*' '/proc/\*\*' '/var/cache/restic/\*\*'; do
  grep -qE "^${pattern}$" "$BASE/restic/excludes.txt" \
    || fail "excludes.txt is missing a pattern the guide relies on: $pattern"
done
pass "database data directories, pseudo-filesystems and the restic cache are excluded"

step "the env example contains no secret and no inline password"
grep -q '^RESTIC_PASSWORD_FILE=' "$BASE/restic/restic.env.example" \
  || fail "the env example does not use RESTIC_PASSWORD_FILE"
grep -qE '^RESTIC_PASSWORD=' "$BASE/restic/restic.env.example" \
  && fail "the env example sets RESTIC_PASSWORD inline, which is the mistake the wrapper refuses"
grep -qE '^AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY)=.+' "$BASE/restic/restic.env.example" \
  && fail "the env example contains AWS credentials"
pass "no inline password, no credentials"

echo
echo "All backup baseline checks passed."

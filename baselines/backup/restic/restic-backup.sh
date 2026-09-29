#!/usr/bin/env bash
# Take one restic backup, apply the retention policy, and verify part of the
# repository. Driven entirely by the environment file that the systemd unit
# loads (restic.env.example), so the same script runs by hand and from the timer.
#
# Validated end to end by tests/backup.sh: a real repository is initialised,
# backed up, pruned, verified, restored, and compared byte for byte — and the
# integrity check is proven to FAIL on a corrupted pack file.
#
# Required in the environment:
#   RESTIC_REPOSITORY        e.g. s3:s3.eu-west-1.amazonaws.com/org-backups/host
#   RESTIC_PASSWORD_FILE     path to the repository password, mode 0400
#   BACKUP_PATHS             space-separated paths to back up
# Optional:
#   BACKUP_EXCLUDE_FILE      default /etc/restic/excludes.txt
#   BACKUP_TAG               default "scheduled"
#   RETENTION_ARGS           default "--keep-daily 14 --keep-weekly 8 --keep-monthly 12 --keep-yearly 3"
#   CHECK_SUBSET             default "5%"  (how much data to re-read per run)
#   STALE_LOCK_MINUTES       default 0 = never remove a lock automatically
#
# Exit status: 0 backup and retention succeeded; 1 backup failed; 2 usage or
# environment error; 3 backup succeeded but verification failed — which is a
# different alert, because the data is on the host but the repository is not
# trustworthy.
set -euo pipefail

die() { echo "restic-backup: $*" >&2; exit 2; }

# Checked with die(), not with ${VAR:?msg}: the shell's own form exits 1, and
# this script documents 2 for an environment error so a monitoring rule can tell
# "misconfigured" (2) from "the backup failed" (1) and "the repository is
# suspect" (3).
[[ -n "${RESTIC_REPOSITORY:-}" ]] || die "RESTIC_REPOSITORY is required"
[[ -n "${BACKUP_PATHS:-}" ]] || die "BACKUP_PATHS is required"

# RESTIC_PASSWORD_FILE, never RESTIC_PASSWORD. An inline password is visible in
# /proc/<pid>/environ to anything that can read it and lands in `systemctl show`
# output, in journald and in any core dump of the process.
[[ -n "${RESTIC_PASSWORD_FILE:-}" ]] || die "RESTIC_PASSWORD_FILE is required (do not use RESTIC_PASSWORD)"
[[ -r "$RESTIC_PASSWORD_FILE" ]] || die "cannot read RESTIC_PASSWORD_FILE: $RESTIC_PASSWORD_FILE"
[[ -z "${RESTIC_PASSWORD:-}" ]] || die "RESTIC_PASSWORD is set; unset it and use RESTIC_PASSWORD_FILE"

exclude_file="${BACKUP_EXCLUDE_FILE:-/etc/restic/excludes.txt}"
tag="${BACKUP_TAG:-scheduled}"
retention_args="${RETENTION_ARGS:---keep-daily 14 --keep-weekly 8 --keep-monthly 12 --keep-yearly 3}"
check_subset="${CHECK_SUBSET:-5%}"
stale_lock_minutes="${STALE_LOCK_MINUTES:-0}"

[[ "$stale_lock_minutes" =~ ^[0-9]+$ ]] || die "STALE_LOCK_MINUTES must be a whole number of minutes"

command -v restic >/dev/null 2>&1 || die "restic is not on PATH"

# `restic init` on an existing repository is a no-op error, so the check is
# separate: a first run must create the repository, a later run must not try.
if ! restic cat config >/dev/null 2>&1; then
  echo "restic-backup: repository does not exist yet, initialising $RESTIC_REPOSITORY"
  restic init
fi

# Only ever remove a lock that is provably older than the longest a real run can
# take. A lock removed while another process holds it means two writers on one
# repository, which is how a repository gets corrupted. Default is 0: do nothing.
if [[ "$stale_lock_minutes" -gt 0 ]]; then
  if restic list locks 2>/dev/null | grep -q .; then
    echo "restic-backup: locks present; removing only those older than ${stale_lock_minutes}m"
    restic unlock --remove-all=false
  fi
fi

exclude_args=()
if [[ -f "$exclude_file" ]]; then
  exclude_args+=(--exclude-file "$exclude_file")
else
  echo "restic-backup: no exclude file at $exclude_file, backing up everything under BACKUP_PATHS" >&2
fi

backup_rc=0
# --one-file-system: never follow a mount into a network share or another disk
#   that has its own backup (or no business being in this one).
# --exclude-caches: honours CACHEDIR.TAG, which is what build and package caches
#   use to say "do not back me up".
# --no-scan: skips the pre-scan pass; the progress percentage is lost, the run is
#   faster, and a scheduled job has nobody watching the percentage.
# shellcheck disable=SC2086  # BACKUP_PATHS is a deliberate word-split list
restic backup \
  --tag "$tag" \
  --one-file-system \
  --exclude-caches \
  --no-scan \
  "${exclude_args[@]}" \
  $BACKUP_PATHS || backup_rc=$?

if [[ "$backup_rc" -ne 0 ]]; then
  # 3 is restic's "some files could not be read" status: the snapshot exists and
  # is usable, and treating it as a total failure hides a partial success that
  # somebody still has to look at.
  if [[ "$backup_rc" -eq 3 ]]; then
    echo "restic-backup: snapshot created but some files were unreadable (restic exit 3)" >&2
  else
    echo "restic-backup: backup failed (restic exit $backup_rc)" >&2
    exit 1
  fi
fi

# Retention. `forget` alone only removes snapshot references; without --prune the
# data stays in the repository forever and the bill grows regardless of policy.
# shellcheck disable=SC2086  # RETENTION_ARGS is a deliberate word-split list
restic forget --tag "$tag" --prune --group-by "host,tags" $retention_args

# Verify a slice of the actual data on every run. `restic check` on its own
# verifies the repository's structure and each pack's header, so whether it
# notices a corrupted pack depends on WHERE the corruption landed — measured
# both ways on 0.19.1 in tests/backup.sh. Only --read-data re-reads and re-hashes
# blob contents, which is what proves the bytes a restore will need are still the
# bytes that were written. --read-data-subset spreads that cost over many runs.
if ! restic check --read-data-subset "$check_subset"; then
  echo "restic-backup: repository verification FAILED — treat the repository as suspect" >&2
  exit 3
fi

restic snapshots --tag "$tag" --latest 1

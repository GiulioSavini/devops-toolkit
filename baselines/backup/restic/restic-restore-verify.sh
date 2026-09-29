#!/usr/bin/env bash
# Restore one path from the latest snapshot into a scratch directory and compare
# it with the live copy. This is the only check that proves a backup is a
# backup: `restic check` proves the repository is internally consistent, not
# that what comes out of it is what went in.
#
# Run it from a timer, on a host that is NOT the one being backed up where you
# can, and alert on a non-zero exit.
#
# Required in the environment: RESTIC_REPOSITORY, RESTIC_PASSWORD_FILE.
# Required arguments:
#   -p PATH     the path inside the snapshot to restore (also compared on disk)
# Optional:
#   -d DIR      scratch directory (default: mktemp -d); removed on exit
#   -t TAG      snapshot tag to select (default: scheduled)
#   -c          compare against the live filesystem (default: restore only)
#
# Exit status: 0 restored (and matched, with -c); 1 restore or comparison
# failed; 2 usage or environment error.
set -euo pipefail

die() { echo "restore-verify: $*" >&2; exit 2; }

target=""
scratch=""
tag="scheduled"
compare=0

while getopts ":p:d:t:c" opt; do
  case "$opt" in
    p) target="$OPTARG" ;;
    d) scratch="$OPTARG" ;;
    t) tag="$OPTARG" ;;
    c) compare=1 ;;
    *) die "usage: $0 -p PATH [-d DIR] [-t TAG] [-c]" ;;
  esac
done

[[ -n "$target" ]] || die "-p PATH is required"
[[ -n "${RESTIC_REPOSITORY:-}" ]] || die "RESTIC_REPOSITORY is required"
[[ -n "${RESTIC_PASSWORD_FILE:-}" ]] || die "RESTIC_PASSWORD_FILE is required"
command -v restic >/dev/null 2>&1 || die "restic is not on PATH"

own_scratch=0
if [[ -z "$scratch" ]]; then
  scratch="$(mktemp -d)"
  own_scratch=1
fi
cleanup() { [[ "$own_scratch" -eq 1 ]] && rm -rf "$scratch"; }
trap cleanup EXIT

start="$(date +%s)"
# `restore latest` resolves the newest snapshot for the tag; --target places the
# tree under the scratch directory with its original absolute path preserved,
# which is what makes the diff below a like-for-like comparison.
restic restore "latest" --tag "$tag" --include "$target" --target "$scratch" \
  || { echo "restore-verify: restore failed" >&2; exit 1; }
elapsed="$(( $(date +%s) - start ))"

restored="$scratch$target"
[[ -e "$restored" ]] || { echo "restore-verify: nothing was restored at $restored" >&2; exit 1; }

bytes="$(du -sb "$restored" | cut -f1)"
echo "restore-verify: restored $target in ${elapsed}s (${bytes} bytes) — this is your measured RTO for this path"

if [[ "$compare" -eq 1 ]]; then
  # diff -r, not a checksum of a tarball: it reports WHICH file differs, and a
  # single differing file is the finding. Mismatches on files that change
  # constantly are expected; point -p at something stable, or accept the noise
  # and read the list.
  if diff -r --no-dereference "$target" "$restored" > "$scratch/diff.txt" 2>&1; then
    echo "restore-verify: restored copy is identical to the live copy"
  else
    echo "restore-verify: restored copy DIFFERS from the live copy:" >&2
    head -50 "$scratch/diff.txt" >&2
    exit 1
  fi
fi

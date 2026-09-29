#!/usr/bin/env bash
# List IAM user credentials (console passwords and access keys) that are
# active but unused for more than N days, from the IAM credential report.
#
# Usage:
#   aws-stale-credentials.sh [-d DAYS] [-f REPORT.csv]
#
#   -d DAYS   staleness threshold in days (default 90)
#   -f FILE   read an already-downloaded credential report instead of calling
#             the API (useful for offline review and for tests)
#
# Output: one TSV line per stale credential:
#   user  credential  last_used_or_created  reason
# Exit status: 0 = nothing stale, 1 = stale credentials found, 2 = error.
#
# Requires: bash, awk, GNU date or BSD date; aws CLI v2 unless -f is used.
# IAM permissions: iam:GenerateCredentialReport, iam:GetCredentialReport.
set -euo pipefail

days=90
report_file=""

while getopts ":d:f:" opt; do
  case "$opt" in
    d) days="$OPTARG" ;;
    f) report_file="$OPTARG" ;;
    *) echo "usage: $0 [-d DAYS] [-f REPORT.csv]" >&2; exit 2 ;;
  esac
done

if ! [[ "$days" =~ ^[0-9]+$ ]]; then
  echo "error: -d must be a whole number of days" >&2
  exit 2
fi

# Cutoff as an ISO 8601 UTC timestamp. The report uses the same format
# (2024-05-01T10:20:30+00:00), so a plain string comparison orders correctly.
if cutoff=$(date -u -d "-${days} days" +%Y-%m-%dT%H:%M:%S+00:00 2>/dev/null); then
  :
else
  cutoff=$(date -u -v "-${days}d" +%Y-%m-%dT%H:%M:%S+00:00)   # BSD/macOS date
fi

fetch_report() {
  # The report is generated asynchronously; poll until it is COMPLETE.
  local state i
  for i in $(seq 1 30); do
    state=$(aws iam generate-credential-report --query State --output text)
    [[ "$state" == "COMPLETE" ]] && break
    sleep 2
  done
  if [[ "$state" != "COMPLETE" ]]; then
    echo "error: credential report still $state after ${i} attempts" >&2
    exit 2
  fi
  # Content is a blob; the CLI prints blobs base64-encoded, so decode it.
  aws iam get-credential-report --query Content --output text | base64 -d
}

if [[ -n "$report_file" ]]; then
  report=$(cat "$report_file")
else
  report=$(fetch_report)
fi

rc=0
printf '%s\n' "$report" | awk -F, -v cutoff="$cutoff" '
  NR == 1 {
    for (i = 1; i <= NF; i++) col[$i] = i
    need = "user user_creation_time password_enabled password_last_used access_key_1_active access_key_1_last_rotated access_key_1_last_used_date access_key_2_active access_key_2_last_rotated access_key_2_last_used_date"
    n = split(need, req, " ")
    for (i = 1; i <= n; i++) if (!(req[i] in col)) { print "error: report has no column " req[i] > "/dev/stderr"; bad = 1; exit 2 }
    next
  }
  function stale(user, cred, used, created) {
    # used is N/A or no_information when the credential was never used:
    # judge it by its creation/rotation date instead.
    if (used == "N/A" || used == "no_information") {
      if (created < cutoff) { printf "%s\t%s\t%s\tnever used\n", user, cred, created; found = 1 }
    } else if (used < cutoff) {
      printf "%s\t%s\t%s\tnot used since\n", user, cred, used; found = 1
    }
  }
  {
    user = $col["user"]
    if (tolower($col["password_enabled"]) == "true")
      stale(user, "password", $col["password_last_used"], $col["user_creation_time"])
    if (tolower($col["access_key_1_active"]) == "true")
      stale(user, "access_key_1", $col["access_key_1_last_used_date"], $col["access_key_1_last_rotated"])
    if (tolower($col["access_key_2_active"]) == "true")
      stale(user, "access_key_2", $col["access_key_2_last_used_date"], $col["access_key_2_last_rotated"])
  }
  END { if (bad) exit 2; exit found ? 1 : 0 }
' || rc=$?

exit "$rc"

#!/usr/bin/env bash
# Collect volatile evidence from a running Linux host in RFC 3227 order of
# volatility (https://www.rfc-editor.org/rfc/rfc3227.html section 2.1), hash
# every artifact, and write a manifest plus a chain-of-custody stub.
#
# This script deliberately does NOT reboot, stop, patch or clean anything: a
# reboot destroys RAM, tmpfs, established sockets and the process table, which
# is most of what an intrusion investigation depends on. Containment happens by
# isolating the host (security group, VLAN, `ip link set down` on a data NIC),
# not by powering it off.
#
# Usage:
#   ir-collect.sh -o OUTDIR [-c CASE_ID] [-t SECONDS] [-m] [-n] [-F]
#
#   -t SECONDS  per-artifact timeout, default 60. A hung tool (lsof on a dead
#               NFS mount is the classic) must not stall the collection.
#   -o OUTDIR   destination directory (must already exist). Put it on removable
#               or remote storage; writing evidence onto the suspect filesystem
#               overwrites unallocated blocks and slack space.
#   -c CASE_ID  case identifier (default: ir-<hostname>-<UTC timestamp>)
#   -m          also acquire physical memory with avml ($AVML, default
#               /usr/local/bin/avml). Memory first: it is the most volatile
#               artifact that is still recoverable.
#   -n          dry run: print the collection plan, write nothing
#   -F          allow OUTDIR on the same filesystem as / (not recommended)
#
# Exit status: 0 collected, 2 usage/environment error.
#
# Run it from trusted media where possible: on a compromised host the local
# ps/ss/lsmod may be replaced (RFC 3227 section 2.2, "Don't trust the programs
# on the system").
set -euo pipefail

outdir=""
case_id=""
capture_memory=0
dry_run=0
force_same_fs=0
avml="${AVML:-/usr/local/bin/avml}"
timeout_s=60

die() { echo "ir-collect: $*" >&2; exit 2; }

while getopts ":o:c:t:mnF" opt; do
  case "$opt" in
    o) outdir="$OPTARG" ;;
    c) case_id="$OPTARG" ;;
    t) timeout_s="$OPTARG" ;;
    m) capture_memory=1 ;;
    n) dry_run=1 ;;
    F) force_same_fs=1 ;;
    *) die "usage: $0 -o OUTDIR [-c CASE_ID] [-t SECONDS] [-m] [-n] [-F]" ;;
  esac
done

[[ "$timeout_s" =~ ^[0-9]+$ ]] || die "-t must be a whole number of seconds"
[[ -n "$outdir" ]] || die "-o OUTDIR is required"
[[ -d "$outdir" ]] || die "OUTDIR does not exist: $outdir"
[[ -w "$outdir" ]] || die "OUTDIR is not writable: $outdir"

if [[ "$force_same_fs" -eq 0 ]]; then
  out_fs="$(stat -c %d "$outdir")"
  root_fs="$(stat -c %d /)"
  if [[ "$out_fs" == "$root_fs" ]]; then
    die "OUTDIR is on the same filesystem as / — use removable or remote storage, or -F to override"
  fi
fi

started_utc="$(date -u +%Y%m%dT%H%M%SZ)"
[[ -n "$case_id" ]] || case_id="ir-$(hostname -s 2>/dev/null || echo unknown)-$started_utc"
case_dir="$outdir/$case_id"

# The collection plan, in RFC 3227 order. Each entry is "artifact|command".
# Order matters and is asserted by tests/incident-response.sh.
plan=(
  "00-clock.txt|{ date -u --iso-8601=seconds; date --iso-8601=seconds; cat /proc/uptime; timedatectl status 2>/dev/null || true; chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null || true; }"
  "10-processes.txt|ps -eo pid,ppid,user,lstart,etimes,stat,wchan:20,args"
  "11-process-links.txt|ls -l /proc/*/exe /proc/*/cwd 2>/dev/null || true"
  "20-network-sockets.txt|{ ss -tunapO 2>/dev/null || netstat -tunap 2>/dev/null || true; }"
  "21-network-links.txt|{ ip -d addr; ip -d link; ip route show table all; ip neigh; } 2>/dev/null || true"
  "22-firewall.txt|{ nft list ruleset 2>/dev/null || iptables-save 2>/dev/null || true; }"
  "30-kernel-modules.txt|{ lsmod; cat /proc/modules; } 2>/dev/null || true"
  "31-kernel-ring.txt|dmesg --ctime 2>/dev/null || true"
  "40-mounts.txt|{ cat /proc/mounts; findmnt -a 2>/dev/null || true; }"
  "41-open-files.txt|{ lsof -n -P 2>/dev/null || ls -l /proc/*/fd 2>/dev/null || true; }"
  "50-sessions.txt|{ who -a; w -h 2>/dev/null || true; last -F -n 200 2>/dev/null || true; }"
  "60-packages.txt|{ dpkg -l 2>/dev/null || rpm -qa 2>/dev/null || true; }"
  "61-cron-and-units.txt|{ ls -la /etc/cron.* /var/spool/cron 2>/dev/null; systemctl list-units --type=service --all --no-pager 2>/dev/null; systemctl list-timers --all --no-pager 2>/dev/null; } || true"
  "70-persistence-paths.txt|find /etc /usr/local /opt /root /home -xdev -maxdepth 4 -newermt '-30 days' -printf '%TY-%Tm-%TdT%TH:%TM:%TSZ %s %p\\n' 2>/dev/null || true"
)

if [[ "$dry_run" -eq 1 ]]; then
  echo "case:       $case_id"
  echo "output:     $case_dir (dry run, nothing written)"
  [[ "$capture_memory" -eq 1 ]] && echo "memory:     $avml -> 05-memory.lime (before disk artifacts)"
  for entry in "${plan[@]}"; do
    echo "artifact:   ${entry%%|*}"
  done
  exit 0
fi

mkdir -p "$case_dir"
order_log="$case_dir/collection-order.tsv"
printf 'utc\tartifact\texit_status\n' > "$order_log"

record() {
  local artifact="$1" command="$2" rc=0
  # Never abort the whole collection because one tool is missing: a partial
  # evidence set beats none, and the manifest records what was captured.
  timeout "$timeout_s" bash -c "$command" > "$case_dir/$artifact" 2> "$case_dir/$artifact.stderr" || rc=$?
  # 124 is timeout(1)'s own status: the artifact is truncated, not missing.
  [[ "$rc" -eq 124 ]] && echo "ir-collect: timed out after ${timeout_s}s: $artifact" >&2
  [[ -s "$case_dir/$artifact.stderr" ]] || rm -f "$case_dir/$artifact.stderr"
  printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$artifact" "$rc" >> "$order_log"
}

# Clock state first: every later timestamp is only interpretable against the
# host's own notion of time and its offset from UTC.
record "${plan[0]%%|*}" "${plan[0]#*|}"

# Memory before anything on disk. On a kernel with lockdown enabled, or built
# with CONFIG_STRICT_DEVMEM, acquisition fails: that is a finding to record, not
# a reason to stop, and not a reason to reboot into something more cooperative.
if [[ "$capture_memory" -eq 1 ]]; then
  mem_rc=0
  if [[ -x "$avml" ]]; then
    "$avml" "$case_dir/05-memory.lime" 2> "$case_dir/05-memory.lime.stderr" || mem_rc=$?
    [[ -s "$case_dir/05-memory.lime.stderr" ]] || rm -f "$case_dir/05-memory.lime.stderr"
  else
    echo "ir-collect: memory capture requested but $avml is not executable" >&2
    mem_rc="missing-tool"
  fi
  printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "05-memory.lime" "$mem_rc" >> "$order_log"
fi

for entry in "${plan[@]:1}"; do
  record "${entry%%|*}" "${entry#*|}"
done

# Hash everything, including the order log: the manifest is what makes the set
# verifiable after it has moved between hands and storage.
( cd "$case_dir" && find . -type f ! -name manifest.sha256 -print0 \
    | sort -z | xargs -0 sha256sum > manifest.sha256 )

cat > "$case_dir/chain-of-custody.md" <<CUSTODY
# Chain of custody — $case_id

Host: $(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)
Collection started (UTC): $started_utc
Collected by: FILL IN (name, role, contact)
Tool: ir-collect.sh from baselines/incident-response/bin
Manifest: manifest.sha256 (verify with \`sha256sum -c manifest.sha256\`)

| # | UTC timestamp | Action | Handler (name, signature) | Storage location | Manifest verified |
|---|---|---|---|---|---|
| 1 | $started_utc | Volatile evidence collected on host | | $case_dir | yes |
| 2 | | | | | |

Every later row is filled in when the evidence changes hands or storage, and
the receiving party re-runs \`sha256sum -c manifest.sha256\` before signing.
CUSTODY

echo "$case_dir"

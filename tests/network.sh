#!/usr/bin/env bash
# Validation of baselines/network/*.
#
# What is checked for real:
#   - nftables-hub.nft is accepted by nft's own parser (`nft -c -f`);
#   - the ruleset is then actually LOADED onto a real nftables instance (in
#     the test container's own network namespace) and read back with
#     `nft list ruleset`/`nft list tables`, to prove the SHAPE the guide
#     claims: it owns one table and coexists with a pre-existing table
#     (standing in for Docker's/a CNI's own tables) instead of flushing
#     everything, all three base chains have policy drop, the management SSH
#     allow rule exists, and the per-site forward rules are actually scoped
#     per site rather than collapsed into one shared "any tunnel peer, any
#     routed site" rule;
#   - wg0-hub.conf is loaded onto a REAL kernel WireGuard interface (this
#     host's kernel auto-loads the `wireguard` module on
#     `ip link add type wireguard`, confirmed present during development) via
#     the real `wg-quick strip` / `wg setconf` / `wg show` tools, and each
#     peer's AllowedIPs as actually loaded by the kernel is compared against
#     what the file declares;
#   - every key in sysctl.d/99-wireguard-forwarding.conf exists under
#     /proc/sys on the host actually running this script;
#   - shellcheck on this script.
#
# Every check is paired with a control that must FAIL/be DETECTED, so a check
# that silently stopped validating anything cannot stay green:
#   - a ruleset with an unknown chain hook, and one with a bogus set datatype,
#     must both be rejected by `nft -c -f` with the expected diagnostic;
#   - a WireGuard peer with a malformed public key must be rejected by the
#     real `wg setconf` (it is — with "Key is not the correct length or
#     format");
#   - two peers claiming the same AllowedIPs prefix are NOT rejected by
#     `wg setconf` (verified empirically: the kernel's routing trie silently
#     hands the exact-match prefix to whichever peer is set last, and the
#     earlier peer loses it with no warning). This script does not rely on
#     wg's exit code for that case: it compares each peer's DECLARED
#     AllowedIPs against what the kernel actually loaded, and a silent
#     overlap shows up as a mismatch;
#   - a peer with AllowedIPs 0.0.0.0/0 (or ::/0) that is not marked with a
#     "full-tunnel" comment is flagged by this script's own peer-comment
#     check, since neither `wg setconf` nor `wg-quick strip` cares about that
#     at all.
#
# What this explicitly does NOT do:
#   - it does not prove packets actually flow, or that a real handshake
#     completes between two independent hosts. There is no second host here.
#     "Site A cannot reach site B through the hub" is proven by loading the
#     real ruleset and reading back that the per-site sets and rules are
#     structured the way the guide claims (grep-verified against the ACTUAL
#     `nft list ruleset` output, printed below for a skeptical reader to
#     re-check by eye) — not by sending a UDP packet through two live tunnels
#     and watching it get dropped;
#   - it never claims a blocked path is "refused" when only a timeout would
#     prove a drop. This script does not test connectivity across a network
#     path at all (nothing here is reachable from "outside"), so that
#     confusion cannot arise; the live drop test in the guide is a manual,
#     two-host procedure and says so;
#   - it uses the default (bridged) docker network, not `--network none`, for
#     the containers that need to `apt-get install` a tool first. That still
#     gives each container its own network namespace and its own nftables/
#     WireGuard state — the isolation the plan asked for — it just also has a
#     route to the package mirror. Nothing in these containers is exposed;
#   - it does not validate auditd, sshd, or anything under baselines/linux/ —
#     see tests/linux.sh for that, and it is not repeated here.
#
# Host requirements: docker and bash. Everything else runs in pinned images.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET_DIR="$ROOT_DIR/baselines/network"

# Pinned by digest. Tags shown are what was resolved at the time of pinning:
#   debian:13-slim               (resolved 2026-09-29)
#   koalaman/shellcheck:v0.10.0  (resolved 2026-09-29)
DEBIAN_IMAGE="debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a"
SHELLCHECK_IMAGE="koalaman/shellcheck@sha256:2097951f02e735b613f4a34de20c40f937a6c8f18ecb170612c88c34517221fb"

TMP_DIR="$(mktemp -d)"
cleanup() {
  # Files written by root inside a container can't be removed by this user
  # without first handing ownership back.
  docker run --rm -v "$TMP_DIR:/t" "$DEBIAN_IMAGE" chown -R "$(id -u):$(id -g)" /t >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "    ok: $*"; }

command -v docker >/dev/null || fail "docker is required"
docker info >/dev/null 2>&1 || fail "cannot reach a docker daemon (docker info failed)"

echo "==> docker preflight: pinned images are pullable"
for image in "$DEBIAN_IMAGE" "$SHELLCHECK_IMAGE"; do
  docker pull -q "$image" >/dev/null || fail "cannot pull $image"
done

NFT_INSTALL='apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y nftables >/dev/null 2>&1'

# ---------------------------------------------------------------------------
# 1. nft -c -f parses the real ruleset
# ---------------------------------------------------------------------------
echo "==> nft -c -f: baselines/network/nftables-hub.nft"
docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$NET_DIR:/n:ro" "$DEBIAN_IMAGE" \
  sh -c "$NFT_INSTALL && nft -c -f /n/nftables-hub.nft" \
  || fail "nft rejected nftables-hub.nft"
ok "ruleset accepted by nft's own parser"

echo "==> control: nft must REJECT an unknown chain hook"
mkdir -p "$TMP_DIR/nft"
sed 's/hook input priority filter/hook nonexistenthook priority filter/' \
  "$NET_DIR/nftables-hub.nft" > "$TMP_DIR/nft/broken-hook.nft"
OUT="$(docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$TMP_DIR/nft:/n:ro" "$DEBIAN_IMAGE" \
  sh -c "$NFT_INSTALL && nft -c -f /n/broken-hook.nft" 2>&1)" && \
  fail "nft accepted a ruleset with an unknown chain hook"
echo "$OUT" | grep -q "unknown chain hook" \
  || fail "expected diagnostic 'unknown chain hook', got: $OUT"
ok "control: unknown chain hook rejected with the expected diagnostic"

echo "==> control: nft must REJECT a bogus set datatype"
sed 's/type ipv4_addr/type nonexistenttype/' \
  "$NET_DIR/nftables-hub.nft" > "$TMP_DIR/nft/broken-type.nft"
OUT="$(docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$TMP_DIR/nft:/n:ro" "$DEBIAN_IMAGE" \
  sh -c "$NFT_INSTALL && nft -c -f /n/broken-type.nft" 2>&1)" && \
  fail "nft accepted a ruleset with an unknown set datatype"
echo "$OUT" | grep -q "unknown datatype" \
  || fail "expected diagnostic 'unknown datatype', got: $OUT"
ok "control: bogus set datatype rejected with the expected diagnostic"

# ---------------------------------------------------------------------------
# 2. load the ruleset for real and read the SHAPE back
# ---------------------------------------------------------------------------
# A parse-only check proves the grammar is valid. It proves nothing about
# whether the file actually does what the guide says: owns its own table,
# coexists with tables it did not create, defaults to drop, and separates
# site A from site B in the forward chain rather than merely commenting that
# it does. All of that is only visible after the ruleset is loaded and read
# back from the kernel.
echo "==> load nftables-hub.nft for real and inspect the loaded ruleset"
# Single-quoted on purpose: this runs inside the container via `sh -c`, so
# none of this should expand in the outer script.
# shellcheck disable=SC2016
SHAPE_SCRIPT='
set -e
apt-get -qq update >/dev/null 2>&1
apt-get -qq install -y nftables >/dev/null 2>&1
# Stand-in for a table Docker or a CNI already owns. If loading our file
# removes this, the file is doing something equivalent to `flush ruleset`
# and would take container networking down with it on a real host.
nft add table inet fake_docker
nft add chain inet fake_docker DOCKER
nft -f /n/nftables-hub.nft
echo "___TABLES___"
nft list tables
echo "___RULESET___"
nft list ruleset
'
SHAPE_OUT="$(docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$NET_DIR:/n:ro" "$DEBIAN_IMAGE" sh -c "$SHAPE_SCRIPT")" \
  || fail "failed to load nftables-hub.nft into a live nft instance"

TABLES_OUT="$(printf '%s\n' "$SHAPE_OUT" | sed -n '/___TABLES___/,/___RULESET___/p')"
RULESET_OUT="$(printf '%s\n' "$SHAPE_OUT" | sed -n '/___RULESET___/,$p')"
echo "$RULESET_OUT"

printf '%s\n' "$TABLES_OUT" | grep -q "table inet fake_docker" \
  || fail "the pre-existing table was removed — nftables-hub.nft is flushing the whole ruleset, not owning one table"
printf '%s\n' "$TABLES_OUT" | grep -q "table inet wg_hub" \
  || fail "table inet wg_hub was not created"
ok "coexists with a pre-existing table instead of flushing the ruleset"

for chain in input forward output; do
  printf '%s\n' "$RULESET_OUT" | grep -A2 "chain $chain {" | grep -q "policy drop" \
    || fail "chain $chain does not have policy drop"
done
ok "input, forward and output all default to drop"

printf '%s\n' "$RULESET_OUT" | grep -q 'tcp dport 22 ip saddr @mgmt_bastion' \
  || fail "management SSH allow rule (tcp dport 22, @mgmt_bastion) is missing from the loaded ruleset"
printf '%s\n' "$RULESET_OUT" | grep -q 'udp dport 51820 accept' \
  || fail "WireGuard listener allow rule (udp dport 51820) is missing from the loaded ruleset"
ok "management allow rule and the WireGuard listener rule are present"

# Segmentation shape: the rule that admits site A's tunnel traffic must name
# site A's own LAN set and must NOT also name site B's LAN set (and the
# reverse). If both sites shared one set pair, both greps below would see
# the SAME line and this check could not fail. Written as a function so the
# control below can run the IDENTICAL check against a genuinely broken
# ruleset, instead of just asserting a hand-written line would match.
check_segmentation() {
  local ruleset="$1"
  local site_a_fwd site_b_fwd
  site_a_fwd="$(printf '%s\n' "$ruleset" | grep 'saddr @site_a_tunnel')" || return 1
  site_b_fwd="$(printf '%s\n' "$ruleset" | grep 'saddr @site_b_tunnel')" || return 1
  echo "$site_a_fwd" | grep -q '@site_a_lan' || return 1
  echo "$site_a_fwd" | grep -q '@site_b_lan' && return 1
  echo "$site_b_fwd" | grep -q '@site_b_lan' || return 1
  echo "$site_b_fwd" | grep -q '@site_a_lan' && return 1
  return 0
}

check_segmentation "$RULESET_OUT" \
  || fail "the shipped ruleset does not keep site A and site B on separate forward rules"
ok "forward chain keeps site A and site B on their own set pairs (real segmentation, not a shared set)"

echo "==> control: a real ruleset using ONE shared set pair for both sites must be caught"
# Rebuilds the exact bug this baseline used to have: a single tunnel_peers /
# routed_sites set pair, so ANY tunnel peer reaches ANY routed site. Loaded
# for real, same as the shipped file, not just pattern-matched in the abstract.
mkdir -p "$TMP_DIR/nft-collapsed"
cat > "$TMP_DIR/nft-collapsed/collapsed.nft" <<'EOF'
table inet wg_hub_collapsed
delete table inet wg_hub_collapsed
table inet wg_hub_collapsed {
	set site_a_tunnel { type ipv4_addr; elements = { 10.100.0.2 } }
	set site_b_tunnel { type ipv4_addr; elements = { 10.100.0.3 } }
	set tunnel_peers { type ipv4_addr; elements = { 10.100.0.2, 10.100.0.3 } }
	set routed_sites { type ipv4_addr; flags interval; elements = { 192.168.10.0/24, 192.168.20.0/24 } }
	set site_a_lan { type ipv4_addr; flags interval; elements = { 192.168.10.0/24 } }
	set site_b_lan { type ipv4_addr; flags interval; elements = { 192.168.20.0/24 } }
	chain forward {
		type filter hook forward priority filter; policy drop;
		iifname "wg0" oifname != "wg0" ip saddr @tunnel_peers ip daddr @routed_sites ct state new accept comment "collapsed: any tunnel peer to any routed site"
	}
}
EOF
COLLAPSED_OUT="$(docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$TMP_DIR/nft-collapsed:/n:ro" "$DEBIAN_IMAGE" \
  sh -c "$NFT_INSTALL && nft -f /n/collapsed.nft && nft list ruleset")" \
  || fail "failed to load the collapsed-segmentation control fixture"
if check_segmentation "$COLLAPSED_OUT"; then
  fail "check_segmentation passed on a ruleset that collapses both sites into one shared set pair — the check above proves nothing"
fi
ok "control: the collapsed shared-set ruleset is correctly rejected by check_segmentation"

# ---------------------------------------------------------------------------
# 3. WireGuard config loaded onto a real kernel interface
# ---------------------------------------------------------------------------
# Declared-vs-loaded comparison used for both the real file and its broken
# copies below. It is bash, not a WireGuard tool, on purpose: wg setconf does
# NOT reject an overlapping AllowedIPs assignment (verified empirically), so
# whether the load matches what the file claims has to be checked here.
declared_peers() {
  # stdout: one line per peer, "pubkey|ip1,ip2,..." (sorted ips), from the
  # ORIGINAL (unstripped) file, in file order.
  awk '
    /^\[Peer\]/ { pub=""; ips="" }
    /^[Pp]ublicKey[ \t]*=/ { sub(/^[Pp]ublicKey[ \t]*=[ \t]*/, ""); pub=$0 }
    /^[Aa]llowedIPs[ \t]*=/ {
      sub(/^[Aa]llowedIPs[ \t]*=[ \t]*/, "");
      ips=$0
      print pub "|" ips
    }
  ' "$1" | while IFS='|' read -r pub ips; do
    norm="$(echo "$ips" | tr -d ' ' | tr ',' '\n' | sort | paste -sd, -)"
    echo "$pub|$norm"
  done
}

loaded_peers() {
  # stdout: one line per peer, "pubkey|ip1,ip2,..." (sorted ips), read back
  # from the kernel via `wg show <iface> allowed-ips` inside the container
  # that just loaded it. $1 = container id/name is not used; this function
  # only formats text already captured on stdin.
  while IFS=$'\t' read -r pub ips; do
    [ -n "$pub" ] || continue
    norm="$(echo "$ips" | tr ' ' '\n' | sort | paste -sd, -)"
    echo "$pub|$norm"
  done
}

check_undocumented_full_tunnel() {
  # $1 = config file. Fails (prints offending pubkey) if any [Peer] block
  # has AllowedIPs containing 0.0.0.0/0 or ::/0 without a "full-tunnel"
  # comment (case-insensitive) anywhere in that same block.
  awk '
    BEGIN { block=""; bad=0 }
    /^\[Peer\]/ { if (block != "") { check(block) } block=$0"\n"; next }
    { block = block $0 "\n" }
    function check(b,    lower) {
      lower = tolower(b)
      if ((index(b, "0.0.0.0/0") > 0 || index(b, "::/0") > 0) && index(lower, "full-tunnel") == 0) {
        print "UNDOCUMENTED_FULL_TUNNEL"
        bad=1
      }
    }
    END { if (block != "") check(block); exit bad }
  ' "$1"
}

# $1 = label, $2 = config file on host, $3 = expect ("pass" or "fail-<reason>")
load_and_compare() {
  local label="$1" conf="$2"
  local cdir; cdir="$(mktemp -d "$TMP_DIR/wg-XXXX")"
  cp "$conf" "$cdir/wg0.conf"

  echo "==> WireGuard: $label"

  if ! check_undocumented_full_tunnel "$conf" >/dev/null; then
    echo "    UNDOCUMENTED FULL-TUNNEL PEER DETECTED in $label"
    LAST_RESULT="undocumented-full-tunnel"
    return 0
  fi

  # Single-quoted on purpose: this runs inside the container via `sh -c`, so
  # none of this should expand in the outer script.
  # shellcheck disable=SC2016
  local script='
set -e
apt-get -qq update >/dev/null 2>&1
apt-get -qq install -y wireguard-tools iproute2 >/dev/null 2>&1
wg-quick strip /w/wg0.conf > /tmp/stripped.conf
ip link add wg0 type wireguard
set +e
SETCONF_OUT="$(wg setconf wg0 /tmp/stripped.conf 2>&1)"
SETCONF_RC=$?
set -e
echo "___SETCONF_RC___$SETCONF_RC"
echo "___SETCONF_OUT___"
echo "$SETCONF_OUT"
if [ "$SETCONF_RC" -eq 0 ]; then
  echo "___ALLOWED___"
  wg show wg0 allowed-ips
fi
'
  local out
  out="$(docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
    -v "$cdir:/w:ro" "$DEBIAN_IMAGE" sh -c "$script")"

  local rc
  rc="$(printf '%s\n' "$out" | sed -n 's/^___SETCONF_RC___//p')"
  if [ "$rc" -ne 0 ]; then
    echo "    wg setconf rejected $label:"
    printf '%s\n' "$out" | sed -n '/___SETCONF_OUT___/,/___ALLOWED___/p' | sed '1d;$d' | sed 's/^/    /'
    LAST_RESULT="setconf-rejected"
    return 0
  fi

  local allowed
  allowed="$(printf '%s\n' "$out" | sed -n '/___ALLOWED___/,$p' | sed '1d')"

  local declared loaded
  declared="$(declared_peers "$conf" | sort)"
  loaded="$(printf '%s\n' "$allowed" | loaded_peers | sort)"

  if [ "$declared" = "$loaded" ]; then
    LAST_RESULT="match"
    ok "$label: every peer's loaded AllowedIPs matches the file exactly"
  else
    echo "    declared:"; printf '%s\n' "$declared" | sed 's/^/      /'
    echo "    loaded:  "; printf '%s\n' "$loaded" | sed 's/^/      /'
    LAST_RESULT="mismatch"
  fi
}

LAST_RESULT=""

# --- the real baseline ---
load_and_compare "baselines/network/wg0-hub.conf" "$NET_DIR/wg0-hub.conf"
[ "$LAST_RESULT" = "match" ] \
  || fail "the shipped wg0-hub.conf did not load with exactly the AllowedIPs it declares"

# --- control: malformed public key must be rejected by wg setconf ---
BAD_KEY_CONF="$TMP_DIR/wg-bad-key.conf"
sed 's#PublicKey           = 8AOzqN7sAYgo801d0msUHd7drq9AbxdF+AUnx/XWXWE=#PublicKey           = NOT_A_VALID_KEY#' \
  "$NET_DIR/wg0-hub.conf" > "$BAD_KEY_CONF"
grep -q NOT_A_VALID_KEY "$BAD_KEY_CONF" || fail "test fixture setup failed: key was not substituted"
load_and_compare "control: malformed public key" "$BAD_KEY_CONF"
[ "$LAST_RESULT" = "setconf-rejected" ] \
  || fail "wg setconf accepted a malformed public key — this control proves nothing"
ok "control: malformed public key rejected by wg setconf"

# --- control: overlapping AllowedIPs between two peers must be DETECTED ---
OVERLAP_CONF="$TMP_DIR/wg-overlap.conf"
sed 's#AllowedIPs          = 10.100.0.3/32, 192.168.20.0/24#AllowedIPs          = 10.100.0.3/32, 192.168.20.0/24, 192.168.10.0/24#' \
  "$NET_DIR/wg0-hub.conf" > "$OVERLAP_CONF"
load_and_compare "control: overlapping AllowedIPs (site B also claims site A's LAN)" "$OVERLAP_CONF"
[ "$LAST_RESULT" = "mismatch" ] \
  || fail "an overlapping AllowedIPs assignment was not detected (wg setconf accepted it silently, and so did this script)"
ok "control: overlapping AllowedIPs detected as a declared-vs-loaded mismatch"

# --- control: undocumented full-tunnel (0.0.0.0/0) peer must be flagged ---
FULLTUNNEL_CONF="$TMP_DIR/wg-fulltunnel.conf"
cp "$NET_DIR/wg0-hub.conf" "$FULLTUNNEL_CONF"
cat >> "$FULLTUNNEL_CONF" <<'EOF'

[Peer]
# a roaming laptop's peer block, added with no marker comment at all
PublicKey           = tOXhBB7wxxAKX9KBUAWMdOWloz0ap8DlG1XT4CQxCd8=
AllowedIPs          = 0.0.0.0/0
PersistentKeepalive = 25
EOF
load_and_compare "control: undocumented 0.0.0.0/0 peer" "$FULLTUNNEL_CONF"
[ "$LAST_RESULT" = "undocumented-full-tunnel" ] \
  || fail "an undocumented full-tunnel (0.0.0.0/0) peer was not flagged"
ok "control: undocumented full-tunnel peer flagged before it was ever loaded"

# ---------------------------------------------------------------------------
# 4. every sysctl key exists on THIS host
# ---------------------------------------------------------------------------
# Same reasoning as tests/linux.sh: net.ipv4.* and net.ipv6.* keys are per
# network namespace, so a container's /proc/sys would only prove the
# container's own (irrelevant) namespace has the key, and Docker Desktop
# containers can run on a different kernel than this host entirely. This
# reads /proc/sys directly on the machine running the test and writes
# nothing.
SYSCTL_FILE="$NET_DIR/sysctl.d/99-wireguard-forwarding.conf"
echo "==> every sysctl key in 99-wireguard-forwarding.conf exists in this kernel ($(uname -r))"
SYSCTL_KEYS="$(grep -vE '^\s*(#|;|$)' "$SYSCTL_FILE" | cut -d= -f1 | tr -d ' \t' | sort -u)"
[ -n "$SYSCTL_KEYS" ] || fail "no sysctl keys parsed out of 99-wireguard-forwarding.conf"

check_sysctl_keys() {
  local key path missing=0 total=0
  while read -r key; do
    [ -n "$key" ] || continue
    total=$((total + 1))
    path="/proc/sys/${key//.//}"
    if [ ! -e "$path" ]; then
      echo "    MISSING $key"
      missing=$((missing + 1))
    fi
  done
  echo "    checked $total keys, missing $missing"
  [ "$missing" -eq 0 ]
}

printf '%s\n' "$SYSCTL_KEYS" | check_sysctl_keys \
  || fail "at least one sysctl key does not exist in this kernel"
ok "$(printf '%s\n' "$SYSCTL_KEYS" | wc -l) keys all present under /proc/sys"

echo "==> control: a nonexistent sysctl key must be reported"
if printf 'net.ipv4.conf.all.not_a_real_key\n' | check_sysctl_keys >/dev/null 2>&1; then
  fail "the sysctl existence check passed on a key that does not exist"
fi
ok "fabricated key reported as missing"

# ---------------------------------------------------------------------------
# 5. shellcheck
# ---------------------------------------------------------------------------
echo "==> shellcheck: tests/network.sh"
docker run --rm -i "$SHELLCHECK_IMAGE" --severity=style - < "$ROOT_DIR/tests/network.sh" \
  || fail "shellcheck reported problems in tests/network.sh"
ok "tests/network.sh is shellcheck-clean (severity=style)"

echo "==> control: shellcheck must flag a broken script"
# shellcheck disable=SC2016
if printf '#!/bin/sh\nif [ $1 = x ]; then echo y\n' \
  | docker run --rm -i "$SHELLCHECK_IMAGE" --severity=style - >/dev/null 2>&1; then
  fail "shellcheck accepted a script with an unquoted variable and a missing fi"
fi
ok "broken script rejected"

echo
echo "All network baseline checks passed."

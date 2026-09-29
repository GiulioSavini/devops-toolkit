#!/usr/bin/env bash
# Validation of baselines/linux/*.
#
# What is checked for real:
#   - the sshd drop-ins are parsed by the real sshd binary (`sshd -t`) on three
#     distributions carrying three different OpenSSH versions, so the version
#     split between 01-crypto-openssh87.conf and 01-crypto-openssh99.conf is
#     proven rather than asserted in a comment;
#   - the drop-in still sorts before the distro files that would otherwise win
#     (Ubuntu's 50-cloud-init.conf, RHEL's 50-redhat.conf), because sshd takes
#     the FIRST value it reads for a keyword;
#   - every sysctl key exists in the running kernel;
#   - the nftables ruleset is accepted by nft's own parser (`nft -c -f`);
#   - every audit rule is accepted by auditctl's parser;
#   - shipped shell scripts are shellcheck-clean.
#
# Every check is paired with a control that must FAIL, so a check that silently
# stopped validating anything cannot stay green.
#
# Host requirements: docker and bash. Everything else runs in pinned images.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LINUX_DIR="$ROOT_DIR/baselines/linux"

DEBIAN12_IMAGE="debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251"
DEBIAN13_IMAGE="debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a"
ALMA9_IMAGE="almalinux@sha256:e03fe7d942a94ad7a72b9fe5eb6af54388b05bc8357151c891f13c023817df98"
SHELLCHECK_IMAGE="koalaman/shellcheck@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "    ok: $*"; }

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
command -v docker >/dev/null || fail "docker is required"
docker info >/dev/null 2>&1 || fail "cannot reach a docker daemon (docker info failed)"

echo "==> docker preflight: pinned images are pullable"
for image in "$DEBIAN12_IMAGE" "$DEBIAN13_IMAGE" "$ALMA9_IMAGE" "$SHELLCHECK_IMAGE"; do
  docker pull -q "$image" >/dev/null || fail "cannot pull $image"
done

# ---------------------------------------------------------------------------
# 1. the real sshd binary parses the drop-ins
# ---------------------------------------------------------------------------
# sshd -t reads the config, resolves every keyword against the version it was
# compiled with, and exits without listening. An unknown keyword or an
# algorithm the build does not support is a hard error, which is exactly the
# failure that otherwise happens on `systemctl restart sshd` with no way back
# in.
#
# The harness below assembles a realistic /etc/ssh: a main sshd_config that
# does nothing but Include the drop-in directory (as every supported distro
# ships), host keys generated with ssh-keygen -A, and the files the optional
# drop-ins point at. 10-user-ca.conf is deliberately included: RevokedKeys
# pointing at a missing file is a real outage (sshd refuses public key auth
# for everyone), so the test creates the KRL the guide tells you to create.
CFG_IN_CONTAINER=/etc/ssh-under-test

prepare_ssh_tree() {
  # $1 = destination directory on the host, remaining args = drop-in basenames.
  # The Include path must be the path INSIDE the container: written with the
  # host path, the glob matches nothing there and sshd cheerfully validates an
  # empty configuration, which is how this harness first passed while checking
  # nothing at all.
  local dest="$1"; shift
  mkdir -p "$dest/sshd_config.d" "$dest/auth_principals"
  printf 'Include %s/sshd_config.d/*.conf\n' "$CFG_IN_CONTAINER" > "$dest/sshd_config"
  local f
  for f in "$@"; do
    cp "$LINUX_DIR/ssh/sshd_config.d/$f" "$dest/sshd_config.d/$f"
  done
  cp "$LINUX_DIR/ssh/issue.net" "$dest/issue.net"
}

# The in-container script: generate host keys, satisfy the file references of
# the optional drop-ins, then parse. Kept as one string so each distro runs
# the identical steps.
SSHD_CHECK_SCRIPT='
set -e
cfg=/etc/ssh-under-test
# sshd -t insists on the privilege separation directory existing even though it
# never forks here. Debian puts it at /run/sshd, RHEL at /var/empty/sshd.
mkdir -p /run/sshd /var/empty/sshd
mkdir -p /etc/ssh
ssh-keygen -A >/dev/null
# Files referenced by 10-user-ca.conf. A missing RevokedKeys file is an
# outage, not a warning, so it is created the way the guide says to.
ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/user_ca >/dev/null 2>&1 || true
cp /etc/ssh/user_ca.pub /etc/ssh/user_ca.pub 2>/dev/null || true
ssh-keygen -k -f /etc/ssh/revoked_keys >/dev/null 2>&1 || : > /etc/ssh/revoked_keys
if [ -f /etc/ssh/ssh_host_ed25519_key.pub ]; then
  ssh-keygen -q -s /etc/ssh/user_ca -I testhost -h \
    -n localhost /etc/ssh/ssh_host_ed25519_key.pub >/dev/null 2>&1 || true
fi
sed -i "s#^Banner .*#Banner $cfg/issue.net#" "$cfg"/sshd_config.d/*.conf 2>/dev/null || true
exec "$SSHD" -t -f "$cfg/sshd_config"
'

run_sshd_check() {
  # $1 = image, $2 = install command, $3 = sshd path, $4 = tree dir
  local image="$1" install="$2" sshd_path="$3" tree="$4"
  docker run --rm -v "$tree:/etc/ssh-under-test" \
    -e SSHD="$sshd_path" "$image" \
    sh -c "$install >/dev/null 2>&1; $SSHD_CHECK_SCRIPT" 2>&1
}

DEB_INSTALL='apt-get -qq update && apt-get -qq install -y openssh-server openssh-client'
ALMA_INSTALL='microdnf install -y openssh-server openssh-clients'

# distro label | image | install | sshd path | OpenSSH major.minor | crypto file
# that must parse | crypto file that must be REJECTED | does it support
# PerSourcePenalties (9.8+)
check_distro() {
  local label="$1" image="$2" install="$3" sshd_path="$4" ok_crypto="$5" bad_crypto="$6" penalties="$7"

  echo "==> sshd -t on $label"

  local tree="$TMP_DIR/ssh-$label-ok"
  local -a files=(00-hardening.conf "$ok_crypto" 10-user-ca.conf 90-bastion-forwarding.conf)
  [ "$penalties" = "yes" ] && files+=(02-persource-penalties.conf)
  prepare_ssh_tree "$tree" "${files[@]}"
  local out
  if ! out="$(run_sshd_check "$image" "$install" "$sshd_path" "$tree")"; then
    echo "$out" >&2
    fail "sshd -t rejected the baseline drop-ins on $label"
  fi
  ok "$label accepts 00-hardening.conf + $ok_crypto$([ "$penalties" = yes ] && echo ' + 02-persource-penalties.conf')"

  # Control: the crypto file for the other OpenSSH generation MUST be refused
  # here. If it is accepted, the version split this repository documents is
  # fiction and the check above proves nothing about it.
  if [ -n "$bad_crypto" ]; then
    local badtree="$TMP_DIR/ssh-$label-bad"
    prepare_ssh_tree "$badtree" 00-hardening.conf "$bad_crypto"
    if run_sshd_check "$image" "$install" "$sshd_path" "$badtree" >/dev/null 2>&1; then
      fail "$label accepted $bad_crypto, which requires a newer OpenSSH — the version split in the guide is wrong"
    fi
    ok "control: $label rejects $bad_crypto (wrong OpenSSH generation)"
  fi
}

# OpenSSH 9.2 (Debian 12): no mlkem768x25519-sha256 (9.9), no
# PerSourcePenalties (9.8).
check_distro debian12 "$DEBIAN12_IMAGE" "$DEB_INSTALL" /usr/sbin/sshd \
  01-crypto-openssh87.conf 01-crypto-openssh99.conf no
# OpenSSH 9.9 (AlmaLinux 9 / RHEL 9.6+): mlkem768x25519-sha256 exists.
check_distro alma9 "$ALMA9_IMAGE" "$ALMA_INSTALL" /usr/sbin/sshd \
  01-crypto-openssh99.conf "" yes
# OpenSSH 10.0 (Debian 13).
check_distro debian13 "$DEBIAN13_IMAGE" "$DEB_INSTALL" /usr/sbin/sshd \
  01-crypto-openssh99.conf "" yes

# Control: a genuinely broken keyword must be caught by the same harness, so a
# passing run above cannot be the harness quietly ignoring sshd's exit code.
echo "==> control: sshd -t must REJECT an invalid keyword"
BROKEN_TREE="$TMP_DIR/ssh-broken"
prepare_ssh_tree "$BROKEN_TREE" 00-hardening.conf
printf 'ThisKeywordDoesNotExist yes\n' >> "$BROKEN_TREE/sshd_config.d/00-hardening.conf"
if run_sshd_check "$DEBIAN13_IMAGE" "$DEB_INSTALL" /usr/sbin/sshd "$BROKEN_TREE" >/dev/null 2>&1; then
  fail "sshd -t accepted an unknown keyword — this harness is not validating anything"
fi
ok "broken keyword rejected"

# ---------------------------------------------------------------------------
# 2. load order: the drop-in must win against the distro's own files
# ---------------------------------------------------------------------------
# sshd applies the first value it reads for a keyword, and Include expands in
# lexical order. Ubuntu cloud images ship 50-cloud-init.conf, which can set
# PasswordAuthentication yes; RHEL ships 50-redhat.conf. A baseline that sorts
# after either is silently ineffective, with no error anywhere.
echo "==> load order: the hardening drop-in sorts before the distro drop-ins"
for distro_file in 50-cloud-init.conf 50-redhat.conf 60-something.conf; do
  first="$(printf '00-hardening.conf\n%s\n' "$distro_file" | LC_ALL=C sort | head -1)"
  [ "$first" = "00-hardening.conf" ] \
    || fail "00-hardening.conf does not sort before $distro_file"
done
ok "00-hardening.conf sorts first against 50-cloud-init.conf, 50-redhat.conf, 60-something.conf"

# And prove it matters: the same keyword set twice keeps the FIRST value.
echo "==> control: sshd keeps the FIRST value for a repeated keyword"
ORDER_TREE="$TMP_DIR/ssh-order"
prepare_ssh_tree "$ORDER_TREE" 00-hardening.conf
printf 'PasswordAuthentication yes\n' > "$ORDER_TREE/sshd_config.d/50-cloud-init.conf"
ORDER_OUT="$(docker run --rm -v "$ORDER_TREE:/etc/ssh-under-test" \
  -e SSHD=/usr/sbin/sshd "$DEBIAN13_IMAGE" \
  sh -c "$DEB_INSTALL >/dev/null 2>&1; /usr/sbin/sshd -T -f /etc/ssh-under-test/sshd_config 2>/dev/null | grep -i '^passwordauthentication'")"
[ "$ORDER_OUT" = "passwordauthentication no" ] \
  || fail "expected the drop-in to win (passwordauthentication no), got: $ORDER_OUT"
ok "with a later 50-cloud-init.conf setting yes, the effective value is still: $ORDER_OUT"

# ---------------------------------------------------------------------------
# 3. every sysctl key exists in the kernel
# ---------------------------------------------------------------------------
# A typo in a sysctl key is not an error at boot: systemd-sysctl logs it and
# carries on, so the setting is simply absent. Checking that each key exists
# under /proc/sys is therefore the check that matters.
#
# This check reads /proc/sys on the machine running the test, not inside a
# container: /proc/sys/net in a container network namespace exposes only the
# namespaced keys, and Docker Desktop containers run on the VM's kernel rather
# than this host's, so a global key such as net.core.bpf_jit_harden looks
# absent there while existing on every real server. Nothing is written.
#
# A key genuinely missing here means either a typo in the baseline or a kernel
# built without that feature; both deserve the failure, because a key that does
# not exist is a setting that silently does nothing.
echo "==> every sysctl key in 99-hardening.conf exists in this kernel ($(uname -r))"
SYSCTL_KEYS="$(grep -vE '^\s*(#|;|$)' "$LINUX_DIR/sysctl.d/99-hardening.conf" \
  | cut -d= -f1 | tr -d ' \t' | sort -u)"
[ -n "$SYSCTL_KEYS" ] || fail "no sysctl keys parsed out of 99-hardening.conf"

check_sysctl_keys() {
  # reads keys on stdin, prints missing ones, returns non-zero if any
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
# 4. nft parses the ruleset
# ---------------------------------------------------------------------------
# `nft -c -f` runs the real parser and the real kernel-side validation of
# expressions without committing the ruleset. It needs CAP_NET_ADMIN to talk to
# netlink at all, hence --cap-add; it still changes nothing, and it runs in the
# container's own network namespace.
echo "==> nft -c -f: baselines/linux/nftables/host-filter.nft"
NFT_RUN='apt-get -qq update >/dev/null 2>&1; apt-get -qq install -y nftables >/dev/null 2>&1; nft -c -f'
docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$LINUX_DIR/nftables:/n:ro" "$DEBIAN13_IMAGE" \
  sh -c "$NFT_RUN /n/host-filter.nft" || fail "nft rejected host-filter.nft"
ok "ruleset accepted by nft $(docker run --rm "$DEBIAN13_IMAGE" sh -c 'apt-get -qq update >/dev/null 2>&1; apt-get -qq install -y nftables >/dev/null 2>&1; nft --version' | awk '{print $2}')"

echo "==> control: nft must REJECT a broken ruleset"
mkdir -p "$TMP_DIR/nft"
sed 's/tcp dport/tcp dprot/' "$LINUX_DIR/nftables/host-filter.nft" > "$TMP_DIR/nft/broken.nft"
if docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$TMP_DIR/nft:/n:ro" "$DEBIAN13_IMAGE" \
  sh -c "$NFT_RUN /n/broken.nft" >/dev/null 2>&1; then
  fail "nft accepted a ruleset with an invalid match — the check above proves nothing"
fi
ok "broken ruleset rejected"

# ---------------------------------------------------------------------------
# 5. auditd rules
# ---------------------------------------------------------------------------
# auditd rules cannot be LOADED here: the kernel refuses audit netlink writes
# from a container even with --privileged, and WSL2 has no audit subsystem at
# all. What can still be validated is the part that actually breaks a rollout —
# whether auditctl understands each line.
#
# For add-rule lines (-a/-A/-w) the two outcomes are distinguishable, because
# auditctl parses first and only then talks to the kernel:
#   parsed, kernel refused -> "Operation not permitted"
#   failed to parse        -> no kernel attempt, no such message
# So a line that reaches the kernel is a line auditctl understood.
#
# Control directives (-e, -b, -f, -D, --backlog_wait_time) give no output
# either way in a container, valid or not, so the netlink trick cannot judge
# them. They are checked structurally instead, against the closed set of
# directives and values auditctl accepts. That is stated here rather than
# papered over: it is a weaker check than the one above.
echo "==> auditd rules: classify lines, then check each class"
RULE_LINES="$TMP_DIR/audit-rules.txt"
: > "$RULE_LINES"
CONTROL_COUNT=0
while IFS= read -r line; do
  case "$line" in
    -a\ *|-A\ *|-w\ *) printf '%s\n' "$line" >> "$RULE_LINES" ;;
    # Closed set of control directives, with the values auditctl accepts:
    #   -e 0|1|2   audit enabled / enabled+locked
    #   -f 0|1|2   failure mode: silent / printk / panic
    #   -b N       backlog limit
    #   -D         delete all rules
    #   --backlog_wait_time N
    -e\ [012]|-f\ [012]|-b\ [1-9]*|-D|--backlog_wait_time\ [0-9]*)
      CONTROL_COUNT=$((CONTROL_COUNT + 1)) ;;
    *) fail "unrecognised audit line (neither a rule nor a known control directive): $line" ;;
  esac
done < <(grep -hvE '^\s*(#|$)' "$LINUX_DIR"/audit/rules.d/*.rules)
ok "$CONTROL_COUNT control directives match the documented set and values"

AUDIT_CHECK='
microdnf install -y audit >/dev/null 2>&1
bad=0; total=0
while IFS= read -r rule; do
  total=$((total + 1))
  printf "%s\n" "$rule" > /tmp/one.rule
  out="$(auditctl -R /tmp/one.rule 2>&1 || true)"
  case "$out" in
    *"Operation not permitted"*) ;;
    *) echo "UNPARSED $rule"; bad=$((bad + 1)) ;;
  esac
done < /rules/audit-rules.txt
echo "    parsed $((total - bad))/$total rules"
[ "$bad" -eq 0 ]
'
docker run --rm --privileged -v "$TMP_DIR:/rules:ro" "$ALMA9_IMAGE" sh -c "$AUDIT_CHECK" \
  || fail "at least one audit rule was not understood by auditctl"
ok "all $(wc -l < "$RULE_LINES") add-rule lines accepted by auditctl's parser"

echo "==> control: auditctl must NOT parse a malformed audit rule"
printf -- '-a always,exit -F arch=b64 -S this_syscall_does_not_exist -k bogus\n' \
  > "$TMP_DIR/audit-rules.txt"
if docker run --rm --privileged -v "$TMP_DIR:/rules:ro" "$ALMA9_IMAGE" \
  sh -c "$AUDIT_CHECK" >/dev/null 2>&1; then
  fail "the audit rule check passed on a rule naming a syscall that does not exist"
fi
ok "malformed rule reported as unparsed"

echo "==> control: an invalid control directive must be rejected"
if printf -- '-e 7\n' | { while IFS= read -r line; do
     case "$line" in
       -e\ [012]|-f\ [012]|-b\ [1-9]*|-D|--backlog_wait_time\ [0-9]*) exit 0 ;;
       *) exit 1 ;;
     esac
   done; }; then
  fail "the control-directive check accepted '-e 7'"
fi
ok "'-e 7' rejected"

# ---------------------------------------------------------------------------
# 6. shellcheck
# ---------------------------------------------------------------------------
echo "==> shellcheck: shipped scripts"
mapfile -t SCRIPTS < <(find "$LINUX_DIR" -type f -name '*.sh' | sort)
[ "${#SCRIPTS[@]}" -gt 0 ] || fail "no scripts found under $LINUX_DIR — expected ssh-rollout-guard.sh"
for script in "${SCRIPTS[@]}"; do
  docker run --rm -i "$SHELLCHECK_IMAGE" --severity=style - < "$script" \
    || fail "shellcheck reported problems in $script"
  ok "$(basename "$script") is shellcheck-clean (severity=style)"
done

echo "==> control: shellcheck must flag a broken script"
if printf '#!/bin/sh\nif [ $1 = x ]; then echo y\n' \
  | docker run --rm -i "$SHELLCHECK_IMAGE" --severity=style - >/dev/null 2>&1; then
  fail "shellcheck accepted a script with an unquoted variable and a missing fi"
fi
ok "broken script rejected"

echo
echo "All Linux baseline checks passed."

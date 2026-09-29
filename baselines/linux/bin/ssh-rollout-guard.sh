#!/usr/bin/env bash
#
# ssh-rollout-guard.sh - install sshd_config drop-ins so that a mistake heals
# itself. Every hardening rollout that can lock you out is run through this:
#
#   sudo ./ssh-rollout-guard.sh stage 00-hardening.conf 01-crypto-openssh87.conf
#   # -> config validated, sshd reloaded, automatic revert armed (default 10m)
#   # open a SECOND ssh session now, from a second terminal
#   sudo ./ssh-rollout-guard.sh commit          # only if the new session worked
#
# Do nothing and the host reverts to the previous drop-in directory on its own.
# The existing session is never dropped: sshd is reloaded, not restarted, and a
# reload does not touch established connections.
#
# Requires: bash, systemd (systemd-run) and root. No other dependencies.

set -euo pipefail

DROPIN_DIR=/etc/ssh/sshd_config.d
BACKUP_ROOT=/var/backups/ssh-rollout-guard
CURRENT_LINK="$BACKUP_ROOT/pending"
REVERT_UNIT=ssh-rollout-revert
TIMEOUT="${TIMEOUT:-10min}"

die() { printf 'ssh-rollout-guard: %s\n' "$*" >&2; exit 1; }
info() { printf '==> %s\n' "$*"; }

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "run as root"
command -v systemd-run >/dev/null || die "systemd-run not found (systemd required)"

# Debian and Ubuntu call the unit ssh.service, RHEL and SUSE call it sshd.service.
sshd_unit() {
  local u
  for u in sshd.service ssh.service; do
    if systemctl cat "$u" >/dev/null 2>&1; then printf '%s\n' "$u"; return 0; fi
  done
  die "no sshd.service or ssh.service on this host"
}

# sshd -t parses the whole include tree and refuses a config it could not serve.
validate() {
  if ! sshd -t; then
    return 1
  fi
}

# Refuse a config that would lock out the account running the rollout: if
# publickey is not an accepted method for that user, nothing else matters.
check_operator() {
  local user="$1" methods
  methods="$(sshd -T -C "user=$user,host=localhost,addr=127.0.0.1" 2>/dev/null |
             sed -n 's/^authenticationmethods //p')"
  case "$methods" in
    *publickey*|'') ;;  # empty: keyword not printed by this sshd version
    *) die "AuthenticationMethods for $user is '$methods' - publickey not allowed, refusing" ;;
  esac
  if [[ "$(sshd -T -C "user=$user,host=localhost,addr=127.0.0.1" 2>/dev/null |
           sed -n 's/^pubkeyauthentication //p')" == "no" ]]; then
    die "PubkeyAuthentication is no for $user, refusing"
  fi
  # AllowUsers/AllowGroups that exclude the operator is the other classic.
  local allow
  allow="$(sshd -T -C "user=$user,host=localhost,addr=127.0.0.1" 2>/dev/null |
           sed -n 's/^allowusers //p')"
  if [[ -n "$allow" && " $allow " != *" $user "* ]]; then
    die "AllowUsers is '$allow' and does not list $user, refusing"
  fi
}

cmd_stage() {
  [[ $# -gt 0 ]] || die "usage: $0 stage <drop-in>..."
  local f stamp backup unit operator
  for f in "$@"; do [[ -f "$f" ]] || die "no such file: $f"; done

  operator="${SUDO_USER:-root}"
  unit="$(sshd_unit)"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup="$BACKUP_ROOT/$stamp"

  if systemctl is-active --quiet "$REVERT_UNIT.timer"; then
    die "a rollout is already pending (commit or revert it first)"
  fi

  info "backing up $DROPIN_DIR to $backup"
  mkdir -p "$backup"
  # cp -a with a trailing /. copies an empty directory too.
  mkdir -p "$DROPIN_DIR"
  cp -a "$DROPIN_DIR/." "$backup/"
  ln -sfn "$backup" "$CURRENT_LINK"

  info "installing: $*"
  install -o root -g root -m 0644 -t "$DROPIN_DIR" "$@"

  if ! validate; then
    info "sshd -t rejected the new config - restoring and aborting"
    restore_from "$backup"
    die "config not applied"
  fi
  check_operator "$operator"

  # Arm the revert BEFORE reloading: if the reload wedges the daemon, the timer
  # is already in place. --on-active starts counting now; the transient unit
  # survives our exit and is not tied to this ssh session.
  info "arming automatic revert in $TIMEOUT (unit $REVERT_UNIT)"
  systemd-run --quiet --collect \
    --unit="$REVERT_UNIT" \
    --on-active="$TIMEOUT" \
    --description="revert unconfirmed sshd_config.d rollout" \
    /bin/bash -c "rm -rf '$DROPIN_DIR'; cp -a '$backup' '$DROPIN_DIR'; \
                  sshd -t && systemctl reload '$unit'; \
                  logger -t ssh-rollout-guard 'reverted unconfirmed rollout from $backup'"

  info "reloading $unit"
  if ! systemctl reload "$unit"; then
    info "reload failed - reverting now"
    cmd_revert
    die "reload failed"
  fi

  cat <<MSG

Staged. sshd is running the new config and will revert in $TIMEOUT.
  1. From ANOTHER terminal:  ssh -v $operator@$(hostname -f 2>/dev/null || hostname)
  2. If that worked:         sudo $0 commit
  3. If it did not:          do nothing, or sudo $0 revert
MSG
}

restore_from() {
  local backup="$1"
  [[ -d "$backup" ]] || die "backup $backup is gone - restore $DROPIN_DIR by hand"
  rm -rf "$DROPIN_DIR"
  cp -a "$backup" "$DROPIN_DIR"
}

cmd_revert() {
  local unit backup
  unit="$(sshd_unit)"
  backup="$(readlink -f "$CURRENT_LINK" 2>/dev/null || true)"
  [[ -n "$backup" ]] || die "nothing to revert (no $CURRENT_LINK)"
  info "restoring $backup"
  restore_from "$backup"
  validate || die "restored config does not pass sshd -t - fix $DROPIN_DIR by hand NOW"
  systemctl reload "$unit"
  systemctl stop "$REVERT_UNIT.timer" 2>/dev/null || true
  rm -f "$CURRENT_LINK"
  info "reverted"
}

cmd_commit() {
  systemctl stop "$REVERT_UNIT.timer" 2>/dev/null || true
  systemctl reset-failed "$REVERT_UNIT.timer" "$REVERT_UNIT.service" 2>/dev/null || true
  rm -f "$CURRENT_LINK"
  info "committed - automatic revert disarmed"
}

cmd_status() {
  if systemctl is-active --quiet "$REVERT_UNIT.timer"; then
    systemctl list-timers --all "$REVERT_UNIT.timer" --no-pager
    printf 'pending backup: %s\n' "$(readlink -f "$CURRENT_LINK" 2>/dev/null || echo none)"
  else
    printf 'no rollout pending\n'
  fi
}

case "${1:-}" in
  stage)  shift; cmd_stage "$@" ;;
  commit) cmd_commit ;;
  revert) cmd_revert ;;
  status) cmd_status ;;
  *) die "usage: $0 {stage <drop-in>... | commit | revert | status}   (TIMEOUT=10min)" ;;
esac

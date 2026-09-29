# Linux Server Hardening

A baseline for internet-facing and internal Linux servers: kernel parameters,
sshd, host firewall, audit trail, account lockout, automatic security updates.
Every setting ships as a file under [`baselines/linux/`](../baselines/linux/)
and is validated by [`tests/linux.sh`](../tests/linux.sh) against the real
tools, on three OpenSSH generations.

| | |
|---|---|
| Applies to | Ubuntu 22.04/24.04 LTS, Debian 12/13, RHEL/Rocky/Alma 9. OpenSSH 8.7 through 10.0, systemd 249+, nftables 1.0.2+ |
| Baseline files | [`baselines/linux/`](../baselines/linux/) |
| Validated by | [`tests/linux.sh`](../tests/linux.sh) |
| Lockout risk | **High.** The sshd drop-in, the nftables default-deny policy and `pam_faillock` can each end remote access. Use the staged rollout below; it auto-reverts |
| Last reviewed | 2026-09 |

## Threat model

What this baseline is for:

- An attacker with network reach to the host and no credentials: brute force
  and credential stuffing against sshd, exposed service ports, spoofed and
  redirected traffic.
- An attacker who lands as an unprivileged local user (web application
  compromise, stolen low-privilege key) and wants root: kernel exploit
  primitives, information leaks that make them reliable, setuid core dumps,
  and module autoloading as attack surface.
- An operator mistake becoming an outage: a config that locks everyone out, a
  firewall applied before the allow rules, a full `/boot` breaking the next
  kernel update.
- Producing the evidence needed after the fact: who changed what, from where,
  and when.

What it is not for:

- **Multi-tenant isolation.** Untrusted workloads on a shared kernel need a VM
  boundary, not sysctl tuning.
- **An attacker with root.** Once root is reached, everything here is
  reversible by the attacker; the audit trail matters only if it is shipped
  off the host in real time.
- **Supply chain.** Packages you install are trusted by definition.
- **Secrets in application config.** See
  [secrets management](secrets-management.md).
- **Compliance evidence.** The control mapping at the end tells you which
  controls a section touches; it is not an audit artifact.

## Package baseline and automatic security updates

Install only what the host's role needs, and let security errata apply
themselves. Unpatched known CVEs, not novel exploits, are what actually gets
hosts compromised.

```bash
# Debian / Ubuntu
apt-get install --no-install-recommends unattended-upgrades \
  libpam-pwquality nftables auditd
# RHEL / Rocky / Alma
dnf install -y dnf-automatic nftables audit
```

Ship the two drop-ins and enable the timer:

| File | Purpose |
|---|---|
| [`updates/apt/20auto-upgrades`](../baselines/linux/updates/apt/20auto-upgrades) | enables the periodic update and upgrade run |
| [`updates/apt/52unattended-upgrades-local`](../baselines/linux/updates/apt/52unattended-upgrades-local) | behaviour only: no automatic reboot, prune old kernels, minimal steps |
| [`updates/dnf/automatic.conf`](../baselines/linux/updates/dnf/automatic.conf) | `upgrade_type = security`, `apply_updates = yes`, `reboot = never` |

```bash
systemctl enable --now dnf-automatic.timer    # RHEL family
```

Three things that go wrong here:

- **Enabling the wrong dnf timer.** `dnf-automatic-install.timer`,
  `-download.timer` and `-notifyonly.timer` each override `apply_updates` in
  the config file. Only `dnf-automatic.timer` honours what you configured.
- **`upgrade_type = security` on a repository with no `updateinfo` metadata.**
  RHEL, Rocky, Alma and EPEL publish it. CentOS Stream and most third-party
  repositories do not, and then nothing is ever installed and nothing warns
  you. Verify with `dnf updateinfo summary`.
- **Reboots.** Kernel and glibc updates change nothing until a reboot. Both
  baselines keep the reboot under your change process, so you must alert on
  `/var/run/reboot-required` (Debian family) or `needs-restarting -r`
  (RHEL family). An automatic update policy with no reboot policy produces
  hosts that are patched on disk and vulnerable in memory.

## Kernel parameters

[`sysctl.d/99-hardening.conf`](../baselines/linux/sysctl.d/99-hardening.conf),
applied with `sysctl --system`. The filename sorts after the distro's own
files, so these values win.

The two groups behave differently, which matters on any host running
containers: `kernel.*`, `fs.*`, `vm.*` and `dev.*` are global, while
`net.ipv4.*` and `net.ipv6.*` are **per network namespace**. Setting them on
the host does not change what a container sees, and a container with
`CAP_NET_ADMIN` sets its own.

The values that are not obvious:

| Key | Value | Why |
|---|---|---|
| `kernel.kptr_restrict` | `2` | Hides kernel pointers from everyone. `perf` and `bpftrace` on the host may need `1` |
| `kernel.yama.ptrace_scope` | `1` | Only a parent may ptrace its children. Breaks `gdb -p` / `strace -p` against unrelated processes for non-root users — this is the intended effect |
| `kernel.unprivileged_bpf_disabled` | `1` | Unprivileged eBPF has been the entry point for several local privilege escalations. **One-way: it cannot be set back without a reboot** |
| `net.core.bpf_jit_harden` | `2` | Constant blinding for JIT'd BPF. Lives under `net.` but is global, and is only visible in the initial network namespace |
| `dev.tty.ldisc_autoload` | `0` | Stops unprivileged users autoloading TTY line disciplines (the CVE-2017-2636 class) |
| `vm.unprivileged_userfaultfd` | `0` | Removes a common exploit primitive for winning kernel races |
| `fs.suid_dumpable` | `0` | A core dump of a setuid binary can contain `/etc/shadow` contents |
| `fs.protected_fifos` / `fs.protected_regular` | `2` | Also covers group-writable directories, not just world-writable ones |
| `net.ipv4.conf.all.rp_filter` | `1` | Strict reverse path filtering. **Use `2` (loose) on multi-homed hosts or with asymmetric routing**, otherwise replies arriving on the "wrong" interface are dropped |
| `net.ipv4.conf.all.send_redirects` | `0` | A server is not a router |
| `net.ipv4.tcp_syncookies` | `1` | Only engages when the SYN backlog overflows; it is not a rate limiter |

Deliberately **not** set, because the right value depends on the host's job:

- `net.ipv4.ip_forward` — required by Docker, Kubernetes, any VPN gateway or
  NAT host. Setting it to `0` fleet-wide breaks all of them.
- `net.ipv6.conf.all.accept_ra` — hosts that get their address from router
  advertisements lose connectivity without it.
- `kernel.kexec_load_disabled` — one-way, and it blocks `kdump`.
- `kernel.perf_event_paranoid` — raising it disables the profilers your
  performance work depends on.

`tests/linux.sh` checks that every key in the file exists in the running
kernel, because a typo is not an error: `systemd-sysctl` logs it and carries
on, leaving the setting silently absent.

## sshd

Four drop-ins, installed in `/etc/ssh/sshd_config.d/`. Install exactly one of
the two crypto files.

| File | Install on |
|---|---|
| [`00-hardening.conf`](../baselines/linux/ssh/sshd_config.d/00-hardening.conf) | every host |
| [`01-crypto-openssh87.conf`](../baselines/linux/ssh/sshd_config.d/01-crypto-openssh87.conf) | OpenSSH 8.7–9.8 (RHEL 9.0–9.5, Ubuntu 22.04, Debian 12) |
| [`01-crypto-openssh99.conf`](../baselines/linux/ssh/sshd_config.d/01-crypto-openssh99.conf) | OpenSSH 9.9+ (RHEL 9.6+, Debian 13, Ubuntu 24.10+) |
| [`02-persource-penalties.conf`](../baselines/linux/ssh/sshd_config.d/02-persource-penalties.conf) | OpenSSH 9.8+ only |
| [`10-user-ca.conf`](../baselines/linux/ssh/sshd_config.d/10-user-ca.conf) | hosts accepting SSH certificates — see [SSH key management](ssh-key-management.md) |
| [`90-bastion-forwarding.conf`](../baselines/linux/ssh/sshd_config.d/90-bastion-forwarding.conf) | bastion hosts only |

### The filename is part of the configuration

sshd keeps the **first** value it reads for each keyword, and `Include
/etc/ssh/sshd_config.d/*.conf` expands in lexical order. Ubuntu cloud images
ship `50-cloud-init.conf`, which may set `PasswordAuthentication yes`; RHEL
ships `50-redhat.conf`. A file named `hardening.conf` or `99-hardening.conf`
sorts after both and loses, with no warning anywhere — the host simply still
accepts passwords.

This is the single most common way an SSH baseline is applied and does
nothing, so `tests/linux.sh` asserts it: with a later `50-cloud-init.conf`
setting `PasswordAuthentication yes`, `sshd -T` must still report `no`.

### What the baseline sets, and what the old advice got wrong

- `PermitRootLogin no`, `PasswordAuthentication no`,
  `KbdInteractiveAuthentication no`, `AuthenticationMethods publickey`.
  Disabling `PasswordAuthentication` alone is not enough: the
  keyboard-interactive path runs the PAM conversation, which can also prompt
  for a password.
- `Protocol 2` is **not** set. The keyword was removed in OpenSSH 7.6; on a
  current build it is an unknown keyword. `Port 22` is not set either — it is
  the default, and writing it down only creates a second place to change.
- `GSSAPIAuthentication no`, because RHEL enables it in `50-redhat.conf`. Leave
  it on only where Kerberos or AD logins are actually used.
- `LogLevel VERBOSE` records the fingerprint of the key or certificate used for
  each login. Without it you know an account logged in, not which key did — the
  difference that matters when a key is later found to be compromised.
- `MaxAuthTries 3` counts every key the client offers. A client with a dozen
  keys in its agent hits the limit before reaching the right one, which is why
  the shipped client config sets `IdentitiesOnly yes`.
- `ClientAliveInterval 300` with `ClientAliveCountMax 3` is **dead-peer
  detection, not an idle timeout**: an idle but responsive session stays
  connected forever. For a real idle limit use `TMOUT` in the shell profile,
  and accept that the user can unset it.
- Forwarding is off fleet-wide (`AllowTcpForwarding no`,
  `AllowAgentForwarding no`, `AllowStreamLocalForwarding no`, `GatewayPorts
  no`, `PermitTunnel no`). This also blocks `ssh -J` **through** the host,
  which is why bastions get `90-bastion-forwarding.conf`, scoping the exception
  to one group with a `Match` block.

### Crypto

The two crypto files exist because the algorithm names differ by OpenSSH
release, and `sshd` treats an unsupported algorithm as a fatal config error:

```text
Unsupported KEX algorithm "mlkem768x25519-sha256"
/etc/ssh/sshd_config.d/01-crypto-openssh99.conf line 14: Bad SSH2 KexAlgorithms
```

That is a host you cannot restart sshd on. `tests/linux.sh` proves the split by
feeding the 9.9 file to OpenSSH 9.2 and requiring the rejection.

- `mlkem768x25519-sha512`'s predecessor `sntrup761x25519-sha512@openssh.com`
  (post-quantum hybrid) appeared in 8.5. `mlkem768x25519-sha256`, the ML-KEM
  (FIPS 203) hybrid, arrived in **9.9** and is the client default from 10.0;
  OpenSSH 10.1+ clients warn when a non-post-quantum KEX is negotiated.
- `RequiredRSASize 2048` needs 9.1. Raising it to 3072 locks out everyone
  holding a 2048-bit key, which is most existing users — a rotation project,
  not a config change.
- On RHEL these files sort before `50-redhat.conf` and therefore **override the
  system-wide crypto policy** for sshd. Do not install them on FIPS-mode hosts;
  use `update-crypto-policies --set FIPS` and leave sshd alone.

### PerSourcePenalties

`PerSourcePenalties` is on by default from OpenSSH 9.8: a source address whose
connections fail to authenticate, or crash sshd, is refused for a growing
period. It replaces most of what fail2ban was used for, in-process, with no log
parsing and no extra daemon.

The one thing worth configuring is the exemption list, so a misconfigured
Ansible run from a jump host cannot block the jump host itself:

```ini
PerSourcePenaltyExemptList 192.0.2.0/24,2001:db8::/32
```

Keep fail2ban only where you need it for services other than sshd, or on
OpenSSH older than 9.8. Running both against sshd means two mechanisms blocking
the same addresses with different timers.

## Host firewall

[`nftables/host-filter.nft`](../baselines/linux/nftables/host-filter.nft):
default-deny on the input hook, SSH from named management sets only,
distro-neutral.

It is deliberately **not** a `flush ruleset`. The file owns one table
(`inet host_filter`) and deletes only that table before recreating it, so it
coexists with Docker, Kubernetes CNIs, fail2ban and libvirt, which all keep
their own tables. Loading the file is one atomic transaction: a syntax error
changes nothing.

Rules that look optional and are not:

- **ICMP must not be dropped wholesale.** `destination-unreachable` carries
  path MTU discovery; without it, connections to some networks hang after the
  handshake instead of failing.
- **IPv6 needs neighbour discovery and `packet-too-big`** or the host loses
  IPv6 entirely. The ruleset matches `meta l4proto icmpv6` rather than the
  protocol name `ipv6-icmp`, which is resolved through `/etc/protocols` and
  absent from minimal images.
- **DHCP replies are not `related`.** They arrive from a different address than
  the broadcast request went to, so `ct state established,related` does not
  cover them. Drop those two rules only on statically addressed hosts,
  otherwise the lease renewal hours after rollout is what locks you out.
- Traffic that only passes **through** the host is not filtered: the ruleset
  hooks `input` only. Container and VM traffic is the `forward` hook, owned by
  Docker and your CNI.

Run one host firewall. If firewalld or ufw is also active, a packet must be
accepted by every base chain on the hook, and debugging that is worse than
choosing.

## Audit trail

Three files in `/etc/audit/rules.d/`, loaded by `augenrules` at boot:

| File | Contents |
|---|---|
| [`30-hardening.rules`](../baselines/linux/audit/rules.d/30-hardening.rules) | architecture-independent rules and file watches: identity files, sudoers, sshd config, MAC policy, login records |
| [`31-hardening-x86_64.rules`](../baselines/linux/audit/rules.d/31-hardening-x86_64.rules) | syscall rules for `b64` and `b32` (32-bit syscalls are reachable on a 64-bit kernel and are a standard bypass if unwatched) |
| [`99-finalize.rules`](../baselines/linux/audit/rules.d/99-finalize.rules) | `-e 2`: make the rule set immutable until reboot |

Notes that decide whether this is useful or just expensive:

- Rules are applied in file order and `-e 2` must be **last**. After it, no
  rule can be added or removed without rebooting — which is the point, and also
  means you test the rule set before enabling it.
- `-F auid>=1000 -F auid!=unset` scopes syscall rules to logged-in humans. Drop
  it and every daemon's `openat` becomes an audit event; the host spends its
  time writing logs.
- `-w /var/log/sudo.log` only ever fires if sudo is configured to write that
  file — hence `Defaults logfile` in
  [`sudoers.d/10-logging`](../baselines/linux/sudoers.d/10-logging). A watch on
  a file nothing writes is a rule that looks like coverage and is not.
- The audit log is local. An attacker who reaches root owns it. It is evidence
  only once it is shipped off the host — see
  [observability and logging](observability-logging.md).

`tests/linux.sh` feeds every add-rule line to the real `auditctl` parser.
Control directives (`-e`, `-b`, `-f`, `-D`) cannot be distinguished from
invalid ones inside a container, so they get a structural check instead; the
test says so rather than implying more.

## Accounts, passwords and sudo

| File | Effect |
|---|---|
| [`security/faillock.conf`](../baselines/linux/security/faillock.conf) | 5 failures in 15 minutes lock the account for 15 minutes |
| [`security/pwquality.conf.d/10-hardening.conf`](../baselines/linux/security/pwquality.conf.d/10-hardening.conf) | `minlen = 14`, `minclass = 2`, dictionary and username checks, enforced for root |
| [`sudoers.d/10-logging`](../baselines/linux/sudoers.d/10-logging) | sudo to syslog and to `/var/log/sudo.log`, `use_pty`, short credential cache |

Three traps:

- **Neither file does anything on its own.** `pam_faillock` and
  `pam_pwquality` have to be in the PAM stack: `authselect enable-feature
  with-faillock` on RHEL, `pam-auth-update --enable faillock` on Debian and
  Ubuntu, plus `libpam-pwquality` installed. Verify by failing a login twice
  and running `faillock --user <name>`.
- **`unlock_time = 0` means never unlock.** Five wrong passwords from anywhere
  then require an administrator with console access. An automatic window stops
  online guessing just as well. For the same reason `even_deny_root` is not
  set: locking root out turns a password spray into a denial of service on your
  last way in, and root has no password SSH access here anyway.
- **A syntax error anywhere under `/etc/sudoers.d` breaks sudo for everyone.**
  Always `visudo -cf` the file before installing it, and keep a second root
  session open until `sudo -v` has worked once. Unlike sshd, the **last**
  matching `Defaults` wins, so a later file can override these.

`pwquality` only sees passwords set through PAM. It cannot grade existing
hashes, and it is bypassed by `usermod -p` and by direct `/etc/shadow` edits —
which is what Ansible's `user: password=` does. Password **expiry** is
deliberately not configured: rotating a strong password every 60 days makes it
weaker (NIST SP 800-63B §5.1.1.2).

## Filesystem, modules and core dumps

| File | Effect |
|---|---|
| [`systemd/tmp.mount.d/00-hardening.conf`](../baselines/linux/systemd/tmp.mount.d/00-hardening.conf) | `/tmp` as tmpfs with `nosuid,nodev,noexec`, sized and inode-capped |
| [`modprobe.d/hardening-blacklist.conf`](../baselines/linux/modprobe.d/hardening-blacklist.conf) | rare filesystems and network protocols cannot autoload |
| [`systemd/coredump.conf.d/00-disable.conf`](../baselines/linux/systemd/coredump.conf.d/00-disable.conf) | `systemd-coredump` stores nothing |
| [`security/limits.d/00-no-core.conf`](../baselines/linux/security/limits.d/00-no-core.conf) | hard `core` limit 0 for PAM sessions |
| [`systemd/journald.conf.d/00-hardening.conf`](../baselines/linux/systemd/journald.conf.d/00-hardening.conf) | persistent journal, explicit size caps, 90-day retention |

- **`noexec` on `/tmp` breaks real things**: some `.run` installers, old RPM
  `%post` scriptlets, Ansible with `remote_tmp` under `/tmp`, self-extracting
  monitoring agents. Test one host per role. If something legitimately needs
  it, set `TMPDIR` to a private directory rather than dropping `noexec`.
- Switching `/tmp` to tmpfs **hides whatever is in `/tmp` now** and charges it
  to RAM plus swap. Do it in a maintenance window.
- `blacklist` alone only stops alias-based autoloading; `install <mod>
  /bin/false` is what makes an explicit `modprobe` fail. The baseline uses
  both, and rebuilding the initramfs is required for early boot to honour it.
- `squashfs`, `udf` and `vfat` are deliberately **not** blacklisted: snapd
  mounts every snap with squashfs, Azure delivers provisioning data on a
  UDF-formatted disk, and the EFI system partition is FAT.
- Core dumps of long-running daemons contain TLS keys, session tokens and
  database passwords. Both files are needed: the drop-in only applies where
  `systemd-coredump` is the `kernel.core_pattern` handler (RHEL by default,
  Debian and Ubuntu only if the package is installed).
- On RHEL 9 the journal is **not** persistent: `/var/log/journal` ships as an
  rpm `%ghost` entry that is never created, so the journal lives in `/run` and
  everything from before a crash-reboot is gone.

Keep SELinux or AppArmor enforcing. Verify with `getenforce` (expect
`Enforcing`) or `aa-status`. Setting SELinux to permissive "temporarily" to fix
an application is how hosts end up permissive permanently; fix the label or
write a policy module instead.

## Rollout

Order matters. Anything that can cut remote access goes last, after its allow
rules are proven.

1. **Time first.** Every log, certificate and audit entry depends on it.
   `timedatectl` must show `System clock synchronized: yes` and an active NTP
   service (`chronyd` on RHEL, `systemd-timesyncd` on Debian and Ubuntu).
2. **Automatic security updates**, then verify one actually applied.
3. **sysctl, modules, core dumps, journald, `/tmp`.** These do not affect
   remote access. Reboot a canary host: module blacklisting and `/tmp` changes
   are only fully exercised at boot.
4. **Passwords and sudo.** `visudo -cf` the sudoers file, install it, confirm
   `sudo -v` still works from a second session before touching PAM.
5. **auditd**, without `99-finalize.rules` at first. Run a day, check the
   volume with `aureport --summary`, then add the immutable flag.
6. **sshd** via the guard script below.
7. **nftables last**, and only once the management sets are correct.

### Staged sshd rollout that heals itself

[`bin/ssh-rollout-guard.sh`](../baselines/linux/bin/ssh-rollout-guard.sh)
installs drop-ins with an armed automatic revert. It needs only bash, systemd
and root.

```bash
sudo ./ssh-rollout-guard.sh stage 00-hardening.conf 01-crypto-openssh87.conf
# config validated with sshd -t, sshd reloaded, revert armed (TIMEOUT=10min)

# now, from a SECOND terminal, open a new session and confirm it works:
ssh -v admin@host 'echo new session ok'

sudo ./ssh-rollout-guard.sh commit    # only after the new session worked
```

Do nothing and the host restores the previous drop-in directory by itself. The
session you are typing in is never dropped: sshd is **reloaded**, not
restarted, and a reload leaves established connections alone. That is also why
a broken config does not disconnect you — it locks out the *next* login, which
is exactly the failure this procedure is built to catch.

### nftables rollout

```bash
# 1. Put your real management ranges in the mgmt_v4 / mgmt_v6 sets first.
# 2. Arm a revert before loading anything:
sudo systemd-run --on-active=10min --unit=nft-revert nft flush ruleset
# 3. Check, then load:
sudo nft -c -f host-filter.nft && sudo nft -f host-filter.nft
# 4. Open a NEW ssh session from the management network. If it works:
sudo systemctl stop nft-revert.timer
```

If the host runs Docker or Kubernetes, `nft flush ruleset` as a revert also
removes their tables and breaks container networking until the daemon
reprograms it. On those hosts revert with `nft delete table inet host_filter`
instead.

## Verification

```bash
# sshd: effective configuration, not the file. This is the only answer that
# counts, because it resolves the whole Include tree in order.
sshd -T | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractive\
authentication|authenticationmethods|maxauthtries|loglevel|allowtcpforwarding)'
# expect: no, no, no, publickey, 3, VERBOSE, no

# and before any restart, always:
sshd -t && echo "config parses"

# sysctl: as applied, not as written
sysctl kernel.kptr_restrict kernel.unprivileged_bpf_disabled fs.suid_dumpable \
  net.ipv4.conf.all.rp_filter net.core.bpf_jit_harden

# firewall: the ruleset the kernel holds, plus the drop counter
sudo nft list table inet host_filter
sudo nft list counters   # "dropped by policy" should be increasing

# audit: rules loaded, and immutable
sudo auditctl -l | wc -l
sudo auditctl -s | grep -E 'enabled|backlog'   # enabled 2 = immutable

# lockout and password policy are live
faillock --user "$USER"
echo 'Password1' | pwscore    # must be rejected

# MAC enforcing
getenforce 2>/dev/null || sudo aa-status --enabled && echo apparmor enabled

# updates actually ran
systemctl list-timers --all | grep -E 'apt-daily|dnf-automatic'
journalctl -u unattended-upgrades -u dnf-automatic --since -7d | tail -20
test -f /var/run/reboot-required && echo "REBOOT PENDING"
```

From a host that must **not** reach the firewalled port:

```bash
nc -zv -w3 <host> 22   # expect a timeout
```

A `connection refused` means the packet reached the host and a service declined
it: the firewall blocked nothing. Only a timeout proves the rule works.

## Rollback

| Change | Undo |
|---|---|
| sshd drop-in | `ssh-rollout-guard.sh revert`, or delete the file and `systemctl reload sshd` |
| nftables | `nft delete table inet host_filter` (not `flush ruleset` on container hosts) |
| sysctl | delete `/etc/sysctl.d/99-hardening.conf`, reboot. `kernel.unprivileged_bpf_disabled=1` and `kexec_load_disabled` are one-way until then |
| auditd | delete the files in `rules.d`, then reboot — `-e 2` blocks `auditctl -D` |
| faillock | `faillock --user <name> --reset`; remove the PAM feature with `authselect`/`pam-auth-update` |
| `/tmp` tmpfs | `systemctl disable --now tmp.mount`, reboot; the old on-disk `/tmp` reappears |
| modules | delete the modprobe file, rebuild the initramfs, reboot |

## Common failure modes

- **The sshd drop-in sorts after a distro file and does nothing.** No error, no
  log line; `sshd -T` is the only way to see it.
- **`rp_filter = 1` on a multi-homed or asymmetrically routed host** drops
  replies on the secondary interface. Symptom: one of two addresses works.
- **A crypto file from the wrong OpenSSH generation** makes sshd refuse to
  start on the next reboot, long after the change was made and forgotten.
- **`net.ipv4.ip_forward = 0` from a "CIS-compliant" baseline** on a Docker or
  Kubernetes node breaks every container's outbound traffic.
- **auditd with no `auid` scoping** fills the disk in hours and gets disabled by
  whoever is on call.
- **`-e 2` shipped on day one**, and then every rule fix needs a reboot.
- **`/boot` fills up** because old kernels were never pruned, and the next
  kernel update fails half-installed. `Remove-Unused-Kernel-Packages` handles
  the Debian side; on RHEL check `installonly_limit` in `dnf.conf`.
- **noexec `/tmp` breaking a vendor agent installer** weeks later, during an
  unrelated upgrade.
- **The firewall applied before the allow rules**, from the only session that
  could have fixed it.

## Control mapping

Section to control families. Benchmark section numbers are deliberately not
cited: verify them against the exact benchmark version you are audited on.

| This guide | CIS Benchmark | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Annex A | NIS2 Art. 21(2) |
|---|---|---|---|---|
| Automatic security updates | CIS Distribution Independent Linux / Ubuntu / RHEL 9 | SI-2, RA-5 | A.8.8, A.8.19 | (e) |
| Kernel parameters | same | CM-6, SC-7, SI-16 | A.8.9, A.8.20 | (e) |
| sshd configuration | same | AC-17, IA-2, IA-5, SC-8, SC-13 | A.8.5, A.8.20, A.8.24 | (h), (j) |
| Host firewall | same | SC-7, AC-4 | A.8.20, A.8.22 | (e) |
| Audit trail | same | AU-2, AU-3, AU-9, AU-12 | A.8.15, A.8.16 | (b) |
| Accounts, passwords, sudo | same | AC-2, AC-6, AC-7, IA-5 | A.5.15, A.5.17, A.8.2 | (i) |
| Filesystem, modules, core dumps | same | CM-7, SC-28 | A.8.9, A.8.19 | (e) |
| MAC enforcing | same | AC-3, CM-7 | A.8.3 | (i) |

## References

- [OpenSSH `sshd_config` manual](https://man.openbsd.org/sshd_config) and the
  [release notes](https://www.openssh.com/releasenotes.html) for when each
  keyword and algorithm appeared
- [`nft(8)`](https://www.netfilter.org/projects/nftables/manpage.html) and the
  [nftables wiki](https://wiki.nftables.org/)
- [Linux kernel sysctl documentation](https://docs.kernel.org/admin-guide/sysctl/index.html)
- [`auditctl(8)`](https://man7.org/linux/man-pages/man8/auditctl.8.html),
  [`audit.rules(7)`](https://man7.org/linux/man-pages/man7/audit.rules.7.html)
- [`pam_faillock(8)`](https://man7.org/linux/man-pages/man8/pam_faillock.8.html),
  [`pwquality.conf(5)`](https://man7.org/linux/man-pages/man5/pwquality.conf.5.html)
- [NIST SP 800-63B, Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
  (password expiry, §5.1.1.2)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) — the
  authoritative section numbers for your audited version
- [SSH key management](ssh-key-management.md) for certificates, FIDO2 keys and
  revocation

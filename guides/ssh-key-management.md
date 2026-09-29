# SSH Key Management

How to run SSH access for a fleet: hardware-backed keys for humans, SSH
certificates instead of `authorized_keys` distribution, and a revocation path
that works in minutes rather than in a config management run.

| | |
|---|---|
| Applies to | OpenSSH 8.2+ clients, OpenSSH 8.7+ servers (Ubuntu 22.04/24.04, Debian 12/13, RHEL/Rocky/Alma 9) |
| Baseline files | [`baselines/linux/ssh/`](../baselines/linux/ssh/) |
| Validated by | [`tests/linux.sh`](../tests/linux.sh) |
| Lockout risk | **High.** `TrustedUserCAKeys`, `AuthorizedPrincipalsFile` and especially a missing `RevokedKeys` file each break authentication for everyone |
| Last reviewed | 2026-09 |

## Threat model

- **A stolen private key.** A key file copied off a laptop, out of a backup, or
  out of a CI artifact. Hardware-backed keys make the key non-exportable;
  certificates with a short lifetime make a stolen credential expire on its own.
- **A key that outlives its owner's access.** Someone leaves, and their public
  key stays in `authorized_keys` on the hosts config management forgot. This is
  the most common real failure, and it is a distribution problem, not a crypto
  problem.
- **Agent forwarding abused on a compromised host.** Anyone with root on the
  host you forwarded into can use your agent to authenticate onwards as you.
- **Host impersonation.** A man in the middle answering for the host you meant
  to reach, accepted because nobody checks a fingerprint on first connection.
- **The audit question.** Given a login six months ago, which key was it, and
  who held that key.

Not covered: securing the CA's signing key itself beyond the requirements
below (that is a [secrets management](secrets-management.md) problem), and
anything after an attacker has root on the host.

## Key types

```bash
# Hardware-backed, for humans. The private key half cannot be exported from
# the security key, so a stolen laptop is not a stolen credential.
ssh-keygen -t ed25519-sk -O resident -O verify-required \
  -C "you@example.com" -f ~/.ssh/id_ed25519_sk

# Software Ed25519: service accounts, and humans without a security key yet.
ssh-keygen -t ed25519 -C "you@example.com" -f ~/.ssh/id_ed25519
```

- `ed25519-sk` requires a FIDO2 authenticator and OpenSSH 8.2+ on both ends.
  `-O verify-required` demands the PIN or biometric on every use, which is what
  makes a key touched by malware useless; the server can insist on it with
  `PubkeyAuthOptions verify-required`. `-O resident` stores the credential on
  the key itself so it can be recovered onto a new machine with
  `ssh-keygen -K`.
- `-a` (KDF rounds) is **not** in the commands above on purpose. It only
  strengthens the passphrase encryption of a software private key; for
  `ed25519-sk` there is no exportable key to protect, and `-a 100` on a
  passphrase-less key protects nothing at all.
- RSA is acceptable at 3072 bits or more, with SHA-2 signatures
  (`rsa-sha2-256`/`rsa-sha2-512`). The `ssh-rsa` signature algorithm
  (SHA-1) is disabled by default since OpenSSH 8.8. ECDSA is fine but has no
  advantage over Ed25519, and DSA is gone — removed entirely in OpenSSH 10.0.
- The baseline sets `RequiredRSASize 2048`, which rejects shorter RSA keys.
  Raising it to 3072 is a rotation project, not a config change.

## Client configuration

[`baselines/linux/ssh/client/config`](../baselines/linux/ssh/client/config),
installed as `~/.ssh/config`. Requires OpenSSH 8.2+.

`ssh_config` is first-match-wins, like `sshd_config`: specific `Host` blocks
must go **above** `Host *`, or the defaults shadow them.

```ini
Host bastion
    HostName bastion.example.com
    User ops

Host prod-*
    ProxyJump bastion
    User admin

Host *
    IdentitiesOnly yes
    IdentityFile ~/.ssh/id_ed25519_sk
    IdentityFile ~/.ssh/id_ed25519
    AddKeysToAgent 8h
    ForwardAgent no
    ForwardX11 no
    HashKnownHosts yes
    UpdateHostKeys yes
    ServerAliveInterval 60
    ServerAliveCountMax 3
    ControlMaster auto
    ControlPath ~/.ssh/cm/%C
    ControlPersist 10m
```

The details that matter:

- **`IdentitiesOnly yes`.** Without it, ssh offers every key in the agent, in
  order. Against the baseline's `MaxAuthTries 3` a developer with four keys
  loaded gets `Too many authentication failures` on a host their correct key
  would have opened.
- **`ControlPath ~/.ssh/cm/%C`, and the directory must exist.** ssh does not
  create it: `install -d -m 700 ~/.ssh/cm`, once. `%C` is a hash of host, port
  and user, so the path is fixed-length (unix socket paths stop at about 108
  bytes) and free of shell metacharacters. The older `%r@%h-%p` overflows on
  long hostnames and breaks silently.
- **`AddKeysToAgent 8h`**, not `yes`: a key added on first use expires with the
  working day instead of living until logout.
- **`UpdateHostKeys yes`** lets the server announce additional or rotated host
  keys over an already-authenticated connection, so planned host key rotation
  does not turn into a fleet-wide known_hosts fix-up.
- **`ProxyJump`, never `ForwardAgent`.** ProxyJump tunnels a second, separate
  SSH session through the first; the private key never leaves your machine and
  the bastion cannot authenticate as you. Agent forwarding gives root on the
  intermediate host the ability to use your agent for as long as you are
  connected. If you must forward, forward per-command and confirm each use:
  `ssh -A -o ForwardAgent=yes` with the agent started as `ssh-agent -c`, and
  add keys with `ssh-add -c` so every signature needs confirmation.

Note that the baseline's `AllowTcpForwarding no` blocks ProxyJump **through** a
host, because ProxyJump opens a `direct-tcpip` channel. Bastions therefore get
[`90-bastion-forwarding.conf`](../baselines/linux/ssh/sshd_config.d/90-bastion-forwarding.conf),
which scopes `AllowTcpForwarding local` to one group — `local` permits `-L` and
ProxyJump but not remote (`-R`) forwards.

## Certificates: the answer to rotation at scale

`authorized_keys` distribution does not scale, and it fails in one direction:
adding a key is easy and noticed, removing one is easy and unnoticed. With
certificates the host trusts a CA, and a credential is valid because it is
signed and unexpired, not because a file somewhere still lists it.

### Set up a user CA

```bash
# On an offline or tightly controlled machine. This key is the fleet's root of
# trust for access: treat it like a root CA.
ssh-keygen -t ed25519 -f user_ca -C "user CA $(date -u +%Y-%m)"
```

Requirements for the CA key, in order of how badly each is usually missed:

1. It never sits on a host that accepts SSH logins.
2. Signing is an audited operation: a signing service or a CI job with an
   approval, not a person with the key on a laptop. Hardware is better still —
   `ssh-keygen -t ecdsa-sk` works as a CA, so signing needs a physical touch.
3. It has a planned successor. Hosts can trust two CA keys at once
   (`TrustedUserCAKeys` takes a file with multiple lines), which is the only
   way to roll one over without a flag day.

### Trust it on the hosts

[`10-user-ca.conf`](../baselines/linux/ssh/sshd_config.d/10-user-ca.conf):

```ini
TrustedUserCAKeys /etc/ssh/user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
RevokedKeys /etc/ssh/revoked_keys
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

- `AuthorizedPrincipalsFile` decouples the certificate from the local username:
  `/etc/ssh/auth_principals/deploy` containing `team-platform` means any
  certificate carrying the `team-platform` principal may log in as `deploy`.
  Without this line the certificate must list the literal username as a
  principal, which puts host-specific knowledge into the certificate.
- **`RevokedKeys` must exist and be readable.** If it is missing, sshd refuses
  public key authentication **for everyone** — a fleet-wide outage from a
  one-line config. Create it before the drop-in lands:
  `ssh-keygen -k -f /etc/ssh/revoked_keys`.

### Issue a certificate

```bash
ssh-keygen -s user_ca \
  -I "alice@example.com"          `# identity: what shows up in the logs` \
  -n team-platform,team-oncall    `# principals` \
  -V -5m:+8h                      `# valid from 5 min ago to 8 hours out` \
  -O clear -O permit-pty          `# drop all default permissions, re-add pty` \
  ~/.ssh/id_ed25519_sk.pub
```

- **`-V` is the whole point.** A certificate with no validity window is a key
  with extra steps. Eight hours for humans, minutes for automation. Short
  lifetimes mean a leaked credential expires before anyone notices, and they
  remove the need to chase revocation in the common case.
- `-5m` back-dates the start by five minutes so a host whose clock is slightly
  behind does not reject a fresh certificate. This is also why time sync is the
  first step of the [Linux hardening](linux-hardening.md) rollout.
- `-O clear` drops the default permissions (`permit-pty`,
  `permit-port-forwarding`, `permit-agent-forwarding`, `permit-user-rc`,
  `permit-X11-forwarding`) and then adds back only what is needed. Certificates
  issued without it carry port and agent forwarding whether you wanted them or
  not.
- `-O source-address=198.51.100.0/24` pins a certificate to a network. For
  automation this is close to free and removes most of the value of stealing it.
- `-O force-command=...` is how a deploy certificate is limited to one action.

Inspect before you trust:

```bash
ssh-keygen -L -f ~/.ssh/id_ed25519_sk-cert.pub
```

### Host certificates

Sign host keys with a **separate** host CA and clients stop being asked about
fingerprints at all:

```bash
ssh-keygen -s host_ca -I "web01" -h -n web01.example.com,web01 -V -5m:+52w \
  /etc/ssh/ssh_host_ed25519_key.pub
```

In each client's `known_hosts`:

```text
@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1... host CA
```

One line replaces every per-host entry, and a rebuilt host with a new host key
does not produce the warning everybody has learned to ignore — which is the
real security gain, because the warning becomes meaningful again.

## `authorized_keys`, where you still need it

For service accounts and hosts without certificates, restrict what a key can
do. Options go before the key type on the same line:

```text
restrict,pty,from="198.51.100.0/24",command="/usr/local/bin/backup-receive" ssh-ed25519 AAAAC3... backup@runner
```

`restrict` (OpenSSH 7.2+) disables port forwarding, agent forwarding, X11, the
pty and `~/.ssh/rc`, and keeps doing so as new capabilities are added to
OpenSSH — then add back only what is needed. A list of individual `no-*`
options ages badly by comparison.

`command=` forces that command regardless of what the client asks for; the
client's original request is in `$SSH_ORIGINAL_COMMAND`, and a script that
passes it to a shell has given the whole thing away.

Keep `authorized_keys` root-owned (`AuthorizedKeysFile
/etc/ssh/authorized_keys/%u`) when the account's own home directory is writable
by a service — otherwise the service can add its own key.

## Revocation

Three mechanisms, in the order you will reach for them:

1. **Let it expire.** With eight-hour certificates, a departing employee loses
   access at the end of the day without anyone doing anything. This is why short
   lifetimes beat long-lived keys plus good hygiene.
2. **KRL, for a specific credential.** A Key Revocation List revokes by key, by
   certificate serial, or by serial range, and is a compact binary file.

   Revoking a raw public key takes the key file. Revoking by serial takes a
   **specification file** — `-z` is the flag that *sets* a serial when signing,
   not the one that revokes it:

   ```bash
   # By key: pass the public key itself
   ssh-keygen -k -f /etc/ssh/revoked_keys -u ~/.ssh/compromised.pub

   # By serial (or range), via a spec file naming the issuing CA
   {
     echo 'serial: 1234'               # one certificate
     echo 'serial: 2000-2999'          # a range, e.g. everything a leaked
                                       # signing job issued
     echo 'id: alice@example.com'      # every certificate with this identity
   } > krl.spec
   ssh-keygen -k -f /etc/ssh/revoked_keys -u -s user_ca krl.spec

   # Verify before shipping. NOTE the exit code: ssh-keygen -Q prints REVOKED
   # and exits NON-zero for a revoked key, and exits 0 for one that is still
   # good. A script that treats 0 as "revoked" gets this exactly backwards.
   ssh-keygen -Q -f /etc/ssh/revoked_keys ~/.ssh/id_ed25519-cert.pub
   ```

   Issue certificates with `-z <serial>` from the start; revoking by serial is
   the only option once you no longer have the public key. Distribute the KRL
   the same way you distribute any config file, and **monitor that it arrived**:
   a KRL that did not reach a host is a host where the credential still works.

   `tests/linux.sh` runs this end to end: a certificate logs in, serial 1234 is
   added to the KRL, and the same certificate is then refused.
3. **Rotate the CA.** For a compromised CA key: add the new CA's public key to
   `TrustedUserCAKeys` on every host, reissue, then remove the old line. Both
   are trusted in between, so there is no flag day.

What does not work: deleting a line from `authorized_keys` on the hosts you can
reach. An active session survives it, and the host that was down during the
change still accepts the key.

## Rollout

1. Create the CA keys offline. Decide the signing path before issuing anything.
2. `ssh-keygen -k -f /etc/ssh/revoked_keys` on every host. **Before** step 3.
3. Create `/etc/ssh/auth_principals/<user>` for each local account that
   certificates should reach.
4. Install `10-user-ca.conf` with
   [`ssh-rollout-guard.sh`](../baselines/linux/bin/ssh-rollout-guard.sh), which
   validates with `sshd -t`, reloads, and arms an automatic revert. Existing
   key-based logins keep working: adding CA trust does not remove it.
5. Issue a certificate to one person, confirm login on one host, then widen.
6. Only once certificates work everywhere, start removing keys from
   `authorized_keys` — the reverse order costs you access.

## Verification

```bash
# The certificate a client holds: principals, validity, extensions
ssh-keygen -L -f ~/.ssh/id_ed25519_sk-cert.pub

# What the server actually enforces
sshd -T | grep -E '^(trustedusercakeys|authorizedprincipalsfile|revokedkeys|pubkeyauthoptions|requiredrsasize)'

# The KRL really revokes what you think. Reads backwards from what you expect:
# REVOKED on stdout and a NON-zero exit; exit 0 means the key is still valid.
ssh-keygen -Q -f /etc/ssh/revoked_keys ~/.ssh/some_key.pub

# Which key or certificate was used for a login. This is the payoff of
# LogLevel VERBOSE in the sshd baseline.
journalctl -u sshd --since -24h | grep -E 'Accepted (publickey|certificate)'
# Accepted publickey for admin from 198.51.100.7 port 51234 ssh2:
#   ED25519 SHA256:abc...   <- match against your inventory of keys

# Prove the hardware key demands a touch: this must block until you touch it
ssh -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519_sk host true
```

## Rollback

| Change | Undo |
|---|---|
| `10-user-ca.conf` | `ssh-rollout-guard.sh revert`, or delete the file and `systemctl reload sshd`. Key-based access is unaffected |
| A KRL that revoked too much | restore the previous file; `sshd` reads it per authentication, no reload needed |
| Certificate-only access, and the CA is unreachable | this is why `authorized_keys` for a break-glass account stays until certificates are proven. Console or cloud-provider serial access is the fallback |

## Common failure modes

- **`RevokedKeys` pointing at a file that does not exist** — public key
  authentication fails for every user on the host, and the error in the log
  names the file, which nobody reads before rolling back the wrong change.
- **Certificates with no `-V`**: long-lived credentials with a CA's blessing and
  no expiry, which is worse than the keys they replaced.
- **Clock skew** rejecting fresh certificates on hosts whose NTP broke.
- **`MaxAuthTries 3` plus a loaded agent** locking out users whose correct key
  was fourth in line. `IdentitiesOnly yes` fixes it.
- **Agent forwarding to a shared bastion**, where anyone with root can
  authenticate onwards as every user currently connected.
- **A ControlPath directory that does not exist**, so every connection silently
  skips multiplexing — or a `%r@%h-%p` path that exceeds the socket path limit
  on long hostnames.
- **The CA key on a build server** that also runs internet-facing services.
- **Nobody monitoring KRL distribution**, so revocation is believed to be done
  while hosts that missed the update still accept the credential.

## Control mapping

| This guide | CIS Benchmark | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Annex A | NIS2 Art. 21(2) |
|---|---|---|---|---|
| Key types, hardware-backed keys | CIS Distribution Independent Linux | IA-2(1), IA-5(2), SC-13 | A.5.17, A.8.5 | (h), (j) |
| Client configuration, ProxyJump | same | AC-17, SC-8 | A.8.5, A.8.20 | (j) |
| Certificates, principals, validity | same | IA-5, AC-2, AC-6 | A.5.16, A.5.18, A.8.2 | (i), (j) |
| `authorized_keys` restrictions | same | AC-3, AC-6, CM-7 | A.8.2, A.8.18 | (i) |
| Revocation, KRL, CA rotation | same | IA-5(1), AC-2(3) | A.5.18, A.8.5 | (i) |
| Login attribution (`LogLevel VERBOSE`) | same | AU-2, AU-3, IA-2 | A.8.15 | (b) |

## References

- [`ssh-keygen(1)`](https://man.openbsd.org/ssh-keygen) — certificates, KRLs,
  FIDO2 options
- [`sshd_config(5)`](https://man.openbsd.org/sshd_config),
  [`ssh_config(5)`](https://man.openbsd.org/ssh_config)
- [`ssh-keygen(1)`, CERTIFICATES section](https://man.openbsd.org/ssh-keygen#CERTIFICATES)
  and the [KRL wire format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.krl)
  (`PROTOCOL.certkeys` no longer exists upstream; the format is documented in the
  manual page)
- [OpenSSH release notes](https://www.openssh.com/releasenotes.html) — when each
  option appeared, and what was removed
- [`ssh-agent(1)`](https://man.openbsd.org/ssh-agent) on `-c` confirmation and
  forwarding risk
- [Linux server hardening](linux-hardening.md) for the sshd baseline these keys
  authenticate against

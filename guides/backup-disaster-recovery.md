# Backup and Disaster Recovery

A baseline for backups you have actually restored: a restic repository with
client-side encryption, storage a compromised client cannot empty, sandboxed
systemd units, a retention policy that survives a slow intrusion, and a drill
that turns claimed RPO and RTO into measured numbers. Everything ships as a file
under [`baselines/backup/`](../baselines/backup/) and is validated by
[`tests/backup.sh`](../tests/backup.sh), which takes real backups, prunes them,
restores them, and proves the integrity check can fail.

| | |
|---|---|
| Applies to | restic 0.17+ (validated on 0.19.1), systemd 249+ (validated on 257), AWS S3 or any S3-compatible store. Terraform module validated on 1.16.4 |
| Baseline files | [`baselines/backup/`](../baselines/backup/) |
| Validated by | [`tests/backup.sh`](../tests/backup.sh) |
| Lockout risk | **The highest in this repository, and it is data loss, not access loss.** Lose the repository password and the backups are unrecoverable — restic encrypts client-side and nobody can decrypt without it. Object Lock in COMPLIANCE mode cannot be shortened by anyone, including the account root |
| Last reviewed | 2026-09 |

## Threat model

What this baseline is for:

- **Ransomware.** The attacker has the host, the backup credentials and the
  repository password, and runs your own retention command to delete the
  snapshots before encrypting the data. This is the scenario that decides the
  whole design: storage the backup client itself cannot delete from.
- **A destructive mistake.** `DROP TABLE`, `rm -rf`, a bad migration, a
  `terraform destroy` in the wrong workspace.
- **Silent corruption.** Bit rot in the repository, or a backup that has been
  "succeeding" for months and cannot be read.
- **Losing the site.** A region, a datacentre, or an account.
- **A backup that restores to something unusable**: a torn database copy, a tree
  that will not boot, a restore that takes four times as long as anyone claimed.
- **Losing the key material** rather than the data, which is the same outcome.

What it is not for:

- **High availability.** A replica is not a backup: it faithfully replicates the
  `DROP TABLE`. A backup is not failover either; restoring takes the time it
  takes.
- **Application-consistent database backups from the filesystem.** The exclude
  list deliberately excludes database data directories; use the database's own
  dump or snapshot tooling and back **that** up.
- **Compliance retention as a legal instrument.** Object Lock enforces a
  duration; whether that duration is the right one is a legal question.
- **Protecting the backups from someone who owns your cloud account.** That is
  organisation-level guardrails — see [cloud IAM](cloud-iam.md) — of which the
  bucket policy here is one piece.
- **Secret management.** The repository password has to live somewhere; see
  [secrets management](secrets-management.md).

## The rule that matters: 3-2-1-1-0

Three copies, on two media, one off-site, **one immutable**, and **zero errors on
verification**. The last two are the ones people leave out, and they are the two
that decide whether you survive ransomware:

- **One immutable copy** means a copy the backup client's own credentials cannot
  delete. Encryption does not provide this. Versioning alone does not either,
  because a delete marker plus a lifecycle rule is still a deletion. Object Lock
  does.
- **Zero errors on verification** means somebody checked, on a schedule, that
  what is in the repository can be read back — not that the backup job exited 0.

## The repository

restic is the tool here because of three properties: it encrypts **client-side**
(the storage provider holds ciphertext and nothing else), it deduplicates
content, and it supports S3-compatible storage directly, so the immutability
story below works without a second tool.

[`restic.env.example`](../baselines/backup/restic/restic.env.example) is the
whole configuration surface, and two lines in it matter more than the rest.

**`RESTIC_PASSWORD_FILE`, never `RESTIC_PASSWORD`.** An inline password is
readable in `/proc/<pid>/environ` by anything that can read it, appears in
`systemctl show` output, lands in journald, and shows up in a core dump. The
wrapper **refuses to run** if `RESTIC_PASSWORD` is set, and `tests/backup.sh`
asserts that refusal.

**Losing the password loses the backups.** There is no recovery path — not
through AWS, not through support, not through restic. Store it in a password
manager **and** print it into a sealed envelope in a different building, and
never store it only on the host being backed up. The drill checklist exists
partly to make somebody go and find it while nothing is on fire.

Credentials for the object store do not belong in that file either: attach an
instance profile, a managed identity or a workload identity and let the SDK find
it. If you genuinely cannot, put the keys in a **separate** root-owned 0400 file
and add a second `EnvironmentFile=` line, so the first file can stay in
configuration management and the second cannot.

## What the wrapper does, and why each flag is there

[`restic-backup.sh`](../baselines/backup/restic/restic-backup.sh) is driven
entirely by the environment file, so the same script runs by hand and from the
timer.

| Flag or step | Reason |
|---|---|
| `--one-file-system` | Never follow a mount into a network share or another disk that has its own backup — or no business being in this one |
| `--exclude-caches` | Honours `CACHEDIR.TAG`, which is how build and package caches say "do not back me up" |
| `--no-scan` | Skips the pre-scan pass. The progress percentage is lost; a scheduled job has nobody watching it |
| `--exclude-file` | The shipped [`excludes.txt`](../baselines/backup/restic/excludes.txt), which the test checks for the patterns that matter |
| `forget --prune` | **Always `--prune`.** `forget` alone removes snapshot *references*; without `--prune` the data stays in the repository forever and the bill grows regardless of the policy |
| `--group-by host,tags` | Retention is applied per host and per tag, so one host's frequent backups cannot age out another's |
| `check --read-data-subset` | Verifies a slice of the real data on every run, which is how bit rot is found before a restore finds it |

Exit codes are deliberately distinct, because they are three different alerts:
**1** the backup failed, **2** the environment is misconfigured, **3** the backup
succeeded but verification failed — the data is on the host and the repository is
not trustworthy. Note that restic's own exit code 3 means "some files could not
be read": the snapshot exists and is usable, so the wrapper logs it and continues
rather than reporting a total failure.

`STALE_LOCK_MINUTES` defaults to **0: never remove a repository lock
automatically**. A lock removed while another process holds it means two writers
on one repository, which is how a repository is corrupted. Raise it only to a
value safely longer than the longest run you have ever seen.

### What `restic check` does and does not prove

`restic check` verifies the repository's structure and each pack file's header.
Whether it notices a corrupted pack therefore depends on **where** the corruption
landed: `tests/backup.sh` corrupted 64 bytes in the middle of a pack and saw it
both flagged and not flagged, on the same repository, across runs. Only
`--read-data` re-reads and re-hashes blob contents.

That is why the usual claim that `check` is "metadata only" is not stated here as
a fact, and why the wrapper always passes `--read-data-subset`. `5%` daily reads
the whole repository roughly every three weeks.

## Immutable storage

[`baselines/backup/terraform/aws-s3-object-lock`](../baselines/backup/terraform/aws-s3-object-lock/)
creates the bucket that makes ransomware survivable: versioning plus Object Lock,
so a `restic forget --prune` run by an attacker holding the repository password
removes references while the object versions survive.

**Object Lock cannot be enabled on a bucket that was created without it.**
Enabling it later is a bucket migration, not a setting change — which is why the
module creates the bucket with `object_lock_enabled = true`.

| Mode | What it means |
|---|---|
| `GOVERNANCE` (the default here) | A version cannot be deleted or overwritten **except** by a principal holding `s3:BypassGovernanceRetention`. Recoverable from an operator mistake |
| `COMPLIANCE` | Nobody can shorten the retention or delete the version. Not the account root, not AWS Support, not you. Storage is billed for the whole retention period whatever happens, and a wrong `retention_days` can only be waited out |

**GOVERNANCE mode is only as strong as the list of principals that may bypass
it**, which is why the module's bucket policy denies
`s3:BypassGovernanceRetention` to everyone except the ARNs you name — and with an
empty list, to everyone. `terraform test` asserts exactly that default. Point it
at a break-glass role whose use is alerted on; see the break-glass section of
[cloud IAM](cloud-iam.md).

The module also denies `s3:PutBucketVersioning` and
`s3:PutBucketObjectLockConfiguration` to everyone but that role (disabling
versioning would take Object Lock with it), denies plain HTTP (the repository
password travels with the request), blocks all four public-access vectors, and
turns on `bucket_key_enabled` — a backup repository is millions of small objects,
and one KMS call per object is what makes people turn encryption off.

Two settings that must be reasoned about together:

- **`retention_days`** must be longer than the time you expect to take to
  **notice** an intrusion, not just longer than your recovery window. A dwell
  time of three weeks against a 14-day retention means every surviving snapshot
  is already encrypted.
- **`noncurrent_version_expiration_days` must be greater than
  `retention_days`**, or the lifecycle rule tries to delete versions that Object
  Lock still protects, and the expiry silently fails for every locked version.
  The module enforces this with a `check` block, and `terraform test` proves the
  rejection.

And the one that has no undo: **the KMS key that encrypts the bucket must not be
scheduled for deletion while backups exist.** Destroying the key destroys them.

## Scheduling

Four units, all validated with `systemd-analyze verify`:
[`restic-backup.service`](../baselines/backup/restic/restic-backup.service) and
its timer, [`restic-verify.service`](../baselines/backup/restic/restic-verify.service)
and its timer.

The backup service is sandboxed rather than simply running as root:

```ini
AmbientCapabilities=CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/cache/restic
```

Reading every file on the host needs exactly **one** capability, not root's whole
set: `CAP_DAC_READ_SEARCH` bypasses read and traverse checks. With
`ProtectSystem=strict` everything else is read-only, so a compromised backup job
cannot modify the host it is reading. `MemoryDenyWriteExecute`,
`SystemCallFilter=@system-service` and the `Protect*` family do the rest.

Three operational details in the units:

- **`Persistent=true`** on the timers runs a missed job as soon as possible. A
  host that is off at 00:00 otherwise simply has no backup for that day, and
  nothing says so.
- **`RandomizedDelaySec=1h`.** Every host firing at exactly midnight is a
  self-inflicted thundering herd on the repository backend.
- **`Nice=10`, `IOSchedulingClass=idle`.** A backup that competes with production
  for IO is a backup that somebody disables.
- **`CacheDirectory=restic` with `RESTIC_CACHE_DIR`.** The cache must be
  writable *and* persistent: without it every run re-downloads the index, which
  on a remote repository is most of the runtime and most of the transfer cost.

`systemd-analyze verify` exits **0** even when it reports a problem, and systemd
257 words a misspelled directive as `Unknown key 'X' in section [Service],
ignoring`. So the log has to be read, not just the exit status — otherwise a
typo'd hardening directive silently does nothing.
`tests/backup.sh` does both, and proves the check can fail.

## Verifying restores

`restic check` proves the repository is internally consistent. Only a restore
proves the backup is a backup.

[`restic-restore-verify.sh`](../baselines/backup/restic/restic-restore-verify.sh)
restores a path from the latest snapshot into a scratch directory, compares it
with the live copy (`-c`), and reports how long it took:

```bash
restic-restore-verify.sh -p /etc -c
# restore-verify: restored /etc in 4s (2148112 bytes) — this is your measured RTO for this path
```

It uses `diff -r` rather than a checksum of a tarball, because a checksum tells
you *that* something differs and `diff -r` tells you **which file**. Point `-p`
at something that does not change every second, or accept the noise and read the
list.

Run it from a timer (weekly, offset from the backup so a drill never races the
job writing to the same repository) **and** by hand as a drill.

### What the test proves

[`tests/backup.sh`](../tests/backup.sh) runs the shipped wrapper against a real
repository: three backups, retention, verification, restore. Four assertions are
controls, and they are the reason the rest means anything:

- **A changed live file must be reported as a difference.** If the comparison
  passes after the live copy changed, it is comparing nothing.
- **An older snapshot must restore the *old* content.** A backup system that only
  ever returns the current state cannot undo an encryption or a truncation. The
  test writes three different values and asserts the older snapshot gives the
  older one.
- **`restic check --read-data` must detect a corrupted pack file.** 64 bytes of
  `/dev/urandom` in the middle of one pack, and the check must fail.
- **`forget` must actually remove snapshots** — `--keep-last 2` must leave
  exactly two.

Plus the refusals: no repository, no paths, no password file, `RESTIC_PASSWORD`
set inline, an unreadable password file, a non-numeric `STALE_LOCK_MINUTES`.

What the suite deliberately does **not** do: talk to S3, create a bucket, or
exercise Object Lock against the real API. That needs an account and costs money
for the whole retention period. The module is proven at plan level with a mocked
provider (9 cases, 4 of them rejections); the bucket itself is proven by the
drill.

## The drill

[`checklists/restore-drill.md`](../baselines/backup/checklists/restore-drill.md),
quarterly at minimum, and after any change to the repository, the retention
policy, the encryption key or the storage backend.

The drill measures three numbers you should otherwise not claim:

- **Actual RPO** — the age of the newest snapshot you can actually list, not the
  timer's interval.
- **Actual RTO** — from "I need this back" to "it is up and serving", including
  finding the password and the credentials.
- **Whether it comes up at all.** A restored file tree that does not boot, start
  or accept a connection has not been restored.

Two rules that make the drill worth running:

1. **Do it on a new host or a scratch path**, never over the live copy. A drill
   that overwrites production is an incident.
2. **Do it without the person who set it up**, at least once a year. If only one
   person can restore, you do not have a restore procedure — you have a person.

Write the result down where you record incidents. If measured beats claimed,
publish the numbers as the new claim. If it misses, that is a finding with an
owner and a date.

## Rollout

1. **Create the bucket first**, with the Terraform module, in GOVERNANCE mode
   with a retention you have thought about. Object Lock cannot be added later.
2. **Generate and escrow the repository password** before the first backup: the
   password manager *and* the sealed envelope. Verify a second person can get it.
3. **Attach an instance role** for the object store and confirm restic can reach
   the repository with no keys in any file.
4. **Run the wrapper by hand once**, with `BACKUP_PATHS` narrowed to one
   directory. Read the output. Time it.
5. **Widen `BACKUP_PATHS`**, then add the exclude file, then check what the first
   full run costs in time and transfer.
6. **Enable the timer**, not the service. Confirm the next run fires and that
   `Persistent=true` behaves as expected by stopping the host over a window.
7. **Enable the verify timer** and alert on its failure — this is the unit whose
   failure should page someone, not the backup's.
8. **Run the full drill**, with the checklist, on a new host. Record the numbers.
9. **Only then** consider COMPLIANCE mode, and only where a regulator requires
   it, with a retention you have already run at in GOVERNANCE mode.

## Verification

```bash
# Can you list the repository at all? And how old is the newest snapshot?
restic snapshots --compact
restic snapshots --json | jq -r '.[-1].time'     # this is your real RPO

# What the last scheduled run actually did
systemctl status restic-backup.service --no-pager -l
journalctl -u restic-backup.service --since '2 days ago' -o cat | tail -40
systemctl list-timers 'restic-*' --all

# Full data verification, on a schedule or before an audit
restic check --read-data                  # everything; expensive
restic check --read-data-subset 10%       # a slice, as the timer does

# Repository size and what retention is actually keeping
restic stats --mode raw-data
restic forget --dry-run --prune --keep-daily 14 --keep-weekly 8

# The restore, which is the only real test
restic-restore-verify.sh -p /etc -c

# Object Lock is really on, and with what retention
aws s3api get-object-lock-configuration --bucket example-org-backups
aws s3api get-bucket-versioning --bucket example-org-backups
# Who may bypass it — the answer that decides whether GOVERNANCE means anything
aws s3api get-bucket-policy --bucket example-org-backups | jq -r .Policy | jq '.Statement[] | select(.Action | tostring | test("Bypass"))'

# A specific object version is actually retained until a date
aws s3api head-object --bucket example-org-backups --key <key> --version-id <id> \
  --query '[ObjectLockMode,ObjectLockRetainUntilDate]'

# The KMS key that the whole bucket depends on is not scheduled for deletion
aws kms describe-key --key-id <arn> --query 'KeyMetadata.[KeyState,DeletionDate]'
```

## Rollback

| Change | Undo |
|---|---|
| Wrapper, units, excludes | Revert and `systemctl daemon-reload`. No repository state changes |
| Retention policy widened | Safe: nothing is deleted until the next `forget --prune` |
| Retention policy narrowed | **Not reversible.** The next prune deletes the data. Run `forget --dry-run` first, always |
| Object Lock GOVERNANCE retention | Can be shortened, but only by a principal with the bypass — which the bucket policy limits to the break-glass role |
| Object Lock COMPLIANCE retention | **No rollback of any kind.** It can only be waited out, and it is billed |
| Bucket lifecycle rule | Editable at any time; check it still expires later than the lock retention |
| A repository migrated to new storage | Keep the old repository until a restore from the new one has been verified. `restic copy` writes to the new one without touching the old |
| Repository password rotated (`restic key add` / `remove`) | Keep the old key until a restore with the new one has been verified. Removing the last key you hold is unrecoverable |
| A restored copy left on disk | Delete it, or bring it under the same access control as the original. A forgotten restore is an unmonitored copy of production data |

## Common failure modes

- **The repository password was only on the host that was lost**, or only in one
  person's password manager.
- **The storage credentials were on the destroyed host**, so the recovery host
  cannot read the backups.
- **The retention window was shorter than the intrusion's dwell time**, so every
  surviving snapshot is already encrypted.
- **Versioning without Object Lock**, so the attacker's delete markers plus the
  lifecycle rule finish the job.
- **`forget` without `--prune`**, so the policy looks applied and the bill keeps
  growing.
- **`forget` with a narrowed policy and no `--dry-run`**, deleting what somebody
  still needed.
- **A lifecycle rule shorter than the Object Lock retention**, so expiry silently
  fails for every locked version.
- **COMPLIANCE mode chosen on the first attempt**, with a retention nobody
  costed.
- **A KMS key scheduled for deletion** while backups encrypted with it exist.
- **A database backed up from its data directory while running**, restoring as
  corruption. Dump or snapshot it, and back **that** up.
- **`RESTIC_PASSWORD` inline**, leaving the password in journald and in
  `systemctl show`.
- **A repository lock removed by hand** while another run held it, giving two
  writers.
- **No `Persistent=true`**, so a host that is off at the scheduled minute simply
  has no backup that day.
- **No cache directory**, so every run re-downloads the whole index.
- **Backup jobs at full IO priority**, until somebody disables them during an
  incident.
- **A restore that has never been timed**, so the RTO in the plan is fiction.
- **The drill always run by the person who built it**, so nobody else can.
- **`restic check` treated as proof of restorability**, when only a restore is.

## Control mapping

Section to control families. Benchmark section numbers are deliberately not
cited: verify them against the exact benchmark version you are audited on.

| This guide | Reference | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Annex A | NIS2 Art. 21(2) |
|---|---|---|---|---|
| 3-2-1-1-0, off-site copy | CIS Controls v8 §11 | CP-6, CP-9 | A.8.13, A.5.29 | (c) |
| Client-side encryption, key escrow | — | SC-12, SC-13, SC-28 | A.8.24, A.5.33 | (h) |
| Immutable storage (Object Lock) | CIS AWS Foundations | CP-9(5), SI-7, AU-9 | A.8.13, A.8.15 | (c) |
| Bucket policy, bypass restriction | same | AC-3, AC-6, CM-5 | A.5.15, A.8.2 | (i) |
| Retention policy | — | CP-9, SI-12, AU-11 | A.8.13, A.5.33 | (c) |
| Scheduling and sandboxing | CIS Linux Benchmarks | CM-6, AC-6, SC-2 | A.8.9, A.8.2 | (e) |
| Integrity verification | — | SI-7, CP-9(1) | A.8.13, A.8.16 | (c) |
| Restore drill, measured RPO/RTO | — | CP-4, CP-10, CP-2 | A.5.29, A.5.30, A.8.14 | (c) |
| Exclusion of live database files | — | CP-9, SI-12 | A.8.13 | (c) |

## References

- [restic documentation](https://restic.readthedocs.io/) — in particular
  [`check`](https://restic.readthedocs.io/en/stable/045_working_with_repos.html#checking-integrity-and-consistency),
  [`forget` and `prune`](https://restic.readthedocs.io/en/stable/060_forget.html),
  and the [exit codes](https://restic.readthedocs.io/en/stable/075_scripting.html)
- [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
  — GOVERNANCE vs COMPLIANCE, and what bypass requires
- [S3 lifecycle and Object Lock interaction](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-overview.html)
- [`systemd.exec(5)`](https://www.freedesktop.org/software/systemd/man/systemd.exec.html)
  and [`systemd.timer(5)`](https://www.freedesktop.org/software/systemd/man/systemd.timer.html)
  for the sandboxing and `Persistent=`
- [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html)
  for `CAP_DAC_READ_SEARCH`
- [CIS Controls v8, Control 11 — Data Recovery](https://www.cisecurity.org/controls/data-recovery)
- [secrets management](secrets-management.md) for the repository password,
  [cloud IAM](cloud-iam.md) for the break-glass role that may bypass Object Lock,
  and [incident response](incident-response.md) for the part where you need all
  of this at 03:00

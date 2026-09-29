# Restore drill

A backup is a claim. A restore is evidence. This is the drill that turns the
claim into a number, and the number into a promise you can keep.

Run it quarterly at minimum, and after any change to the repository, the
retention policy, the encryption key or the storage backend. The automated
weekly version is `restic-verify.timer`; this is the human one, which also
exercises the parts a timer cannot: finding the password, finding the
credentials, and finding out who is allowed to do this.

Record the result in the same place you record incidents. A drill nobody wrote
down did not happen.

## Before you start

- [ ] Decide what you are proving, in one sentence: "we can restore /srv on a
      new host, from the last 24 h, in under 2 hours".
- [ ] Write down the **claimed** RPO and RTO for that scope. You are measuring
      against them, not discovering them afterwards.
- [ ] Do the drill on a **new host or a scratch path**, never over the live copy.
      A drill that overwrites production is an incident.
- [ ] Do it **without the person who set it up**, at least once a year. If only
      one person can restore, you do not have a restore procedure.

## The drill

- [ ] Start a clock. Everything below is timed.
- [ ] Obtain the repository password from where it is supposed to live — the
      password manager, the sealed envelope. **Do not** read it off the host
      being restored. If the only copy is on the host you lost, you have no
      backup.
- [ ] Obtain the storage credentials the same way: an instance role on the
      recovery host, or the documented break-glass path.
- [ ] `restic snapshots` — can you list them at all? Record the newest snapshot
      time: that difference against now is your **actual RPO**, not the
      configured one.
- [ ] `restic restore` the agreed scope to the scratch path.
- [ ] Verify the content, not the exit status: `diff -r` against a known-good
      copy where one exists, checksums where one does not, and for a database, a
      real consistency check (`pg_verifybackup`, `mysqlcheck`, `etcdctl
      snapshot status`).
- [ ] Bring the restored thing **up**. A restored file tree that does not boot,
      start, or accept a connection has not been restored.
- [ ] Stop the clock. That is your **actual RTO** for this scope.

## The parts people fail

- [ ] The password was only in the repository being restored, or only in one
      person's password manager.
- [ ] The storage credentials were on the destroyed host.
- [ ] The retention policy did not keep anything from before the problem
      started. A ransomware dwell time of three weeks against
      `--keep-daily 14` means every kept snapshot is already encrypted.
- [ ] The database restored as a torn copy, because it was backed up from the
      filesystem while running instead of from a dump or a snapshot.
- [ ] The restore worked but took four times the claimed RTO, because nobody had
      ever measured the download.
- [ ] The Object Lock retention had expired, or COMPLIANCE mode was holding a
      cost nobody had budgeted.
- [ ] The KMS key that encrypted the bucket had been scheduled for deletion.

## Afterwards

- [ ] Write down: date, scope, who ran it, measured RPO, measured RTO, what
      failed, what was fixed.
- [ ] If measured beat claimed: publish the numbers as the new claim.
- [ ] If measured missed claimed: that is a finding with an owner and a date,
      not a note.
- [ ] Delete the restored copy, or bring it under the same access control as the
      original. A forgotten restore is an unmonitored copy of production data.

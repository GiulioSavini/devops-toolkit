# Backup, Disaster Recovery & Immutability

Strategies for resilient data protection and zero-loss disaster recovery.

---

## 1. The Modern 3-2-1-1-0 Rule

- **3** Copies of data
- **2** Different media types
- **1** Offsite copy
- **1** Immutable or air-gapped copy (WORM storage / Object Lock)
- **0** Errors during automated recovery verification tests

---

## 2. RTO and RPO Definition

- **RPO (Recovery Point Objective)**: Maximum acceptable data loss period (e.g. 15 minutes).
- **RTO (Recovery Time Objective)**: Maximum acceptable downtime to restore operations (e.g. 2 hours).

Both numbers are business decisions, not technical ones. Derive the backup
frequency from the RPO, never the reverse: a 15-minute RPO cannot be met by a
nightly snapshot, no matter how fast the restore is.

---

## 3. Immutability

An immutable copy is the only defence against ransomware that also encrypts the
backups. On S3, Object Lock in compliance mode cannot be shortened or removed by
anyone, including the account root:

```bash
# Bucket must be created with Object Lock enabled -- it cannot be added later.
aws s3api create-bucket --bucket backups-prod --object-lock-enabled-for-bucket

aws s3api put-object-lock-configuration --bucket backups-prod \
  --object-lock-configuration '{
    "ObjectLockEnabled":"Enabled",
    "Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":30}}
  }'
```

Compliance mode means you are also committing to paying for that storage for the
full retention period. Test with `GOVERNANCE` mode first, which a privileged
role can still override.

---

## 4. Backups with restic

```bash
export RESTIC_REPOSITORY="s3:s3.amazonaws.com/backups-prod/db01"
export RESTIC_PASSWORD_FILE="/etc/restic/passphrase"   # mode 0600, backed up separately

restic backup /var/lib/postgresql --tag nightly --one-file-system
restic forget --keep-daily 7 --keep-weekly 4 --keep-monthly 12 --prune
```

Store the repository passphrase somewhere that survives the loss of the
environment being backed up. A passphrase kept only in the Vault instance that
the backup is protecting is not a backup.

---

## 5. The Zero: Verified Restores

The `0` in 3-2-1-1-0 is the part everyone skips, and it is the only part that
proves the other four worked.

```bash
# Weekly, automated, into a scratch environment:
restic restore latest --target /restore-test
restic check --read-data-subset=5%     # verifies stored data, not just metadata

# Then assert the restore is usable, not merely present:
sudo -u postgres pg_ctl -D /restore-test/var/lib/postgresql start
psql -c 'SELECT count(*) FROM critical_table;'   # compare against production
```

A backup job that reports success has verified that it wrote bytes. Only a
restore verifies that you can get them back.

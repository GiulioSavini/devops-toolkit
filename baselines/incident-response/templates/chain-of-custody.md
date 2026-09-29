# Chain of custody

One document per case, alongside the artifacts. Its purpose is to let a third
party conclude, months later, that what they are looking at is what was taken
off the host and that nothing altered it in between. `ir-collect.sh` writes a
starter copy of this file with row 1 already filled in.

| Field | Value |
|---|---|
| Case ID | ir-HOST-YYYYMMDDTHHMMSSZ |
| Incident ID | INC-YYYY-NNN |
| Subject system | FQDN, cloud instance ID, MAC/IP, role |
| System clock at collection | host time, UTC time, offset, NTP source and sync state |
| Collected by | name, role, organisation, contact |
| Collection tool and version | e.g. ir-collect.sh + avml 0.15.0 |
| Manifest | manifest.sha256 (SHA-256 of every artifact) |
| Legal hold | yes / no, who requested it, retention date |

## Artifacts

| # | Artifact | Type | SHA-256 | Size | Acquired (UTC) |
|---|---|---|---|---|---|
| 1 | 05-memory.lime | RAM image | | | |
| 2 | vol-0abc123 snapshot snap-0def456 | EBS snapshot | n/a (provider-managed) | | |
| 3 | ir-HOST-…/ | volatile collection set | see manifest.sha256 | | |

Cloud snapshots cannot be hashed by you; record the snapshot ID, the region, the
account that owns it, the creation timestamp from the provider API, and who can
read it. Restrict permissions immediately — a shared snapshot is a data breach
of its own.

## Custody log

Every movement gets a row. The receiving party verifies the manifest
(`sha256sum -c manifest.sha256`) **before** signing, and records the result.

| # | UTC timestamp | From (name) | To (name) | Action / reason | Storage location | Manifest verified | Signature |
|---|---|---|---|---|---|---|---|
| 1 | | host | collector | initial acquisition | | yes | |
| 2 | | | | transfer to evidence store | | | |
| 3 | | | | copy released to external counsel | | | |

## Notes

- Work on copies. Keep one pristine acquisition; investigate a duplicate.
- Record failures too: "memory acquisition failed, kernel lockdown enabled" is
  an evidentiary fact, and it explains a gap that would otherwise look like
  tampering.
- Keep the clock evidence. Correlating hosts, cloud audit logs and a customer
  report needs the offsets, not just the timestamps.

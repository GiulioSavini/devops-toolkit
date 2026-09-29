# First hour of an incident

Print this. It is the part people improvise when they are tired, and
improvisation is where evidence and credibility get destroyed.

Times are minutes from declaration, not from the alert.

## 0–5 min: declare and staff

- [ ] Declare the incident explicitly, in the channel of record: "declaring
      SEV2 on checkout, I am IC". An undeclared incident has no owner.
- [ ] Name the **Incident Commander** (decides, delegates, does not type).
- [ ] Name the **Operations lead** — the only person changing the system.
- [ ] Name the **Communications lead** and the **Scribe** (see the roles table
      in `guides/incident-response.md`). Below SEV2 one person can hold both.
- [ ] Open one incident channel and one incident document. Everything else is
      hearsay and will not reconstruct the timeline later.
- [ ] Record the severity and the reason for it. Re-evaluate at every update.

## 5–15 min: stabilise the facts

- [ ] Scribe: first timeline entry, in UTC, with the detection source
      (alert name, customer report, third-party notification).
- [ ] Confirm the blast radius before theorising: which service, which region,
      which customers, since when, and how you know.
- [ ] Check the last change: deploys, feature flags, config pushes, certificate
      and credential rotations, provider status pages.
- [ ] Decide and write down: is this a **failure** or a **compromise**? The two
      diverge immediately. A failure is fixed forward. A compromise means
      evidence first, containment second, remediation third.

## 15–30 min: if it is a compromise

- [ ] Do **not** reboot, reimage, patch or "clean" the host. That destroys RAM,
      tmpfs, sockets and the process table — most of the investigation.
- [ ] Isolate instead of powering off: quarantine security group, VLAN move, or
      revoke the workload's credentials and sessions.
- [ ] Capture volatile evidence in order of volatility
      ([RFC 3227](https://www.rfc-editor.org/rfc/rfc3227.html) §2.1):
      `baselines/incident-response/bin/ir-collect.sh -o /mnt/evidence -m`.
- [ ] Snapshot the disks (EBS/managed disk/PD snapshot) and record the snapshot
      IDs in the incident document.
- [ ] Rotate what the attacker may hold: access keys, tokens, SSH CA-signed
      certificates, session cookies, CI secrets.
- [ ] Start `chain-of-custody.md` for every artifact. Unattributed evidence is
      not evidence.

## 15–45 min: communicate

- [ ] First external update inside 30 minutes for anything customer-visible,
      even with nothing to say beyond "we see it and we are on it". Use the
      templates in `baselines/incident-response/templates/comms.md`.
- [ ] Set and honour a cadence: SEV1 every 30 min, SEV2 hourly. An update that
      arrives late is worse than an update that says nothing new.
- [ ] Flag the regulatory clocks the moment personal data or an in-scope service
      is implicated — GDPR Art. 33 is 72 h, NIS2 Art. 23 is 24 h for the early
      warning. Legal and the DPO decide; you owe them the facts and the time of
      awareness, in writing.

## 45–60 min: hand over or wind down

- [ ] If this will outlast the shift, write the handover in the incident
      document: current state, what has been tried, what is running, open
      decisions, the next check.
- [ ] Before declaring resolved: confirm with a signal, not a hunch — the
      symptom-level alert has cleared and stayed clear.
- [ ] Schedule the review within five working days, while people still
      remember, and record who writes it.

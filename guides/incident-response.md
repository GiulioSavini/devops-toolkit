# Incident Response

A baseline for running an incident: who decides, what gets written down, what
evidence is captured before anything is repaired, which regulatory clocks start,
and what the review has to answer. Everything ships as a file under
[`baselines/incident-response/`](../baselines/incident-response/) and the
collector is validated by
[`tests/incident-response.sh`](../tests/incident-response.sh), which runs it on
a live host in a container and proves its manifest can detect tampering.

| | |
|---|---|
| Applies to | Linux hosts (the collector needs bash, coreutils and whatever tools are present; it records the ones that are missing). Regulatory timings as of 2026-09: GDPR Art. 33/34, NIS2 Art. 23 |
| Baseline files | [`baselines/incident-response/`](../baselines/incident-response/) |
| Validated by | [`tests/incident-response.sh`](../tests/incident-response.sh) |
| Lockout risk | **None from these files.** The risk here is the opposite one: an action taken during the first hour that destroys the evidence you will need, or a notification clock missed while everyone is busy |
| Last reviewed | 2026-09 |

## Threat model

What this baseline is for:

- **The first hour**, which is the part people improvise when they are tired,
  and where evidence and credibility get destroyed.
- **An intrusion being handled like an outage.** A reboot, a reimage or a
  "let's just patch it and move on" destroys RAM, tmpfs, established sockets and
  the process table — which is most of what an investigation depends on.
- **An incident with no owner.** Two people changing the system at once, three
  versions of the timeline, and nobody sure who is talking to customers.
- **Evidence that cannot be used.** Artifacts with no hashes, no custody record
  and no clock reference are a story, not evidence.
- **A missed notification deadline** because nobody wrote down the time of
  awareness, or because the assessment was never made.
- **A review that finds one "root cause"**, fixes it, and ships the other three
  contributors again next quarter.

What it is not for:

- **Doing the forensics.** The collector preserves volatile state; analysing a
  memory image, carving a disk or attributing an intrusion is specialist work,
  and the decision to escalate to it belongs in the first hour.
- **Deciding your severity ladder or your legal obligations.** The templates
  name the clocks; legal and the DPO decide what applies to your entity.
- **Preventing the incident.** That is every other guide in this repository.
- **Detection.** What fires the alert is [observability and
  logging](observability-logging.md) and the audit trails in
  [Linux hardening](linux-hardening.md) and
  [Kubernetes hardening](kubernetes-hardening.md).
- **A substitute for practising.** A checklist nobody has rehearsed is read for
  the first time during the worst hour of the quarter.

## Roles

One decision per person. The failure this prevents is the most common one in
incident response: the most senior engineer typing while also deciding, also
updating customers, and also trying to remember what happened.

| Role | Owns | Explicitly does not |
|---|---|---|
| **Incident Commander** | Decides, delegates, holds the current state and the severity | **Does not type.** An IC with their hands on a keyboard has stopped commanding |
| **Operations lead** | The only person changing the system | Does not talk to customers, does not maintain the timeline |
| **Communications lead** | Internal updates, status page, customer and executive messaging, on a cadence | Does not speculate about cause in anything external |
| **Scribe** | The timeline, in UTC, as it happens: decisions, times, who did what | Does not fix, does not investigate |

Below SEV2 one person can hold Comms and Scribe. Nobody holds IC and Ops. State
the assignment out loud, in the channel: "declaring SEV2 on checkout, I am IC"
— an undeclared incident has no owner, and an unnamed role is unowned work.

## The first hour

[`checklists/first-hour.md`](../baselines/incident-response/checklists/first-hour.md)
is meant to be **printed**. Times are minutes from declaration, not from the
alert.

| Window | What has to be true by the end of it |
|---|---|
| 0–5 min | Incident declared explicitly in the channel of record. IC, Ops, Comms, Scribe named. One channel, one document. Severity recorded **with the reason** |
| 5–15 min | First timeline entry in UTC with the detection source. Blast radius confirmed before any theorising: which service, which region, which customers, since when, and **how you know**. Last change checked: deploys, flags, config, certificate and credential rotations, provider status |
| 15–30 min | The fork in the road answered in writing: **failure or compromise?** |
| 15–45 min | First external update inside 30 minutes for anything customer-visible. A cadence set and honoured. Regulatory clocks flagged the moment personal data or an in-scope service is implicated |
| 45–60 min | Handover written if this outlasts the shift. Resolution confirmed by a signal, not a hunch. Review scheduled within five working days, with a named author |

### Failure or compromise is the decision that changes everything

A **failure** is fixed forward: roll back, shift traffic, restore, repair.

A **compromise** inverts the order: **evidence first, containment second,
remediation third.** Every instinct in an SRE's body — restart it, reimage it,
patch it, clean it up — destroys the evidence and tells the intruder you have
noticed.

Write the decision down. It is re-evaluated as facts arrive, but an incident
that drifts between the two modes without anyone saying so is one where
somebody eventually reboots the host.

### Contain by isolating, not by powering off

```bash
# Good: the host stays alive, the attacker loses reach.
aws ec2 modify-instance-attribute --instance-id i-… --groups sg-quarantine
ip link set dev eth1 down            # a data NIC, not the one you are on
# Revoke what the workload holds, not just the network path:
aws iam delete-access-key --user-name … --access-key-id …
kubectl -n prod delete secret …      # and rotate what it contained
```

A powered-off host has lost its RAM, its tmpfs, its socket table and its process
list. A quarantined host has lost only its usefulness to the attacker. Snapshot
the disks as well (`ec2 create-snapshot`, managed disk snapshot, PD snapshot) and
record the snapshot IDs in the incident document — and restrict who can read
them immediately, because a shared snapshot is a data breach of its own.

## Collecting volatile evidence

[`bin/ir-collect.sh`](../baselines/incident-response/bin/ir-collect.sh) collects
in [RFC 3227](https://www.rfc-editor.org/rfc/rfc3227.html) §2.1 order of
volatility, hashes everything, and writes a chain-of-custody stub:

```bash
ir-collect.sh -o /mnt/evidence -c INC-2026-014 -m
```

```text
-o OUTDIR   destination; must exist and must NOT be on the suspect filesystem
-c CASE_ID  case identifier (default ir-<host>-<UTC timestamp>)
-m          also acquire physical memory with avml — memory first
-t SECONDS  per-artifact timeout, default 60
-n          dry run: print the plan, write nothing
-F          allow OUTDIR on the same filesystem as / (not recommended)
```

Fourteen artifacts, numbered so the order is visible in the directory listing:

| Prefix | Artifact | Why here |
|---|---|---|
| `00` | clock, uptime, NTP sync state | **First.** Every later timestamp is only interpretable against the host's own notion of time and its offset from UTC |
| `05` | memory image (`-m`) | The most volatile artifact that is still recoverable. Before anything on disk |
| `10`, `11` | process table, `/proc/*/exe` and `cwd` links | A deleted binary is still readable through `/proc/<pid>/exe`; it disappears when the process does |
| `20`–`22` | sockets, links and routes, firewall ruleset | Established connections are gone on reboot, and the ruleset shows what was allowed to reach the host |
| `30`, `31` | loaded modules, kernel ring buffer | A rootkit is a module; `dmesg` is where the load shows up |
| `40`, `41` | mounts, open files | A hidden mount over `/proc` or a deleted-but-open file |
| `50` | sessions: `who`, `w`, `last` | Who was on the box |
| `60`, `61` | packages, cron and systemd units and timers | Persistence lives here more often than in anything exotic |
| `70` | files under `/etc`, `/usr/local`, `/opt`, `/root`, `/home` changed in 30 days | The cheap, high-yield persistence sweep |

Design decisions worth copying:

- **It never reboots, stops, patches or cleans anything.** The script says so at
  the top, and the checklist says the same thing: consistency between the tool
  and the paperwork is checked by the test, because a checklist that says
  "reboot" makes the collector pointless.
- **OUTDIR on the same filesystem as `/` is refused.** Writing evidence onto the
  suspect filesystem overwrites unallocated blocks and slack space — the parts a
  forensic examiner most wants. `-F` exists for the case where you have no
  choice, and it makes that choice explicit.
- **A missing tool is a finding, not a failure.** Each artifact is collected with
  a fallback chain (`ss` then `netstat`, `lsof` then `/proc/*/fd`, `dpkg` then
  `rpm`) and its exit status is recorded. A partial evidence set beats none.
- **A hung tool cannot stall the collection.** `timeout` per artifact — `lsof`
  on a dead NFS mount is the classic — and status 124 is recorded, meaning the
  artifact is *truncated*, not *missing*.
- **`collection-order.tsv`** records UTC, artifact and exit status for every
  step, so the order and the failures are part of the evidence.
- **`manifest.sha256` covers everything, including the order log.** It is built
  outside the case directory and moved in, so no `find` can ever see a
  half-written manifest.

Run it from **trusted media** where you can. On a compromised host the local
`ps`, `ss` and `lsmod` may be replaced (RFC 3227 §2.2, "don't trust the programs
on the system").

### What the test proves about it

[`tests/incident-response.sh`](../tests/incident-response.sh) runs the collector
in a container with a tmpfs for the evidence, so it exercises the real thing:
every documented refusal exits 2 with its own message, `-F` overrides the
filesystem check, the plan starts with the clock and ascends in order of
volatility, all fourteen artifacts appear, and `collection-order.tsv` matches
the plan exactly.

Two assertions carry most of the value, and both are controls:

- **The manifest must be able to fail.** `sha256sum -c` passes on the untouched
  set and must **fail** after a single line is appended to one artifact. A
  manifest that cannot fail is a checksum nobody can rely on in a handover.
- **A hung artifact must be survivable.** A copy of the collector with a
  deliberately hanging step must record 124 for it, report the timeout on
  stderr, and still collect everything after it.

Making that pass found a real bug in the collector: shellcheck SC2094, because
`find` and the output redirection touched the same file in one pipeline. It
worked only thanks to a `-name` exclusion. The manifest is now built outside the
case directory and moved in.

## Chain of custody

[`templates/chain-of-custody.md`](../baselines/incident-response/templates/chain-of-custody.md)
exists so that a third party can conclude, months later, that what they are
looking at is what came off the host and that nothing altered it in between.
`ir-collect.sh` writes a starter copy with row 1 already filled in.

The three rules that make it work:

1. **Every movement gets a row**, and the receiving party runs
   `sha256sum -c manifest.sha256` **before** signing, recording the result.
2. **Record the system clock at collection**: host time, UTC, offset, NTP source
   and sync state. A timeline built on an unsynchronised clock cannot be
   correlated with anything.
3. **Work on copies.** Keep one pristine acquisition; investigate a duplicate.

Cloud snapshots cannot be hashed by you. Record the snapshot ID, the region, the
owning account, the provider's creation timestamp, and who can read it.

Unattributed evidence is not evidence. This is also the document that decides
whether an insurer or a regulator takes your account of events at face value.

## Communicating

[`templates/comms.md`](../baselines/incident-response/templates/comms.md) has
four audiences and one set of facts: internal channel update, customer-facing
status page, executive brief, and — separately — notification of a personal data
breach.

Rules that apply to all of them:

- **Timestamps in UTC**, absolute.
- **Say what you know, what you do not know, and when the next update comes.**
  The third one is what stops people asking.
- **Never speculate about cause externally.** Early causal guesses are wrong
  often enough to become the story.
- **Never name an individual**, and never name a customer to another customer.
- **A late update is worse than an update that says nothing new.** Cadence: 30
  minutes at SEV1, hourly at SEV2. Honour it even when there is no news.
- Security incidents: **legal reviews the external wording first.**

### The regulatory clocks start at awareness, not at resolution

| Obligation | Deadline | Note |
|---|---|---|
| GDPR Art. 33 — supervisory authority | **72 h** from becoming aware | A notification may be incomplete; you supply the rest in phases |
| GDPR Art. 34 — data subjects | Without undue delay, where the risk to rights and freedoms is high | Clear and plain language, the DPO contact, likely consequences, measures taken |
| NIS2 Art. 23 — early warning | **24 h** | Must indicate whether it is suspected to be caused by unlawful or malicious acts, and whether it could have cross-border impact. It is a *warning*: incomplete information is expected and is **not** a reason to wait |
| NIS2 Art. 23 — incident notification | **72 h** | Initial severity and impact assessment, indicators of compromise |
| NIS2 Art. 23 — final report | **1 month** after the notification | |
| Contractual customer notice | Whatever your contracts say | Usually tighter than the law, and usually forgotten |

Write down **the time of awareness and how you became aware**, in the incident
document, in the first fifteen minutes. Everything above is measured from it,
and reconstructing it afterwards from chat scrollback is exactly as convincing
as it sounds.

Legal and the DPO decide what applies. You owe them the facts and that
timestamp, in writing. And record the decision either way: a documented
"assessed, not notifiable, because X" is an answer — silence is not.

## The review

[`templates/post-mortem.md`](../baselines/incident-response/templates/post-mortem.md),
within five working days, while people still remember.

**There is deliberately no "root cause" field.** Overt failure in a system that
is defended against failure requires several contributors, none of which is
sufficient alone. A template with one blank labelled "root cause" gets one
contributor written in it, and the other three ship again next quarter.

Instead:

- **Trigger** — the single proximate event. It is not the explanation; it is the
  thing that happened to be last.
- **Contributing factors**, at least three, each one something that could be
  changed: design (coupling, a missing limit, a retry with no budget, a shared
  failure domain nobody drew), safeguards that did not fire (the alert that was
  tuned out, the canary that did not cover the path), operational conditions
  (time pressure, a freeze exception, an expert on leave, an ambiguous runbook),
  information (what operators could and could not see **while deciding**), and
  prior signals (the same alert two months ago, acknowledged and forgotten).
- **What made it worse, what made it better** — including **where you got
  lucky**. Luck is not a control; write down what happens without it.
- **Evidence and preservation** — artifacts, manifest hashes, snapshot IDs,
  retention dates, custody reference.
- **Notifications** — the table above, with the decision and the time for each.
- **Actions**, each addressing a named contributing factor, owned by a **person**
  and not a team, with a type (prevent / detect / mitigate / process). Actions
  that change the system beat actions that ask people to be more careful. "Add
  an alert" is not an action until it says what it alerts on and what the
  responder is supposed to do.
- **Open questions** — what is still unknown, who is chasing it, by when. An
  honest unknown is worth more than a confident invention.

Keep it blameless in the operative sense: the question is what about the system
made this outcome possible, not who typed the command. Judge decisions against
what was knowable at the time.

## Rollout

1. **Assign the roles before an incident**, and publish who is on call for IC
   separately from who is on call for Ops.
2. **Put `first-hour.md` where it can be read on paper**, and in the incident
   channel's pinned message.
3. **Stage the collector** on the hosts or in the image now, and provision the
   evidence destination — removable or remote storage that is not the suspect
   filesystem. Discovering that `-o` has nowhere to point is a first-hour
   problem you can solve today.
4. **Install `avml` if you want memory**, and confirm it works: on a kernel with
   lockdown enabled or built with `CONFIG_STRICT_DEVMEM`, acquisition fails.
   That is a finding to record now, not during the incident.
5. **Agree the severity ladder and the notification owners** with legal and the
   DPO, and write the names in the template.
6. **Rehearse.** A game day with a real `ir-collect.sh` run on a disposable host
   is an hour that pays for itself the first time. Time the collection so you
   know what "we are capturing evidence" costs.
7. **Review the reviews** once a quarter: actions actually closed, and
   contributing factors that keep reappearing.

## Verification

```bash
# The collector runs and refuses the things it should, without touching a host
bash baselines/incident-response/bin/ir-collect.sh -n -o /mnt/evidence
bash baselines/incident-response/bin/ir-collect.sh -o /tmp/x; echo "rc=$?"   # expect 2

# The whole suite, including the tamper-detection control
bash tests/incident-response.sh

# A real collection on a disposable host, then verify it as a recipient would
sudo ir-collect.sh -o /mnt/evidence -c drill-$(date -u +%Y%m%d)
cd /mnt/evidence/drill-*; sha256sum -c manifest.sha256 | tail -3
cut -f2,3 collection-order.tsv        # any non-zero status is a missing tool

# Memory acquisition works on this kernel — check before you need it
avml /tmp/test.lime && ls -l /tmp/test.lime && rm -f /tmp/test.lime

# The evidence destination exists and is not the suspect filesystem
stat -c '%d %m' /mnt/evidence /       # the device numbers must differ

# The clocks the whole timeline depends on
timedatectl status; chronyc tracking 2>/dev/null || ntpq -p
```

## Rollback

| Change | Undo |
|---|---|
| Nothing in `baselines/incident-response/` changes a system | It reads, hashes and writes to a directory you name |
| A host quarantined during containment | Restore the original security group or VLAN, after you are satisfied it is clean — which usually means rebuilt, not cleaned |
| Credentials rotated during containment | Nothing to undo; update the consumers. This is why the rotation runbook belongs with the IR runbook |
| An evidence set that must be disposed of | Only after the retention date in the custody document and only with legal's agreement. Record the disposal as a custody row |
| A premature "resolved" | Re-declare. Re-opening an incident is cheaper than a status page that says resolved while customers still fail |

## Common failure modes

- **Rebooting or reimaging a compromised host**, destroying RAM, sockets and the
  process table, in the name of restoring service.
- **No declaration**, so nobody is IC, and two people change the system at once.
- **The IC typing**, and therefore not commanding.
- **No scribe**, so the timeline is reconstructed afterwards from chat
  scrollback and is wrong in the places that matter.
- **Evidence written to the suspect filesystem**, overwriting the unallocated
  space an examiner needed.
- **Artifacts with no hashes and no custody trail**, which cannot be relied on
  later by anyone.
- **An unsynchronised clock** that nobody recorded, making correlation with
  other systems impossible.
- **A missed 24-hour NIS2 early warning** because the team was waiting for
  complete information that the deadline does not require.
- **No record of the time of awareness**, so every deadline is arguable.
- **Speculating about cause on the status page**, and having the guess become the
  story.
- **A cadence promised and then missed.**
- **Rotating the credentials the attacker holds but not the sessions** —
  cookies, SSH certificates, cloud session tokens — so access survives the
  rotation.
- **Snapshots taken and then shared** with a broad permission, creating a second
  breach out of the evidence.
- **A post-mortem with one root cause**, one action, and the same incident again
  next quarter.
- **Actions owned by a team**, which means owned by nobody.
- **A checklist nobody has rehearsed**, read for the first time at 03:00.

## Control mapping

Section to control families. Benchmark section numbers are deliberately not
cited: verify them against the exact benchmark version you are audited on.

| This guide | Reference | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Annex A | NIS2 Art. 21(2) / 23 |
|---|---|---|---|---|
| Roles and declaration | NIST SP 800-61 | IR-2, IR-4, IR-7 | A.5.24, A.5.25 | (b) |
| First-hour checklist | NIST SP 800-61 | IR-4, IR-8 | A.5.24, A.5.26 | (b) |
| Containment by isolation | NIST SP 800-61 | IR-4(3), SC-7 | A.5.26, A.8.20 | (b) |
| Volatile evidence collection | RFC 3227, ISO/IEC 27037 | IR-4, AU-9, SI-4 | A.5.28 | (b) |
| Chain of custody | ISO/IEC 27037 | AU-9, IR-4 | A.5.28 | (b) |
| Communications | NIST SP 800-61 | IR-6, IR-7 | A.5.5, A.5.6, A.5.24 | Art. 23 |
| Regulatory notification | GDPR Art. 33/34, NIS2 Art. 23 | IR-6 | A.5.34, A.6.8 | Art. 23 |
| Post-incident review | NIST SP 800-61 | IR-4(4), CA-7, PM-4 | A.5.27 | (b) |
| Rehearsal | — | IR-3, CP-4 | A.5.24, A.5.29 | (b) |

## References

- [RFC 3227 — Guidelines for Evidence Collection and Archiving](https://www.rfc-editor.org/rfc/rfc3227.html)
  (§2.1 order of volatility, §2.2 don't trust the programs on the system)
- [NIST SP 800-61 — Computer Security Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [ISO/IEC 27037](https://www.iso.org/standard/44381.html) — identification,
  collection, acquisition and preservation of digital evidence
- [GDPR Art. 33](https://gdpr-info.eu/art-33-gdpr/) and
  [Art. 34](https://gdpr-info.eu/art-34-gdpr/)
- [NIS2 Directive Art. 23](https://eur-lex.europa.eu/eli/dir/2022/2555/oj) —
  reporting obligations and their three deadlines
- [Cook, *How Complex Systems Fail*](https://how.complexsystems.fail/) — why the
  post-mortem template has no "root cause" field
- [avml](https://github.com/microsoft/avml) — memory acquisition that does not
  need a kernel module built for the running kernel
- [Observability and logging](observability-logging.md) for detection,
  [Linux hardening](linux-hardening.md) and
  [Kubernetes hardening](kubernetes-hardening.md) for the audit trails an
  investigation reads, and [backup and disaster
  recovery](backup-disaster-recovery.md) for the restore path after a
  destructive incident

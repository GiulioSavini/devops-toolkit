# Wazuh Host Intrusion Detection

A baseline for host-based detection: file integrity monitoring that says **who**
changed a file, custom rules that are proven to fire, log collection from the
journal and auditd, configuration assessment against the hardening you already
applied, and active response deliberately switched off. Everything ships as a
file under [`baselines/wazuh/`](../baselines/wazuh/) and is validated by
[`tests/wazuh.sh`](../tests/wazuh.sh), which runs the real `wazuh-analysisd`,
`wazuh-logtest-legacy` and `verify-agent-conf`.

| | |
|---|---|
| Applies to | Wazuh 4.9+ (validated on 4.14.8), Linux agents with systemd and auditd. Rule IDs in the reserved 100000+ local range |
| Baseline files | [`baselines/wazuh/`](../baselines/wazuh/) |
| Validated by | [`tests/wazuh.sh`](../tests/wazuh.sh) |
| Lockout risk | **Low, with one real exception: active response.** An automated block keyed on a spoofable source address is a denial-of-service primitive pointed at your own users. It is off in this baseline, on purpose |
| Last reviewed | 2026-09 |

## Threat model

What this baseline is for:

- **Persistence.** A changed unit file, a new cron entry, a modified
  `authorized_keys`, a binary dropped in `/usr/local/bin` — the cheap,
  high-yield places an intruder returns through.
- **Privilege escalation.** A change to `sudoers`, an unauthorised `sudo`
  attempt, a direct root login.
- **Drift away from the hardening you applied.** The settings in
  [Linux hardening](linux-hardening.md) are applied once; SCA is what answers
  "is this host still hardened" six months later.
- **The agent itself being silenced.** An intruder who stops the agent produces
  silence, and silence is what monitoring is worst at noticing.
- **Answering the question after the fact**: who changed this file, from which
  process, as which user, and when.

What it is not for:

- **Being a SIEM.** Wazuh will index alerts and you can search them, but the
  detection content here is host-level. Correlating across services is
  [observability and logging](observability-logging.md), and the audit trails it
  reads are in [Linux hardening](linux-hardening.md) and
  [Kubernetes hardening](kubernetes-hardening.md).
- **Preventing anything.** This is detection. The prevention is every other
  guide in this repository.
- **Surviving root on the monitored host.** An intruder with root can stop the
  agent, edit its config, or feed it lies. Rule 100050 exists because the only
  defence is noticing the silence, and alerts must be stored off the host.
- **Container or Kubernetes runtime detection.** FIM inside a container is the
  wrong layer; see the admission and runtime sections of
  [Kubernetes hardening](kubernetes-hardening.md).
- **Doing the forensics.** An alert starts the process in
  [incident response](incident-response.md); the collector there preserves the
  evidence.

## Centralised agent configuration

[`agent.conf`](../baselines/wazuh/agent.conf) is pushed from the manager to a
group rather than maintained per host:

```bash
# /var/ossec/etc/shared/<group>/agent.conf on the manager, then:
/var/ossec/bin/verify-agent-conf
/var/ossec/bin/agent_groups -c -g <group>
```

Centralised beats per-host `ossec.conf` for one reason: **an agent whose local
config has drifted is invisible until you go looking.**

Always run `verify-agent-conf` before pushing. It is the only thing that catches
a misspelled option — an unknown element is otherwise skipped with a line in the
agent's log that nobody reads, and the setting silently does nothing.
`tests/wazuh.sh` asserts both that the shipped file verifies **clean, with no
warnings**, and that an unknown option is rejected.

### File integrity monitoring: three decisions

```xml
<directories check_all="yes" whodata="yes" report_changes="yes">/etc/sudoers,/etc/sudoers.d</directories>
```

**`whodata="yes"` is the reason to run FIM at all** rather than a cron job with
`sha256sum`. It attaches the uid, the process and the parent process that made
the change, via the kernel audit subsystem. Two consequences to plan for: it
**implies** `realtime`, and it **installs its own audit rules**, which appear in
`auditctl -l` and can collide with a hand-managed audit ruleset — see the audit
section of [Linux hardening](linux-hardening.md). If that host's auditd rules are
immutable (`-e 2`), whodata cannot install anything and fails at startup.

**`realtime="yes"` uses inotify**, so a change is reported in seconds instead of
at the next scan. It costs one watch per directory, and
`fs.inotify.max_user_watches` is what breaks first on a host with many
directories. Raise it deliberately rather than discovering it.

**`report_changes="yes"` stores the diff** — and must never be set on a directory
that can contain secrets. The diff is shipped to the manager and stored there, so
a changed `.env` file becomes a copy of your credentials in the alert store. The
baseline sets `report_changes` only on `/etc/sudoers*`, `/etc/ssh` and the
account files, and adds `<nodiff>` for `/etc/shadow`, `/etc/gshadow` and
`/root/.ssh`.

What is monitored, and why each group is there:

| Paths | Why |
|---|---|
| `/etc/sudoers`, `/etc/sudoers.d`, `/etc/ssh`, `/root/.ssh` | Who can become root, and who can log in |
| `/etc/passwd`, `group`, `shadow`, `gshadow`, `/etc/pam.d`, `/etc/security` | Accounts and authentication |
| `/etc/systemd/system`, `/usr/lib/systemd/system`, cron paths, `/etc/modprobe.d` | Persistence, in the order an intruder actually uses it |
| `/usr/local/bin`, `/usr/local/sbin` (realtime), `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` (scheduled) | Binaries that should only change when a package changes |

Every `<ignore>` is a blind spot. The ones in the baseline are there because they
change constantly (`/etc/mtab`, `/etc/resolv.conf`, `/etc/ld.so.cache`) and each
is justified in a comment. **An exclusion without a justification becomes
permanent by accident.**

`<process_priority>15</process_priority>` and `<max_eps>50</max_eps>` are not
cosmetic: a FIM scan that competes with production IO is a FIM scan somebody
disables.

### The rest of the agent

- **`journald` first.** On a systemd host, reading `/var/log/auth.log` misses
  everything that only ever went to the journal — and on a host with no rsyslog
  that file does not exist at all.
- **`/var/log/audit/audit.log`** with `log_format audit`, which is where the
  whodata events and the rules from `baselines/linux/auditd/` land.
- **`rootcheck`** for known rootkit signatures, odd permissions and hidden
  processes. The hidden-process check is one of the few things that finds an LKM
  rootkit without a memory image.
- **`sca`**, the CIS-derived configuration assessment. This is the part of Wazuh
  that answers the question a hardening guide cannot: is the host still in the
  state you left it in.
- **`syscollector`**, because the manager's vulnerability detection has nothing
  to work from without the package and OS inventory.
- **`wodle name="command"`** for data that is not a log — listening ports, here.
  Each one is a process spawned on every agent at that interval, so the cost
  scales with the fleet.

## Custom rules and decoders

Decoding happens **on the manager**; an agent only ships the log line. So
[`local_rules.xml`](../baselines/wazuh/rules/local_rules.xml) and
[`local_decoder.xml`](../baselines/wazuh/decoders/local_decoder.xml) are manager
files.

Four conventions, and one of them is not in the documentation.

**IDs live in 100000–120000.** Reusing a built-in ID silently replaces that rule
for the whole installation. `tests/wazuh.sh` tries it as a control: on 4.14.8
analysisd rejects it outright, and the test records which way it went so a future
version change is visible.

**Build on a built-in rule with `<if_sid>`.** The decoding work is already done,
and the local rule only expresses the local policy. A rule written from scratch
with its own `<match>` duplicates upstream and rots on the next ruleset update.

**Levels are a routing decision, not a severity opinion.** 0–3 is noise worth
storing, 5–7 is "look at it in the morning", 10–12 is "a human now", and above 12
should be rare enough that nobody learns to ignore it. Integrations and active
response key off the level, so inflating one is how an alert ends up paging at
03:00 forever.

**Static and dynamic fields are matched differently, and getting it wrong stops
the whole file loading** — taking your entire local ruleset with it. This cost an
afternoon and is worth stating precisely, because all three plausible spellings
fail differently:

| Written as | What the real parser says |
|---|---|
| `<field name="dstuser">^root$</field>` | `ERROR: Failure to read rule 100010. Field 'dstuser' is static.` |
| `<dstuser>^root$</dstuser>` | `ERROR: Invalid option 'dstuser' for rule '100010'.` |
| `<srcuser negate="yes">…</srcuser>` | `ERROR: Invalid option 'srcuser' for rule '100011'.` |
| `<user>^root$</user>` | Accepted — and it resolves to whichever user field the decoder filled |

`<field name="...">` is for **dynamic** fields, such as the FIM events' `file`.
And `<user>` is not a synonym for "the person who did it": for a `sudo` event it
resolves to the **target** user (`root`), not the invoking one. Expressing "an
account not on the allow list used sudo" therefore needs a CDB list, not a
negated field — which is why the baseline's sudo rule keys on the built-in
"unauthorized user attempted to use sudo" instead, and says so.

`tests/wazuh.sh` asserts the first row of that table as a control: if analysisd
ever accepts a static field written as a dynamic one, the check that the ruleset
loads proves nothing.

### The rules, and what is proven about each

| ID | Fires on | Proven by |
|---|---|---|
| 100010 | Direct root login over SSH (`if_sid 5715` + `<user>^root$</user>`), level 12 | Fires on `Accepted publickey for root`; a login as `deploy` matches only the built-in 5715 |
| 100011 | Unauthorised `sudo` attempt (`if_sid 5405`), escalated from level 5 to 12 | Fires on `user NOT in sudoers`; a normal `sudo` matches 5403 instead |
| 100020 | Application authentication failure, through the custom decoder, level 5 | Fires on `RESULT=fail`; `RESULT=ok` matches nothing |
| 100021 | 5 failures from the **same source** in 120s, level 10 | **Not fired by the test** — see below |
| 100030 | An admin role granted inside the application, level 10 | Fires on `ROLE=admin`; `ROLE=viewer` matches nothing |
| 100040–100042 | FIM on sudoers, SSH configuration and `authorized_keys`, and binaries outside package management | Syntax only — see below |
| 100050 | The agent disconnecting (`if_sid 505`), level 12 | Syntax only |

Each rule is paired with the benign line next to it. A rule that fires is half
the proof; **a rule that also fires on the benign line is worse than no rule**,
because it trains people to close the alert.

The decoder's field names are asserted too (`status`, `srcuser`, `srcip`). A
decoder whose `<prematch>` never matches produces no fields, so every rule
matching on them is dead — silently, with no error anywhere. And the names are
not free-form: `srcip`, `dstuser`, `status`, `url` and the rest are what rules,
the API and the dashboards filter on. Inventing `source_ip` gives you a field
nothing else can query.

One narrowing condition in rule 100030 had to be **removed** because it silently
killed the rule: `<user>\.+</user>`, intended as "any non-empty value", matched
nothing, because in Wazuh's own regex syntax `\.` is not a literal dot. A
condition that no test exercises is a condition that can quietly disable the rule
it was meant to tighten.

### What the test deliberately does not prove

- **The FIM rules (100040–100042) are not fired.** Syscheck events arrive as JSON
  from `wazuh-syscheckd`, and `wazuh-logtest-legacy` reads syslog-shaped lines.
  Proving these needs a running manager **and** agent with a real file change —
  an integration test, not a container check. They are checked for syntax by
  `wazuh-analysisd -t`, which is what catches the field-matching mistake above.
- **The correlation rule (100021) is not fired.** `logtest` evaluates one event at
  a time and cannot build correlation state.
- **`<frequency>` rules need `<timeframe>` *and* a `<same_*>` field.** Without
  `<same_srcip />`, five unrelated users mistyping a password become a
  brute-force alert. That is stated in the rule's comment; it is not asserted,
  because nothing in a container can assert it.

## Manager configuration

[`manager-ossec-fragment.xml`](../baselines/wazuh/manager-ossec-fragment.xml) is
a **fragment** to merge into the existing `<ossec_config>`, not a replacement.
`ossec.conf` ships with a working per-platform configuration, and replacing it
wholesale is how a manager loses its cluster, its API or its indexer connection.

| Setting | Value | Why |
|---|---|---|
| `log_alert_level` | 3 | Everything from 3 up is stored and queryable afterwards |
| `email_alert_level` | 12 | Only 12 and above interrupts a human. Set the two equal and you get either an unsearchable history or a team that filters the alert mailbox into a folder nobody opens |
| `logall_json` | `no` | Stores **every** event, alert or not. The difference between "we can answer that question" and 400 GB/day. Turn it on deliberately, with retention |
| `vulnerability-detection` | enabled | Correlates the syscollector inventory with the feeds, on the manager, so it costs nothing on the agents |
| `rule_test` | enabled, 1 thread | Rule testing over the API, in its own process with a timeout, so a runaway regular expression cannot take analysisd with it |

`tests/wazuh.sh` asserts those three alert settings, because they are the claims
this guide makes about the file.

### Wazuh config files are XML fragments

Rule files, decoder files, `agent.conf` and this fragment all have **several root
elements**. They are not standalone XML documents, and `xmllint` rejects every
correct one with:

```text
parser error : Extra content at the end of the document
```

`tests/wazuh.sh` wraps each file in a single synthetic root before checking
well-formedness, and asserts that the **unwrapped** file is still rejected — so if
that ever changes, the wrapping and the explanation for it get corrected rather
than silently kept. The authoritative check is `wazuh-analysisd -t`, which parses
them the way Wazuh does.

## Active response is off, on purpose

Wazuh can run a command on an agent when a rule fires. It is the most dangerous
feature in the product, and
[`active-response/README.md`](../baselines/wazuh/active-response/README.md) is why
the baseline ships none.

An automated block keyed on `srcip` is a **denial-of-service primitive pointed at
your own infrastructure**:

1. **The address is frequently not the attacker's.** Behind a load balancer, a NAT
   gateway, a CDN or an ingress controller it is shared, and blocking it blocks
   everyone behind it.
2. **The first thing it blocks is usually a monitoring probe** — a health check
   that fails authentication, a scanner you paid for, a backup agent with a stale
   credential.
3. **A spoofable trigger is a remote block primitive.** Any log line an attacker
   can influence — a username, a hostname, a reflected HTTP header — becomes a way
   to make you block an address of their choosing.

The failure mode is not "it did nothing". It is an outage caused by your own
security tooling, at the moment everyone assumes the security tooling is the
thing helping.

When you do enable it: one action, one rule, one group. Scope by `<rules_id>` and
**never** by `<level>` — a level-based response fires on every future rule anybody
writes at that level, including the ones the next ruleset update adds. Always set
a `<timeout>`, so a wrong block recovers on its own. Put the management ranges,
the monitoring system, the load balancers, the NAT egress addresses, the CI
runners and the VPN concentrator in `<white_list>` **first**. And alert on every
response taken: a response nobody reviews is a firewall change nobody reviewed.

`tests/wazuh.sh` asserts that the baseline ships no enabled `<active-response>`,
so adding one is a reviewable change rather than something that arrives with a
config update.

## Rollout

1. **Manager first, with the default ruleset only.** Confirm agents enrol, alerts
   arrive, and the indexer is storing them. Do not add custom rules to a manager
   that is not yet working.
2. **One agent, in its own group**, with the baseline `agent.conf`. Run
   `verify-agent-conf` before every push — and read its output, not just its exit
   status.
3. **FIM without `whodata` first**, to see the alert volume. Then turn `whodata`
   on for the paths that matter and check `auditctl -l` for collisions with your
   own audit rules.
4. **Add the custom decoder and rules to the manager**, and run
   `/var/ossec/bin/wazuh-analysisd -t` **before** restarting: a bad rule file
   stops analysisd from starting, which stops **all** alerting.
5. **Test every rule with `wazuh-logtest`** before trusting it, with a line that
   should match and a line that should not. That is exactly what
   `tests/wazuh.sh` automates.
6. **Tune for a month with nothing but alerts.** Count how often each rule fires;
   anything that fires daily and is closed daily is either misconfigured or
   pointed at the wrong path.
7. **Only then** consider active response, following the order in its README.
8. **Enable SCA and vulnerability detection last**, when the alert pipeline is
   already quiet enough that a report has somewhere to land.

## Verification

```bash
# The ruleset parses — ALWAYS before restarting the manager
/var/ossec/bin/wazuh-analysisd -t

# A rule does what you think, on a line you choose
/var/ossec/bin/wazuh-logtest
# or, non-interactively:
printf 'Dec 29 10:00:00 host sshd[1]: Accepted publickey for root from 10.0.0.9 port 22 ssh2\n' \
  | /var/ossec/bin/wazuh-logtest-legacy -q | grep -E "Rule id|Level|Description"

# The centralised config is valid, and what agents actually received
/var/ossec/bin/verify-agent-conf
/var/ossec/bin/agent_groups -l
/var/ossec/bin/agent_control -i <agent-id>

# Which agents are NOT reporting — the most important single answer here
/var/ossec/bin/agent_control -l | grep -v Active

# What FIM is really watching on an agent, and whether whodata started
grep -E 'whodata|realtime' /var/ossec/etc/shared/<group>/agent.conf
grep -iE 'whodata|audit' /var/ossec/logs/ossec.log | tail -20
auditctl -l | grep wazuh_fim      # the rules whodata installed

# inotify headroom, which is what breaks realtime FIM first
sysctl fs.inotify.max_user_watches
find /var/ossec/queue/fim -type f | wc -l

# Alerts are arriving, and at which levels
tail -f /var/ossec/logs/alerts/alerts.json | jq -c '{level:.rule.level,id:.rule.id,desc:.rule.description}'
jq -r '.rule.id' /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn | head -20
# the second command is the tuning tool: the top of that list is your noise

# No active response is configured anywhere
grep -rn '<active-response>' /var/ossec/etc/ | grep -v '^\s*<!--'
```

## Rollback

| Change | Undo |
|---|---|
| Custom rules or decoders | Remove the file, `wazuh-analysisd -t`, restart the manager. **A bad rule file stops analysisd starting, which stops all alerting** — always run `-t` first |
| A rule that is too noisy | Lower its level, or narrow it with a condition you have tested. Do not delete built-in rules; override them with a local rule at level 0 |
| `agent.conf` push | Restore the previous file and push again; agents pull the new version on their next check-in |
| `whodata` | Set `realtime="yes"` instead. Wazuh removes its own audit rules when whodata is disabled — verify with `auditctl -l` |
| `report_changes` on a path that held secrets | Remove the setting, then **delete the stored diffs** on the manager (`/var/ossec/queue/diff/`) and treat the secret as leaked |
| FIM on a path that flooded | Add the path to `<ignore>` with a comment saying why, or narrow the directory. Restart the agent |
| Active response | Remove the `<active-response>` block and restart. Anything already blocked stays blocked until its timeout — or forever, if you did not set one |
| SCA or vulnerability detection | Disable in the config; the findings are dropped, the agents are unaffected |

## Common failure modes

- **A misspelled option in `agent.conf`**, silently ignored on every agent in the
  group, so the setting everyone believes is on is off.
- **A static field written as `<field name="...">`**, which stops the whole local
  ruleset loading — and with it every custom rule.
- **A rule id reused from the built-in range**, replacing an upstream rule.
- **A narrowing condition that silently disables its own rule**, like
  `<user>\.+</user>` meaning something other than "any value".
- **A decoder whose `<prematch>` never matches**, so every rule that depends on
  its fields is dead with no error.
- **`<frequency>` without `<same_srcip />`**, correlating unrelated events into a
  fake brute-force alert.
- **Restarting the manager without `wazuh-analysisd -t`**, turning a typo into a
  total alerting outage.
- **`report_changes` on a directory with secrets**, copying credentials into the
  alert store.
- **`whodata` on a host with immutable auditd rules (`-e 2`)**, which cannot
  install its own rules and fails at startup.
- **`fs.inotify.max_user_watches` exhausted**, so realtime FIM silently degrades
  to scheduled scans.
- **FIM on `/var` or `/home` wholesale**, producing thousands of alerts a day
  until somebody turns FIM off entirely.
- **An agent that stopped reporting and nobody noticed**, which is why rule
  100050 is level 12.
- **Alerts stored only on the monitored host**, so an intruder with root edits
  them.
- **Active response scoped by `<level>`**, firing on every future rule at that
  level.
- **Active response with no `<timeout>` and no allow list**, blocking the
  monitoring system permanently.
- **`logall_json` on by accident**, and a disk that fills in a week.

## Control mapping

Section to control families. Benchmark section numbers are deliberately not
cited: verify them against the exact benchmark version you are audited on.

| This guide | Reference | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Annex A | NIS2 Art. 21(2) |
|---|---|---|---|---|
| File integrity monitoring | CIS Controls v8 §3, §8 | SI-7, CM-3, AU-2 | A.8.9, A.8.15 | (b) |
| whodata attribution | — | AU-3, AU-12, SI-4 | A.8.15, A.8.16 | (b) |
| Custom rules and levels | — | SI-4, AU-6, IR-4 | A.8.16 | (b) |
| Log collection (journald, auditd) | CIS Linux Benchmarks | AU-2, AU-3, AU-6 | A.8.15 | (b) |
| Rootcheck | — | SI-3, SI-4 | A.8.7 | (b) |
| SCA (configuration assessment) | CIS Benchmarks | CM-6, CA-7, RA-5 | A.8.9, A.5.36 | (e) |
| Vulnerability detection | — | RA-5, SI-2 | A.8.8 | (e) |
| Agent-down detection | — | SI-4(7), AU-5 | A.8.16 | (b) |
| Active response (deliberately off) | — | IR-4(1), SI-4(7) | A.5.26 | (b) |

## References

- [Wazuh documentation](https://documentation.wazuh.com/) — in particular
  [FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
  and [`syscheck` options](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html)
- [Rules syntax and options](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
  and [decoders syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html)
- [`wazuh-logtest`](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
  and [`verify-agent-conf`](https://documentation.wazuh.com/current/user-manual/reference/tools/verify-agent-conf.html)
- [Centralised configuration](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html)
- [Active response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)
  — read it with the README in this baseline next to it
- [Security Configuration Assessment](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html)
- [MITRE ATT&CK](https://attack.mitre.org/) for the technique IDs the rules carry
- [Linux hardening](linux-hardening.md) for the auditd rules whodata shares the
  kernel with, [incident response](incident-response.md) for what happens after
  an alert, and [observability and logging](observability-logging.md) for getting
  the alerts off the host

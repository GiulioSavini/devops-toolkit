# Ansible for Production

A baseline for running Ansible against real infrastructure: pinned
collections, a role that is safe to re-run, per-play privilege escalation,
batched rollouts, secrets that are never plain text on disk, and a lint gate
that fails the build. Everything ships as a file under
[`baselines/ansible/`](../baselines/ansible/) and is validated by
[`tests/ansible.sh`](../tests/ansible.sh), which installs the pinned
collections and runs the real `ansible-lint` and `ansible-playbook
--syntax-check`.

| | |
|---|---|
| Applies to | ansible-core 2.17+ (validated on 2.21.4), ansible-lint production profile (validated on 26.9.0), targets Debian/Ubuntu and RHEL/Rocky/Alma 9 |
| Baseline files | [`baselines/ansible/`](../baselines/ansible/) |
| Validated by | [`tests/ansible.sh`](../tests/ansible.sh) |
| Lockout risk | **High.** The hardening role manages the admin account, its `authorized_keys` (with `exclusive: true`) and a sudoers drop-in. A wrong key or a wrong privileged group leaves the account with no path to root |
| Last reviewed | 2026-09 |

## Threat model

What this baseline is for:

- **The controller as a lateral movement hub.** An Ansible controller holds
  credentials for every host it manages. A compromised controller, or a
  compromised playbook in the repository, is a compromise of the whole estate.
- **Secrets in the repository.** `group_vars` is plain text in git by default,
  and it is where people put passwords, tokens and private keys.
- **An automated change becoming an outage.** Ansible applies to all hosts in
  parallel unless told otherwise, so a bad package version takes down a whole
  tier in one run.
- **A play that silently does nothing.** A renamed group, a config file that
  was never loaded, a conditional that resolved to false on half the estate —
  all of which exit 0.
- **Drift in the automation itself.** An unpinned collection means the playbook
  reviewed last week is not the playbook that runs today.
- **No attribution.** A shared root login means every change in the audit log
  has the same name on it.

What it is not for:

- **Deciding what "hardened" means.** The role applies a small baseline; the
  content of that baseline is [Linux hardening](linux-hardening.md).
- **Being a secret store.** SOPS keeps secrets encrypted at rest in git; it
  does not rotate them or audit access. See
  [secrets management](secrets-management.md).
- **Replacing immutable infrastructure.** Configuration management converges a
  mutable host. Where you can rebuild instead, rebuild.
- **Protecting against a malicious operator with controller access.** They have
  root on every host by design; the controls there are code review, branch
  protection and the audit trail.

## Configuration

[`ansible.cfg`](../baselines/ansible/ansible.cfg) is short, and one line in it
is the most commonly misunderstood behaviour in Ansible:

**Ansible reads `ansible.cfg` from the current working directory or
`$ANSIBLE_CONFIG`, never from a parent directory of the playbook.** Run the
playbooks from `baselines/ansible/`, or export
`ANSIBLE_CONFIG=/path/to/baselines/ansible/ansible.cfg`. A config file that is
silently not loaded is the single most common cause of "it behaved differently
in CI". Check which one is in effect with `ansible --version`, which prints the
config file path it actually used.

| Setting | Why |
|---|---|
| `host_key_checking = True` | The default, and the thing people turn off first. Off means an attacker who can answer on port 22 gets your automation's credentials on the first connection |
| `become = False` in `[privilege_escalation]` | Escalation is declared per play and per task, so a play with no business being root cannot quietly acquire it |
| `gathering = smart` + `fact_caching = jsonfile` | A play that only reads `os_family` does not re-run `setup` on every host, every run |
| `pipelining = True` | Removes one SSH round trip per task. It requires `requiretty` to be **off** in sudoers on the target — the default on Debian and RHEL 9+, but this is the knob that breaks older hosts |
| `vars_plugins_enabled = host_group_vars,community.sops.sops` | Makes `group_vars/*.sops.yml` decrypt transparently at vars-loading time. Order matters: `community.sops.sops` must come **after** `host_group_vars` |
| `retry_files_enabled = False` | `.retry` files are stale within minutes and get committed by accident |
| `forks = 20` | A deliberate number. The default 5 is slow; unbounded is how you DDoS your own package mirror |

## Pinned collections

[`requirements.yml`](../baselines/ansible/requirements.yml) pins every
collection to an **exact** version — never a range, never omitted:

```yaml
collections:
  - name: ansible.posix
    version: "2.2.2"
```

`ansible-galaxy install -r` with an unpinned collection resolves to whatever is
newest on Galaxy at that moment, which makes a pipeline that passed yesterday
fail today for reasons that are not in the diff.

`tests/ansible.sh` proves the pins **resolve and install**, not merely that
they are syntactically present: a typo in a version, or a version yanked from
Galaxy, fails the test.

Bump deliberately: read the collection changelog, run `bash tests/ansible.sh`,
commit the new pin as its own change.

### Execution environments

[`execution-environment.yml`](../baselines/ansible/execution-environment.yml) is
an `ansible-builder` (schema version 3) definition:

```bash
ansible-builder build -f execution-environment.yml -t devops-toolkit-ee:1.0.0
```

"Works on my laptop" for Ansible means a specific ansible-core, a specific set
of collections, **and** a specific set of Python libraries that the modules
import on the *controller*. An execution environment freezes all three into one
image, so the controller in CI, the one in AWX and the one on a laptop are the
same machine. It also removes the class of failure where a collection bump on
the controller changes behaviour on hosts nobody touched.

The base image is pinned by digest, the `ansible-core` pin matches what the
repository lints with, and `galaxy: requirements.yml` reuses the same pinned
file the playbooks use, so the image cannot drift away from the source tree.
`tests/ansible.sh` asserts that consistency — an EE whose `ansible-core` pin
has drifted from the linted version fails.

## The role

[`roles/hardening/`](../baselines/ansible/roles/hardening/) is small on
purpose. What is worth copying is its shape.

### Fail fast, with a message that says what to do

```yaml
- name: Fail fast when the admin public key was not supplied
  ansible.builtin.assert:
    that:
      - hardening_admin_pubkey | length > 0
    fail_msg: >-
      hardening_admin_pubkey is empty. Pass the key from the inventory or from a
      sops-encrypted group_vars file - never from a file committed next to the
      role.
```

The default is an empty string, so the role fails loudly rather than
configuring an account nobody can log into. `authorized_key` with
`exclusive: true` and an empty key would otherwise **remove** every existing
key.

The second assert rejects an unsupported `os_family` outright, because the
privileged group and the sudoers path differ per family and guessing is how a
play silently grants nothing.

### The distro trap this baseline exists to fix

```yaml
hardening_privileged_group: "{{ 'wheel' if ansible_facts['os_family'] == 'RedHat' else 'sudo' }}"
```

Debian and Ubuntu ship a `sudo` group; RHEL, Rocky, Alma and Fedora ship
`wheel` and have **no** `sudo` group at all. A task hard-coded to
`groups: sudo` fails on RHEL with `Group sudo does not exist` — or, worse,
succeeds after someone "fixes" it by creating an empty `sudo` group that grants
nothing, leaving the account with no path to root and the play green.

`tests/ansible.sh` **executes** this conditional on both fact sets rather than
reading it, and also asserts that the hard-coded `sudo` version fails on
RedHat. It is the one check in that file written against a bug the published
version of this guide actually shipped.

### Every variable is role-prefixed

`hardening_admin_user`, not `admin_user`. ansible-lint's production profile
enforces it (`var-naming[no-role-prefix]`) and it stops two roles from silently
fighting over a generic name.

### Validate before you write

```yaml
- name: Grant the privileged group passwordless sudo
  community.general.sudoers:
    name: "10-{{ hardening_privileged_group }}-nopasswd"
    group: "{{ hardening_privileged_group }}"
    commands: ALL
    nopassword: true
    validation: required
```

`validation: required` runs `visudo -c` before the file is put in place. A
syntactically broken sudoers file means **nobody** can use sudo on that host,
including you, including Ansible. The same applies to every `validate:`
parameter on `copy` and `template` — use it for sshd (`sshd -t -f %s`), nginx,
sudoers and anything else where a bad file locks you out.

### Assert the outcome, not that the module ran

```yaml
- name: Read the effective sshd configuration
  ansible.builtin.command:
    cmd: sshd -T
  changed_when: false
  check_mode: false
  register: hardening_sshd_effective

- name: Assert sshd does not accept password authentication
  ansible.builtin.assert:
    that:
      - "'passwordauthentication no' in hardening_sshd_effective.stdout | lower"
```

`sshd -T` resolves the whole `Include` tree in order, so this is the only
answer that counts — see the drop-in load-order section of
[Linux hardening](linux-hardening.md) for why a file that "looks right" often
is not in effect.

`changed_when: false` on a read-only command is what keeps the run honest:
without it every `command` task reports `changed`, and a playbook that always
reports changes is a playbook nobody reads the output of. `check_mode: false`
lets the read still happen under `--check`, so the dry run reports something
real.

### Secrets get `no_log`

```yaml
- name: Install the monitoring agent token
  ansible.builtin.copy:
    content: "{{ hardening_agent_token }}"
    dest: "{{ hardening_agent_config_dir }}/token"
    mode: "0600"
  no_log: true
```

Without `no_log: true`, the token appears in `--diff` output, in the callback
log, and in whatever CI system keeps that log. Note that `no_log` hides the
task's output entirely, which makes debugging harder — that is the trade, and
it is the right one.

### Handlers and check mode

Ansible already skips handlers under `--check`, so a handler cannot report a
restart that never happened — unless someone adds `check_mode: false` to the
task that notifies it. The handler in this role carries that note for whoever
does.

## Rollouts

[`playbooks/rolling-update.yml`](../baselines/ansible/playbooks/rolling-update.yml)
turns one blast radius into three:

```yaml
serial:
  - 1
  - 25%
  - 100%
max_fail_percentage: 0
```

The first batch is a single canary. If it fails, `max_fail_percentage: 0`
aborts the play before the second batch starts, so three of four hosts are
still serving the old version. Without `serial`, Ansible works on all hosts in
parallel and a bad package takes the whole tier down at once.

**`max_fail_percentage` is exclusive and evaluated per batch.** With 4 hosts in
a batch, `max_fail_percentage: 25` tolerates **zero** failures — 25% of 4 is 1,
and the check is "more than 25%". That off-by-one is why people think the
setting is broken. If you want "tolerate one host", work out the number
deliberately.

Two more details in that playbook:

- **`delegate_to: localhost` with `become: false`** for the load balancer API
  calls. The drain call must run from the controller, not from the host that is
  about to stop answering.
- **`until` with `retries`/`delay`** on the health check, and
  `changed_when: false` on it. A rollout that does not wait for readiness is a
  rollout that drains the next host while the previous one is still starting.

Pin the version you install:

```yaml
web_app_version: "1.26.3-1~bookworm"
```

`state: latest` means the version that rolls out is not the version that was
reviewed, and two hosts updated an hour apart can get different
versions. ansible-lint's production profile rejects it (`package-latest`).

## Inventory and secrets

Group names are the contract: renaming a group silently makes every `hosts:`
line that references it match zero hosts — **and a play that matches zero hosts
exits 0**. Nothing fails, nothing is configured. Guard against it in CI by
asserting the host count, or with `--limit` plus `ansible-inventory --graph` in
review.

Connection identity is one unprivileged account per automation platform,
escalating through the sudoers rule the role installs:

```yaml
ansible_user: ansible
ansible_ssh_private_key_file: ~/.ssh/id_ed25519_ansible
```

Never a shared root login. With a per-platform account, `journalctl _COMM=sudo`
attributes every change to the thing that made it. Better still, give the
controller an SSH **certificate** with a short lifetime instead of a long-lived
key — see [SSH key management](ssh-key-management.md).

**Secrets never go in `group_vars/*.yml`.** That file is plain text in git.
They go in `group_vars/<group>.sops.yml`, encrypted with the age recipients in
[`baselines/secrets/`](../baselines/secrets/) and decrypted at runtime by the
`community.sops` vars plugin enabled in `ansible.cfg`, so no plain-text copy of
a secret ever has to exist in the working tree.

This is why SOPS is preferred over `ansible-vault` here: a SOPS file encrypts
**values** and leaves keys readable, so a diff shows which secret changed
without revealing it, and access is granted per age/KMS recipient instead of by
sharing one vault password with everyone who needs any secret.

## Lint as a gate

```bash
ansible-lint --profile production
```

The production profile is the one worth enforcing, and it is strict: fully
qualified collection names, explicit file modes, no `state: latest`, named
tasks, `changed_when` on commands, role-prefixed variables, no bare variables
in `when`. Each of those rules corresponds to a real failure mode in this
guide.

`tests/ansible.sh` requires **zero** violations and zero warnings, runs
`--syntax-check` on every playbook including the molecule scenario's, and
proves each check can fail by running it against a deliberately broken copy
first.

Start with `--profile production` on new code and
`ansible-lint --write` for the mechanical fixes; do not start by adding
`skip_list` entries. An exception belongs in `.ansible-lint` with a comment
saying why, not scattered as `# noqa` across the tree.

## Testing the role

[`molecule/default/molecule.yml`](../baselines/ansible/roles/hardening/molecule/default/molecule.yml)
runs the role on **two** platforms — Debian and Enterprise Linux — because the
`os_family` conditional is the thing under test, and a single-distro scenario
would never have caught the `groups: sudo` bug this baseline exists to fix.

```bash
cd baselines/ansible/roles/hardening && molecule test
```

`tests/ansible.sh` lints and syntax-checks this scenario but does **not**
converge it: molecule needs privileged, systemd-capable containers, and the
test suite is meant to run anywhere bash and docker are present. That is a
documented gap, not a silent skip.

[`verify.yml`](../baselines/ansible/roles/hardening/molecule/default/verify.yml)
asserts the outcome rather than the fact that Ansible reported `ok`:
group membership read with `id -nG`, the sudoers drop-in's existence **and**
mode, `visudo -c` on the whole tree, and `sysctl -n` for the value in the
running kernel. A converge that is green proves the modules ran; only these
checks prove the host ended up in the state the role promises.

The images are pinned by digest because `geerlingguy` publishes only a `latest`
tag for them, so a digest is the only way to get a reproducible run.

## Rollout

1. **`--check --diff` first**, with `diff: true` set at play level so every
   file task shows what it would change. `--check` alone tells you "changed" and
   nothing else.
2. **`--limit` one host.** Confirm the outcome by hand — the account, the
   sudoers file, `sshd -T` — before widening.
3. **`--limit` one group**, then the rest. For anything with a version, use the
   `serial` pattern above rather than a single wide run.
4. **Keep a second session open** on the host you are changing, exactly as with
   an sshd change made by hand. `authorized_key` with `exclusive: true` and a
   sudoers drop-in are both lockout-capable.
5. **Run from the execution environment**, not from a laptop's Python, once the
   playbook is real. Same controller everywhere or the test proved nothing.

Things that are not dry-run safe: a `command`/`shell` task without
`check_mode: false` reports skipped under `--check` and every task that depends
on its `register` behaves unpredictably. Read `--check` output knowing which
tasks did not actually run.

## Verification

```bash
# Which config file is actually in effect — the answer to most surprises
ansible --version

# Inventory resolves to the hosts you think, and the groups still exist
ansible-inventory --graph
ansible all --list-hosts | wc -l

# Connectivity and escalation, separately
ansible all -m ansible.builtin.ping
ansible all -m ansible.builtin.command -a 'id -u' --become

# Which collection versions are really installed
ansible-galaxy collection list

# Lint gate, the same one CI runs
ansible-lint --profile production

# Dry run with diffs, on one host
ansible-playbook playbooks/site.yml --check --diff --limit web01.example.internal

# After a real run, verify on the host rather than trusting the recap
ssh web01 'id -nG ops; sudo -n true && echo sudo-ok; visudo -c; sshd -T | grep -i ^passwordauthentication'
```

## Rollback

| Change | Undo |
|---|---|
| Collection bump | Restore the previous pin in `requirements.yml` and `ansible-galaxy install -r requirements.yml --force` |
| Admin key (`exclusive: true`) | Re-run with the correct key from a session that is still open, or out-of-band console access. There is no remote undo once the only key is gone |
| Sudoers drop-in | `community.general.sudoers` with `state: absent`. `validation: required` is what stops the broken-file case from happening at all |
| sysctl | Remove the entry and re-run; `ansible.posix.sysctl` with `state: absent` also reverts the running value |
| Application version | Re-run `rolling-update.yml` with the previous `web_app_version`. This is why it is pinned |
| A play that drained hosts and then failed | The enable call is a separate task: re-run the play with `--limit` on the drained host, or call the LB API by hand. Check the pool before assuming |
| Execution environment | Point CI back at the previous image tag; the definition file is reproducible |

## Common failure modes

- **`ansible.cfg` not loaded**, because the playbook was run from a parent
  directory. Every setting in this guide silently does not apply.
- **A group renamed**, so `hosts: web` matches zero hosts and the play exits 0
  having configured nothing.
- **`groups: sudo` on RHEL**: the task fails, or someone creates an empty
  `sudo` group and the account ends up with no path to root.
- **`authorized_key` with `exclusive: true` and an empty variable**, removing
  every key on the host.
- **A broken sudoers file** written without `validation: required` — no sudo
  for anyone, including the automation that would fix it.
- **`state: latest`**, so two hosts updated an hour apart run different
  versions, and the version that rolled out was never reviewed.
- **No `serial`**, so one bad package version takes down the whole tier in
  parallel.
- **`max_fail_percentage` misread** as inclusive, so a rollout continues past a
  failure someone thought was covered.
- **A secret in `group_vars/all.yml`**, plain text in git, in every clone and
  in every fork.
- **A secret without `no_log`**, in the CI log for as long as that log is kept.
- **`host_key_checking = False`** left in from a lab setup.
- **`command` without `changed_when: false`**, so every run reports changes and
  nobody reads the output any more.
- **Unpinned collections**, so a green pipeline turns red with no diff to
  explain it.
- **`--check` trusted as a full dry run**, when `command`/`shell` tasks and
  everything depending on their `register` did not really run.

## Control mapping

Section to control families. Benchmark section numbers are deliberately not
cited: verify them against the exact benchmark version you are audited on.

| This guide | Reference | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Annex A | NIS2 Art. 21(2) |
|---|---|---|---|---|
| Pinned collections, execution environment | SLSA, CIS Supply Chain | CM-2, CM-6, SA-10 | A.8.9, A.8.30 | (d) |
| Per-play privilege escalation, sudoers | CIS Linux Benchmarks | AC-6, AC-2 | A.8.2, A.5.15 | (i) |
| Admin account and key management | same | IA-2, IA-5, AC-2 | A.5.15, A.5.17, A.8.5 | (i) |
| Host key checking | same | SC-8, SC-23, IA-3 | A.8.24 | (h) |
| Secrets via SOPS, `no_log` | — | IA-5, SC-12, SC-28 | A.5.33, A.8.24 | (h) |
| Batched rollout, health gating | — | CM-3, CM-4, CP-10 | A.8.32, A.8.6 | (c), (e) |
| Lint and syntax gate | — | CM-3, SI-7 | A.8.32 | (e) |
| Molecule verification | — | CM-4, SA-11 | A.8.29, A.8.32 | (e) |
| Change attribution | CIS Linux Benchmarks | AU-2, AU-3, AU-12 | A.8.15 | (b) |

## References

- [ansible-lint profiles](https://ansible.readthedocs.io/projects/lint/profiles/)
  — what `production` actually enforces
- [Ansible configuration settings](https://docs.ansible.com/ansible/latest/reference_appendices/config.html)
  and [configuration file precedence](https://docs.ansible.com/ansible/latest/reference_appendices/general_precedence.html)
- [Rolling updates: `serial` and `max_fail_percentage`](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_strategies.html)
- [Molecule](https://ansible.readthedocs.io/projects/molecule/) and
  [ansible-builder](https://ansible.readthedocs.io/projects/builder/)
- [`community.sops`](https://galaxy.ansible.com/ui/repo/published/community/sops/)
  and [SOPS](https://github.com/getsops/sops)
- [`community.general.sudoers`](https://docs.ansible.com/ansible/latest/collections/community/general/sudoers_module.html)
  (`validation: required`)
- [Linux hardening](linux-hardening.md) for the baseline this role applies,
  [secrets management](secrets-management.md) for the SOPS setup, and
  [SSH key management](ssh-key-management.md) for the controller's credentials

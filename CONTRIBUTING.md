# Contributing

This repository is a set of **configuration baselines that are executed, not
described**. Every guide points at files under `baselines/`, and every baseline
is validated by a script under `tests/` that runs the real tool. A change that
does not fit that shape is not ready to merge, however correct it looks.

Corrections are especially welcome where a setting is wrong, has aged badly, or
is right for one distro and quietly wrong for another.

## How the repository is laid out

```text
guides/      one guide per domain, in the structure below
baselines/   the actual files: no fragments, no ellipses, no "..."
tests/       one script per domain; each proves its baseline works
```

A snippet in a guide is a quotation from a file in `baselines/`. If it is not
in a file, it cannot be tested, and nobody can apply it without retyping it.

## Running everything locally

```bash
make lint   # markdownlint over every guide
make test   # every tests/*.sh except the Kubernetes end-to-end suite
make e2e    # the Kubernetes suite: creates and destroys a kind cluster
make all    # all three
```

The only host requirements are `bash`, `docker` and `curl`. Every tool runs in a
pinned container image, so a local run resolves the same versions CI does. If a
test needs a tool you do not have installed, that is a bug in the test.

## The guide structure

Every guide follows the same order. A reader in the middle of an incident needs
to find the verification command without reading the prose above it.

1. **H1 title**, then one paragraph saying what the baseline covers, naming the
   `baselines/` directory and the `tests/` script that validates it.
2. **Metadata table**: `Applies to` (exact versions, including the ones where
   behaviour differs), `Baseline files`, `Validated by`, `Lockout risk` (say
   plainly what can cut off access, and how bad it is), `Last reviewed`.
3. **`## Threat model`**: what the baseline is for, as concrete attacker
   behaviours — and then **what it is not for**. The second list matters more.
   A guide that claims to solve multi-tenant isolation with sysctl settings is
   worse than no guide.
4. **Per-setting sections**: for each setting, what it does, why the default is
   wrong, and what breaks when you change it. Tables where there are more than
   three settings.
5. **`## Rollout`**: numbered and staged, with the riskiest change last. If a
   step can lock you out, arm a revert before applying it (see the
   `systemd-run --on-active` pattern in `guides/linux-hardening.md`).
6. **`## Verification`**: copy-pasteable commands that read the **effective**
   state, not the file — `sshd -T`, not `cat sshd_config`. Say what the expected
   output is.
7. **`## Rollback`**: a table, one row per change, including the changes that
   have no rollback. Say so where that is the case.
8. **`## Common failure modes`**: concrete failures, the kind that show up weeks
   later. This is usually the most valuable section in the file.
9. **`## Control mapping`**: a table mapping sections to CIS, NIST SP 800-53
   Rev. 5, ISO/IEC 27001:2022 Annex A and NIS2 Art. 21(2) families. **Do not
   cite benchmark section numbers**: they move between versions, and a wrong
   citation in a compliance table is worse than no citation. Say that in the
   section, as the existing guides do.
10. **`## References`**: primary sources — vendor documentation, man pages,
    release notes. Not blog posts.

`guides/linux-hardening.md` is the reference implementation of this structure.

Two rules about the prose:

- **Explain the trap, not the setting.** Anyone can read a man page. What they
  cannot get from the man page is that the drop-in filename decides whether the
  file has any effect, or that `rp_filter = 1` breaks an asymmetrically routed
  host.
- **Record what you actually hit.** If a setting cost you an afternoon, that
  afternoon is the most useful thing you can write down.

## The baseline contract

- **A real file, complete.** No `...`, no `<snip>`, no partial YAML. Someone
  will copy it.
- **Heavily commented**, in the same voice as the guides: why, and what breaks.
- **Pin what you depend on.** Container images by digest with the tag in a
  comment, provider and collection versions exactly, action versions by commit
  SHA. A tag is a mutable pointer; a digest is not.
- **Placeholders must be obviously fake and documented as such** — example ARNs,
  `ORG_ID`, `111122223333`. Any key material in a baseline is a placeholder that
  must be regenerated, and the file must say so in the same breath.

## The test contract

This is the part that makes the repository worth something. Each `tests/*.sh`:

- Starts with `set -euo pipefail` and a header comment listing **what it proves**
  and **what it explicitly does not**.
- Runs the **real tool** — `sshd -t`, `nft -c -f`, `terraform validate`,
  `promtool`, the actual kubelet binary — from a digest-pinned image. Never a
  regular expression standing in for a parser.
- Pairs **every** assertion with a negative control: the same check run first
  against a deliberately broken copy, which must fail with the expected
  diagnostic. Then the good copy is restored.
- Never uses `|| true`, `continue-on-error`, or an `exit-code: 0` scanner. A
  check that cannot fail is not a check.
- Never lets an empty string satisfy an assertion. If a helper can return
  nothing, make it return an explicit token (`CONNECTED` / `BLOCKED_TIMEOUT` /
  `REFUSED`) and assert on that.
- Cleans up in a `trap ... EXIT`, including fixing ownership of root-owned files
  a container left in a bind mount.
- **Documents a gap rather than faking it.** Where something genuinely cannot be
  validated without a cluster, two hosts or cloud credentials, drop the check
  and say so in the header and in the guide. A skipped check that reports
  success is the only unacceptable outcome.

### Why the negative control is not optional

Three real examples from this repository, each caught only because a control
existed:

- `tests/linux.sh` validated **nothing** for a while: the `Include` directive
  used the host path, so inside the container the glob matched no files and
  `sshd -t` happily validated an empty configuration. The control — "a 9.9-only
  crypto file must be **rejected** on OpenSSH 9.2" — is what exposed it.
- `jq -e empty` exits 4 on valid JSON, so a "JSON is valid" check failed on
  correct files and would have been "fixed" by removing the check.
- A lock-file control that corrupted **one** hash in `.terraform.lock.hcl`
  passed: the file records several hashes and the install only has to match one.
  Every hash has to be corrupted before `terraform init` rejects it.

In each case the check looked right and proved nothing.

## Pull requests

- One domain per pull request. A change to a baseline comes with the test change
  and the guide change in the same PR.
- Run `make lint` and the affected `tests/*.sh` before pushing. Say in the PR
  description what you ran and what the output was.
- Commit messages: imperative subject, and a body that records **what you
  learned**, not what you typed. `docs: rewrite the Docker guide` tells a future
  reader nothing; the reason `--user 0` overrides a Dockerfile `USER` is worth a
  paragraph.
- If you verified an action or image version, say how (`gh api
  repos/<owner>/<repo>/git/ref/tags/<tag>`), so the next person does not have to
  trust it.
- New guide? Add it to the table in `README.md` in the same PR.

## Reporting something that is wrong

Use the **incorrect guidance** issue template. The most useful report names the
exact file and line, the version you are running, and what actually happened —
"this is out of date" is hard to act on; "`PerSourcePenalties` does not exist
before OpenSSH 9.8 and sshd refuses to start" is one commit.

Security issues in the baselines themselves: see [SECURITY.md](SECURITY.md).

## License

Contributions are accepted under the [MIT licence](LICENSE), the same terms as
the rest of the repository.

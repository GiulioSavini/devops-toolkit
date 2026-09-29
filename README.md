# DevOps & DevSecOps Toolkit

[![CI](https://github.com/GiulioSavini/devops-toolkit/actions/workflows/docs.yml/badge.svg)](https://github.com/GiulioSavini/devops-toolkit/actions/workflows/docs.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Hardening and automation baselines for Linux, containers, Kubernetes, the three
major clouds and the pipelines that deploy to them — **as files that are
executed by a test, not snippets in a document**.

Every guide points at real configuration under `baselines/`. Every baseline is
validated by a script under `tests/` that runs the actual tool — `sshd -t`,
`nft -c -f`, `terraform test`, `promtool test rules`, `wazuh-logtest`, a real
kubelet binary, a real kind cluster — from a digest-pinned container image. Every
assertion is paired with a **negative control**: the same check run first against
a deliberately broken copy, which must fail. A check that cannot fail is not a
check, and this repository has the commit history of five of its own checks that
proved nothing until a control was added.

```bash
make lint   # markdownlint over every guide
make test   # every baseline suite except the Kubernetes end-to-end one
make e2e    # boots a throwaway kind cluster and asserts behaviour on it
make all    # all three
```

The only host requirements are `bash`, `docker` and `curl`.

## Guides

| Guide | Baselines | Validated by |
|---|---|---|
| [Linux server hardening](guides/linux-hardening.md) | [`baselines/linux/`](baselines/linux/) | [`tests/linux.sh`](tests/linux.sh) — `sshd -t` on three OpenSSH generations, drop-in load order, `nft -c -f`, auditd rule parsing, SSH certificates end to end |
| [SSH key management](guides/ssh-key-management.md) | [`baselines/linux/ssh/`](baselines/linux/ssh/) | [`tests/linux.sh`](tests/linux.sh) — certificate issue, principals, and a revoked certificate actually refused |
| [Docker & container security](guides/docker-security.md) | [`baselines/docker/`](baselines/docker/) | [`tests/docker.sh`](tests/docker.sh) — the image is built and run, then asked from inside what the kernel gave it |
| [Kubernetes hardening](guides/kubernetes-hardening.md) | [`baselines/kubernetes/`](baselines/kubernetes/) | [`tests/kubernetes.sh`](tests/kubernetes.sh) (schema + the real kubelet) and [`tests/kubernetes-e2e.sh`](tests/kubernetes-e2e.sh) (kind cluster, 28 assertions) |
| [Secrets management](guides/secrets-management.md) | [`baselines/secrets/`](baselines/secrets/) | [`tests/secrets.sh`](tests/secrets.sh) — SOPS round trip, a live Vault denying a sibling path, ESO manifests against real CRD schemas |
| [CI/CD security](guides/cicd-security.md) | [`baselines/cicd/`](baselines/cicd/) | [`tests/cicd.sh`](tests/cicd.sh) — actionlint with shellcheck, GitLab's own CI schema, pre-commit config |
| [Terraform & IaC security](guides/terraform-security.md) | [`baselines/terraform/`](baselines/terraform/) | [`tests/terraform.sh`](tests/terraform.sh) — `validate`, an enforced lock file, `tofu` vs `terraform` on state encryption, conftest with its own unit tests, tflint |
| [Ansible for production](guides/ansible-best-practices.md) | [`baselines/ansible/`](baselines/ansible/) | [`tests/ansible.sh`](tests/ansible.sh) — pinned collections installed, ansible-lint production profile, the sudo/wheel branch executed on both fact sets |
| [Network security & zero trust](guides/network-zero-trust.md) | [`baselines/network/`](baselines/network/) | [`tests/network.sh`](tests/network.sh) — the ruleset is loaded in a netns and read back, WireGuard config loaded onto a real interface |
| [Observability & logging](guides/observability-logging.md) | [`baselines/observability/`](baselines/observability/) | [`tests/observability.sh`](tests/observability.sh) — `promtool test rules` fires every SLO alert, and a live Alertmanager proves inhibition |
| [Wazuh host intrusion detection](guides/wazuh-hids.md) | [`baselines/wazuh/`](baselines/wazuh/) | [`tests/wazuh.sh`](tests/wazuh.sh) — every custom rule fired through the real `wazuh-logtest`, and not fired on the benign line |
| [Backup & disaster recovery](guides/backup-disaster-recovery.md) | [`baselines/backup/`](baselines/backup/) | [`tests/backup.sh`](tests/backup.sh) — a real repository backed up, pruned, restored and compared; the integrity check proven able to fail |
| [Cloud IAM](guides/cloud-iam.md) | [`baselines/iam/`](baselines/iam/) | [`tests/iam.sh`](tests/iam.sh) — AWS policy grammar, `terraform test` on the OIDC trust policies, SCP size and global-service exemptions |
| [Incident response](guides/incident-response.md) | [`baselines/incident-response/`](baselines/incident-response/) | [`tests/incident-response.sh`](tests/incident-response.sh) — the collector run on a live host, and its manifest proven to detect tampering |

A repo-wide mapping to CIS, NIST SP 800-53, ISO/IEC 27001:2022 and NIS2 is in
[CONTROLS.md](CONTROLS.md).

## What each guide contains

The same structure, in the same order, because someone reading one of these is
usually in the middle of something:

- **Threat model** — and, more importantly, what the baseline is *not* for.
- **Per-setting rationale**: what it does, why the default is wrong, what breaks
  when you change it.
- **Rollout**, staged, riskiest last, with an armed auto-revert where a change can
  cut off your own access.
- **Verification** — commands that read the *effective* state (`sshd -T`, not
  `cat sshd_config`), with the expected output.
- **Rollback**, as a table, including the changes that have no rollback.
- **Common failure modes** — the ones that show up weeks later.
- **Control mapping** and primary-source references.

## Scope and caveats

- Targets **Ubuntu/Debian and RHEL/Rocky/Alma**; other distributions need
  adjustment. Versions that behave differently are named in each guide's
  metadata table.
- **Nothing here is a compliance artifact.** The control mapping says which
  families a section touches. Benchmark section numbers are deliberately not
  cited, because they move between versions and a wrong citation in an audit
  table is worse than none.
- **Several baselines can lock you out or cost money** if applied without
  reading: default-deny firewalls, `pam_faillock`, a region-restricting SCP, S3
  Object Lock in COMPLIANCE mode, Wazuh active response. Each guide's metadata
  table states its lockout risk, and the rollout section is written to be
  followed rather than skimmed.
- **Placeholders are obviously fake and are documented as such** — example ARNs,
  `ORG_ID`, `111122223333`. Any key material in a baseline is a placeholder that
  must be regenerated; the file says so next to it.
- **Where something cannot be proven in a container, the test says so** instead
  of reporting success. Those gaps are listed in each test's header and in the
  matching guide.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) has the guide structure, the baseline
contract and the test contract — including why every assertion needs a negative
control, with three examples from this repository where a check looked right and
proved nothing.

Corrections are especially welcome where a setting is wrong, has aged badly, or
is right on one distribution and quietly wrong on another. The
[incorrect guidance](.github/ISSUE_TEMPLATE/incorrect-guidance.yml) issue
template asks for the file, the version and what actually happened.

Security issues in the baselines themselves: [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).

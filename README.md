# DevOps & DevSecOps Toolkit

[![Docs](https://github.com/GiulioSavini/devops-toolkit/actions/workflows/docs.yml/badge.svg)](https://github.com/GiulioSavini/devops-toolkit/actions/workflows/docs.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Operational reference notes on hardening, automation and security for Linux,
containers and the three major clouds — written down as I needed them on real
infrastructure, kept short enough to actually be read during an incident.

These are **checklists and working configuration snippets**, not tutorials. Each
guide assumes you already know the tool and want the settings that matter, the
defaults that are wrong, and the failure mode that bites in production.

## Guides

| Guide | Domain | Covers |
|---|---|---|
| [Linux server hardening](guides/linux-hardening.md) | OS | sysctl baseline, sshd config, UFW/firewalld, unattended upgrades |
| [SSH key management](guides/ssh-key-management.md) | Access | Ed25519 generation, client config, rotation policy |
| [Docker & container security](guides/docker-security.md) | Containers | daemon.json, non-root images, dropped capabilities, read-only rootfs |
| [Kubernetes hardening](guides/kubernetes-hardening.md) | Orchestration | Pod Security Standards, default-deny NetworkPolicy, control plane checklist |
| [Secrets management](guides/secrets-management.md) | Data | storage hierarchy, SOPS + age, rotation lifecycle |
| [CI/CD security](guides/cicd-security.md) | Pipelines | gitleaks, Semgrep, Trivy, PR quality gates |
| [Terraform & IaC security](guides/terraform-security.md) | IaC | remote state encryption, tflint/trivy, least-privilege providers |
| [Ansible best practices](guides/ansible-best-practices.md) | Config mgmt | idempotency, role layout, ansible-lint |
| [Network security & zero trust](guides/network-zero-trust.md) | Networking | WireGuard overlay, micro-segmentation rollout, verifying a rule works |
| [Observability & logging](guides/observability-logging.md) | Observability | structured logs, storage tiering, symptom-based alerting |
| [Wazuh host intrusion detection](guides/wazuh-hids.md) | SIEM/XDR | FIM with whodata, active response, agent verification |
| [Backup & disaster recovery](guides/backup-disaster-recovery.md) | Continuity | 3-2-1-1-0, S3 Object Lock, restic, verified restores |
| [Cloud IAM](guides/cloud-iam.md) | Governance | OIDC federation, SCPs vs IAM, credential auditing |
| [Incident response](guides/incident-response.md) | SRE | NIST triage lifecycle, blameless post-mortem template |

## Scope and caveats

- Snippets are written for **Ubuntu/Debian and RHEL/Rocky**; other distros will
  need adjustment.
- Nothing here is a compliance artifact. The checklists overlap heavily with CIS
  Benchmarks and ISO 27001 controls, but mapping them to a specific audit is
  work these notes do not do for you.
- Read a config before applying it. Several snippets (default-deny firewalls,
  Wazuh active response, S3 Object Lock in compliance mode) will lock you out or
  cost money if applied without thought. Where that risk exists the guide says so.

## Contributing

Corrections are welcome — particularly if a snippet is wrong or has aged badly.
Open an issue or a PR.

## License

MIT — see [LICENSE](LICENSE).

# Control mapping

Where each domain in this repository sits against the frameworks people are
audited on, and — the column most control matrices leave out — **what actually
proves it**.

Read it as a map, not as evidence. Two deliberate omissions:

- **No benchmark section numbers.** CIS renumbers between versions, and a wrong
  "CIS 5.2.4" in an audit table is worse than an empty cell. Each row names the
  benchmark; verify the numbering against the exact version you are audited on.
- **No claim of completeness.** A row means the baseline touches that control
  family, not that it satisfies it for your organisation. Scope, ownership and
  evidence retention are yours.

NIS2 references are to Article 21(2) unless stated; the incident-reporting
obligations are Article 23.

## By domain

| Domain | Guide | CIS | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 | NIS2 | Proven by |
|---|---|---|---|---|---|---|
| OS hardening | [linux-hardening](guides/linux-hardening.md) | CIS Distribution Independent Linux, Ubuntu, RHEL 9 | AC-17, AU-2, CM-6, CM-7, IA-5, SC-7, SI-2 | A.8.5, A.8.8, A.8.9, A.8.15, A.8.20 | (e), (h), (i) | `sshd -t` on OpenSSH 8.7/9.2/9.9, drop-in load order, `nft -c -f`, auditd netlink parse |
| SSH access | [ssh-key-management](guides/ssh-key-management.md) | same | AC-2, IA-2, IA-5, SC-13 | A.5.15, A.5.17, A.8.5 | (i) | certificate issued, principals enforced, a revoked certificate actually refused |
| Container images and runtime | [docker-security](guides/docker-security.md) | CIS Docker Benchmark | AC-6, CM-2, CM-6, CM-7, SC-2, SC-5 | A.8.2, A.8.9, A.8.19, A.8.30 | (d), (e), (i) | image built and run, then asked from inside for uid, rootfs, `CapBnd`, `NoNewPrivs` |
| Orchestration | [kubernetes-hardening](guides/kubernetes-hardening.md) | CIS Kubernetes Benchmark | AC-3, AC-6, AU-2, SC-7, SC-28 | A.8.2, A.8.15, A.8.20, A.8.24 | (b), (e), (h), (i) | kind cluster: PSA rejection, containerd's own view of the pod, NetworkPolicy timeouts, etcd read raw |
| Secrets | [secrets-management](guides/secrets-management.md) | — | IA-5, SC-12, SC-28, AC-3 | A.5.17, A.5.33, A.8.24 | (h), (i) | SOPS round trip, a live Vault denying a sibling path, gitleaks on a dirty and a clean fixture |
| Pipelines | [cicd-security](guides/cicd-security.md) | CIS Supply Chain, OWASP CICD-SEC | AC-2, AC-6, CM-2, SA-10, SI-7, SR-4 | A.5.21, A.8.28, A.8.30 | (d), (e), (i) | actionlint with shellcheck, GitLab's CI schema, a broken permissions block rejected |
| Infrastructure as code | [terraform-security](guides/terraform-security.md) | CIS cloud benchmarks | CM-2, CM-3, CP-9, SA-10, SC-12, SC-28 | A.5.33, A.8.9, A.8.13, A.8.24 | (c), (d), (h) | `validate`, an enforced lock file, rego with its own unit tests, `tofu` vs `terraform` on encryption |
| Configuration management | [ansible-best-practices](guides/ansible-best-practices.md) | CIS Linux Benchmarks | AC-6, CM-2, CM-3, CM-6, IA-5 | A.8.2, A.8.9, A.8.32 | (d), (e), (i) | pinned collections installed, ansible-lint production profile, the sudo/wheel branch executed |
| Network segmentation | [network-zero-trust](guides/network-zero-trust.md) | CIS Controls v8 §12, §13 | AC-4, AC-17, SC-7, SC-8 | A.8.20, A.8.21, A.8.22 | (e), (h) | ruleset loaded in a netns and read back, WireGuard config on a real interface |
| Monitoring and alerting | [observability-logging](guides/observability-logging.md) | CIS Controls v8 §8 | AU-2, AU-4, AU-6, AU-11, SI-4 | A.8.15, A.8.16 | (b) | every SLO alert fired with `promtool test rules`, inhibition proven on a live Alertmanager |
| Host intrusion detection | [wazuh-hids](guides/wazuh-hids.md) | CIS Controls v8 §3, §8 | AU-3, AU-12, CM-3, SI-3, SI-4, SI-7 | A.8.7, A.8.9, A.8.15, A.8.16 | (b), (e) | every custom rule fired through the real `wazuh-logtest`, and not fired on the benign line |
| Continuity | [backup-disaster-recovery](guides/backup-disaster-recovery.md) | CIS Controls v8 §11 | CP-2, CP-4, CP-6, CP-9, CP-10, SI-7 | A.5.29, A.5.30, A.8.13, A.8.14 | (c) | real backup, prune, restore and byte comparison; corrupted pack detected; point-in-time restore |
| Cloud identity | [cloud-iam](guides/cloud-iam.md) | CIS AWS/Azure/GCP Foundations | AC-2, AC-3, AC-6, AU-9, IA-2, IA-5 | A.5.15, A.5.16, A.5.18, A.8.2 | (i) | AWS policy grammar, `terraform test` on the OIDC trust policies, SCP size and global-service exemptions |
| Incident handling | [incident-response](guides/incident-response.md) | NIST SP 800-61, ISO/IEC 27037 | AU-9, IR-2, IR-4, IR-6, IR-7, IR-8 | A.5.24, A.5.26, A.5.27, A.5.28 | Art. 23 | collector run on a live host, manifest proven to detect tampering, timeout survived |

## By NIS2 Article 21(2)

The Article's own lettering, against the domains that carry it.

| NIS2 21(2) | Requirement, in short | Where |
|---|---|---|
| (a) | Risk analysis and information security policy | Threat model section of every guide; scope statements in [README](README.md) |
| (b) | Incident handling | [incident-response](guides/incident-response.md), [wazuh-hids](guides/wazuh-hids.md), [observability-logging](guides/observability-logging.md), plus the audit trails in [linux-hardening](guides/linux-hardening.md) and [kubernetes-hardening](guides/kubernetes-hardening.md) |
| (c) | Business continuity, backup management, crisis management | [backup-disaster-recovery](guides/backup-disaster-recovery.md), and the restore drill in particular |
| (d) | Supply chain security | Digest and SHA pinning in [docker-security](guides/docker-security.md), [cicd-security](guides/cicd-security.md), [terraform-security](guides/terraform-security.md), [ansible-best-practices](guides/ansible-best-practices.md); SBOM and signing in [cicd-security](guides/cicd-security.md) |
| (e) | Security in acquisition, development and maintenance, including vulnerability handling | Automatic security updates in [linux-hardening](guides/linux-hardening.md), scanning gates in [cicd-security](guides/cicd-security.md), vulnerability detection in [wazuh-hids](guides/wazuh-hids.md), policy as code in [terraform-security](guides/terraform-security.md) |
| (f) | Assessing the effectiveness of the measures | `tests/*.sh` — this repository's answer to (f) is that every baseline has a test that can fail, and SCA in [wazuh-hids](guides/wazuh-hids.md) for ongoing drift |
| (g) | Cyber hygiene and training | Out of scope here, except for the checklists and templates in [incident-response](guides/incident-response.md) |
| (h) | Cryptography and encryption | Crypto selection in [linux-hardening](guides/linux-hardening.md) and [ssh-key-management](guides/ssh-key-management.md), state and plan encryption in [terraform-security](guides/terraform-security.md), encryption at rest in [kubernetes-hardening](guides/kubernetes-hardening.md), client-side encryption in [backup-disaster-recovery](guides/backup-disaster-recovery.md), transport in [network-zero-trust](guides/network-zero-trust.md) |
| (i) | Human resources security, access control, asset management | [cloud-iam](guides/cloud-iam.md), [ssh-key-management](guides/ssh-key-management.md), the RBAC section of [kubernetes-hardening](guides/kubernetes-hardening.md), least privilege in [secrets-management](guides/secrets-management.md) |
| (j) | Multi-factor authentication and secured communications | FIDO2 and certificates in [ssh-key-management](guides/ssh-key-management.md); federated short-lived credentials instead of static keys in [cloud-iam](guides/cloud-iam.md) |
| Art. 23 | Reporting: 24 h early warning, 72 h notification, 1 month final report | [incident-response](guides/incident-response.md), with the clocks and the templates |

## What is deliberately not covered

Named here so an assessor does not have to infer it from silence:

- **Governance, risk registers, supplier contracts, training programmes and
  business-continuity planning above the technical layer.** These are process
  controls; nothing here produces them.
- **Physical security** and anything about the datacentre.
- **Multi-tenant isolation on a shared kernel.** Stated in the Docker and
  Kubernetes threat models: PSA and seccomp raise the cost of an escape, they do
  not create a boundary. That needs a VM boundary or separate clusters.
- **Detection content beyond the host.** The Wazuh rules here are host-level; a
  SIEM's correlation content is not in scope.
- **Data classification and retention schedules**, beyond saying where a setting
  makes a retention decision (audit logs, alert storage, Object Lock, plan
  artifacts).
- **Anything that requires a running production estate to prove**: cross-host
  segmentation, live WireGuard handshakes, Object Lock against the real S3 API,
  FIM events from a real agent, `memory_limiter` under real pressure. Each of
  these is listed as a gap in the relevant test header and guide rather than
  approximated.

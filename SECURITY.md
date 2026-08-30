# Security Policy

## Scope

This repository contains documentation and configuration snippets only. There is
no deployed service and no released artifact.

The security-relevant risk here is **incorrect advice**: a snippet that weakens a
system, disables a protection it claims to enable, or locks an operator out.

## Reporting

If a guide in this repository recommends something insecure or wrong, please
report it:

- Open a [GitHub issue](https://github.com/GiulioSavini/devops-toolkit/issues)
  for anything already public (a wrong sysctl value, an outdated cipher list, a
  deprecated flag).
- For anything you would rather not post publicly, email
  **giuliosavini@proton.me**.

Please include the guide, the specific snippet, and why it is wrong. A pointer to
upstream documentation or a CVE is the fastest path to a fix.

## Response

I aim to acknowledge reports within 7 days. Corrections to a guide are usually
merged the same week; there is no release process to wait for.

## What this policy does not cover

Vulnerabilities in the third-party tools discussed here (Docker, Kubernetes,
Wazuh, Terraform, restic, and so on) should go to those projects' own security
contacts, not here.

# Terraform & Infrastructure-as-Code Security

Standard practices for writing secure, modular, and compliant Terraform / OpenTofu code.

---

## 1. Remote State Security

- Always encrypt remote backend buckets (S3 with SSE-KMS, GCS Customer-Managed Keys, Azure Storage CMK).
- Enable State Locking via DynamoDB / native table locking to prevent race conditions.
- Prevent state file leakage in logs: mark sensitive variables with `sensitive = true`.

---

## 2. Static Security Scanning

Integrate `tflint` and `tfsec`/`trivy` in pre-commit and CI:

```bash
# Linting
tflint --init && tflint

# Security vulnerability analysis
trivy config .
```

---

## 3. Least Privilege Cloud Providers

Never use root/owner accounts for Terraform CI/CD. Use OIDC (OpenID Connect) workload identity federation without static long-lived credentials.

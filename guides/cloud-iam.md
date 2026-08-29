# Cloud Identity & Access Management (IAM Least Privilege)

Patterns for secure access control in AWS, Azure, and Google Cloud Platform.

---

## 1. IAM Principles

- Never attach policies directly to users; use Groups and Roles.
- Implement Permission Boundaries and Service Control Policies (SCPs).
- Enforce MFA on all human access and disable access keys in favor of IAM Identity Center (SSO).
- Audit unused permissions and credentials automatically (AWS Access Advisor, GCP IAM Recommender).

---

## 2. Federated Access Instead of Long-Lived Keys

Static access keys are the single most common source of cloud compromise. Every
major CI platform can assume a role through OIDC instead:

```hcl
# AWS: trust GitHub Actions for one repo, one branch
data "aws_iam_policy_document" "github_oidc" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      # Scope to the exact repo AND ref. A wildcard here lets any repo
      # in the org assume this role.
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:my-org/my-repo:ref:refs/heads/main"]
    }
  }
}
```

The `sub` condition is the whole security boundary. `repo:my-org/*` is a common
and serious misconfiguration.

---

## 3. Provider-Specific Guardrails

| | AWS | Azure | GCP |
|---|---|---|---|
| Org-wide deny | Service Control Policies | Azure Policy (deny effect) | Organization Policy Constraints |
| Per-identity ceiling | Permission Boundaries | — (use scope + custom roles) | — (use IAM Conditions) |
| Unused-permission audit | IAM Access Analyzer, Access Advisor | Entra ID Access Reviews | IAM Recommender |
| Short-lived credentials | IAM Identity Center / `sts:AssumeRole` | Managed Identities | Workload Identity Federation |

An SCP or Organization Policy is the only control a compromised account
administrator cannot remove. Everything expressed only in per-account IAM is
revocable by whoever holds that account.

---

## 4. Auditing

```bash
# AWS: credentials not used in 90 days
aws iam generate-credential-report >/dev/null
aws iam get-credential-report --query Content --output text \
  | base64 -d | column -t -s,

# GCP: who can act as which service account
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --filter="bindings.role:roles/iam.serviceAccountUser" \
  --format="table(bindings.role, bindings.members)"
```

Run these on a schedule and open a ticket from the output. An audit whose
results nobody is obliged to act on changes nothing.

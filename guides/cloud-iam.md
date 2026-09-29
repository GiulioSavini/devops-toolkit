# Cloud IAM

A baseline for identity in AWS, Azure and GCP: no long-lived keys, workload
identity federated from the CI platform, a permissions ceiling that delegated
admins cannot raise, organisation-level guardrails that protect the audit trail,
a break-glass path that is watched, and a review loop that finds the permissions
nobody uses. Everything ships as a file under
[`baselines/iam/`](../baselines/iam/) and is validated by
[`tests/iam.sh`](../tests/iam.sh), which runs the policies through a real AWS
policy grammar checker, the Azure Policy schema, Google's own constraint
reference, and `terraform test` with mocked providers.

| | |
|---|---|
| Applies to | AWS Organizations (SCPs, permissions boundaries, ABAC), Microsoft Entra ID + Azure Policy, GCP organisation policies + Workload Identity Federation. Terraform modules validated on 1.16.4 |
| Baseline files | [`baselines/iam/`](../baselines/iam/) |
| Validated by | [`tests/iam.sh`](../tests/iam.sh) |
| Lockout risk | **High at organisation level.** An SCP applies to every principal in the OU **including the account root** and including you. A region allowlist that forgets the global services locks the account out of its own control plane. Always attach to a test OU first |
| Last reviewed | 2026-09 |

## Threat model

What this baseline is for:

- **A leaked static credential.** An access key in a repository, a CI variable,
  a laptop backup or a Slack message. It has no expiry, works from anywhere, and
  nothing about its use looks unusual.
- **Privilege escalation inside the cloud account.** A principal that can create
  a role, attach a policy, set a permissions boundary, or pass a role to a
  service reaches administrator without ever holding an admin policy.
- **An attacker disabling the evidence.** Stopping CloudTrail, deleting a
  GuardDuty detector, or stopping the Config recorder is step one of a
  well-run intrusion, and it is cheap unless something denies it.
- **An account leaving the organisation**, taking itself out of every guardrail
  and every centralised log at once.
- **Permission sprawl.** Roles granted for a migration three years ago, access
  keys nobody rotated, actions inside a policy that have never once been called.
- **Break-glass access used quietly.** An emergency path that nobody is
  notified about is an attacker's preferred path.

What it is not for:

- **Replacing an identity provider.** These files assume humans arrive through
  SSO with MFA and conditional access; that is the prerequisite, not the
  content.
- **Data-layer authorisation.** IAM decides who can call the API. What a row in
  a database is allowed to show is the application's problem.
- **Preventing a legitimate administrator from doing damage.** Guardrails raise
  the cost and produce the record; they do not remove the capability.
- **Secret storage.** Short-lived credentials remove most of the need for
  stored secrets; the rest is [secrets management](secrets-management.md).
- **Compliance evidence.** The control mapping at the end says which families a
  section touches; it is not an audit artifact.

## No long-lived keys

This is the highest-value change in the whole guide, and it is one decision:
**every workload and every pipeline authenticates with a short-lived credential
obtained from a federated identity, and there are no access keys to leak.**

Three Terraform modules implement it, one per cloud, each with `terraform test`
assertions that run with mocked providers — no cloud account needed:

| Module | What it creates | Assertions in `tests/` |
|---|---|---|
| [`aws-github-oidc`](../baselines/iam/terraform/aws-github-oidc/) | The `token.actions.githubusercontent.com` OIDC provider and a role whose trust policy names exact subjects | 6 cases: exact subject and audience, the immutable subject form, and four forms that **must be rejected** |
| [`azure-github-oidc`](../baselines/iam/terraform/azure-github-oidc/) | A user-assigned managed identity with federated credentials per subject, plus role assignments | issuer/audience/subject pinned; wildcard subject rejected |
| [`gcp-github-wif`](../baselines/iam/terraform/gcp-github-wif/) | A workload identity pool and provider with an attribute condition, plus per-subject service account bindings | provider restricted to the owner **id**; binding is per subject; two rejection cases |

### The trust policy is the security boundary

```hcl
Condition = {
  StringEquals = {
    "${local.issuer_host}:aud" = "sts.amazonaws.com"
    # StringEquals, never StringLike: exact subjects only.
    "${local.issuer_host}:sub" = var.allowed_subjects
  }
}
```

GitHub uses **one issuer for every customer on the platform**. The `sub` claim
is the only thing that distinguishes your repository from anyone else's, so a
trust policy that is loose about `sub` is a role any GitHub user can assume.

The module refuses the loose forms rather than documenting them, with variable
validations that `terraform test` exercises:

- **No wildcards.** A `*` in the `sub` condition lets other repositories,
  branches or pull requests assume the role. `StringLike` with
  `repo:org/app:*` includes `pull_request`, which means a fork's pull request.
- **No bare `repo:org/app`**, and no bare `repository_owner`. Those match every
  ref in the repository, or every repository in the organisation.
- **The subject must carry a claim prefix** (`repo:`, `job_workflow_ref:`, …),
  because a subject that does not is not a subject GitHub ever sends.

Use the immutable forms where you can: `job_workflow_ref:` pins the exact
workflow file and ref, which is what you want for a reusable deployment
workflow, and `repository_id`/`repository_owner_id` survive a repository being
renamed — a **name** can be released and re-registered by someone else, an
**id** cannot. That is why the GCP module's attribute condition uses
`repository_owner_id` and rejects a name:

```hcl
attribute_condition = "assertion.repository_owner_id == '${var.github_owner_id}'"
```

Without that condition, any GitHub repository in the world can exchange a token
against the pool. And bind **individual subjects** —
`principal://…/subject/<sub>` — not the whole pool with
`principalSet://…/*`, which accepts every repository of the owner.

On the GitHub side, [`oidc-sub-template-repo.json`](../baselines/iam/github/oidc-sub-template-repo.json)
customises which claims the `sub` is built from:

```json
{ "use_default": false, "include_claim_keys": ["repo", "context", "job_workflow_ref"] }
```

`tests/iam.sh` checks these against the claim keys GitHub actually documents —
an invented key is silently ignored by GitHub, which produces a `sub` that does
not match your trust policy and an error that says nothing about why.

Two more settings worth stating: `max_session_duration` should be close to the
longest job (the default here is 3600s, and the module validates the 900–43200
range AWS allows), and on Azure the audience is
`api://AzureADTokenExchange`, which is what `azure/login` requests by default.

### The rest of the long-lived credentials

GCP organisation policies turn off the mechanism entirely:

- [`iam.managed.disableServiceAccountKeyCreation`](../baselines/iam/gcp/org-policies/iam.managed.disableServiceAccountKeyCreation.yaml)
- [`iam.managed.disableServiceAccountKeyUpload`](../baselines/iam/gcp/org-policies/iam.managed.disableServiceAccountKeyUpload.yaml)

A service account JSON key is the single most-leaked credential type in GCP;
with these two enforced, one cannot be created at all.

Every GCP policy file in this baseline carries **both** a `spec` and a
`dryRunSpec`, and the header records the two-step rollout:

```bash
gcloud org-policies set-policy <file> --update-mask=dryRunSpec
# review the violations that appear in the audit log, then:
gcloud org-policies set-policy <file> --update-mask=spec
```

Dry run first is not optional at organisation scope. `tests/iam.sh` checks each
constraint name against Google's published constraint reference, because a
typo in a constraint name is a policy that applies to nothing and reports no
error.

For AWS IAM users that already exist,
[`bin/aws-stale-credentials.sh`](../baselines/iam/bin/aws-stale-credentials.sh)
reads the IAM credential report and lists console passwords and access keys that
are **active but unused** past a threshold:

```bash
aws-stale-credentials.sh -d 90              # from the API
aws-stale-credentials.sh -d 90 -f report.csv # offline review
```

Exit status 1 means findings, 2 means error, so it works as a scheduled check.
`tests/iam.sh` runs it against a synthetic credential report with known stale
rows, a clean report, and a malformed one — three cases, because a script that
reports nothing on a clean report and nothing on a dirty one is a script that
reports nothing.

## Permissions boundaries and delegated administration

The problem: teams need to create their own IAM roles, and `iam:CreateRole` is
privilege escalation — you create a role with `AdministratorAccess` and assume
it.

The answer is two policies that only work together.

[`workload-permissions-boundary.json`](../baselines/iam/aws/iam/workload-permissions-boundary.json)
is the **ceiling**: an allow list of the services workloads legitimately use,
plus an explicit deny on `iam:*`, `sts:AssumeRole`, `organizations:*` and
`account:*`.

A boundary is not a grant. It caps what an identity's own policies can
achieve, so `Resource: "*"` inside it is correct and expected — it is a
maximum, not a permission. `tests/iam.sh` mutes exactly that one parliament
finding for exactly that one file, and nowhere else.

[`delegated-role-admin.json`](../baselines/iam/aws/iam/delegated-role-admin.json)
is the grant, and every statement in it exists to close a specific escape:

| Statement | What it stops |
|---|---|
| `CreateAndManageRolesOnlyWithBoundary`, conditioned on `iam:PermissionsBoundary` matching the boundary ARN | Creating a role **without** the ceiling. Without this condition, the delegation is administrator access |
| Resources scoped to `role/app/*` | Editing roles outside the team's own path — including the security and break-glass roles |
| `ProtectTheBoundaryItself` denying `iam:CreatePolicyVersion` and friends on the boundary policy | Raising the ceiling instead of escaping it, which is the same outcome by a different route |
| `NoBoundaryRemoval` denying `iam:DeleteRolePermissionsBoundary` | Taking the ceiling off after the role was created |

All four are needed. Any three of them is a privilege escalation path.

## ABAC

[`abac-project-ec2.json`](../baselines/iam/aws/iam/abac-project-ec2.json)
grants instance control only where the resource's `project` tag equals the
principal's `project` tag:

```json
"Condition": { "StringEquals": { "aws:ResourceTag/project": "${aws:PrincipalTag/project}" } }
```

ABAC scales where RBAC does not: one policy covers every project, and a new
project needs a tag rather than a new role. It has three traps, and this file
closes all three:

1. **A tag that is an authorisation key must not be editable by the principals
   it authorises.** `NoRetaggingOfAuthorizationKeys` denies `ec2:CreateTags`
   and `ec2:DeleteTags` when the request touches the `project` key —
   `ForAnyValue:StringEquals` on `aws:TagKeys`. Without it, a user retags an
   instance into their own project and the access control is decorative.
2. **A missing principal tag must fail closed.** `Null` on
   `aws:PrincipalTag/project` denies `ec2:*` outright when the principal has no
   project tag. Without it, an untagged principal can behave surprisingly
   depending on the condition operator.
3. **Not every action is resource-tagged.** `ec2:DescribeInstances` does not
   support resource-level permissions at all, so it is granted separately on
   `*` and the file says so. A policy that conditions a `Describe` on a
   resource tag denies it always, and the error looks like a broken policy
   rather than an impossible one.

`tests/iam.sh` puts every AWS policy through parliament, which catches the
adjacent class of bug: a misspelled action, a condition key that does not exist
for that service, a malformed ARN. Those are silent in production — an action
that does not exist simply never matches.

## Organisation guardrails

Service control policies apply to **every principal in the OU, including the
account root**. They do not grant anything; they remove what identity policies
could otherwise allow.

[`deny-leave-organization.json`](../baselines/iam/aws/scp/deny-leave-organization.json)
is one statement and belongs on every OU: an account that leaves takes itself
out of every guardrail, every centralised log and every consolidated bill, in
one API call.

[`protect-security-services.json`](../baselines/iam/aws/scp/protect-security-services.json)
denies tampering with CloudTrail, GuardDuty, Config and Access Analyzer, except
for named security roles via `ArnNotLike` on `aws:PrincipalArn`. Note what is in
the CloudTrail list beyond the obvious: `UpdateTrail` and `PutEventSelectors`,
because narrowing a trail's selectors is how you stop logging **without**
stopping the trail, and the console still shows it as enabled.

[`protect-break-glass.json`](../baselines/iam/aws/scp/protect-break-glass.json)
does three things at once: only the identity-admin role may modify the
break-glass role; only security roles may touch the EventBridge rules that
**detect** its use; and the break-glass role itself may not create access keys,
users or console passwords. That last statement is the one people leave out: an
emergency role that can mint a permanent credential is a temporary
authorisation that becomes permanent the first time it is used.

[`region-allowlist.json`](../baselines/iam/aws/scp/region-allowlist.json) denies
`aws:RequestedRegion` outside the allowed set. **This is the SCP that locks
accounts out**, and the exemption list is the whole file: IAM, STS,
Organizations and KMS key administration are global, and CloudFront, Route 53,
WAF, Shield, Support and everything billing-related only have endpoints in
`us-east-1`. A region deny that forgets them takes away the account's own
control plane.

`tests/iam.sh` asserts this specific failure: the `NotAction` list must still
exempt the global and `us-east-1`-only services, and each SCP must fit AWS's
size limit (10240 characters, minified — the limit people discover after
writing the policy, as it is measured on the minified document).

Azure's equivalent for one very common gap is
[`deny-role-assignments-to-users.json`](../baselines/iam/azure/policy/deny-role-assignments-to-users.json):
RBAC assignments must target groups, service principals or managed identities,
never individual users, because direct assignments bypass group-based access
reviews and are left behind when people change teams. It ships with an `effect`
parameter defaulting to `Deny`, with `Audit` available — start there, move to
`Deny` when the compliance report is clean — and an exemption array for
emergency accounts. `tests/iam.sh` validates it against the published Azure
Policy definition schema.

On GCP, [`iam.managed.allowedPolicyMembers`](../baselines/iam/gcp/org-policies/iam.managed.allowedPolicyMembers.yaml)
is domain-restricted sharing. One detail that costs an afternoon: **your own
organisation's principal set is not allowed implicitly** — it must be listed, or
the policy denies every grant including yours.

## Break-glass access

A break-glass path that is not watched is an attacker's favourite door. Three
EventBridge patterns exist to make its use loud:

| Pattern | Fires on |
|---|---|
| [`root-activity.json`](../baselines/iam/aws/eventbridge/root-activity.json) | Any API call or console sign-in where `userIdentity.type` is `Root`. In a well-run account this should fire **never** |
| [`break-glass-signin.json`](../baselines/iam/aws/eventbridge/break-glass-signin.json) | A console sign-in by a `breakglass-*` user |
| [`break-glass-role-assumption.json`](../baselines/iam/aws/eventbridge/break-glass-role-assumption.json) | `sts:AssumeRole` against the `OrgBreakGlass` role |

`tests/iam.sh` validates that the top-level keys in each pattern are real
EventBridge event fields — a misspelled field makes a rule that matches nothing,
with no error anywhere, which is exactly the failure that only shows up on the
day you needed the alert.

Route these to a channel humans watch, not to an inbox. Pair each one with the
question "was this expected, and who authorised it?", and see
[incident response](incident-response.md) for what happens next.

## Finding the permissions nobody uses

Least privilege is not a design activity, it is a review loop.

[`aws-access-analyzer-unused`](../baselines/iam/terraform/aws-access-analyzer-unused/)
creates an IAM Access Analyzer **unused access** analyzer: it reports unused
roles, unused users, unused access keys and unused actions inside a policy.

Three things to know:

- It is **not** the same thing as external access analysis. An account can run
  one external-access and one unused-access analyzer side by side, and the
  unused-access one must be created explicitly.
- It is charged per IAM role and user analysed per month. The cost is the reason
  people scope it to an OU; scoping it away from production is the reason it
  finds nothing useful.
- **Findings are the input to a review, not an automation target.** Deleting a
  role because a finding says it is unused is how you break the quarterly job
  that runs in three weeks.

Every exclusion (`excluded_account_ids`, `excluded_resource_tags`) is a blind
spot. List them in the ticket that asked for them, with an expiry.

## Rollout

1. **SSO with MFA first.** Everything else assumes humans do not have static
   credentials.
2. **Deploy the OIDC module for one pipeline**, with one exact subject and a
   read-only policy. Confirm a run assumes the role, then widen by adding
   subjects — never by loosening the condition to a wildcard.
3. **Delete the static keys that the pipeline was using**, after the OIDC path
   has worked from a throwaway branch. Not before.
4. **Attach the boundary and the delegated-admin policy together**, in a
   non-production account first. Verify the escape attempts fail: create a role
   without the boundary, try to remove a boundary, try to edit the boundary
   policy.
5. **SCPs: test OU first, always.** Attach to an OU containing one disposable
   account, exercise the account's normal work, then move up. For the region
   allowlist, specifically verify that IAM, STS, CloudFront, Route 53, Support
   and the billing console still work.
6. **GCP and Azure: dry run / `Audit` effect first**, review the violations,
   then enforce.
7. **The detection rules before the break-glass role is needed**, and test them
   by assuming the role on purpose. An alert nobody has ever seen fire is an
   alert that does not work.
8. **Schedule the review loop**: the analyzer findings and
   `aws-stale-credentials.sh` on a calendar, with an owner.

## Verification

```bash
# Who can actually do what, from the account's own view
aws iam get-account-authorization-details > auth.json
jq -r '.RoleDetailList[] | select(.PermissionsBoundary == null) | .Arn' auth.json   # roles with no ceiling

# Which principals are exempt from the SCPs you wrote
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
aws organizations list-targets-for-policy --policy-id <id>

# The OIDC trust policy as it really is — no wildcards, exact audience
aws iam get-role --role-name gha-terraform-plan \
  --query 'Role.AssumeRolePolicyDocument' | jq .

# Static credentials that still exist and are not used
bash baselines/iam/bin/aws-stale-credentials.sh -d 90; echo "rc=$?"
aws iam list-users --query 'Users[].UserName'

# Unused permissions
aws accessanalyzer list-findings-v2 --analyzer-arn <arn> \
  --query 'findings[?status==`ACTIVE`].[resource,findingType]' --output table

# GCP: is the policy enforced or still dry run
gcloud org-policies describe iam.managed.disableServiceAccountKeyCreation \
  --organization=ORG_ID
gcloud iam service-accounts keys list --iam-account=<sa>   # expect only the Google-managed key

# Azure: direct user assignments that should not exist
az role assignment list --all --query "[?principalType=='User'].{p:principalName,r:roleDefinitionName,s:scope}" -o table

# The break-glass detection actually fires: assume the role on purpose, then
aws logs filter-log-events --log-group-name <alert-target> --start-time $(( ($(date +%s) - 900) * 1000 ))
```

## Rollback

| Change | Undo |
|---|---|
| OIDC role | Delete the role. Re-add the static key only if the trust policy itself is broken, with an expiry date attached |
| Permissions boundary | `iam:DeleteRolePermissionsBoundary` from a principal that the delegated-admin policy does not deny. Removing a boundary silently widens every role that had it |
| Delegated-admin policy | Detach it. The boundary alone grants nothing, so the order is safe |
| SCP | Detach from the OU — effective immediately. **If the SCP denied `organizations:*` for your own role, you need the management account's root**; this is the reason for the test OU |
| Region allowlist | Detach, then add the missing global service to `NotAction` and re-attach. Do not widen the region list to work around a missing exemption |
| GCP org policy | Set `spec` back to non-enforced, or delete the policy. Existing keys are not deleted by the policy, so removing it re-enables creation only |
| Azure Policy | Change `effect` to `Audit` or `Disabled`. Existing assignments are untouched |
| Access Analyzer | Delete the analyzer; billing stops, findings are lost |
| A deleted role that was "unused" | Recreate from the Terraform or CloudFormation that made it. If it was created by hand, there is nothing to recreate from — which is the real finding |

## Common failure modes

- **`StringLike` with a wildcard in an OIDC `sub` condition**, so any
  repository, branch or fork pull request can assume the role.
- **A trust policy keyed on a repository or owner *name***, which can be
  released and re-registered by someone else. Use the id.
- **Binding a GCP service account to the whole pool** (`principalSet://…/*`)
  instead of per subject, which accepts every repository of the owner.
- **No attribute condition on the GCP provider**, which accepts every GitHub
  repository in the world.
- **A region-deny SCP without the global-service exemptions**: no IAM, no STS,
  no billing console, and the fix needs an API call the SCP now denies.
- **An SCP attached at the root** on the first attempt, so the blast radius is
  every account at once.
- **A permissions boundary without the delegated-admin conditions**, so a role
  can be created without the boundary and the ceiling is optional.
- **A boundary policy that delegated admins can edit**, raising the ceiling
  instead of escaping it.
- **An ABAC tag key the principals can write**, making the control decorative.
- **An ABAC policy with no `Null` deny**, so an untagged principal's access is
  whatever the condition operator happens to do.
- **A condition on an action that has no resource-level permissions**
  (`ec2:DescribeInstances`), which denies it always and looks like a broken
  policy.
- **A misspelled action or condition key**: it never matches, and nothing warns
  you. This is what parliament in `tests/iam.sh` exists to catch.
- **A break-glass role that can create access keys**, so the emergency
  credential becomes a permanent one.
- **EventBridge patterns with a misspelled field**, matching nothing, silently,
  until the day the alert was needed.
- **An SCP over 10240 characters** (minified), rejected at attach time after the
  policy is written.
- **`DeleteAnalyzer` or `StopLogging` left un-denied**, so the first thing an
  intruder does is turn off the evidence.
- **Access Analyzer findings automated into deletions**, breaking the quarterly
  job that had not run yet.
- **A GCP org policy enforced without a dry run**, breaking every pipeline in
  the organisation at once.

## Control mapping

Section to control families. Benchmark section numbers are deliberately not
cited: verify them against the exact benchmark version you are audited on.

| This guide | CIS Benchmark | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Annex A | NIS2 Art. 21(2) |
|---|---|---|---|---|
| Federated workload identity, no static keys | CIS AWS / Azure / GCP Foundations | IA-2, IA-5, AC-2, SC-12 | A.5.15, A.5.17, A.8.5 | (i) |
| Permissions boundaries, delegated administration | same | AC-6, CM-5, AC-3 | A.8.2, A.8.18 | (i) |
| ABAC | same | AC-3, AC-16, AC-24 | A.5.15, A.8.3 | (i) |
| Service control policies / org policies | same | AC-3, CM-6, CM-7 | A.5.15, A.8.9 | (e), (i) |
| Protecting the audit trail | same | AU-6, AU-9, SI-4 | A.8.15, A.8.16 | (b) |
| Break-glass and its detection | same | AC-2(11), AC-6(9), IR-4 | A.5.15, A.8.16 | (b), (i) |
| Unused access review, stale credentials | same | AC-2(3), AC-2(13), AC-6(7) | A.5.16, A.5.18 | (i) |
| Region and service restriction | same | AC-3, SC-7, CM-7 | A.8.20, A.8.9 | (e) |

## References

- [AWS: SCP evaluation and inheritance](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html)
  and [SCP size limits](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html)
- [AWS: permissions boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
  and [delegating role creation safely](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries_delegate.html)
- [AWS: global condition context keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)
  (`aws:PrincipalTag`, `aws:TagKeys`, `aws:RequestedRegion`)
- [AWS: IAM Access Analyzer unused access](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [GitHub: OIDC `sub` claim and customisation](https://docs.github.com/en/actions/concepts/security/openid-connect)
- [GCP: Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
  and [organisation policy constraints](https://docs.cloud.google.com/organization-policy/reference/org-policy-constraints)
- [Azure: workload identity federation](https://learn.microsoft.com/entra/workload-id/workload-identity-federation)
  and [Azure Policy definition structure](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure)
- [parliament](https://github.com/duo-labs/parliament) — the AWS policy linter
  `tests/iam.sh` uses
- [CI/CD security](cicd-security.md) for the pipeline that assumes these roles,
  [Terraform security](terraform-security.md) for the plan and apply role split,
  and [secrets management](secrets-management.md) for what is left once the
  static keys are gone

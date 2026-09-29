# Terraform and OpenTofu Security

A baseline for infrastructure as code: state protection, version and provider
pinning, policy as code, and a pull-request plan pipeline that cannot apply.
Everything ships as a file under
[`baselines/terraform/`](../baselines/terraform/) and is validated by
[`tests/terraform.sh`](../tests/terraform.sh), which runs the real `terraform`,
`tofu`, `tflint`, `conftest` and `actionlint` binaries against it.

| | |
|---|---|
| Applies to | Terraform 1.11+ (S3 native locking), OpenTofu 1.7+ (state encryption). Validated on Terraform 1.16.4 and OpenTofu 1.12.6 |
| Baseline files | [`baselines/terraform/`](../baselines/terraform/) |
| Validated by | [`tests/terraform.sh`](../tests/terraform.sh) |
| Lockout risk | **High on state.** A lost or destroyed state file, or a destroyed KMS key that encrypted it, means rebuilding state by hand with `terraform import`. Everything else here is reversible |
| Last reviewed | 2026-09 |

## Threat model

What this baseline is for:

- **State as the crown jewel.** The state file contains every resource
  attribute, and for several providers that includes secrets in plain
  text. Read access to the state bucket is read access to those secrets;
  write access to it is the ability to make Terraform destroy or adopt
  anything.
- **A pull request that becomes an apply.** An attacker who can open a pull
  request, or inject a value that a workflow interpolates into a shell command,
  reaching the credentials that change production.
- **Long-lived cloud credentials in CI.** A static access key in a CI variable
  is a credential that outlives every incident, every employee and every
  rotation policy that was meant to cover it.
- **Silent drift in what actually runs.** An unpinned provider version means
  the code reviewed last week and the code applied today are not the same code.
- **Misconfiguration reaching production** because nobody enforces the rules
  the team agreed on: public buckets, unencrypted storage, no versioning.
- **Two concurrent applies** corrupting state, which is what locking prevents.

What it is not for:

- **Secrets in the code.** No amount of state protection helps if a password is
  a `variable` default in the repository. See
  [secrets management](secrets-management.md).
- **Cloud permission design.** This guide assumes the plan and apply roles
  exist and are correctly scoped; building them is
  [cloud IAM](cloud-iam.md), with working examples under
  [`baselines/iam/`](../baselines/iam/).
- **Runtime security of what is created.** A Terraform-managed EC2 instance is
  still a Linux host — see [Linux hardening](linux-hardening.md).
- **Preventing a determined operator with apply rights from destroying
  everything.** That is what state versioning, backups and
  [backup and disaster recovery](backup-disaster-recovery.md) are for.

## State backends

State is the most sensitive file in the repository's blast radius, and the
backend block is where it is protected. Four are provided:
[`aws-s3`](../baselines/terraform/backends/aws-s3/backend.tf),
[`azure-blob`](../baselines/terraform/backends/azure-blob/backend.tf),
[`gcp-gcs`](../baselines/terraform/backends/gcp-gcs/backend.tf) and
[`opentofu-encrypted`](../baselines/terraform/backends/opentofu-encrypted/backend.tf).

### Locking

| Backend | Mechanism | Notes |
|---|---|---|
| S3 | `use_lockfile = true` — a conditional `PutObject` (`If-None-Match`) on `<key>.tflock` | Terraform 1.10, generally available in 1.11. No DynamoDB table, no extra IAM statement, no write capacity to size |
| azurerm | A blob lease on the state blob | Not configurable. A killed run leaves the lease until it expires; the fix is `terraform force-unlock <lock-id>`, **never** deleting the blob |
| gcs | `default.tflock` written with `x-goog-if-generation-match: 0` | Not configurable, nothing to provision. Same conditional-write trick as S3 |

Migrating S3 from DynamoDB locking: set `use_lockfile = true` **while keeping**
`dynamodb_table`, so both locks must be acquired. Run that way until every copy
of the configuration — laptops, runners, that one Jenkins job — has the new
setting, then delete `dynamodb_table`. Removing the table first while an older
config is still in use gives you two writers that cannot see each other's lock.

### What the backend block does not do for you

None of these backends create or configure the bucket they use. The
prerequisites are the actual controls, and they are all outside the block:

- **Versioning.** This is the only undo for a corrupted state write; the
  backend keeps no backups of its own.
- **A lifecycle rule expiring noncurrent versions.** With versioning on, every
  lock acquire and release adds object versions of the `.tflock` file, forever.
- **Encryption with a key you control** (SSE-KMS with a CMK, `kms_encryption_key`
  on GCS, infrastructure encryption on the Azure account).
- **Public access blocked** at the account level, and a policy denying
  unencrypted transport.
- **A resource lock or deletion protection** on the container that holds the
  state of everything else.

### Server-side encryption is not state encryption

`encrypt = true` on the S3 backend is **server-side** encryption: S3 decrypts
the object for anyone with `s3:GetObject`, so any principal that can read the
bucket reads the state in plain text, and so can anyone who ends up with a copy
of the file.

OpenTofu's `encryption` block is the one capability with no Terraform
equivalent: it encrypts the state *before* it leaves the process (AES-GCM with
a data key from a KMS-held key), so the bucket only ever holds ciphertext and
the read permission alone is not enough. It covers the plan file too, which
matters — a plan contains the same attribute values as the state, plus
everything about to change, and CI artifacts outlive the job that made them.

`tests/terraform.sh` asserts both halves of that portability claim: `tofu
validate` accepts the file, and `terraform init` **rejects** it. If Terraform
ever accepts the block, the test fails and the note in the file is wrong.

Rollout order matters, and getting it wrong locks you out of your own state:

1. Add the block with `enforced = false` and a `fallback` method of
   `unencrypted`: reads accept plain text, writes produce ciphertext.
2. Run a plan or apply (or `tofu state push`) once per workspace, so every
   state object is rewritten encrypted.
3. Remove the fallback and set `enforced = true`, which makes a plain-text
   state a hard error instead of a silent downgrade.

Reverse the order to decrypt. Keep the key undeletable: **a destroyed KMS key
is a destroyed state file**, and the recovery path is rebuilding state by hand.

## Version pinning

Three different things get pinned, and they are not interchangeable.

**`required_version`** — a floor and a ceiling, not a pin:

```hcl
required_version = ">= 1.11.0, < 2.0.0"
```

The floor is where the features actually used became available (1.11 for S3
native locking). The ceiling stops a 2.x with breaking changes from being
picked up by a runner that happens to have it installed.

A **module's** floor should be the oldest version it genuinely works on, not
the newest the caller happens to run: raising it breaks every consumer. The
root module is where the stricter floor and the upper bound belong — which is
why [`example/modules/app/versions.tf`](../baselines/terraform/example/modules/app/versions.tf)
has a lower floor than
[`example/root/versions.tf`](../baselines/terraform/example/root/versions.tf).

**`required_providers`** — a pessimistic constraint on the major version:

```hcl
version = "~> 6.0"     # allows 6.x, refuses 7.0
```

**`.terraform.lock.hcl`** — the actual pin. It records the exact provider
version and its checksums, and it is committed. The constraint above decides
what *may* be used; the lock file decides what *is* used.

### A lock file nobody verifies is decoration

The pin only holds if CI refuses to change it:

```bash
terraform init -input=false -lockfile=readonly
```

Without `-lockfile=readonly`, CI quietly updates the lock file when a newer
matching provider exists, which is the difference between "pinned" and "pinned
until something bumps it". With it, a provider that is missing, changed, or
lacks a hash for the runner's platform fails the build.

`tests/terraform.sh` proves this is enforced rather than assumed, and the
control took two attempts to get right. **Corrupting one hash is not enough.**
The lock file records a `zh:` hash per platform archive plus an `h1:` hash per
platform, and an install only has to match **one** of them — so a control that
breaks a single line passes while proving nothing, and a control that breaks
only the `h1:` lines passes too when the provider is fetched from the registry
and a `zh:` still matches. Every hash has to be replaced before `init` reports:

```text
Error: Failed to install provider
the current package for registry.terraform.io/hashicorp/aws 6.66.0 doesn't
match any of the checksums previously recorded in the dependency lock file
```

When you add a platform (an Apple Silicon laptop next to Linux runners), do not
let each machine append its own hash; regenerate the lock deliberately:

```bash
terraform providers lock \
  -platform=linux_amd64 -platform=darwin_arm64 -platform=darwin_amd64
```

## Provider credentials

[`example/root/providers.tf`](../baselines/terraform/example/root/providers.tf)
deliberately contains **no** `assume_role` or
`assume_role_with_web_identity` block:

```hcl
provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      ManagedBy = "terraform"
      Repo      = "devops-toolkit-example"
    }
  }
}
```

In CI, `aws-actions/configure-aws-credentials` (or the GitLab OIDC equivalent)
exchanges the platform's OIDC token for short-lived credentials **before**
Terraform runs and exports them as the standard `AWS_*` environment
variables. The provider picks them up from the credential chain with zero
provider configuration — and the same configuration still works unchanged for a
human running `terraform plan` locally after `aws sso login`.

The alternative, a static access key in a CI variable, is a credential with no
expiry, usable from anywhere, that survives every rotation policy written to
cover it.

`default_tags` is not cosmetic: it is how you find, and attribute cost to,
resources six months later, and how you tell Terraform-managed resources from
the ones somebody created by hand in the console.

## Policy as code

[`policy/s3.rego`](../baselines/terraform/policy/s3.rego) is a conftest policy
that denies buckets without a public-access block, without server-side
encryption, with a weak algorithm, or without versioning enabled. It runs two
ways:

```bash
# Unit-test the rules themselves. No .tf files needed.
conftest verify -p policy

# Run the rules against real Terraform source.
conftest test -p policy example/modules/app/main.tf
```

**The policy has its own unit tests**
([`policy/s3_test.rego`](../baselines/terraform/policy/s3_test.rego)), and this
is the part people skip. A rego rule that silently stops matching — a renamed
field, a changed input shape — turns into a gate that approves everything, and
the pipeline stays green. `tests/terraform.sh` runs `conftest verify`, then
runs the policy against one deliberately broken module **per rule**, so a rule
that stopped matching shows up as a specific missing denial rather than as
"something still failed".

### Source HCL and plan JSON are different inputs

conftest's built-in HCL parser turns each resource block into
`input.resource.<type>.<name>[]`, which is what the rules above match. That
sees only what is written in the file.

To gate on **computed** values — an AMI id, a rendered IAM policy document, a
`count` that resolves at plan time, anything from a data source — write rules
against `input.resource_changes[_].change.after` from `terraform show -json
tfplan`. The source parser cannot see any of it. Both are useful: source rules
fail fast on a laptop, plan rules catch what only exists after
resolution. [`ci/plan.yml`](../baselines/terraform/ci/plan.yml) produces
`plan.json` for exactly that reason.

For a broader ruleset without writing rego, add `tfsec`/`trivy config` or
`checkov` — but keep a hand-written policy for the rules that are specific to
your organisation, because a generic scanner will never encode "buckets in this
account must use our CMK".

## Linting

[`.tflint.hcl`](../baselines/terraform/.tflint.hcl) enables the `terraform`
recommended preset and the AWS ruleset, pinned to a version, plus four rules
worth calling out: `terraform_required_version`,
`terraform_required_providers`, `terraform_documented_variables` and
`terraform_documented_outputs`, and `terraform_naming_convention` set to
`snake_case`.

The AWS ruleset is what catches an invalid instance type or a malformed ARN
before a plan spends five minutes finding out. It downloads on `tflint --init`,
which is a network dependency: in CI, cache `~/.tflint.d/plugins` and set
`GITHUB_TOKEN` so the download is not rate-limited.

`terraform validate` and `tflint` do not overlap as much as people assume.
`validate` checks that the configuration is internally consistent — syntax,
types, references. `tflint` checks provider-specific values and style. Neither
sees cloud state, and neither needs credentials.

## The plan pipeline

[`ci/plan.yml`](../baselines/terraform/ci/plan.yml) is the review gate, and its
shape is the whole point: **a pull request gets a read-only plan produced by a
role that cannot change anything, posted where reviewers read it.** Apply
happens from a different workflow, on the default branch, with a different
role, behind an environment approval.

Those two roles must not be the same role. If they are, every fork pull-request
author is one template injection away from your production account.

Six things in that file that are easy to get wrong:

```yaml
permissions: {}          # default nothing, grant per job
```

- **`if: github.event.pull_request.head.repo.full_name == github.repository`.**
  `pull_request` already withholds secrets from forks, but the OIDC `id-token`
  is **not a secret** — this guard is what stops a fork from minting one.
- **`terraform_wrapper: false`** on `setup-terraform`. The wrapper rewrites
  stdout, which breaks `-detailed-exitcode` handling and any parsing of the
  plan output.
- **`-detailed-exitcode`**: 0 means no changes, 2 means changes, 1 means
  error. Without it, a failed plan and an empty plan look identical to every
  later step — which is how a broken plan gets reported as "no changes".
- **`role-duration-seconds: 900`.** The credential should not outlive the job.
- **The plan artifact is a secret.** `tfplan` and `plan.json` contain every
  attribute value in the diff. Short retention, and never a public-repo
  artifact anyone can download.
- **The plan text reaches the API from a file**, not from a shell string and
  not through `${{ }}`. Interpolating plan output makes every resource name and
  tag value in the diff executable — this is the template injection that turns
  a read-only pipeline into an apply.

`tests/terraform.sh` runs `actionlint` over this workflow, which also
shellchecks every `run:` block, and proves the check can fail by breaking the
`permissions` value.

## Rollout

1. **Format, validate, lint locally first**: `terraform fmt -recursive`,
   `terraform init -backend=false`, `terraform validate`, `tflint`. None of
   these need credentials.
2. **Write the policy before enforcing it.** Run `conftest test` in warn mode
   (report the output, do not fail the job) until it is clean on the existing
   code, then make it a gate.
3. **Provision the state bucket by hand or in a separate bootstrap
   configuration**, with versioning, lifecycle, encryption and public access
   blocked, before pointing any backend at it. The backend block does not
   create it.
4. **Migrate state with `terraform init -migrate-state`**, and take a copy of
   the old state file first. This is the one step with no undo.
5. **OIDC before anything else in CI**, then delete the static keys — not the
   other way round, and verify the OIDC role works from a throwaway branch
   before deleting them.
6. **Enable state encryption (OpenTofu) in the three ordered steps above.** Not
   in one change.
7. **Make the plan job required**, then add the apply workflow behind an
   environment approval with its own role.

## Verification

```bash
# Formatting and internal consistency, no credentials needed
terraform fmt -check -recursive -diff
terraform init -backend=false && terraform validate

# The lock file is actually enforced (this is what CI must run)
terraform init -input=false -lockfile=readonly

# Which provider version is really selected
terraform providers

# State locking works: start a plan, then from a second shell
terraform plan -lock-timeout=0
# expect: Error acquiring the state lock

# What is in the state that should not be
terraform show -json | jq -r '.values.root_module.resources[]?.values | keys[]' | sort -u
# then grep the state for the obvious ones
terraform state pull | jq -r '..|strings' | grep -iE 'password|secret|private_key' | head

# Policy gate, both ways
conftest verify -p policy
conftest test -p policy example/modules/app/main.tf

# Who can read the state bucket — the answer that matters most
aws s3api get-bucket-policy --bucket example-org-tfstate | jq -r '.Policy' | jq .
aws s3api get-bucket-versioning --bucket example-org-tfstate
```

## Rollback

| Change | Undo |
|---|---|
| Formatting, lint, policy | Revert the commit. No infrastructure state involved |
| Provider version bump | Restore the previous `.terraform.lock.hcl` and run `terraform init -lockfile=readonly`. Beware: a provider that already **wrote** new state schema may not downgrade cleanly |
| Backend migration | `terraform init -migrate-state` back, using the copy of the old state you took first. Without that copy there is no rollback |
| `use_lockfile` | Removing it is safe; removing `dynamodb_table` while older configs still use it is not |
| OpenTofu state encryption | Add the `unencrypted` fallback method back, set `enforced = false`, run once per workspace to rewrite the state, then remove the block. **Losing the KMS key has no rollback** |
| CI switched to OIDC | Restore the static credentials only if the role itself is broken; prefer fixing the trust policy |
| An applied change | `terraform apply` of the previous commit, reviewed as a plan like any other change. Not `terraform state rm` |

## Common failure modes

- **A corrupted or truncated state write** on a backend with no versioning, and
  no copy to go back to.
- **A destroyed KMS key** that encrypted the state: the state is gone, and the
  path back is `terraform import` for every resource.
- **`-lockfile=readonly` missing in CI**, so the "pinned" provider bumps itself
  and the lock change appears in an unrelated pull request.
- **A lock file with hashes for only one platform**, so the first run on a
  different architecture fails or rewrites the file.
- **Plan and apply using the same role**, making every pull request a potential
  apply.
- **Plan output interpolated into a shell command or `${{ }}`**, turning a
  resource name into code execution in the pipeline.
- **The plan artifact left in a public repository** with a long retention, with
  every value in the diff inside it.
- **`terraform force-unlock` used to clear a lock that another run still
  holds**, giving two concurrent writers.
- **A `terraform destroy` run against the wrong workspace**, because the
  workspace is selected by environment variable and nothing echoed it.
- **Secrets in state** — a database password, a generated private key — and a
  state bucket readable by the whole team.
- **A rego rule that silently stopped matching** after an input shape change,
  so the gate approves everything and CI stays green.
- **`required_version` raised in a shared module**, breaking every consumer at
  once.
- **A provider constraint of `>= 6.0`** with no upper bound, so a 7.0 release
  lands in whatever runs next.

## Control mapping

Section to control families. Benchmark section numbers are deliberately not
cited: verify them against the exact benchmark version you are audited on.

| This guide | Reference | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Annex A | NIS2 Art. 21(2) |
|---|---|---|---|---|
| State backend protection | CIS cloud provider benchmarks | SC-28, CP-9, AC-3 | A.5.33, A.8.13, A.8.24 | (c), (h) |
| State and plan encryption | same | SC-12, SC-13, SC-28 | A.8.24 | (h) |
| State locking | — | CM-3, CM-5 | A.8.32 | (e) |
| Version and provider pinning | SLSA, CIS Supply Chain | CM-2, CM-6, SA-10 | A.8.9, A.8.30 | (d) |
| Policy as code | — | CM-3, CM-6, SI-7 | A.8.9, A.8.32 | (e) |
| OIDC instead of static keys | CIS IAM benchmarks | AC-2, IA-5, SC-12 | A.5.15, A.5.17 | (i) |
| Plan and apply separation | — | AC-5, AC-6, CM-3 | A.5.3, A.8.2, A.8.32 | (i) |
| Plan artifact handling | — | SC-28, AU-9 | A.5.33, A.8.12 | (h) |

## References

- [Terraform backend configuration](https://developer.hashicorp.com/terraform/language/backend)
  and the [S3 backend](https://developer.hashicorp.com/terraform/language/backend/s3)
  (`use_lockfile`)
- [Dependency lock file and checksum verification](https://developer.hashicorp.com/terraform/language/files/dependency-lock)
- [OpenTofu state and plan encryption](https://opentofu.org/docs/language/state/encryption/)
- [conftest](https://www.conftest.dev/) and the
  [Rego policy language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [tflint](https://github.com/terraform-linters/tflint) and the
  [AWS ruleset](https://github.com/terraform-linters/tflint-ruleset-aws)
- [GitHub OIDC for AWS](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
  and [`aws-actions/configure-aws-credentials`](https://github.com/aws-actions/configure-aws-credentials)
- [CI/CD security](cicd-security.md) for the pipeline hardening this guide
  depends on, and [cloud IAM](cloud-iam.md) for the plan and apply roles

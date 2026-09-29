# Secrets Management

How credentials get from a human's head to a running process without ever
sitting in git as plaintext or in a Kubernetes Secret as the only copy that
matters: SOPS with age for the small set of secrets that must live in git,
HashiCorp Vault for everything with a lifecycle, and External Secrets
Operator to get a Vault secret into a cluster with no `kubectl create secret`
ever typed by a human. Every file ships under
[`baselines/secrets/`](../baselines/secrets/) and is validated by
[`tests/secrets.sh`](../tests/secrets.sh) against the real `gitleaks`, `sops`,
`vault` and `kubeconform` binaries, including a live dev-mode Vault server.

| | |
|---|---|
| Applies to | gitleaks 8.30+ (default ruleset), SOPS 3.9+ with age recipients, HashiCorp Vault 1.15+ (KV v2, Kubernetes auth), External Secrets Operator 0.9+ (CRD `external-secrets.io/v1`) |
| Baseline files | [`baselines/secrets/`](../baselines/secrets/) |
| Validated by | [`tests/secrets.sh`](../tests/secrets.sh) |
| Lockout risk | **Low for the mechanisms themselves — they fail closed, not open.** A wrong SOPS recipient means nobody can decrypt, not that the file is left readable; a wrong Vault policy path denies access, it does not grant it. The real risk is operational: lose the last age private key that can decrypt a file, or the last identity that can write to a Vault policy, and there is no vendor support line to call |
| Last reviewed | 2026-09 |

## Threat model

What this baseline is for:

- **A secret committed to git.** Caught before merge and in history by
  gitleaks; if one still lands, revoked before the commit is ever rewritten
  (see "Detection" below).
- **An attacker who reads the git repository** (a misconfigured mirror, a
  compromised CI runner, a laptop with a clone on it) but does not hold any
  age private key or Vault token. SOPS-encrypted values and a Vault reference
  are useless to them.
- **A compromised workload with a narrow, scoped credential**, because the
  Vault policy it authenticated with grants exactly one path prefix and nothing
  else — the blast radius of that compromise is the app's own secrets, not
  every secret in the organisation.
- **A static, long-lived credential that outlives the reason it was issued.**
  Vault's Kubernetes-auth tokens and dynamic secrets expire on their own; the
  hierarchy below is ordered specifically to get everything possible off
  static credentials.
- **A human being the delivery mechanism for a Kubernetes Secret.** External
  Secrets Operator materialises the Secret from Vault directly; nobody pastes
  a password into `kubectl create secret` or a values file.

What it is not for:

- **Network- or IAM-level blast-radius reduction.** A Vault policy scopes
  which *secrets* an identity can read; it says nothing about which
  *networks* or *cloud APIs* that identity's compute can reach. See
  [cloud IAM](cloud-iam.md).
- **Encryption at rest for the Kubernetes Secret object itself.** External
  Secrets Operator writes a normal Kubernetes Secret — base64, not
  encrypted — into etcd. See "Kubernetes Secrets are base64, not encrypted"
  below and [Kubernetes hardening](kubernetes-hardening.md).
- **PKI / TLS certificate issuance.** Vault also has a PKI secrets engine;
  this guide only covers the KV v2 + Kubernetes-auth pattern actually shipped
  here.
- **An attacker who already has root on a box holding a decrypted secret in
  process memory.** Nothing here defends memory that has already been
  handed the plaintext; see [Linux hardening](linux-hardening.md) for the
  host-level controls that make reaching that memory harder in the first
  place.
- **Compliance evidence.** The control mapping at the end says which control
  families a section touches; it is not an audit artifact.

## The hierarchy

In order of preference, from safest to a fallback that should shrink over
time:

1. **Never in git, in any form, plaintext or encrypted.** Anything with a
   short lifecycle or that needs revocation-on-demand belongs in Vault as a
   dynamic secret, not in a file at all.
2. **SOPS-encrypted in git**, for the small set of secrets that genuinely need
   to be reviewable alongside the code that uses them and that don't need a
   revocation lifecycle — Ansible `group_vars`, a handful of Kubernetes
   bootstrap Secrets needed before a secret manager can run.
3. **A secret manager with dynamic, short-lived credentials** (Vault) for
   everything else, especially database credentials, cloud API keys and
   anything else that benefits from expiring on a timer instead of on someone
   remembering to rotate it.

The two failure modes this ordering exists to prevent are the same failure at
different scales: a plaintext credential sitting somewhere it does not need
to (a `.env` file, a values file, a Slack message) and outliving the reason it
was created.

## SOPS + age

[`baselines/secrets/.sops.yaml`](../baselines/secrets/.sops.yaml) defines
`creation_rules`: which age recipients a file gets encrypted for, based on
its path. Two concrete rules plus a catch-all:

| `path_regex` | Recipient(s) | Notes |
|---|---|---|
| `baselines/ansible/inventory/group_vars/.*\.sops\.ya?ml$` | ops/ansible team only | decrypted transparently by the `community.sops` vars plugin — see [Ansible best practices](ansible-best-practices.md) and [`baselines/ansible/ansible.cfg`](../baselines/ansible/ansible.cfg) |
| `baselines/kubernetes/bootstrap-secrets/.*\.sops\.ya?ml$` | platform/k8s team only | `encrypted_regex: ^(data\|stringData)$` — only those two keys are encrypted, so `apiVersion`, `kind`, `metadata` and `type` stay plaintext and `kubectl diff`/code review still show what kind of object changed |
| `.*\.sops\.ya?ml$` (catch-all, last) | both teams | must stay last: `creation_rules` match top to bottom and the first match wins, so a catch-all placed first would swallow the two rules above silently |

`tests/secrets.sh` proves all three by creating a real file at each rule's
matching path, running `sops -e` for real, and reading the resulting
`sops.age[].recipient` list back out of the ciphertext — not asserting the
regex is correct from reading it, but that it actually captures the path it
is meant to.

### Why SOPS instead of ansible-vault or sealed-secrets

| | Encrypts | Diff shows | Access model | Where it lives |
|---|---|---|---|---|
| **SOPS** | Each leaf value | Which key changed, not its value | Per-recipient (age/PGP/KMS), several recipients per file | Git, any format (YAML/JSON/ENV) |
| **ansible-vault** | The whole file | Nothing — an opaque blob | One shared password for everyone who needs *anything* in the file | Git, Ansible-specific |
| **sealed-secrets** | The whole Kubernetes Secret | Nothing useful without decrypting | One cluster-held private key; anyone with cluster access to the controller can decrypt everything it ever sealed | Git, Kubernetes-only |

ansible-vault's single shared password is the real problem: there is no way
to give someone decrypt access to *one* secret in a vault file without giving
them every secret in it. sealed-secrets has the opposite problem — it is
Kubernetes-only and centralises decrypt capability in one controller-held
key with no per-recipient scoping at all. SOPS with age recipients gives
per-file, per-recipient access and works for any text format, which is why
it is used for both the Ansible and the Kubernetes-bootstrap case here with
two different recipient sets in the same `.sops.yaml`.

### Rotation

"Rotate" means something different depending on what changed:

- **A recipient is added or removed** (someone joins/leaves the team that
  should read a class of secrets): edit `keys:`/`creation_rules` in
  `.sops.yaml`, then run `sops updatekeys <file>` for every already-encrypted
  file the rule covers. `updatekeys` re-wraps the file's data key for the new
  recipient set and shows a diff of who gains/loses access before writing —
  it does not touch the encrypted values themselves. Removing a recipient
  here does **not** revoke anything retroactively: anyone who already
  decrypted a copy still has the plaintext, and the old private key can still
  open any file encrypted before `updatekeys` ran on it.
- **The secret VALUE itself needs to change** (a leaked password, a periodic
  rotation): decrypt, edit the value, re-encrypt (`sops <file>` does both in
  one editor session), commit. The recipient list is untouched.
- **A private key is lost or compromised**: generate a new age keypair,
  add the new public key as a recipient, `updatekeys` every file it should
  reach, remove the old public key, `updatekeys` again, and — separately —
  rotate every secret value that old private key could ever have decrypted,
  because SOPS has no way to prove it never did.

## HashiCorp Vault

[`baselines/secrets/vault/policy-app-readonly.hcl`](../baselines/secrets/vault/policy-app-readonly.hcl)
is a least-privilege policy for one application's read path, plus
[`k8s-auth-role.sh`](../baselines/secrets/vault/k8s-auth-role.sh) (the
Kubernetes-auth binding) and
[`kv-v2-path-layout.json`](../baselines/secrets/vault/kv-v2-path-layout.json)
(a reference for the trap below).

### The KV v2 path trap

This is the single most common way a Vault policy is written and grants
nothing. KV v2 has **three** different paths for one secret, and only one of
them is what the CLI shows you:

| Operation | CLI (what you type) | Real backend path (API + policy) |
|---|---|---|
| Read/write current version | `vault kv get/put secret/app/db` | `secret/data/app/db` |
| List, version history, soft-delete/undelete | `vault kv list/metadata secret/app/` | `secret/metadata/app/` |

`tests/secrets.sh` proves this live rather than describing it: with the
policy loaded into a real dev-mode Vault server, `vault kv get
secret/app-readonly/db` (the CLI, which adds `data/` for you) returns the
secret; a **raw** `vault read secret/app-readonly/db` — the CLI-shaped, KV
v1-looking path that a policy naively copy-pasted from a v1 mount would use —
returns nothing and a warning, while `vault read
secret/data/app-readonly/db` returns it. A policy written against the
CLI-shaped path silently protects nothing: no error at write time, no error
at read time from the app's own perspective if it also gets the path wrong
the same way, just a working app until the day some other client calls the
real API path and gets denied.

### Least privilege, proven live

The policy grants `read` on `secret/data/app-readonly/*` and
`list`+`read` on `secret/metadata/app-readonly/*` — nothing else. No
`create`, `update`, `delete` or `sudo` anywhere in the file; this identity is
a consumer, not an owner. `tests/secrets.sh` does not just run `vault policy
fmt` and call it proven: it creates a token scoped to exactly this policy
against a real dev-mode server, confirms it **can** read
`secret/app-readonly/db`, and confirms it is **denied with a 403** reading a
sibling app's `secret/other-app/db` — the actual scoping claim, exercised,
not asserted in a comment.

### Auth methods, and why not static tokens

- **Kubernetes auth** (what `k8s-auth-role.sh` configures): a pod's own
  ServiceAccount token is exchanged for a short-lived Vault token scoped to a
  role, which is bound to a specific ServiceAccount name and namespace and a
  specific policy. No Vault credential is ever stored in a Kubernetes Secret.
  This is what [`baselines/secrets/eso/cluster-secret-store.yaml`](../baselines/secrets/eso/cluster-secret-store.yaml)
  uses.
- **AppRole**, for non-Kubernetes automation (a CI runner, a VM): a
  `role_id` (not secret, can live in config) plus a `secret_id` (short-lived,
  fetched once at pipeline start) authenticate the same way, without needing
  a Kubernetes API to validate against.
- **Static, long-lived Vault tokens are the thing both of the above exist to
  avoid.** A static token pasted into a CI variable or a `.env` file has
  every property a secret manager exists to eliminate: no automatic
  expiry, no per-workload scoping beyond what was baked in at creation, and
  no proof of who is currently holding a copy of it.

`tests/secrets.sh` does **not** validate `k8s-auth-role.sh` against a real
Kubernetes API — see "What this test does not do" below.

## External Secrets Operator

[`baselines/secrets/eso/cluster-secret-store.yaml`](../baselines/secrets/eso/cluster-secret-store.yaml)
connects the cluster to Vault via Kubernetes auth;
[`external-secret.yaml`](../baselines/secrets/eso/external-secret.yaml)
materialises one Kubernetes Secret from `secret/app/db` on a `refreshInterval`
of one hour. This is the mechanism that gets a secret into a cluster with no
human running `kubectl create secret` or committing it to a values file: ESO's
controller authenticates to Vault itself and keeps the target Secret in sync.

Both manifests are schema-validated by `tests/secrets.sh` with `kubeconform
-strict` against the **real ESO CRD OpenAPI schemas**, vendored under
[`baselines/secrets/eso/schemas/`](../baselines/secrets/eso/schemas/) so the
check needs no network at test time. `kubectl apply --dry-run=client` alone
would only confirm the YAML parses — it does not have the CRD's own
validation rules unless the CRD is actually installed on the cluster it runs
against, which a container-only test does not have.

Rotation through ESO: when the value at `secret/app/db` changes in Vault, the
next `refreshInterval` tick updates the target Kubernetes Secret's data — but
**the pod does not automatically reload it**. A Secret mounted as a volume
eventually reflects the new value (via the kubelet's periodic sync, on the
order of a minute), a Secret exposed as an environment variable never does
until the pod restarts. Rotation is not complete until whatever consumes the
credential re-reads it, which for an env-var-shaped secret means the
workload needs a restart mechanism (a Deployment rollout, or a sidecar like
Reloader watching for the Secret's hash to change).

## Rotation, summarised by kind

| Secret kind | What "rotate" means |
|---|---|
| SOPS-encrypted value in git | Decrypt, edit, re-encrypt, commit. Recipients unaffected |
| SOPS recipient list | `sops updatekeys` per affected file; does not revoke past access |
| Vault static KV v2 secret | Write a new version (`vault kv put`); old versions remain readable via `metadata` unless destroyed — `vault kv metadata` policy scoping matters here |
| Vault dynamic secret (database, cloud) | Nothing to do manually — it expires on its own lease; revoking early is `vault lease revoke` |
| Kubernetes Secret materialised by ESO | Change the Vault value; ESO updates the Secret on its `refreshInterval`; the **workload** still needs to reload it |
| Vault Kubernetes-auth / AppRole token | Nothing to rotate directly — it already expires on its TTL; rotate the underlying role/policy instead if access needs to change |

## Detection

Gitleaks runs in two places, and both matter for a different reason:

- **Pre-commit** ([`baselines/cicd/.pre-commit-config.yaml`](../baselines/cicd/.pre-commit-config.yaml)),
  against the files about to be committed — catches a secret before it ever
  reaches a shared branch.
- **CI**, scanning full history (`gitleaks git`, not `gitleaks dir`) — see
  [CI/CD security](cicd-security.md). A secret that was committed and later
  deleted is still in every clone's pack file; a scan of the working tree
  alone never sees it.

[`baselines/secrets/.gitleaks.toml`](../baselines/secrets/.gitleaks.toml)
extends gitleaks' default ruleset with one org-specific rule
(`internal-service-token`, format `svc_<32 hex>`) and an allowlist for the
one placeholder value that would otherwise match it. `tests/secrets.sh`
proves the pair, not just the rule: gitleaks must find the planted secret in
`fixtures/dirty/` **and** find nothing in `fixtures/clean/`. A config that
matched nothing anywhere would still pass a "scans clean fixtures clean"
check on its own — the dirty half is what catches that.

**If gitleaks finds a real secret, revoke it first.** Deleting the commit or
rewriting history does not undo the fact that the credential was exposed —
anyone who cloned the repo, any CI cache, any log that captured the diff
already has it. Rewrite history only after the credential itself no longer
works.

## Kubernetes Secrets are base64, not encrypted

A Kubernetes Secret — including the one ESO materialises above — is
base64-encoded in the API and stored **unencrypted** in etcd unless the
cluster has `EncryptionConfiguration` configured, and even then it is
readable in plaintext by anything with RBAC `get` on it. Getting the value
out of Vault correctly and into the cluster the right way (this guide) and
protecting the etcd copy once it is there (a control-plane concern) are two
different problems. See
[Kubernetes hardening](kubernetes-hardening.md#pod-security-admission) for
the API server encryption-at-rest and RBAC controls.

## Rollout

1. **Generate age keypairs for each recipient team**, out of band —
   `age-keygen`. Private keys go into each operator's/CI runner's keychain
   (`$HOME/.config/sops/age/keys.txt` or `SOPS_AGE_KEY_FILE`), never into git.
2. **Land `.sops.yaml`** with the real recipients, and encrypt one throwaway
   file per rule to confirm the path regexes match what you expect before any
   real secret goes through it — this is exactly what `tests/secrets.sh`'s
   check (c) does.
3. **Stand up Vault**, enable the Kubernetes auth method, load the
   least-privilege policy, bind the role — `k8s-auth-role.sh` in order.
   Validate the policy with `vault policy fmt` before writing it, every time.
4. **Deploy External Secrets Operator**, apply the `ClusterSecretStore`, and
   confirm its status condition is `Valid` (`kubectl describe
   clustersecretstore vault-backend`) before pointing any `ExternalSecret` at
   it — an unauthenticated store fails every `ExternalSecret` referencing it
   silently degraded, not loudly rejected.
5. **Apply one `ExternalSecret`** for a non-critical workload first, confirm
   the target Secret's value round-trips correctly, then roll out to the rest.
6. **Wire gitleaks into pre-commit and CI** before any of the above, not
   after — the point is to stop the FIRST plaintext secret from being
   committed, not to clean up after it.

## Verification

```bash
# SOPS: the recipient list is unencrypted metadata -- no key needed to see
# WHO can decrypt a file, only to decrypt it
grep -A2 '^    age:' <path-to-file>.sops.yml

# Vault: policy is syntactically valid and matches what is checked in
vault policy fmt baselines/secrets/vault/policy-app-readonly.hcl
vault policy read app-readonly

# Vault: the classic KV v2 trap, live -- the first must return nothing useful,
# the second must return the value
vault read secret/app-readonly/db
vault read secret/data/app-readonly/db

# Vault: prove least privilege with a real scoped token, not the root token
vault token create -policy=app-readonly -field=token
VAULT_TOKEN=<that token> vault kv get secret/app-readonly/db      # works
VAULT_TOKEN=<that token> vault kv get secret/some-other-app/db    # 403

# ESO: the store actually authenticated
kubectl get clustersecretstore vault-backend -o jsonpath='{.status.conditions[0].type}{"\n"}'
# expect: Valid

# ESO: the ExternalSecret produced a real Secret, and it round-trips
kubectl get externalsecret app-db-creds -n app \
  -o jsonpath='{.status.conditions[0].reason}{"\n"}'
kubectl get secret app-db-creds -n app -o jsonpath='{.data.password}' | base64 -d

# gitleaks: the pair that proves the rule and allowlist both work
gitleaks dir baselines/secrets/fixtures/dirty -c baselines/secrets/.gitleaks.toml   # must find 1
gitleaks dir baselines/secrets/fixtures/clean -c baselines/secrets/.gitleaks.toml   # must find 0
```

## Rollback

| Change | Undo |
|---|---|
| A `.sops.yaml` recipient added in error | Remove it, `sops updatekeys` every file the rule covers — does not retroactively revoke what that recipient already decrypted |
| A bad Vault policy applied | `vault policy write <name> <previous-version.hcl>`, or `vault policy delete <name>` if it should never have existed; existing tokens keep whatever they already had until they expire or are revoked |
| A Vault token issued in error | `vault token revoke <accessor>` — immediate, does not wait for TTL |
| An `ExternalSecret`/`ClusterSecretStore` applied in error | `kubectl delete`; the materialised Kubernetes Secret is NOT automatically deleted unless `creationPolicy: Owner` (the default here) ties its lifecycle to the `ExternalSecret` |
| A secret rotated to a bad value | Write the previous version back (`vault kv put` with the old value, or `vault kv rollback` if the KV v2 version history still has it) |

## Common failure modes

- **A Vault policy path written against the CLI-shaped KV v2 path**
  (`secret/app/db` instead of `secret/data/app/db`). No error anywhere; the
  token just gets "permission denied" the first time something calls the real
  API path. This is why `policy-app-readonly.hcl`'s own comments spell out
  the full `data/`/`metadata/` split instead of the shorthand.
- **A `.sops.yaml` catch-all rule placed before, not after, the specific
  rules.** `creation_rules` match top to bottom and the first match wins; a
  catch-all placed first silently grants every recipient access to files that
  were meant to be scoped to one team, with no error and no warning.
- **`kubectl apply --dry-run=client` treated as schema validation for a
  CRD.** It only confirms the YAML parses. An `ExternalSecret` with a typo'd
  field name or a `ClusterSecretStore` missing a required field both apply
  successfully client-side and fail only once the controller tries to
  reconcile them — which is why this baseline is validated with `kubeconform
  -strict` against the real CRD schema instead.
- **`age-keygen -o` refuses to overwrite an existing key file** rather than
  silently replacing it — a script that assumes idempotent key generation
  and doesn't clean up between runs gets a hard failure, which is the
  correct behaviour, not a bug to work around with `-f`.
- **A gitleaks config that matches nothing, anywhere, and stays green
  forever.** A config validated only against a clean fixture never proves the
  rule itself works — it takes the dirty/clean pair to catch that, which is
  why `tests/secrets.sh` runs the dirty fixture first.
- **A Kubernetes Secret exposed as an environment variable, rotated in
  Vault, and never actually rotated in the running pod** because env vars are
  read once at process start and ESO's `refreshInterval` only updates the
  Secret object, not the process holding the old value in memory.
- **A container-only test asked to validate `vault write
  auth/kubernetes/role/...` against a real cluster.** It accepts any string
  for `kubernetes_host`/`kubernetes_ca_cert` without checking reachability,
  so a green result there proves the CLI parsed its flags and nothing about
  whether the binding actually works — `tests/secrets.sh` does not run this
  check for exactly that reason; see the script's header.

## Control mapping

Section to control families. Benchmark section numbers are deliberately not
cited: verify them against the exact benchmark version you are audited on.

| This guide | CIS Benchmark | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Annex A | NIS2 Art. 21(2) |
|---|---|---|---|---|
| SOPS + age, `.sops.yaml` | CIS Software Supply Chain | IA-5, SC-12, SC-28 | A.5.33, A.8.24 | (h) |
| Vault least-privilege policy | CIS HashiCorp Vault | AC-3, AC-6, IA-5 | A.5.15, A.8.2, A.8.3 | (i) |
| Vault Kubernetes auth / AppRole, no static tokens | same | IA-2, IA-5, IA-9 | A.5.17, A.8.5 | (h), (j) |
| External Secrets Operator | CIS Kubernetes Benchmark | AC-3, CM-7, SC-28 | A.8.9, A.8.24 | (e), (i) |
| gitleaks pre-commit + CI, history scanning | OWASP CICD-SEC-6 | IA-5, SI-4 | A.5.17, A.8.12 | (b) |
| Kubernetes Secret encryption at rest | CIS Kubernetes Benchmark | SC-28 | A.8.24 | (e) |

## References

- [SOPS](https://github.com/getsops/sops) and
  [age](https://github.com/FiloSottile/age) —
  encryption format, `updatekeys`, `.sops.yaml` `creation_rules` reference
- [HashiCorp Vault: policies](https://developer.hashicorp.com/vault/docs/concepts/policies),
  [KV v2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2), and
  [Kubernetes auth method](https://developer.hashicorp.com/vault/docs/auth/kubernetes)
- [External Secrets Operator](https://external-secrets.io/) —
  `SecretStore`/`ClusterSecretStore`/`ExternalSecret` reference and CRD schemas
- [datreeio/CRDs-catalog](https://github.com/datreeio/CRDs-catalog) — the
  source of the vendored ESO JSON schemas under `baselines/secrets/eso/schemas/`
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [Ansible best practices](ansible-best-practices.md) for the
  `community.sops` vars plugin wiring
- [CI/CD security](cicd-security.md) for history-scanning gitleaks in CI and
  the reusable-workflow secrets handling
- [Kubernetes hardening](kubernetes-hardening.md) for encryption at rest and
  RBAC on Secret objects
- [Cloud IAM](cloud-iam.md) for the identity/network side that Vault policies
  do not cover
- [SSH key management](ssh-key-management.md) for certificate-based access,
  a related but separate credential lifecycle

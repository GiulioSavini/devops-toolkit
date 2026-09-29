#!/usr/bin/env bash
# Validates everything under baselines/ansible/. Run from the repository root:
#
#   bash tests/ansible.sh
#
# Host requirements: bash and docker. The whole Ansible toolchain runs inside
# one pinned image so a local run and a CI run resolve the same versions.
#
# What this proves:
#   1. Every collection in requirements.yml is pinned to an exact version, and
#      those pins actually resolve and install from Galaxy.
#   2. baselines/ansible/ passes ansible-lint's *production* profile with zero
#      violations (FQCN, explicit file modes, no `state: latest`, named tasks,
#      changed_when on commands, role-prefixed variables...).
#   3. Every playbook and the molecule scenario's playbooks pass
#      `ansible-playbook --syntax-check`.
#   4. The privileged-group conditional resolves to `wheel` on RedHat and
#      `sudo` on Debian. This is executed, not read: it is the bug the
#      published guide shipped (`groups: sudo`, which does not exist on RHEL).
#   5. Each of the above can fail. Every check is run once against a
#      deliberately broken copy of the tree first, asserting both a non-zero
#      exit and the expected diagnostic, then the copy is restored.
#
# What this does NOT do: run `molecule test`. Molecule needs privileged,
# systemd-capable containers; converging it is a local/e2e activity. See
# baselines/ansible/roles/hardening/molecule/default/molecule.yml.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
BASE="baselines/ansible"
[[ -d "$BASE" ]] || { echo "run from the repository root" >&2; exit 2; }

PYTHON_IMAGE="python:3.13.15-slim-trixie@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b"
ANSIBLE_CORE_VERSION="2.21.4"
ANSIBLE_LINT_VERSION="26.9.0"

PLAYBOOKS=(
  playbooks/site.yml
  playbooks/rolling-update.yml
  roles/hardening/molecule/default/converge.yml
  roles/hardening/molecule/default/verify.yml
)

step() { printf '\n==> %s\n' "$*"; }
ok()   { echo "ok  $*"; }
die()  { echo "FAIL $*" >&2; exit 1; }

work="$(mktemp -d)"
cleanup() {
  # Containers run as root and leave root-owned files in the bind mount; fix
  # ownership before removing so cleanup cannot mask the real exit status.
  docker run --rm -v "$work:/w" "$PYTHON_IMAGE" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

# Run a command with the pinned toolchain. $work is /w (writable, holds the
# venv, the installed collections and the working copy of the tree); the
# repository is mounted read-only so no check can modify it.
ansible_sh() {
  docker run --rm \
    -e HOME=/w \
    -e ANSIBLE_HOME=/w/ansible \
    -e ANSIBLE_COLLECTIONS_PATH=/w/collections \
    -v "$work:/w" -v "$ROOT:/repo:ro" \
    "$PYTHON_IMAGE" sh -euc "$1"
}

# Restore the working copy from the read-only source of truth.
reset_tree() {
  ansible_sh "rm -rf /w/tree && cp -r /repo/$BASE /w/tree"
}

step "bootstrap ansible-core $ANSIBLE_CORE_VERSION + ansible-lint $ANSIBLE_LINT_VERSION in $PYTHON_IMAGE"
ansible_sh "
  python -m venv /w/venv
  /w/venv/bin/pip install -q --disable-pip-version-check --root-user-action=ignore \
    ansible-core==$ANSIBLE_CORE_VERSION ansible-lint==$ANSIBLE_LINT_VERSION
  /w/venv/bin/ansible-lint --version
"
reset_tree
ok "toolchain ready"

### 1. requirements.yml pins ------------------------------------------------
step "requirements.yml: pinned collections resolve and install"
ansible_sh "/w/venv/bin/ansible-galaxy collection install -r /repo/$BASE/requirements.yml -p /w/collections >/dev/null"
ok "every pin in requirements.yml installed from Galaxy"

cat >"$work/check_pins.py" <<'PY'
"""Assert every collection in requirements.yml is pinned to an exact version
and that the version installed is exactly that one."""
import json
import pathlib
import re
import sys

import yaml

req_path = pathlib.Path(sys.argv[1])
installed_root = pathlib.Path(sys.argv[2]) / "ansible_collections"
doc = yaml.safe_load(req_path.read_text())

errors = []
declared = {}
for entry in doc.get("collections") or []:
    if not isinstance(entry, dict):
        errors.append(f"{entry!r} is a bare name with no pinned version")
        continue
    name = entry.get("name")
    version = entry.get("version")
    if version is None:
        errors.append(f"{name} has no version: floating pin")
        continue
    version = str(version)
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        errors.append(f"{name} version {version!r} is not an exact x.y.z pin")
        continue
    declared[name] = version
    namespace, _, short = name.partition(".")
    manifest = installed_root / namespace / short / "MANIFEST.json"
    if not manifest.is_file():
        errors.append(f"{name} is declared but not installed")
        continue
    got = json.loads(manifest.read_text())["collection_info"]["version"]
    if got != version:
        errors.append(f"{name}: requirements.yml pins {version}, installed {got}")

if errors:
    for e in errors:
        print(f"FAIL {e}")
    sys.exit(1)

for name, version in sorted(declared.items()):
    print(f"ok  {name}=={version}")

# Dependencies pulled in transitively are NOT pinned by this file. Surfacing
# them is the point: `ansible-galaxy` resolves a dependency to whatever is
# newest unless you pin it here too.
extra = sorted(
    f"{p.parent.parent.name}.{p.parent.name}"
    for p in installed_root.glob("*/*/MANIFEST.json")
)
for name in extra:
    if name not in declared:
        got = json.loads(
            (installed_root / name.split(".")[0] / name.split(".")[1] / "MANIFEST.json").read_text()
        )["collection_info"]["version"]
        print(f"note  transitive dependency not pinned in requirements.yml: {name}=={got}")
PY

# 1a. Prove the pin audit can fail: drop the version from one entry.
ansible_sh "
  sed -i '/name: ansible.posix/{n;/version:/d;}' /w/tree/requirements.yml
  if /w/venv/bin/python /w/check_pins.py /w/tree/requirements.yml /w/collections >/w/pins.break.log 2>&1; then
    echo 'UNEXPECTED PASS'; exit 9
  fi
  grep -q 'ansible.posix has no version: floating pin' /w/pins.break.log \
    || { echo 'wrong diagnostic:'; cat /w/pins.break.log; exit 1; }
"
reset_tree
ok "the pin audit rejects an unpinned collection (ansible.posix)"

# 1b. The real file must pass.
ansible_sh "/w/venv/bin/python /w/check_pins.py /repo/$BASE/requirements.yml /w/collections"
ok "requirements.yml: every collection pinned to an exact, installed version"

### 2. ansible-lint, production profile -------------------------------------
lint() { ansible_sh "cd /w/tree && /w/venv/bin/ansible-lint --offline . $*"; }

step "ansible-lint (profile: production) must be capable of failing"

# 2a. Drop an FQCN.
ansible_sh "
  sed -i '0,/ansible.builtin.group:/s//group:/' /w/tree/roles/hardening/tasks/main.yml
  cd /w/tree
  if /w/venv/bin/ansible-lint --offline . >/w/lint.fqcn.log 2>&1; then echo 'UNEXPECTED PASS'; exit 9; fi
  grep -q 'fqcn' /w/lint.fqcn.log || { echo 'wrong diagnostic:'; cat /w/lint.fqcn.log; exit 1; }
"
reset_tree
ok "ansible-lint rejects a short module name (fqcn)"

# 2b. Drop an explicit file mode.
ansible_sh "
  sed -i '/dest: \"{{ hardening_agent_config_dir }}\\/token\"/,+3{/mode: \"0600\"/d}' /w/tree/roles/hardening/tasks/main.yml
  cd /w/tree
  if /w/venv/bin/ansible-lint --offline . >/w/lint.mode.log 2>&1; then echo 'UNEXPECTED PASS'; exit 9; fi
  grep -q 'risky-file-permissions' /w/lint.mode.log || { echo 'wrong diagnostic:'; cat /w/lint.mode.log; exit 1; }
"
reset_tree
ok "ansible-lint rejects a file task with no explicit mode (risky-file-permissions)"

# 2c. state: latest on a package.
ansible_sh "
  sed -i 's/^        state: present\$/        state: latest/' /w/tree/playbooks/rolling-update.yml
  cd /w/tree
  if /w/venv/bin/ansible-lint --offline . >/w/lint.latest.log 2>&1; then echo 'UNEXPECTED PASS'; exit 9; fi
  grep -q 'package-latest' /w/lint.latest.log || { echo 'wrong diagnostic:'; cat /w/lint.latest.log; exit 1; }
"
reset_tree
ok "ansible-lint rejects state: latest on a package (package-latest)"

step "ansible-lint (profile: production) on baselines/ansible"
lint || die "ansible-lint failed on the checked-in tree"
ok "0 violations, 0 warnings, production profile satisfied"

### 3. syntax check ---------------------------------------------------------
step "ansible-playbook --syntax-check"

# 3a. Prove it can fail: break the YAML.
ansible_sh "
  printf '  this: is: not: valid: yaml\n' >> /w/tree/playbooks/site.yml
  cd /w/tree
  if /w/venv/bin/ansible-playbook --syntax-check playbooks/site.yml >/w/syntax.break.log 2>&1; then
    echo 'UNEXPECTED PASS'; exit 9
  fi
  grep -qi 'syntax\|mapping values are not allowed\|ERROR' /w/syntax.break.log \
    || { echo 'wrong diagnostic:'; cat /w/syntax.break.log; exit 1; }
"
reset_tree
ok "--syntax-check rejects malformed YAML"

for pb in "${PLAYBOOKS[@]}"; do
  ansible_sh "cd /w/tree && /w/venv/bin/ansible-playbook --syntax-check '$pb' >/dev/null"
  ok "$BASE/$pb"
done

### 4. the privileged group actually resolves per OS family -----------------
# This is the regression test for the published guide's bug. The role default
# is loaded for real and the expression is rendered by Ansible, with
# ansible_facts injected per platform.
cat >"$work/groupcheck.yml" <<'PY'
---
- name: Check the privileged group resolves for this OS family
  hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - "{{ role_defaults }}"
  tasks:
    - name: Assert the privileged group matches the platform
      ansible.builtin.assert:
        that:
          - hardening_privileged_group == expected
        fail_msg: >-
          os_family={{ ansible_facts['os_family'] }} resolved to
          {{ hardening_privileged_group }}, expected {{ expected }}
        success_msg: >-
          os_family={{ ansible_facts['os_family'] }} ->
          {{ hardening_privileged_group }}
        quiet: true
PY

groupcheck() { # <defaults-file> <os_family> <expected-group>
  ansible_sh "/w/venv/bin/ansible-playbook /w/groupcheck.yml \
    -e role_defaults=$1 \
    -e expected=$3 \
    -e '{\"ansible_facts\":{\"os_family\":\"$2\"}}' >/w/group.$2.log 2>&1 \
    || { cat /w/group.$2.log; exit 1; }"
}

step "privileged group: wheel on RedHat, sudo on Debian"

# 4a. Prove it can fail, with exactly the bug the old guide shipped:
# hard-code `sudo` and watch the RedHat case break.
ansible_sh "
  sed -i 's#^hardening_privileged_group:.*#hardening_privileged_group: sudo#' /w/tree/roles/hardening/defaults/main.yml
  if /w/venv/bin/ansible-playbook /w/groupcheck.yml \
       -e role_defaults=/w/tree/roles/hardening/defaults/main.yml \
       -e expected=wheel \
       -e '{\"ansible_facts\":{\"os_family\":\"RedHat\"}}' >/w/group.break.log 2>&1; then
    echo 'UNEXPECTED PASS: hard-coded sudo was accepted on RedHat'; exit 9
  fi
  grep -q 'resolved to' /w/group.break.log || { cat /w/group.break.log; exit 1; }
"
reset_tree
ok "a hard-coded 'sudo' group fails on RedHat (the bug this baseline fixes)"

groupcheck "/w/tree/roles/hardening/defaults/main.yml" RedHat wheel
ok "os_family=RedHat  -> wheel"
groupcheck "/w/tree/roles/hardening/defaults/main.yml" Debian sudo
ok "os_family=Debian  -> sudo"

### 5. execution environment definition -------------------------------------
step "execution-environment.yml: version 3 schema, pinned base image by digest"
ansible_sh "/w/venv/bin/python - <<'PY'
import sys, yaml
d = yaml.safe_load(open('/repo/$BASE/execution-environment.yml'))
assert d['version'] == 3, 'ansible-builder schema version must be 3'
base = d['images']['base_image']['name']
assert '@sha256:' in base, f'base image must be pinned by digest: {base}'
core = d['dependencies']['ansible_core']['package_pip']
assert core == 'ansible-core==$ANSIBLE_CORE_VERSION', f'EE ansible-core {core} does not match the version this suite tests'
assert d['dependencies']['galaxy'] == 'requirements.yml', 'EE must build collections from requirements.yml'
print('ok  version 3, base pinned by digest, ansible-core and galaxy pins consistent')
PY"

printf '\nAll Ansible baseline checks passed.\n'

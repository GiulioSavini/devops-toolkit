# Ansible Automation & Idempotency Best Practices

Designing robust, repeatable, and audit-friendly Ansible playbooks and collections.

---

## 1. Idempotency Rule

Every task must only alter the target state if the current state does not match the desired state:

```yaml
# Good: Idempotent user creation with SSH key
- name: Ensure ops user exists with authorized key
  ansible.builtin.user:
    name: ops
    state: present
    shell: /bin/bash
    groups: sudo
    append: yes

- name: Deploy authorized SSH key
  ansible.posix.authorized_key:
    user: ops
    state: present
    key: "{{ lookup('file', 'files/ops_id_ed25519.pub') }}"
```

---

## 2. Linting & Validation

```bash
# Run ansible-lint
ansible-lint site.yml
```

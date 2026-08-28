# SSH Key Management & Security Best Practices

Guidelines for generating, storing, rotating, and managing secure SSH access across teams and infrastructure.

---

## 1. Key Generation Standards

Always use modern **Ed25519** keys over legacy RSA:

```bash
# Generate Ed25519 with comment and high key derivation rounds
ssh-keygen -t ed25519 -a 100 -C "user@enterprise.internal" -f ~/.ssh/id_ed25519
```

---

## 2. SSH Client Config Optimization (`~/.ssh/config`)

```ini
Host *
    AddKeysToAgent yes
    IdentitiesOnly yes
    ServerAliveInterval 60
    ServerAliveCountMax 3
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 10m

Host bastion
    HostName jump.company.com
    User ops
    Port 2222
    IdentityFile ~/.ssh/id_ed25519

Host prod-*
    ProxyJump bastion
    User admin
    IdentityFile ~/.ssh/id_ed25519_prod
```

---

## 3. Key Rotation & Audit Policy

1. **Expiry**: Rotate personal keys every 180 days; service account keys every 90 days.
2. **Revocation**: Immediately remove unauthorized public keys from `~/.ssh/authorized_keys`.
3. **Audit**: Use automated tools (e.g. `ansible-role-manage-users`) to guarantee key synchronization.

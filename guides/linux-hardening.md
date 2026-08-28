# Linux Server Hardening & Baseline Security

Comprehensive production guide for hardening Ubuntu/Debian and RHEL/Rocky Linux servers.

---

## 1. System Updates & Minimal Packages

- Keep the system updated automatically:
  ```bash
  # Ubuntu/Debian
  sudo apt update && sudo apt upgrade -y
  sudo apt install -y unattended-upgrades fail2ban ufw libpam-pwquality

  # RHEL/Rocky Linux
  sudo dnf update -y
  sudo dnf install -y dnf-automatic firewalld fail2ban
  ```

---

## 2. Kernel Hardening (`/etc/sysctl.d/99-security.conf`)

Add the following kernel parameters to prevent common network attacks and memory exploits:

```ini
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable Source Routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Disable ICMP Redirect Acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Enable SYN Cookies protection against SYN floods
net.ipv4.tcp_syncookies = 1

# Protect against ASLR bypass
kernel.randomize_va_space = 2

# Restrict dmesg access to root only
kernel.dmesg_restrict = 1
```

Apply with:
```bash
sudo sysctl -p /etc/sysctl.d/99-security.conf
```

---

## 3. SSH Configuration Hardening (`/etc/ssh/sshd_config.d/security.conf`)

```ini
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com
```

---

## 4. Firewall Baseline (UFW / Firewalld)

```bash
# Ubuntu UFW
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw enable
```

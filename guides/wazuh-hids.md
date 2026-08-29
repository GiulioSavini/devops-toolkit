# Host Intrusion Detection with Wazuh & OSSEC

Deploying and operating Wazuh SIEM/XDR for endpoint security and compliance.

---

## 1. Wazuh Agent Deployment

```bash
# Deploy Wazuh agent on Linux
WAZUH_MANAGER="wazuh.internal.domain" WAZUH_AGENT_GROUP="production" \
  apt-get install -y wazuh-agent
systemctl enable --now wazuh-agent
```

---

## 2. Key Detection Capabilities

- File Integrity Monitoring (FIM) for critical system binaries (`/etc`, `/bin`, `/sbin`).
- Real-time log analysis and correlation against MITRE ATT&CK techniques.
- Vulnerability detection based on installed package inventory.
- Active response automated countermeasures against brute-force attacks.

---

## 3. File Integrity Monitoring

FIM is the highest-value Wazuh feature and the one most often left at defaults.
Configure it on the manager, in `/var/ossec/etc/ossec.conf`:

```xml
<syscheck>
  <frequency>43200</frequency>          <!-- baseline scan every 12h -->
  <alert_new_files>yes</alert_new_files>

  <!-- realtime: inotify watch, alerts within seconds -->
  <directories check_all="yes" realtime="yes">/etc,/bin,/sbin,/usr/bin,/usr/sbin</directories>

  <!-- whodata: ties the change to the user and process that made it -->
  <directories check_all="yes" whodata="yes">/etc/ssh,/etc/sudoers.d</directories>

  <!-- noise reduction: files that legitimately change constantly -->
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/resolv.conf</ignore>
  <ignore type="sregex">.log$|.tmp$</ignore>
</syscheck>
```

`whodata` costs more (it uses the audit subsystem) but without it an alert tells
you a file changed and nothing about who changed it — which is rarely
actionable on its own.

---

## 4. Active Response

Active response executes a countermeasure on the agent. It is genuinely useful
and genuinely dangerous: a bad rule locks you out of your own fleet.

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5710,5712</rules_id>   <!-- sshd brute force -->
  <timeout>600</timeout>            <!-- always bound the block -->
</active-response>
```

Non-negotiable precautions:

- **Always set a `timeout`.** A permanent block from an automated rule will
  eventually catch your own jump host.
- Whitelist your management ranges in `<white_list>` before enabling anything.
- Run any new active-response rule in alert-only mode for a week first.

---

## 5. Verifying the Agent Actually Reports

An agent that installed cleanly but never registered is the most common silent
failure:

```bash
# On the manager
/var/ossec/bin/agent_control -l          # every agent should be "Active"
/var/ossec/bin/agent_control -i 003      # detail for one agent

# On the agent
tail -f /var/ossec/logs/ossec.log | grep -i 'connected to server'
```

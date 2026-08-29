# Network Security & Zero-Trust Segmentation

Principles of micro-segmentation, encrypted overlays, and perimeter defense.

---

## 1. Zero-Trust Network Principles

- **Explicit Verification**: Always authenticate and authorize based on all available data points.
- **Least Privilege Access**: Limit user and service access with Just-In-Time and Just-Enough-Access (JIT/JEA).
- **Assume Breach**: Minimize blast radius by segmenting networks, encrypting end-to-end, and utilizing analytics.

---

## 2. WireGuard Overlay Network

WireGuard provides kernel-space, blazingly fast encrypted tunnels between cloud VPCs and on-premise clusters.

A WireGuard interface is defined declaratively. This is a hub (cloud gateway)
peering with an on-premise site:

```ini
# /etc/wireguard/wg0.conf  -- hub
[Interface]
Address    = 10.100.0.1/24
ListenPort = 51820
PostUp     = sysctl -w net.ipv4.ip_forward=1
# Keep the private key out of the repo: read it from a file mode 0600.
PostUp     = wg set %i private-key /etc/wireguard/hub.key

[Peer]
# on-prem site A
PublicKey           = <site-a-public-key>
AllowedIPs          = 10.100.0.2/32, 192.168.10.0/24
PersistentKeepalive = 25
```

```bash
wg-quick up wg0
systemctl enable wg-quick@wg0
wg show wg0 latest-handshakes   # verify the tunnel is actually established
```

Operational rules:

- `AllowedIPs` is the routing *and* the ACL — WireGuard drops any packet whose
  source does not match the peer's `AllowedIPs`. Keep it as narrow as the
  subnet actually requires.
- Rotate peer keys by adding the new key as a second peer, shifting traffic,
  then removing the old one. There is no in-place key rotation.
- `PersistentKeepalive` is only needed for peers behind NAT; setting it on
  every peer wastes battery and bandwidth on mobile clients.

---

## 3. Micro-Segmentation

Segmentation only reduces blast radius if the default is deny. Order of work:

1. **Inventory the flows first.** Enable flow logs (VPC Flow Logs, NSX-T IPFIX,
   `conntrack -L`) and collect at least one full business cycle — a month for
   anything touching billing or reporting.
2. **Write allow rules from the observed matrix**, source/destination/port, one
   rule per flow, each with a description naming the service and the ticket.
3. **Switch the default rule to deny last**, and only after the allow rules have
   run in log-only mode long enough to catch the quarterly jobs.

The failure mode is always the same: the default is flipped to deny before the
low-frequency flows (backup windows, DR replication, certificate renewal) have
been observed.

---

## 4. Verifying Segmentation

```bash
# From a host that should NOT reach the target:
nc -zv -w3 10.20.30.40 5432   # expect: timeout, not "connection refused"
```

A refused connection means the packet reached the host and the service declined
it — the firewall did not block anything. Only a timeout proves the rule works.

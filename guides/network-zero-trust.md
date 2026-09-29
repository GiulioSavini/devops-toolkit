# Network Segmentation and a WireGuard Hub

A WireGuard hub-and-spoke overlay plus a default-deny host firewall for the
hub, covering the gap between "everyone on the VPN can reach everything" and
actual per-identity access control. Every setting ships as a file under
[`baselines/network/`](../baselines/network/) and is validated by
[`tests/network.sh`](../tests/network.sh) against the real `nft` and `wg`
tooling, including loading the firewall ruleset onto a live nftables instance
and the WireGuard config onto a real kernel interface.

| | |
|---|---|
| Applies to | A WireGuard hub (cloud gateway) running Linux with nftables 1.0.2+ and WireGuard-capable kernel (5.6+, or `wireguard-tools`' DKMS/out-of-tree module on older kernels); spokes are any WireGuard-capable OS |
| Baseline files | [`baselines/network/`](../baselines/network/) |
| Validated by | [`tests/network.sh`](../tests/network.sh) |
| Lockout risk | **High.** The nftables default-deny policy and the WireGuard interface itself can each cut the only path to a remote hub. Use the staged rollout below; it auto-reverts |
| Last reviewed | 2026-09 |

## Threat model

What this baseline is for:

- **A flat, VPN-joined network where "on the VPN" means "trusted everywhere."**
  The classic legacy-VPN failure: one client compromise gives an attacker a
  routable path to every other host on the tunnel, because the tunnel itself
  was the only access boundary.
- **A stolen VPN credential or key used from an unexpected place.** WireGuard
  has no username/password to steal, but a copied private key is the
  equivalent — see key rotation below for what limits the blast radius.
- **An exposed management port on the hub itself.** The hub is the one host on
  this design with a public IP; everything reachable on it other than the
  WireGuard port is a target.
- **Lateral movement between two otherwise-unrelated sites that both happen to
  tunnel through the same hub.** Being a WireGuard peer of the hub is not the
  same thing as being allowed to reach every other peer's LAN.

What it is not for:

- **Zero trust, on its own.** A WireGuard hub is a transport. It authenticates
  a device (whoever holds the private key) and authorizes a route
  (`AllowedIPs`), but it says nothing about the user or the request once
  traffic lands on the routed subnet. Calling this "zero trust" and stopping
  here is exactly the gap this guide tries not to paper over — see
  "Segmentation vs identity-aware proxy" below for where the rest of the
  model lives.
- **Pod-to-pod segmentation.** That is NetworkPolicy, enforced by the CNI
  inside the cluster — see
  [Kubernetes hardening](kubernetes-hardening.md#networkpolicy). This guide
  stops at the host's own firewall and the tunnel between hosts.
- **Host hardening.** sshd, sysctl, auditd and the host's own inbound firewall
  posture are [Linux hardening](linux-hardening.md); this guide's nftables
  ruleset is additional, hub-specific policy layered on the same host, not a
  replacement for it.
- **DDoS resistance.** WireGuard silently drops packets that fail the
  cryptographic check, which helps, but a saturated link is a saturated link.
- **Confidentiality of traffic once it leaves the tunnel.** WireGuard encrypts
  hub-to-spoke; what happens on the LAN behind a spoke is that LAN's own
  problem.

## WireGuard hub design

[`baselines/network/wg0-hub.conf`](../baselines/network/wg0-hub.conf), one
`[Peer]` block per site, no shared keys anywhere.

| Decision | Why |
|---|---|
| One keypair per client/site, never shared | `AllowedIPs` is matched per peer. Two sites sharing a key are indistinguishable to WireGuard and to every log; revoking one revokes both |
| `AllowedIPs` as both the route and the ACL | WireGuard decrypts a packet only if its source address is covered by the sending peer's `AllowedIPs`, and only routes outbound traffic to a destination covered by the receiving peer's `AllowedIPs`. There is no separate "allow" step — the field IS the authorization decision |
| No `PrivateKey =` in the tracked file | Loaded via `PostUp = wg set %i private-key <path>` (or set directly on a host with no templating) so the secret never appears in a rendered-config diff, CI log, or `wg-quick strip` output |
| `PersistentKeepalive = 25` on the hub-side peer block | Needed whenever the spoke is behind NAT: without a periodic keepalive, the NAT mapping expires and the hub can no longer reach the spoke first, even though the spoke could always reach the hub. 25s is comfortably under most NAT/conntrack idle timeouts (commonly 30–300s for UDP) |
| MTU left at wg-quick's default (1420) unless a peer's path adds encapsulation | Getting this wrong does not look like "no connection" — small packets (handshake, DNS, an SSH login) work, and anything with a full-size payload silently stalls, because the resulting ICMP "fragmentation needed" has nowhere to go if it is also dropped by the firewall (this baseline's `nftables-hub.nft` does not drop it) |

Key rotation has no in-place step: add the new keypair as a second `[Peer]`
block with the *same* `AllowedIPs`, roll the matching private key out to that
one client, confirm `wg show wg0 latest-handshakes` advances on the new
public key, then delete the old block and `wg syncconf`. Editing a
`PublicKey` value in an existing block is indistinguishable from an attacker
swapping the key mid-flight, with no window to confirm the right client
answered.

A shared key across clients is unmanageable for the same reason a shared SSH
key is: revocation means rotating every holder at once, and the log for
"who connected" says nothing more specific than "someone with the key."

## The nftables policy

[`baselines/network/nftables-hub.nft`](../baselines/network/nftables-hub.nft):
default-deny on all three base chains, one table, named sets, and per-site
forward rules.

This nftables ruleset is the hub-specific analogue of
[`baselines/linux/nftables/host-filter.nft`](../baselines/linux/nftables/host-filter.nft)
in [Linux hardening](linux-hardening.md#host-firewall); read that guide's
"Host firewall" section for the ICMP, IPv6 neighbour-discovery and DHCP
caveats, which apply here unchanged and are not repeated below.

| Decision | Why |
|---|---|
| `table inet wg_hub`, declared then deleted, never `flush ruleset` | Loading the file is one atomic transaction (a syntax error changes nothing), and it only ever touches its own table — a hub that also runs Docker or a Kubernetes CNI keeps their tables intact. `tests/network.sh` proves this by pre-creating an unrelated table and confirming it survives the load, not just by reading the comment |
| Management ranges in a named set (`mgmt_bastion`) | One place to update when the bastion's address changes, and the rule reads as policy ("who may reach sshd") rather than a bare IP literal buried in a match expression |
| A named set pair PER SITE in the forward chain (`site_a_tunnel`/`site_a_lan`, `site_b_tunnel`/`site_b_lan`, …), not one shared "any tunnel peer / any routed site" pair | This is the actual segmentation control. A single shared set pair looks like segmentation in a comment but is not one in practice: site A's tunnel address matches the one `tunnel_peers` set and site B's LAN matches the one `routed_sites` set, so site A is forwarded straight into site B. One set pair per site is what makes "site A cannot reach site B through this hub" true rather than merely documented as true — see the control in `tests/network.sh` that reproduces the collapsed version and confirms it would have been caught |
| `counter log prefix "nft-*-drop: "` on every default-drop | A drop with no counter and no log line is unfalsifiable — you cannot tell "nothing is being blocked" from "the rule silently isn't there" |
| `egress_v4` starts empty | nftables rejects `elements = { }` outright, so an empty set is simply declared with no elements — and an empty destination set fails closed: forgetting to populate it is a timeout for the hub's own outbound HTTP/HTTPS, not a silent bypass |

## Forwarding sysctls

[`baselines/network/sysctl.d/99-wireguard-forwarding.conf`](../baselines/network/sysctl.d/99-wireguard-forwarding.conf),
applied with `sysctl --system`, **hub only** — spokes route their own
traffic into the tunnel and never forward other hosts' traffic through it.

[Linux hardening](linux-hardening.md#kernel-parameters) deliberately leaves
`net.ipv4.ip_forward` unset in its generic baseline, precisely because
setting it to `0` fleet-wide — the common "CIS-compliant" mistake — breaks
every router, NAT gateway, Docker host and, not incidentally, this WireGuard
hub. This file is the explicit, role-scoped override for the one class of
host where forwarding is the entire point.

| Key | Value | Why |
|---|---|---|
| `net.ipv4.ip_forward` | `1` | Required to forward tunnel traffic to the routed LAN at all |
| `net.ipv6.conf.all.forwarding` | `1` | Same, for any site that routes IPv6 through the hub |
| `net.ipv4.conf.all.rp_filter` / `.default.rp_filter` | `2` (loose) | Strict mode (`1`, the single-homed default) drops replies that legitimately arrive on a different interface than the request went out on — exactly what happens on a router forwarding between the tunnel and the LAN for the same destination. Loose mode still drops obviously spoofed source addresses |

Do not set these with `sysctl -w` in `wg0.conf`'s `PostUp`: that only lasts
until reboot, silently no-ops if anything earlier in the file has a syntax
error, and gives you no single place to answer "is this host supposed to be
forwarding." `tests/network.sh` checks these keys exist under this host's
own `/proc/sys` for the same documented reason
[`tests/linux.sh`](../tests/linux.sh) does: `net.ipv4.*`/`net.ipv6.*` keys are
per network namespace, so a container's `/proc/sys` proves nothing about the
host, and a typo here is not an error at boot — `systemd-sysctl` logs it and
the setting is simply absent.

## Segmentation vs identity-aware proxy

Being a WireGuard peer answers one question: *can this device's traffic reach
this subnet at all.* It does not answer *should this specific request, from
this specific user, to this specific service, be allowed right now* — that
is a separate control plane, and conflating the two is how "zero trust" ends
up meaning "flat network with encryption."

| Layer | What it decides | Where it lives |
|---|---|---|
| WireGuard `AllowedIPs` | Which subnets a device may reach at all | This guide |
| Host firewall (nftables) | Which ports on which hosts, from which sources | This guide, [Linux hardening](linux-hardening.md) |
| mTLS / SPIFFE / an identity-aware proxy | Which *workload identity* may call which *service*, independent of network path | Not covered here — see your service mesh or proxy's own hardening notes |
| NetworkPolicy | Which *pod* may talk to which pod, inside the cluster | [Kubernetes hardening](kubernetes-hardening.md#networkpolicy) |

A VPN cannot do what the third row does: it has no concept of a workload
identity, cannot make a per-request decision, and (with a shared tunnel
subnet) cannot even see past "this packet came from a routable address" to
ask whether the calling service should be making this particular call. If
the actual requirement is "service A may call service B's API, nothing else
on site A's LAN may," a route to the LAN is the wrong tool regardless of how
tightly `AllowedIPs` is scoped.

## DNS and split-horizon traps

- **A resolver reachable over the tunnel and reachable directly answer
  differently on purpose** (split-horizon DNS), and a client that queries
  whichever resolver its OS picked first will get the wrong answer for
  internal names when off the VPN and the wrong answer for public names when
  the tunnel's resolver is used for everything. Scope DNS routing explicitly:
  only the internal zones should be forced through the tunnel resolver.
- **The output chain's `dns_resolvers` set is the hub's OWN egress allowlist**
  for DNS the hub itself makes (health checks, package installs), not a
  general-purpose recursive resolver for spokes. If spokes are meant to
  resolve internal names through the hub, that is a separate, deliberate
  `udp/tcp dport 53` forward-chain rule scoped to the resolver's actual
  address — do not widen the existing output rule for it, and do not assume
  it already covers spoke traffic (it is the `output` hook, not `forward`).
- **A client with a full-tunnel `AllowedIPs = 0.0.0.0/0`** (see the note at
  the bottom of `wg0-hub.conf` — none is shipped by default) also needs its
  DNS traffic routed deliberately, or it leaks queries to whatever resolver
  the local network hands out over DHCP while its actual internet traffic
  goes through the tunnel.

## Rollout

Order matters. Anything that can cut remote access goes last, after its
allow rules are proven, exactly as in
[Linux hardening's rollout](linux-hardening.md#rollout).

1. **Forwarding sysctls first**, on the hub only. This does not affect
   reachability of the hub itself and needs to be in place before any
   traffic is expected to forward.
2. **Bring up WireGuard with `wg-quick up wg0`** and confirm
   `wg show wg0 latest-handshakes` advances for a real spoke before touching
   the firewall. At this point the hub has no host firewall of its own yet —
   acceptable only because the next step is immediate.
3. **nftables, staged with an armed auto-revert**, the same pattern as
   [Linux hardening's nftables rollout](linux-hardening.md#nftables-rollout):

   ```bash
   # 1. Put your real bastion address(es) and site subnets into
   #    mgmt_bastion / site_*_lan / site_*_tunnel first.
   # 2. Arm a revert before loading anything:
   sudo systemd-run --on-active=10min --unit=nft-hub-revert nft delete table inet wg_hub
   # 3. Check, then load:
   sudo nft -c -f nftables-hub.nft && sudo nft -f nftables-hub.nft
   # 4. From a session over the WireGuard tunnel (not the console you are
   #    typing in), confirm SSH to the bastion range still works AND that a
   #    site A host can still reach its own LAN. If both work:
   sudo systemctl stop nft-hub-revert.timer
   ```

   The revert deletes only `inet wg_hub`, never `flush ruleset` — the hub may
   also run Docker or a CNI, and a full flush takes their tables down with
   it until their own daemon reprograms it.
4. **Verify segmentation before calling it done**: from site A, attempt to
   reach an address on site B's LAN through the hub. It must time out (see
   Verification below) — if it succeeds, the forward-chain sets in
   `nftables-hub.nft` were not populated per-site as shipped.

## Verification

```bash
# WireGuard: the tunnel is actually up, not just configured
sudo wg show wg0
sudo wg show wg0 latest-handshakes   # a stale/zero handshake means no live peer

# firewall: the ruleset the kernel actually holds. The counters are anonymous
# (attached to the drop rules, not declared as named counter objects), so
# they show up inline here — NOT in `nft list counters`, which only lists
# named counter objects and would print nothing for this ruleset.
sudo nft list table inet wg_hub   # "nft-*-drop" packet counts should be increasing, not static at 0

# routing decision for a specific destination, as the kernel would make it
ip route get 192.168.10.5

# segmentation: from a site A host, a site B address must time out —
# NOT be refused. A "connection refused" means the packet reached something
# that declined it (routed, not blocked); only a timeout proves the forward
# chain dropped it before it ever reached site B.
nc -zv -w3 192.168.20.10 22

# reachability that SHOULD work, from the same site A host, must succeed
nc -zv -w3 192.168.10.5 22
```

## Rollback

| Change | Undo |
|---|---|
| nftables ruleset | `nft delete table inet wg_hub` (never `flush ruleset` on a hub that also runs Docker/a CNI) |
| WireGuard interface | `wg-quick down wg0`; the tunnel drops immediately, spokes fail over to nothing unless a backup path exists |
| A single compromised/rotated peer | Remove its `[Peer]` block, `wg syncconf wg0 <(wg-quick strip wg0.conf)` — this drops only that peer's session, not the interface |
| Forwarding sysctls | Delete `99-wireguard-forwarding.conf`, `sysctl --system`. Existing forwarded connections are not retroactively torn down; new ones stop |

## Common failure modes

- **A shared WireGuard key across multiple "clients."** Revocation means
  rotating everyone at once, and the connection log cannot say which of them
  actually connected.
- **The forward chain built from one shared set pair instead of one pair per
  site.** Parses fine, loads fine, and quietly lets every spoke reach every
  other spoke's LAN — the exact bug this baseline's own test suite reproduces
  and rejects.
- **`net.ipv4.ip_forward = 0` inherited from a generic hardening baseline**
  applied fleet-wide, breaking the hub's entire reason for existing. See
  [Linux hardening's kernel parameters section](linux-hardening.md#kernel-parameters).
- **Believing "connection refused" proves a firewall rule works.** It proves
  the opposite: the packet reached a host and a service declined it. Only a
  timeout demonstrates a drop.
- **No `PersistentKeepalive` on a peer behind NAT.** The tunnel looks
  configured and shows a stale handshake; the NAT mapping expired and the hub
  can no longer reach that spoke first.
- **Calling this setup "zero trust" and stopping.** A device that is a valid
  WireGuard peer of a routed subnet can still reach every service on it with
  no further check — see "Segmentation vs identity-aware proxy" above.
- **The firewall (or a routing change) applied from the only session that
  could have fixed it**, with no timed revert armed first.

## Control mapping

Section to control families. Benchmark section numbers are deliberately not
cited: verify them against the exact benchmark version you are audited on.

| This guide | CIS Benchmark | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Annex A | NIS2 Art. 21(2) |
|---|---|---|---|---|
| WireGuard hub design (per-peer keys, AllowedIPs, rotation) | CIS Distribution Independent Linux | AC-4, AC-17, SC-8, SC-13, IA-3 | A.8.20, A.8.24 | (e), (h), (j) |
| nftables policy (default-deny, own table, per-site sets) | same | SC-7, AC-4 | A.8.20, A.8.22 | (e) |
| Forwarding sysctls | same | CM-6, SC-7 | A.8.9, A.8.20 | (e) |
| Segmentation vs identity-aware proxy | same | AC-3, AC-4, SC-7 | A.8.3, A.8.22 | (e), (i) |
| DNS / split-horizon | same | SC-20, SC-21 | A.8.20 | (e) |

## References

- [`wg(8)`](https://man7.org/linux/man-pages/man8/wg.8.html) and
  [`wg-quick(8)`](https://man7.org/linux/man-pages/man8/wg-quick.8.html)
- [WireGuard protocol whitepaper](https://www.wireguard.com/papers/wireguard.pdf)
  for why `AllowedIPs` is both the routing and the cryptokey-routing decision
- [`nft(8)`](https://www.netfilter.org/projects/nftables/manpage.html) and the
  [nftables wiki](https://wiki.nftables.org/)
- [Linux kernel sysctl documentation](https://docs.kernel.org/admin-guide/sysctl/index.html)
- [Linux hardening](linux-hardening.md) for the host firewall pattern this
  ruleset follows, and the generic sysctl baseline this one intentionally
  overrides
- [Kubernetes hardening](kubernetes-hardening.md#networkpolicy) for
  pod-to-pod segmentation, which is out of scope here
- [SPIFFE/SPIRE](https://spiffe.io/docs/latest/spiffe-about/overview/) as one
  concrete identity-aware workload-identity system, for the layer a VPN does
  not provide
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) — the
  authoritative section numbers for your audited version

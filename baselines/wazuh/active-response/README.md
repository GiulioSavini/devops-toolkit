# Active response

Wazuh can run a command on an agent when a rule fires. It is the most dangerous
feature in the product, and it is off in this baseline.

## Why it is off

An automated block keyed on `srcip` is a **denial-of-service primitive pointed
at your own infrastructure**, for three reasons that all show up in the first
week:

1. **The source address is frequently not the attacker's.** Behind a load
   balancer, a NAT gateway, a CDN or an ingress controller, `srcip` is a shared
   address. Blocking it blocks everyone behind it.
2. **The first thing it blocks is usually a monitoring probe.** A health check
   that fails authentication, a scanner you paid for, a backup agent with a
   stale credential.
3. **A spoofable trigger is a remote block primitive.** Any log line an attacker
   can influence — a hostname, a username, an HTTP header reflected into a log
   — becomes a way to make you block an address of their choosing.

The failure mode is not "it did nothing". It is an outage caused by your own
security tooling, at a moment when everybody assumes the security tooling is the
one thing that is helping.

## How to enable it, when you decide to

One action, one rule, one agent group, in this order:

1. **Run the detection for a month with no response.** Count how often the rule
   fires and look at every `srcip`. If you would not have been willing to block
   each of them by hand, the rule is not ready.
2. **Add an allow list first**, and put in it: your management ranges, the
   monitoring system, the load balancers, the NAT egress addresses, the CI
   runners, and the VPN concentrator.
3. **Start with `timeout` set, never with a permanent block.** A 300-second
   block that was wrong recovers on its own; `iptables -A` that was wrong is a
   ticket at 03:00.
4. **Scope by `<rules_id>`, not by `<level>`.** A level-based response fires on
   every future rule anybody writes at that level, including the one added by
   the next ruleset update.
5. **Alert on every response taken**, and review them weekly. A response nobody
   reviews is a change to the firewall nobody reviewed.

The configuration, for the manager's `ossec.conf`, once all of the above is
true:

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <!-- One specific rule. Never <level>. -->
  <rules_id>100021</rules_id>
  <timeout>300</timeout>
</active-response>
```

And in the agent's `ossec.conf`, the addresses that must never be blocked:

```xml
<global>
  <white_list>127.0.0.1</white_list>
  <white_list>10.0.0.0/8</white_list>
  <white_list>203.0.113.10</white_list> <!-- monitoring -->
</global>
```

`tests/wazuh.sh` asserts that this baseline ships **no** enabled
`<active-response>` block, so enabling one is a deliberate, reviewable change
rather than something that arrived with a config update.

## What to use instead, most of the time

Alert, and let a human decide — or respond somewhere with a smaller blast
radius: revoke a session, rotate a credential, isolate the host (see
[incident response](../../../guides/incident-response.md)). Blocking an address
treats the symptom and is the option most likely to hurt you.

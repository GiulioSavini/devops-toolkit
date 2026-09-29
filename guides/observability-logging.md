# Observability and Logging

A baseline for the metrics, alerting and telemetry-egress layer: SLO recording
and burn-rate alert rules, an Alertmanager routing tree with real inhibition,
and an OpenTelemetry Collector configuration that is the single point
telemetry leaves a host or cluster through. Every setting ships as a file
under [`baselines/observability/`](../baselines/observability/) and is
validated by [`tests/observability.sh`](../tests/observability.sh) against
the real `promtool`, `amtool` and `otelcol-contrib` binaries, including a
live Alertmanager instance for the inhibition proof.

| | |
|---|---|
| Applies to | Prometheus 3.x (`promtool`), Alertmanager 0.28+, OpenTelemetry Collector Contrib 0.116+ |
| Baseline files | [`baselines/observability/`](../baselines/observability/) |
| Validated by | [`tests/observability.sh`](../tests/observability.sh) |
| Lockout risk | **Low for remote access — nothing here can lock you out of a host.** The real risk is silent, not a lockout: a route that resolves to the wrong receiver, or an alert that never fires, fails with no error message at all. The verification steps below exist because "the config parsed" and "the alert works" are different claims |
| Last reviewed | 2026-09 |

## Threat model

What this baseline is for:

- **Noticing a service degrading before a customer files a ticket**, via SLO
  error-budget burn-rate alerting rather than a single noisy threshold.
- **Getting the right alert to the right human with enough context to act**,
  and not to the wrong channel, or to everyone, or nowhere — routing,
  grouping and inhibition exist to make the pager trustworthy enough that
  people do not learn to ignore it.
- **One controlled, auditable point where telemetry leaves the host or
  cluster**, so a span attribute or log field carrying a secret or a raw PII
  value does not silently end up in a third-party backend's retention.
- **Diagnosing an incident after the fact** by correlating a trace ID across
  logs, metrics and traces, at whichever of the three actually has the
  answer for the smallest cost.

What it is not for:

- **A SIEM.** This pipeline is built for operational health — is the service
  meeting its SLO, is a node about to OOM — not for security event
  correlation, threat hunting or intrusion detection. Those have different
  retention, query and alerting shapes; see
  [Wazuh HIDS](wazuh-hids.md).
- **A substitute for the audit trail.** A burn-rate alert tells you a
  service's error rate crossed a line; it does not tell you which identity
  did what. That is what an audit log is for, and an audit log that never
  leaves the host it was written on is not evidence — see the "Audit trail"
  section of [Linux hardening](linux-hardening.md) and "API server audit" in
  [Kubernetes hardening](kubernetes-hardening.md). Both make the same point
  this guide makes about the OpenTelemetry Collector below: the value is in
  getting the record off the box that could be compromised, not in writing
  it in the first place.
- **A place to keep secrets or full PII.** Metrics, logs and traces are a
  leak vector for both, not a vault; see
  [Secrets management](secrets-management.md) for where credentials actually
  belong, and "Logs, PII and secrets" below for what that means for this
  pipeline specifically.
- **Compliance evidence by itself.** The control mapping at the end says
  which control families a section touches; it is not an audit artifact.

## Metrics, logs and traces: pick the cheapest one that answers the question

The three signals answer different questions and cost different amounts, and
reaching for the wrong one is how an observability budget disappears:

| Signal | Answers | Typical cost driver | Gets expensive when |
|---|---|---|---|
| Metrics | "How much / how often / is it within budget" | Number of active time series (cardinality), not event volume | A label carries an unbounded value — see "Cardinality" below |
| Logs | "What exactly happened, in this one case" | Bytes stored × retention | Every request is logged at `info`, or a stack trace is logged per retry |
| Traces | "Where did the time go, across services, for this one request" | Spans × attributes, usually sampled | 100% sampling on a high-QPS path with rich attributes |

A single request landing in all three at once is normal and correct — a
`5xx` shows up as one increment on a counter, one structured log line, and
one span with an error status — but reaching for a trace to answer "how
often" (a metrics question) or for a metric to answer "what exactly
happened to this one customer's request" (a logs question) means paying the
more expensive signal's cost for the cheaper signal's job.

## SLOs and multi-window, multi-burn-rate alerting

[`prometheus/slo-rules.yml`](../baselines/observability/prometheus/slo-rules.yml)
(recording rules) and
[`prometheus/slo-alerts.yml`](../baselines/observability/prometheus/slo-alerts.yml)
(the alerts themselves), unit-tested against synthetic traffic by
[`prometheus/slo-alerts_test.yml`](../baselines/observability/prometheus/slo-alerts_test.yml).
Both files carry extensive comments of their own on the arithmetic; this
section covers why the approach exists at all, and what actually proving it
took.

### Why not a single "error rate > X% for 10m" alert

A single threshold is always wrong in one of two directions:

- **Set it sensitive enough to catch a real incident fast**, and normal
  traffic noise crosses it often enough that the alert gets muted, which is
  the same as not having it.
- **Set it high enough to stay quiet on noise**, and a real incident has to
  burn a large fraction of the error budget before it pages — by which point
  the damage, and the compliance conversation about the missed SLO, is
  already done.

The [Google SRE workbook's multi-window, multi-burn-rate
approach](https://sre.google/workbook/alerting-on-slos/) (what
`slo-alerts.yml` implements) uses a PAIR of windows per severity instead: a
long window that decides whether a burn is real, and a short window — about
1/12th of the long one — that confirms it is *still* happening right now.

| | Long window | Short window | Budget spent | Action |
|---|---|---|---|---|
| Fast burn | 1h | 5m | 2% in 1h | page |
| | 6h | 30m | 5% in 6h | page |
| Slow burn | 1d | 2h | 10% in 1d | ticket |
| | 3d | 6h | 10% in 3d | ticket |

The long window suppresses noise: a 30-second blip does not move a 1-hour
average enough to cross 14.4x the normal burn rate, so nobody pages for it.
The short window bounds how long the alert stays firing after the incident
ends: without it, a 1-hour window keeps paging for the better part of an
hour after the problem is already fixed, and the on-call learns to ignore
the "still firing" page along with the real ones.

### Recording rules, not six copies of the same expression

`slo-rules.yml` records one ratio per window (5m, 30m, 1h, 2h, 6h, 1d, 3d)
rather than inlining `rate(...)` six times per alert. The comment in that
file gives the full reasoning; the short version is that six inline copies
of the same expression are six places to fix a status-code matcher
inconsistently, and a 3-day rate over a busy counter is expensive to
recompute per alert evaluation instead of once per recording interval.

### The check that actually proves the arithmetic: `promtool test rules`

`promtool check rules` only proves the PromQL parses and every reference
resolves — it says nothing about whether `ErrorBudgetBurnFast` fires when it
should. `slo-alerts_test.yml` feeds synthetic `http_requests_total` series
into the real rules and asserts each alert fires when it should and stays
quiet when it should not, including a case built specifically to isolate the
fast alert's 1h/5m branch from its 6h/30m branch: 270 minutes of clean
traffic followed by a 90-minute incident, sized so the 1-hour window sees an
undiluted 2% error ratio (comfortably past its 1.44% bar) while the 6-hour
window, diluted by 4.5 clean hours, stays under its own 0.6% bar. A single
constant error ratio held for the whole series would have cleared both
branches' thresholds identically and proven nothing about which threshold
gates which window — this is the difference between testing that an alert
*can* fire and testing that its *specific* multi-window logic is correct.

That branch-isolation case is also what caught a real problem: the first
version of it used a 30-minute incident ending exactly at the evaluation
time, and `promtool test rules` gave a **different** answer across separate
runs of the identical file — 2.801% one run, 2.901% the next, with no file
changes in between. The cause: `slo-rules.yml` and `slo-alerts.yml` are two
different rule files, and Prometheus gives no ordering guarantee between
rule groups in different files at the same evaluation tick, so the alert can
read a recording rule's value from one tick behind. Which one a given
process picks is effectively arbitrary. The fix was not a retry loop; it was
widening the incident so the ratio plateaus well before the window edges the
test cares about, so whichever tick gets read renders the same number. Keep
this in mind for any alert that reads a recording rule from a different
file: a test (or a real incident) that lands exactly on a fast-moving
transition can observe either side of it.

`tests/observability.sh` also runs a corruption control that raises the
`14.4` burn-rate multiplier to `144` and asserts the unit tests then FAIL —
proving the test file is actually pinned to that specific constant, not just
exercising the file without checking its numbers.

## Alert routing, grouping and inhibition

[`alertmanager/alertmanager.yml`](../baselines/observability/alertmanager/alertmanager.yml).
The severity vocabulary is the one the alert rules actually emit —
`severity: page` for `ErrorBudgetBurnFast`, `severity: ticket` for
`ErrorBudgetBurnSlow` and the two `monitoring_meta` alerts — not a generic
`critical`/`warning` pair invented for this file. A routing tree written
against label values the alerts don't set is a routing tree that silently
matches nothing.

| Route | Matches | Receiver | `group_wait` | `group_interval` | `repeat_interval` |
|---|---|---|---|---|---|
| root (fallback) | anything else | `default-fallback` | 30s | 5m | 4h |
| page | `severity="page"` | `page-slack-critical` | 10s | 2m | 1h |
| ticket | `severity="ticket"` | `ticket-queue` | 5m | 30m | 24h |

The three timing knobs are chosen deliberately, not left at their defaults
(the comments in the file give the full reasoning):

- `group_wait` is how long a *new* group waits before its first
  notification, to let near-simultaneous alerts (the fast and slow burn
  firing together) collapse into one message instead of paging twice for one
  cause. Short on the page route (10s) because every extra second here is a
  second added to detection time; long on the ticket route (5m) because
  nothing there is urgent enough to justify paying that cost.
- `group_interval` is how long an *already-notified* group waits before a
  notification about newly added alerts. Short on the page route so a
  second rule crossing its threshold rides along with the existing incident
  quickly; long on the ticket route so it doesn't retrigger a queue entry
  every time a new rule joins.
- `repeat_interval` is how long a still-firing alert waits before being
  re-sent. 1h on the page route assumes a page that goes unacknowledged for
  an hour was missed, not that the incident is being worked quietly; 24h on
  the ticket route because re-notifying hourly just trains whoever owns the
  queue to mute the channel.

### Inhibition: a firing page suppresses its matching ticket, not everything

```yaml
inhibit_rules:
  - source_matchers: [severity = "page", slo = "availability"]
    target_matchers: [severity = "ticket", slo = "availability"]
    equal: ["job", "slo"]
```

If the fast burn-rate alert is already firing for a job, the slow burn-rate
alert for the *same* job is redundant noise — the page already means someone
is looking at that job's error rate. `equal: ["job", "slo"]` is what keeps
this scoped: a checkout page must never suppress a search ticket.

`amtool config routes test` resolves a label set to a receiver against the
config file alone, which is enough to prove routing but not inhibition —
inhibition compares two live alerts against each other, which a static
config check cannot do. `tests/observability.sh` proves it for real: it
starts an actual Alertmanager container against this file, posts a page
alert and a ticket alert for `job=checkout` through `amtool alert add`, and
reads the `/api/v2/alerts` response back to confirm the ticket alert is
reported `suppressed` with `inhibitedBy` pointing at the page alert's
fingerprint. A second pair — a ticket alert for `job=billing` with no
matching page alert — proves the `equal` scoping isn't leaking: that alert
must stay `active`.

### Secrets: `_file`, never inline

Every receiver credential in the file is a `_file` path
(`api_url_file` on the Slack receivers, `url_file` on the webhook receiver),
never a literal `api_url:` or `url:`. Two reasons: the file is meant to be
read — by reviewers, by this guide, by whoever debugs routing at 03:00 — and
a bearer credential inlined in a file that ends up in git history and
ConfigMaps defeats that; and `amtool check-config` and
`tests/observability.sh` both read this file as part of validating it, so a
secret that must never appear in a diff or a test log cannot live in the
file that diff and log come from.

Getting this right took one real correction: Alertmanager's Slack receiver
field for a `_file`-based webhook URL is `api_url_file`, not
`slack_api_url_file` — that longer name only exists on the *global* config
block, as a fleet-wide default. `amtool check-config` caught the mismatch
immediately (`field slack_api_url_file not found in type config.plain`), not
after a deploy. A second correction: the webhook receiver's URL cannot be an
environment-substituted placeholder like `${WEBHOOK_URL}` left in the file
verbatim, because Alertmanager validates it as a real URL at parse time
(`unsupported scheme ""`) — it has to be `url_file` too, resolved to an
actual secret file at deploy time rather than templated into the YAML.

Every alert also needs a runbook link and an implicit owner (the receiver it
routes to). `slo-alerts.yml` sets `runbook_url` on every alert; an alert
with no runbook and no clear owner is a dashboard panel wearing a pager,
and the honest fix is to make it one.

## The OpenTelemetry Collector as the only egress point

[`otel-collector/config.yaml`](../baselines/observability/otel-collector/config.yaml).
Every trace, metric and log leaving a host or cluster passes through this one
collector, which is what makes redaction and rate control possible at a
single point instead of duplicated into every application's SDK config.

| Component | Role |
|---|---|
| `receivers.otlp` | The only ingest path — no legacy Jaeger/Zipkin receivers, one wire format to secure |
| `processors.memory_limiter` | See below — this is the one that matters most |
| `processors.attributes/redact` | Deletes `authorization` / `http.request.header.authorization` / `db.statement`; hashes `enduser.id` so per-user correlation survives without storing the raw identifier |
| `processors.batch` | Bounds worst-case export latency (`timeout: 5s`) without waiting to fill `send_batch_size` on quiet pipelines |
| `exporters.otlphttp` / `exporters.prometheusremotewrite` | TLS to the next hop — the same data the redaction processor just spent effort scrubbing, so cleartext transport would undo that work at the network layer |

### `memory_limiter`: the control that stops monitoring from taking down the monitored

Every processor after `memory_limiter` in a pipeline buffers data in memory.
A retry storm, or a client suddenly emitting ten times its normal trace
volume, grows that buffer without bound. A collector with no
`memory_limiter` does not degrade gracefully under that load — it gets
OOM-killed by the kernel, and on a node that is also running the workload it
monitors, that is the collector taking the node down with it, at the exact
moment (an incident) it is needed most. `limit_mib` has to sit comfortably
under the container or pod's memory limit, not equal to it: the Go
runtime's own overhead and GC headroom live above that number.

### `service.pipelines` is the only thing that activates a component

A receiver, processor or exporter defined at the top level of the file does
nothing until its name also appears in a pipeline under `service.pipelines`.
This is the trap `otelcol validate` was checked against directly, empirically,
rather than assumed:

| Broken copy | `otelcol validate` result |
|---|---|
| A processor with an unknown config key (`bogus_unknown_key: true` under `memory_limiter`) | **Rejected** — `'' has invalid keys: bogus_unknown_key` |
| A processor (`resource/unused`) defined at the top level and never referenced from any pipeline | **Accepted, exit 0** |

The second row is a documented gap, not an oversight papered over: this
build of `otelcol validate` (Collector Contrib 0.116.1) parses and validates
every component's own configuration, but it does not check that every
defined component is actually used. Renaming a processor everywhere except
one pipeline that still references the old name produces the identical
failure mode in reverse — the processor under the *old* name silently drops
out of that pipeline, `validate` says nothing, and the collector starts
normally while quietly running fewer processing steps than the file appears
to configure. `tests/observability.sh` asserts this gap the way it actually
behaves (exit 0), specifically so a future Collector version that starts
catching it breaks the test — forcing this paragraph to be corrected instead
of being wrong forever. There is no substitute today for reading
`service.pipelines` by eye against the components defined above it.

## Cardinality: the failure mode that kills Prometheus

Every unique combination of label values on a metric is a distinct time
series that Prometheus keeps in memory. A label that carries a user ID, a
request ID, a raw URL path with an embedded ID, or a customer email turns a
metric with a handful of expected series into one with millions — and unlike
a slow query, this failure mode does not politely degrade; it exhausts
memory and takes the whole instance down, alerting rules included.

Detecting it before it exhausts memory:

```promql
# Series count per metric name, highest first — the metric with an
# unexpectedly large number here is the one with a high-cardinality label.
topk(10, count by (__name__) ({__name__=~".+"}))

# Prometheus's own view of how expensive each metric currently is.
prometheus_tsdb_symbol_table_size_bytes
topk(10, scrape_series_added)
```

The OpenTelemetry Collector's `attributes/redact` processor in this baseline
takes the same problem from the other direction, at the point telemetry
enters the pipeline rather than after it has already caused damage:
`enduser.id` is hashed rather than dropped specifically so a query that
needs "how many distinct users hit this error" still works, capped at one
fixed-width value per user instead of an unbounded one.

## Logs, PII and secrets

Logs and trace/log attributes are a leak vector for the same things
[Secrets management](secrets-management.md) exists to keep out of git:
credentials, tokens, and full request/response bodies that happen to carry
them. Once a value is in the log or trace pipeline it is in the backend's
storage, its backups, and everyone with read access to that backend — there
is no equivalent of `git revert` for a log line already shipped and indexed.

The rule this baseline enforces at the collector (`attributes/redact`
in `otel-collector/config.yaml`) rather than hoping every application gets
right on its own: delete `authorization` headers and raw SQL statements
outright; hash identifiers that are legitimately useful for correlation
instead of deleting them. Deleting at the collector, not downstream, matters
because the collector is the last point with the *original* attribute name
available — a processor further downstream only sees whatever survived, and
cannot tell what it already lost.

Retention is a cost and liability decision as much as a technical one: the
longer PII-adjacent data is kept, the larger the blast radius of a backend
compromise and the more expensive a "delete this customer's data" request
becomes to honour. Set log and trace retention by what the org can
justify keeping, not by the backend's default.

### The audit log is a different thing and lives somewhere else

This guide's logs are operational: what a service did, for diagnosing it.
The audit trail — who did it, from where, with which credential — is a
separate, security-critical log covered in
[Linux hardening](linux-hardening.md#audit-trail) and
[Kubernetes hardening](kubernetes-hardening.md#api-server-audit), and both
make the same point that applies here too: a log that stays on the host or
node that produced it is not evidence, because an attacker who reaches that
host can edit it before anyone reads it, and a Secret must never be logged
at `Request` level or above — the Kubernetes audit policy in this baseline's
sibling guide records *that* a Secret was read, never its contents, for
exactly that reason. This pipeline's OpenTelemetry Collector is one
reasonable way to get the audit log off the host in real time; it does not
replace the audit log's own retention and access-control requirements.

## Dashboards that answer a question

A dashboard with every metric a service exposes is not more useful than one
with three — it is a wall nobody reads during an incident, because finding
the one relevant panel among forty costs time that an incident does not
have. Build each dashboard to answer one specific question ("is checkout
inside its error budget right now", "which downstream call is slow"), and
link to the runbook and the query behind the number, not just the number
itself. If a panel has never been looked at during an actual incident, that
is a sign to remove it, not to add another one next to it.

## Rollout

1. **Recording and alerting rules first, alone.** Load `slo-rules.yml` and
   `slo-alerts.yml` into a Prometheus instance with `--lint-fatal` already
   run in CI (see Verification). Watch for a day before wiring Alertmanager
   to anything real — confirm the recorded ratios look sane against actual
   traffic before trusting an alert built on top of them.
2. **Alertmanager, routing to a low-stakes receiver first.** Point
   `page-slack-critical` and `ticket-queue` at a test channel, not the real
   pager, until the routing tree and inhibition have been watched fire on a
   real (or deliberately synthetic) alert.
3. **Cut the receivers over to the real pager and ticket queue** once
   routing is confirmed, and only then remove the test-channel routing.
4. **OpenTelemetry Collector last**, and only after `attributes/redact` has
   been checked against a sample of real traffic in a non-production
   environment — confirm the attribute names it targets actually match what
   the real SDKs emit before it is the only egress path telemetry has.

## Verification

```bash
# Rule files parse, with no dangling references or duplicate identities.
# --lint-fatal is required: without it, promtool prints "duplicate rule(s)
# found" and still exits 0.
promtool check rules --lint-fatal slo-rules.yml slo-alerts.yml

# The burn-rate alerts actually fire on synthetic traffic, and stay quiet
# when they should. This is the check that proves the arithmetic, not just
# the syntax.
promtool test rules slo-alerts_test.yml

# Alertmanager config parses, with its routes, inhibit rules and receivers.
amtool check-config alertmanager.yml

# A label set actually resolves to the receiver you expect.
amtool config routes test --config.file=alertmanager.yml \
  severity=page job=checkout slo=availability
# expect: page-slack-critical

# The collector config is valid, and every component you expect is wired
# into a pipeline (validate will not tell you about the second half of
# that sentence — read service.pipelines yourself).
otelcol-contrib validate --config file:/etc/otelcol/config.yaml
```

Proving inhibition needs a running Alertmanager, not just `check-config`:

```bash
alertmanager --config.file=alertmanager.yml &
amtool alert add alertname=ErrorBudgetBurnFast severity=page job=checkout slo=availability
amtool alert add alertname=ErrorBudgetBurnSlow severity=ticket job=checkout slo=availability
curl -s localhost:9093/api/v2/alerts | jq '.[] | {alertname: .labels.alertname, state: .status.state, inhibitedBy: .status.inhibitedBy}'
# the ErrorBudgetBurnSlow entry must show state "suppressed" and
# inhibitedBy containing the ErrorBudgetBurnFast alert's fingerprint.
```

## Rollback

| Change | Undo |
|---|---|
| Recording/alerting rules | Remove the two files from `rule_files:` and reload Prometheus (`kill -HUP` or the `/-/reload` endpoint); no restart needed |
| Alertmanager config | Restore the previous `alertmanager.yml` and reload (`/-/reload`); a syntactically invalid file is refused at load, so the previous config stays live until a valid one is provided |
| Collector config | Restore the previous `config.yaml` and restart the collector process — the collector does not hot-reload its config |

## Common failure modes

- **A rule file with a duplicate rule identity passes `promtool check rules`**
  because `--lint-fatal` was left off — the tool prints the warning and still
  exits 0.
- **An alert that reads a recording rule from a different rule file** can
  observe a stale, one-tick-behind value at the exact moment the underlying
  ratio is changing quickly, because Prometheus gives no ordering guarantee
  between rule groups in different files evaluated at the same tick. Usually
  invisible; visible only right at a fast transition.
- **A routing-tree matcher using a label the alert doesn't actually set**
  (guessing at `critical`/`warning` instead of reading what `severity` value
  the alert rule emits) matches nothing, and nothing reports that it matched
  nothing.
- **A receiver secret referenced as `slack_api_url_file` at the receiver
  level** instead of `api_url_file` — that longer name is valid only on the
  global config block.
- **A processor renamed in one place and not another** silently drops out of
  whichever pipeline still names the old identifier; `otelcol validate`
  will not catch it, because a component that used to be referenced and now
  isn't looks identical to one that was never referenced.
- **No `memory_limiter`, or one sized to the container's full memory limit**
  turns a traffic spike in what the collector is monitoring into an OOM-kill
  of the collector itself, and often of the node.
- **An unhashed, unbounded label** (a user ID, a request ID, a raw path with
  an ID segment) turns one metric into millions of time series and takes
  down the Prometheus instance that was supposed to be watching for exactly
  this kind of problem.

## Control mapping

Section to control families. Benchmark section numbers are deliberately not
cited: verify them against the exact benchmark version you are audited on.

| This guide | CIS Benchmark | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Annex A | NIS2 Art. 21(2) |
|---|---|---|---|---|
| SLOs and burn-rate alerting | CIS Benchmark for Kubernetes / Docker (monitoring controls) | SI-4, AU-6 | A.8.16 | (b), (c) |
| Alert routing, grouping, inhibition | same | IR-4, IR-6 | A.5.24, A.5.26 | (c) |
| OpenTelemetry Collector egress and redaction | same | SC-7, SI-4, SC-8 | A.8.16, A.8.20 | (e), (h) |
| Cardinality controls | same | SI-4, CP-2 | A.8.16 | (c) |
| Logs, PII and secrets | same | AU-9, SC-28, SI-4 | A.8.10, A.8.15 | (b), (i) |

## References

- [Google SRE workbook — Alerting on
  SLOs](https://sre.google/workbook/alerting-on-slos/), the basis for the
  multi-window, multi-burn-rate design in `slo-alerts.yml`
- [`promtool` documentation](https://prometheus.io/docs/prometheus/latest/command-line/promtool/)
  and [unit testing for
  rules](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/)
- [Alertmanager configuration
  reference](https://prometheus.io/docs/alerting/latest/configuration/) and
  [`amtool`](https://github.com/prometheus/alertmanager/blob/main/docs/cli/amtool.md)
- [OpenTelemetry Collector configuration and the `memory_limiter`
  processor](https://opentelemetry.io/docs/collector/configuration/)
- [Linux hardening — Audit trail](linux-hardening.md#audit-trail) and
  [Kubernetes hardening — API server audit](kubernetes-hardening.md#api-server-audit)
  for the audit log this pipeline does not replace
- [Secrets management](secrets-management.md) for where credentials belong
  instead of in a log or trace attribute
- [Wazuh HIDS](wazuh-hids.md) for security event correlation and intrusion
  detection, which this baseline is not built for

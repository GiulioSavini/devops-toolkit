# Observability & Centralized Logging Architecture

Architecting scalable logging, metrics, and alerting infrastructure.

---

## 1. The Observability Triad

1. **Logs**: Structured JSON logs (`timestamp`, `level`, `service`, `trace_id`, `message`).
2. **Metrics**: Time-series counters, gauges, histograms (Prometheus / OpenTelemetry).
3. **Traces**: Distributed context tracking across microservices (Jaeger / Tempo).

---

## 2. Log Retention & Tiering

| Tier | Storage Type | Retention | Query Speed |
|------|--------------|-----------|-------------|
| **Hot** | SSD / NVMe | 7 Days | Sub-second |
| **Warm** | Standard Block Storage | 30 Days | Seconds |
| **Cold** | Object Storage (S3 / GCS) | 365 Days | Minutes |
| **Frozen / Archive** | Glacier / Archive Storage | 7 Years (Compliance) | Hours |

Tier transitions must be automated at the storage layer, not by a cron job that
deletes files. On S3, an object lifecycle policy handles it:

```json
{
  "Rules": [{
    "ID": "logs-tiering",
    "Status": "Enabled",
    "Filter": { "Prefix": "logs/" },
    "Transitions": [
      { "Days": 30,  "StorageClass": "STANDARD_IA" },
      { "Days": 365, "StorageClass": "GLACIER_IR" }
    ],
    "Expiration": { "Days": 2555 }
  }]
}
```

---

## 3. Structured Logging

Emit JSON, one object per line, and never build log lines by string
concatenation — it breaks parsing the first time a field contains a quote.

```json
{"timestamp":"2026-08-30T09:14:22.481Z","level":"error","service":"billing-api","trace_id":"4bf92f3577b34da6","event":"payment_declined","customer_id":"c_8812","duration_ms":142}
```

Rules that matter in practice:

- **Never log secrets, tokens, full card numbers, or full request bodies.** Once
  a secret is in the log pipeline it is in backups, in the SIEM, and in the cold
  tier for seven years.
- Carry `trace_id` through every service so a log line can be joined to a trace.
- Log the *outcome*, not the intent: `event: payment_declined` is queryable,
  `"about to process payment"` is noise.

---

## 4. Alerting on Symptoms, Not Causes

Alert on what the user experiences; leave causes to the dashboard.

```yaml
# Prometheus alerting rule
groups:
  - name: availability
    rules:
      - alert: HighErrorRate
        expr: |
          sum(rate(http_requests_total{status=~"5.."}[5m])) by (service)
            / sum(rate(http_requests_total[5m])) by (service) > 0.05
        for: 10m
        labels:
          severity: page
        annotations:
          summary: "{{ $labels.service }} is serving >5% 5xx for 10 minutes"
          runbook: "https://runbooks.internal/high-error-rate"
```

Every paging alert needs a runbook link and an action a human can take at 03:00.
An alert with neither should be a dashboard panel, not a page.

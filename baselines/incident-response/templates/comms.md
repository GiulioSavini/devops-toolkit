# Communication templates

Four audiences, four different messages, one set of facts. The Communications
lead owns these; the Incident Commander approves anything that leaves the
company. Never speculate about cause in an external update — early causal
guesses are wrong often enough to become the story.

Rules that apply to all of them:

- Timestamps in UTC, absolute, with the offset spelled out if you must localise.
- Say what you know, what you do not know, and when the next update comes.
- Never name an individual. Never name a customer to another customer.
- If it is a security incident, legal reviews the external wording first.

## Internal update (incident channel, every 30 min at SEV1)

```text
[SEV2 / checkout] UPDATE 14:20 UTC
Impact: ~12% of checkout requests failing (HTTP 503), EU region only, since 13:48 UTC.
Current state: traffic shifted away from eu-west-1b, error rate falling (12% -> 3%).
Working on: confirming the failing node pool is drained; rollback of release 2026.9.4 prepared, not applied.
Not yet known: why only one AZ is affected.
IC: A. Ops: B. Comms: C. Scribe: D.
Next update: 14:50 UTC.
```

## Customer-facing status page

```text
Investigating — 13:55 UTC
Some customers in Europe are seeing errors when completing a purchase. We have
identified the affected component and are rerouting traffic. Payments already
confirmed are not affected. Next update by 14:25 UTC.

Identified — 14:25 UTC
Errors were caused by a fault in one availability zone in our EU region.
Traffic has been moved away from it and the error rate is returning to normal.
We are monitoring before declaring this resolved. Next update by 14:55 UTC.

Resolved — 15:10 UTC
Checkout has been operating normally since 14:38 UTC. Total impact: 13:48–14:38
UTC, up to 12% of EU checkout attempts failed and needed to be retried. We will
publish a review of this incident within five working days.
```

## Executive brief (short, decision-oriented)

```text
What happened: EU checkout degraded 13:48–14:38 UTC, up to 12% of attempts failed.
Customer impact: ~4,100 failed attempts, 38 support contacts, no data loss, no unauthorised access.
Money: ~EUR 25k of delayed orders, ~EUR 1.2k SLA credits expected.
Status: resolved and monitored, no ongoing risk.
Regulatory: no personal data breach, GDPR Art. 33 assessed and not notifiable (record kept).
Decisions needed: approve the single-AZ capacity headroom increase (cost ~EUR 3k/month).
Review: published by 2026-10-05, owner C.
```

## Customer notification of a personal data breach

Send after legal and the DPO have approved, and only once the facts hold. GDPR
Art. 34 requires a communication to data subjects when the breach is likely to
result in a high risk to their rights and freedoms, in clear and plain language,
covering the nature of the breach, the DPO contact, the likely consequences and
the measures taken.

```text
Subject: Security incident affecting your account — what happened and what to do

On 2026-09-28 we discovered that an unauthorised third party accessed a database
containing NAMES, EMAIL ADDRESSES and HASHED PASSWORDS between DATE and DATE.
PAYMENT CARD DETAILS / GOVERNMENT IDs WERE NOT / WERE affected.

What we have done: revoked the access used, forced a password reset on affected
accounts, and rotated the credentials involved. We notified SUPERVISORY
AUTHORITY on DATE.

What we recommend you do: change your password anywhere you reused it, and treat
unexpected messages referring to your account with suspicion.

Questions: dpo@example.com. We will update this page as we learn more: URL.
```

## Regulator notification (NIS2 Art. 23 early warning, within 24 h)

The early warning goes to the CSIRT or the competent authority and must indicate,
where applicable, whether the incident is suspected of being caused by unlawful
or malicious acts, and whether it could have cross-border impact. It is a
warning, not a report: incomplete information is expected and not a reason to
wait past the deadline.

```text
Entity: LEGAL NAME, sector, national identifier.
Contact: name, role, 24/7 telephone, email.
Became aware (UTC): YYYY-MM-DDTHH:MMZ — and how (alert, third party, customer).
Incident: one paragraph of observed facts.
Suspected unlawful or malicious act: yes / no / unknown, with the basis.
Cross-border impact: yes / no / unknown, member states possibly affected.
Services affected and current status.
Measures already taken.
Next report: incident notification within 72 h of awareness, with the initial
severity and impact assessment and any indicators of compromise available.
```

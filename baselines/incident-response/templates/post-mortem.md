# Incident review: SHORT NAME

Fill this in within five working days. Keep it blameless: the question is what
about the system made this outcome possible, not who typed the command.

There is deliberately no "root cause" field. Overt failure in a system that is
defended against failure requires several contributors, none of which is
sufficient alone ([Cook, *How Complex Systems
Fail*](https://how.complexsystems.fail/)). A template with one blank labelled
"root cause" gets one contributor written in it, and the other three ship again
next quarter.

| Field | Value |
|---|---|
| Incident ID | INC-YYYY-NNN |
| Severity | SEV1 / SEV2 / SEV3 / SEV4 (final, with the reason) |
| Detected (UTC) | YYYY-MM-DDTHH:MM:SSZ |
| Resolved (UTC) | YYYY-MM-DDTHH:MM:SSZ |
| Customer-visible duration | |
| Incident Commander | |
| Authors | |
| Reviewers | |
| Status | draft / in review / accepted |

## Summary

Three or four sentences: what customers experienced, for how long, and what was
done about it. No causes yet. Written so that someone outside the team can read
only this section and be correctly informed.

## Impact

- Users or tenants affected, and how that number was established.
- Requests, transactions or messages lost, delayed or duplicated.
- Data integrity: anything lost, corrupted, or restored from backup.
- Money, SLA credits, contractual or regulatory exposure.
- Internal impact: staff hours, deferred work, on-call load.

## Detection

- How it was found: alert name, dashboard, customer report, third party.
- Time from onset to detection, and from detection to declaration.
- If a customer found it first, that is a monitoring finding: say so here.

## Timeline (UTC)

Facts and observations only. No interpretation — interpretation goes below.
Cite where each entry came from (alert, log, chat message, snapshot ID).

| UTC | Actor | Event / observation | Source |
|---|---|---|---|
| | | | |

## Trigger

The single proximate event that moved the system from working to not working
(a deploy, a config push, a traffic shift, a certificate expiry, a disk filling
up). The trigger is not the explanation; it is the thing that happened to be
last.

## Contributing factors

At least three, each one something that could be changed. Cover more than code:

- **Design**: the coupling, the missing limit, the retry without a budget, the
  shared failure domain nobody drew on the diagram.
- **Safeguards that did not fire**: the alert that was tuned out, the canary
  that did not cover the path, the validation that only ran in CI.
- **Operational conditions**: time pressure, a change freeze exception, a
  recent reorg, an expert on leave, an ambiguous runbook.
- **Information**: what the operators could and could not see while deciding.
  Judge the decisions against what was knowable at the time, not against what
  you know now.
- **Prior signals**: near misses, related tickets, or the same alert two months
  ago that got acknowledged and forgotten.

## What made it worse, what made it better

- What lengthened the outage (slow rollback, missing access, wrong escalation).
- What shortened it (a good dashboard, a recent runbook, a lucky guess).
- Where we got lucky. Luck is not a control; write down what happens without it.

## Evidence and preservation

- Artifacts collected, with manifest hashes and where they are stored.
- Snapshot and image IDs, retention date, who has access.
- Chain-of-custody document reference, if the incident may become a legal or
  regulatory matter.

## Regulatory and contractual notifications

| Obligation | Trigger assessed | Decision and time (UTC) | Owner |
|---|---|---|---|
| GDPR Art. 33 (72 h to the supervisory authority) | | | |
| GDPR Art. 34 (data subjects, high risk) | | | |
| NIS2 Art. 23 early warning (24 h) | | | |
| NIS2 Art. 23 notification (72 h) | | | |
| NIS2 Art. 23 final report (1 month after the notification) | | | |
| Customer contractual notice | | | |

A documented "assessed, not notifiable, because X" is an answer. Silence is not.

## Actions

Each action addresses a contributing factor and is owned by a person, not a
team. Actions that change the system beat actions that ask people to be more
careful. If an action is "add an alert", say what it alerts on and what the
responder is meant to do.

| # | Action | Contributing factor it addresses | Type | Owner | Due | Ticket |
|---|---|---|---|---|---|---|
| 1 | | | prevent / detect / mitigate / process | | | |

## Open questions

What is still unknown, who is chasing it, and by when. An honest unknown is
worth more than a confident invention.

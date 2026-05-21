# MFU ATDR Final Demo Script

Use this script for the supervisor walkthrough. Keep the story focused on evidence, explainability, safe response, and a realistic path to deployment.

## 1. Opening

MFU ATDR is a defensive security monitoring prototype for Palo Alto firewall logs. It imports logs, preserves raw evidence, normalizes events, generates rule-first alerts, uses ML only as assistive scoring, supports SOC workflow, simulates response actions, and audits every sensitive operation.

Current stage:

- Senior project prototype: complete
- Lab pilot readiness: mostly ready
- Production deployment: requires PostgreSQL/Docker validation, HTTPS, backup jobs, real baseline tuning, and approved firewall integration

## 2. Executive Demo

Show **Executive Demo** first. Present it as the SOC Command Center landing page.

Point out:

- API and database readiness
- response mode is simulated
- raw evidence log count
- critical open alerts
- mission path: Ingest -> Detect -> Investigate -> Respond -> Audit -> ML Governance
- operational flow: ingest, detect, investigate, respond
- ML drift signals and model governance

Key phrase: "The system does not ask the AI to make security decisions alone. Rules explain the alert first; ML adds anomaly context."

## 3. Overview

Show:

- total logs
- active alerts
- severity and status distribution
- top alert types
- top suspicious source IPs
- anomaly rate
- suppression and watchlist metrics
- Plotly charts for workflow, actions, protocols, app risk, and alert mix
- recent alert triage cards

Explain that grouped alerts reduce alert noise while preserving evidence links.

## 4. Alert Investigation

Open **Alerts** and select a High or Critical alert.

Show:

- threat score
- severity
- matched rules
- evidence log IDs
- raw log excerpt
- recommended response
- workflow timeline

Perform:

- assign to yourself
- mark investigating
- add an analyst note
- optionally add ticket/escalation metadata

## 5. Simulated Response

In the alert response tab:

- select a source IP
- run simulated block
- show that the response is recorded but no firewall device is modified

Then open:

- **Response Center**
- **Audit Log**

Show actor, action, target, timestamp, and details.

## 6. Threat Controls

Open **Threat Controls**.

Show:

- suppression review queue
- watchlist indicators
- false-positive review queue

Explain that known-benign noise is governed and audited instead of silently deleted.

## 7. ML Governance

Open **ML Governance**.

Show:

- model artifact status
- baseline candidate count
- anomaly rate
- top anomalous apps/IPs/ports
- run history
- drift signals

Key phrase: "IsolationForest helps prioritize unusual behavior, but the system still depends on analyst review and explainable rule evidence."

## 8. Evidence Bundle

Open **Demo Controls** and run **Generate Demo Evidence Bundle**.

Show the generated files:

- dashboard summary
- top alerts
- recent audit
- ML evaluation
- JSON/CSV/HTML/PDF alert report
- Markdown demo summary

Close by explaining the production path: PostgreSQL, HTTPS, backups, retention jobs, real syslog pilot, baseline tuning, and approved firewall integration.

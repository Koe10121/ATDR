# ATDR Final Demonstration Script

## Demonstration Goal

Demonstrate ATDR as a controlled lab-scale SOC triage prototype:

1. start the backend and React dashboard;
2. validate the scenario safely in a temporary database;
3. run the same scenario into the dashboard;
4. inspect source health, logs, alert evidence, and case grouping;
5. show response safeguards and audit;
6. explain AI Governance honestly.

Do not claim production readiness, automatic response, or real firewall
enforcement.

## Before The Presentation

### 1. Check Repository State

Run:

```powershell
git status --short
```

**What to say**

"The repository excludes real logs, databases, environment secrets, model
artifacts, reviewed CSV exports, processed logs, and generated validation
reports."

Do not show `.env` contents or private log payloads.

### 2. Optional Release Preflight

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release
```

**What to say**

"The release gate checks configuration, Python compilation, backend tests,
and Alembic migration consistency."

## Start The System

### Terminal 1: Backend

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

**What to say**

"The backend is FastAPI. It exposes authenticated APIs for ingestion, sources,
detection, alerts, ML Governance, response simulation, and audit."

Optional health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

### Terminal 2: React Dashboard

```powershell
cd frontend
npm.cmd run dev
```

Open:

```text
http://127.0.0.1:5173
```

**What to say**

"React is the primary SOC dashboard. The normal local backend and frontend
commands have remained stable throughout development."

## Safe Scenario Preflight

Return to the repository root in a third terminal:

```powershell
cd <ATDR_ROOT>
```

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name final-demo-firewall-live --source-type firewall --parser-profile palo_alto --run-detection --use-temp-db --pretty
```

**What to say before running**

"I will first run the scenario against a temporary SQLite database. This
confirms the expected behavior without changing the dashboard database."

**Expected output**

- `ok: true`
- source health: healthy
- 10 logs received
- 10 normalized logs
- 10 parse successes
- 0 parse failures
- 10 logs evaluated
- 1 critical port-scan alert
- run attack type: `port_scan (1)`
- 1 case
- occurrence count: 10
- related logs: 10
- automatic response actions: 0
- response automation: false
- real firewall blocking: false

**What to say after running**

"The preflight passed. The attack-type summary is scoped to this detection run
and reports one port-scan alert. No automatic response was created."

## Dashboard-Visible Scenario

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name final-demo-firewall-live --source-type firewall --parser-profile palo_alto --run-detection --pretty
```

**What to say before running**

"Now I will intentionally write the same safe synthetic scenario to the local
dashboard database so we can investigate it through the SOC workflow."

**Important**

If the source or alert already exists, ATDR may deduplicate the result and
increase occurrence/evidence counts. Explain this accurately rather than
claiming that a new alert was created.

## Dashboard Walkthrough

### 1. Overview

Open **Overview**.

**Show**

- `Final Controlled Validation Candidate`
- `Decision Support Only`
- `Not Production Promoted`
- `Response Automation Disabled`
- Operations Health
- latest ingestion run
- latest detection run
- Log Sources

**What to say**

"This is the system's controlled academic readiness state. It does not mean
production promotion or autonomous enforcement."

### 2. Source Health

In **Log Sources**, open `final-demo-firewall-live`.

**Show**

- source type: firewall
- parser profile: `palo_alto`
- source status: healthy
- last seen
- logs received
- normalized logs
- parse success/failure
- unknown application note
- recent ingestion run
- recent detection run
- `Run attack types: port_scan (1)`

**What to say**

"Source health combines recent activity and parser quality. All ten records
were received and parsed. The scenario intentionally uses incomplete or
unknown application values because scan connections are rapidly denied. That
is a data-quality note, not an ingestion failure."

### 3. Investigation / Log Explorer

Open **Investigation** and filter by source
`final-demo-firewall-live`.

**Show**

- raw evidence
- normalized timestamp
- source IP `203.0.113.44`
- destination hosts
- destination ports
- deny action
- parser/source information

**What to say**

"ATDR stores the raw line before normalization. Even when structured parsing
is limited, the original evidence is retained."

### 4. Alerts

Open **Alerts** and filter by the scenario source. Open the critical port-scan
alert.

**Show**

- critical severity
- risk score
- attack type
- detection source
- occurrence count
- related-log count
- related ports and destinations
- ATT&CK-style context
- `Why flagged?`
- recommended analyst action

**What to say**

"This source contacted multiple internal destinations and destination ports
through repeated denied or incomplete connections. The rule and
behavior-window evidence indicate scanning-like behavior. The system recommends
investigation; it does not automatically block the source."

### 5. Why Flagged?

Keep the alert detail open and focus on the explanation.

**What to say**

"The explanation connects the alert to evidence: repeated behavior, distinct
ports, deny/drop context, traffic direction, rule contribution, and model or
anomaly support when available. This lets the analyst verify the decision."

### 6. Case Grouping

Open the related case or case summary.

**Show**

- case title
- source IP
- related alert count
- total related logs
- first/last seen
- top destination ports
- top actions
- recommended analyst focus

**What to say**

"The case groups related behavior so the analyst sees one investigation
context rather than isolated alerts. It is lightweight correlation, not a
complete ticketing platform."

### 7. Response And Audit

Open **Response & Audit**.

**Show**

- simulated response wording
- manual approval requirement
- target preview
- confirmation dialog
- justification-note requirement

**What to say**

"ML cannot trigger this action. An authorized analyst must confirm the target
and provide a reason. The current action records a simulation only; it does not
change a firewall."

If demonstrating a protected target, use a safe local protected address such
as `127.0.0.1`.

**Expected result**

- request denied
- protected-target reason shown
- denied attempt audited
- no firewall change

**What to say**

"Protected infrastructure cannot be blocked. Even the denied attempt is
audited for accountability."

### 8. Audit Trail

Show:

- actor
- attempted action
- target
- timestamp
- result
- justification or denial context

**What to say**

"The audit trail records both approved simulations and denied attempts."

### 9. AI Governance

Open **AI Governance**.

**Show**

- candidate: `independent_fpr_stabilized`
- final decision: `final_controlled_validation_candidate`
- readiness v8: 22/22
- 700-row fresh blind holdout
- seven sources
- sixteen scenario families
- threat precision 0.8906
- threat recall 0.9459
- threat F1 0.9174
- benign-like FPR 0.1303
- suspicious recall 0.8556
- malicious recall 0.9000
- calibration passed
- production promotion false
- response automation false

**What to say**

"The profile was frozen before the fresh blind evaluation and was not tuned on
blind labels. These are controlled validation metrics, not production
accuracy. The model remains SOC triage decision support."

## If The Committee Asks Why It Is Not Production Ready

Use this answer:

"The engineering prototype passed its controlled academic validation, but
production deployment requires evidence that is outside the present scope:
real-device forwarding over time, production IAM, TLS and secret management,
backup and retention, high availability, independent security assessment,
larger independently reviewed real-source labels, and a vendor-approved
response connector with rollback. ATDR therefore remains Decision Support Only
with Response Automation Disabled."

## Closing Statement

"ATDR demonstrates a controlled end-to-end SOC workflow: source-aware
ingestion, evidence-preserving parsing, layered threat detection, explainable
alerts, lightweight case correlation, AI-assisted triage, and audited
simulated response. The final candidate achieved strong fresh blind
threat-positive results while preserving human approval and an honest
non-production boundary."

## Fast Troubleshooting

### `Failed to fetch`

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

If it fails, restart the backend.

### Port 8000 already in use

Stop the duplicate backend process. Avoid running multiple write processes
against SQLite during the demonstration.

### Scenario produces no new alert

Check whether the existing alert was deduplicated and its occurrence count
increased.

### Source shows an unknown-app warning

Explain that the port-scan scenario intentionally uses incomplete/unknown app
values. Confirm parse success is 10/10 and source health is healthy.

### Default sample imports only two logs

`data/samples/paloalto-demo.txt` is intentionally a two-line safe sample. Use
the scenario command for the final demonstration.

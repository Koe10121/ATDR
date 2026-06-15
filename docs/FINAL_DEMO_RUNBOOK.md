# ATDR Final Demo Runbook

## Demo Scope

This runbook demonstrates ATDR as a controlled, lab-scale, AI-assisted SOC
triage prototype. It does not demonstrate production deployment, automatic
response, or real firewall enforcement.

Use synthetic samples only. Do not place real or private logs in Git.

## Before The Presentation

1. Confirm `.env` exists and uses response simulation.
2. Confirm the local database contains the data you intend to show.
3. Close duplicate backend processes to avoid SQLite locking.
4. Run the release gate:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release
```

5. Optionally validate the demonstration scenario in a temporary database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name final-demo-check --source-type firewall --parser-profile palo_alto --run-detection --use-temp-db --pretty
```

## Start ATDR

Open PowerShell in the repository root and start the backend:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open a second PowerShell window and start the React dashboard:

```powershell
cd frontend
npm.cmd run dev
```

Open:

```text
http://127.0.0.1:5173
```

Verify the API separately if needed:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

## Recommended Demonstration Scenario

To place a safe port-scan-like scenario in the current dashboard intentionally:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name final-demo-firewall --source-type firewall --parser-profile palo_alto --run-detection --pretty
```

Expected result:

- 10 synthetic raw logs are preserved;
- 10 normalized records are created;
- 10 records parse successfully with 0 parse failures;
- the source reports healthy;
- the source becomes healthy, with a possible unknown-app warning;
- one critical explainable port-scan alert is created;
- the alert has 10 occurrences and 10 related logs;
- one lightweight related case is available;
- no response action is created automatically.

The source's recent detection run should report `port_scan (1)` as its
run-scoped attack type. It must not display unrelated historical attack counts
as if they were produced by this 10-log run.

The sample intentionally uses `incomplete`/unknown application values to
exercise scanning behavior. A 100% unknown-app rate is therefore shown as a
data-quality note, not as source failure.

If the scenario has already been imported, use a new source name or explain
alert deduplication and occurrence counts instead of claiming a new alert.

## Dashboard Presentation Order

### 1. Overview

Show:

- total logs and alert counts;
- Operations Health and latest ingestion/detection runs;
- Log Sources and source health;
- v2.0 readiness summary;
- `Decision Support Only`;
- `Response Automation Disabled`;
- `Not Production Promoted`;
- `Final Controlled Validation Candidate`.

Explain that these statuses describe controlled engineering evidence, not
production approval.

### 2. Log Source Detail

Open `final-demo-firewall` in the Log Sources panel.

Show:

- source type and `palo_alto` parser profile;
- healthy/warning status;
- last seen time;
- logs received;
- parse success/failure counts;
- unknown application rate;
- recent ingestion and detection runs.

Explain that source health is based on recent activity and parser quality.

### 3. Investigation / Log Explorer

Filter by `final-demo-firewall`.

Show:

- preserved raw evidence;
- normalized timestamp, source, destination, port, action, and application;
- source-aware filtering;
- parser status;
- safe handling of missing or malformed fields.

Explain that ATDR preserves raw logs even when structured parsing is limited.

### 4. Alerts

Filter by the scenario source and open the port-scan alert.

Show:

- severity and risk score;
- source/destination context;
- attack type and detection source;
- occurrence count and related log count;
- ATT&CK-style mapping;
- `Why flagged?`;
- related evidence;
- recommended analyst action.

Explain that rules, behavior-window features, anomaly scoring, and supervised
triage can contribute to the hybrid decision, while the analyst retains
control.

### 5. Cases

Show the computed case linked to the scenario.

Explain:

- related alerts are grouped using source, destination, attack type, time, and
  repeated behavior;
- the case summarizes first/last seen, logs, ports, actions, and analyst focus;
- this is lightweight case correlation, not a complete ticketing platform.

### 6. AI Governance

Show:

- candidate: `independent_fpr_stabilized`;
- readiness v8: `22/22`;
- decision: `final_controlled_validation_candidate`;
- 700-row fresh blind holdout;
- threat precision `0.8906`;
- threat recall `0.9459`;
- threat F1 `0.9174`;
- benign-like false-positive rate `0.1303`;
- suspicious recall `0.8556`;
- malicious recall `0.9000`;
- raw-confidence calibration passed without blind-label fitting.

State clearly:

> ML is SOC triage decision support. It is not production-promoted and cannot
> trigger an automatic response.

### 7. Simulated Response Approval

Open Response & Audit.

For an alert with evidence and a non-protected test IP:

1. enter a justification note;
2. select `Record simulated block`;
3. confirm the dialog;
4. show the resulting simulated containment record;
5. show the matching audit entry.

Explain exactly what happened: ATDR recorded an analyst-approved simulation;
no firewall device changed.

### 8. Protected-IP Denial

Attempt a simulated block against a protected internal or management IP, such
as `127.0.0.1`, and provide a justification.

Expected result:

- the action is denied;
- the protected allowlist reason is visible;
- the denied attempt is recorded in the audit trail;
- no firewall state changes.

Do not use a real operational target during the presentation.

### 9. Audit Trail

Show:

- actor;
- attempted action;
- target;
- result;
- timestamp;
- justification or denial context.

Explain that successful and denied response attempts are auditable.

## Closing Statement

Use this wording:

> ATDR validates a controlled end-to-end SOC workflow: source-aware ingestion,
> evidence-preserving parsing, layered threat detection, explainable alerts,
> lightweight case correlation, AI-assisted triage, and audited simulated
> response. The current candidate passed fresh blind and controlled source
> validation, but it remains decision support only. Automatic response and
> real firewall enforcement are disabled.

## Troubleshooting

- `Failed to fetch`: confirm the backend health endpoint responds on port 8000.
- SQLite `database is locked`: stop duplicate backend/import processes before
  running a reset or large write operation.
- Scenario creates no new alert: check whether an existing alert was
  deduplicated and its occurrence count increased.
- Source is warning: review parser profile, unknown-app rate, and parse errors.
- Default sample imports only two rows: `data/samples/paloalto-demo.txt` is a
  two-line safe sample. Use a scenario file or an explicit external path.

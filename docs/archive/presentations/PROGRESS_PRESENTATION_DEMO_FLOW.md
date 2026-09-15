# ATDR Progress Presentation Demo Flow

## Before The Presentation

Start the backend:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Start the frontend:

```powershell
cd frontend
npm.cmd run dev
```

Open:

```text
http://127.0.0.1:5173
```

Optional projector mode:

```powershell
$env:VITE_ATDR_PRESENTATION_MODE="true"
npm.cmd run dev
```

## Safe Final Scenario

Run this from the repo root:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name final-demo-firewall --source-type firewall --parser-profile palo_alto --run-detection --pretty
```

Expected result:

- `ok: true`
- source is `final-demo-firewall`
- source health is healthy
- 10 logs received
- 10 normalized logs
- 0 parse failures
- 1 critical possible port-scan alert
- 1 case
- occurrence count is 10
- related logs count is 10
- no response actions are created

## Dashboard Walkthrough

1. Overview
   - Show system health and safety badges.
   - Show source activity and operations status.

2. Alerts
   - Filter or search for the final demo alert.
   - Open alert detail.
   - Show severity, risk score, attack type, occurrence count, related logs, and "Why flagged?" evidence.

3. Investigation
   - Filter logs by source or source IP.
   - Show raw evidence and normalized fields.

4. AI Governance
   - Show Decision Support Only.
   - Explain that the model is not production-promoted.
   - Mention reviewed labels and validation gates.

5. Response & Audit
   - Show Simulation Mode.
   - Explain that analyst approval and justification are required.
   - Confirm no automatic response occurred.

## If Something Goes Wrong

- If the frontend says `Failed to fetch`, start or restart the backend.
- If port 8000 or 5173 is busy, close the old process or use a different terminal.
- If the scenario already ran before, alert deduplication may update occurrence counts instead of creating many new duplicate alerts.
- Do not reset the database during the presentation unless explicitly planned.


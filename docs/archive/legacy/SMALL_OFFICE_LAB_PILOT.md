# Small Office Lab Pilot Plan

This project uses "prototype" to mean a controlled small-office security monitoring pilot, not a full MFU-wide deployment. The system should process real firewall/router logs, support live ingestion tests, and prepare a safe response workflow while avoiding accidental damage to production networks.

## Current Pilot-Safe Capabilities

- Import Palo Alto log files and preserve raw evidence.
- Receive UDP syslog on an approved host/port for lab testing.
- Normalize logs and generate rule-first alerts.
- Use IsolationForest anomaly scoring as assistive evidence.
- Show SOC workflows in Streamlit and the React production dashboard.
- Simulate block/unblock IP actions with audit evidence.
- Export incident reports, demo bundles, and ML baseline review packages.

## Live Log Test

Keep live ingestion bound to localhost until the lab network path is approved:

```powershell
python -m atdr.scripts.syslog_lab_smoke --count 5
```

For a supervised receiver:

```powershell
python -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
```

For a real firewall/router lab test:

1. Set `SYSLOG_HOST` to the approved ATDR host interface.
2. Keep host firewall rules scoped to the lab sender IP.
3. Configure the firewall/router to forward syslog to the ATDR host and UDP port.
4. Watch log counts in the dashboard and API.
5. Stop the test and verify audit entries for syslog ingestion batches.

## Response Path

Response actions remain simulated by default:

```env
RESPONSE_SIMULATION=true
RESPONSE_PROVIDER="simulation"
```

This is correct for the current codebase. Disabling simulation does **not** make ATDR modify a firewall yet. It records the action as `pending_connector` unless a future approved connector is implemented.

Before real blocking is allowed in a small-office pilot:

- Identify the exact firewall platform and API method.
- Use a dedicated service account with least privilege.
- Require admin role and a change reason/ticket.
- Protect critical IP ranges and management addresses with allowlists.
- Add a dry-run preview.
- Add automatic unblock/rollback instructions.
- Test first against a non-production firewall or isolated lab VLAN.
- Keep audit logs for every block/unblock.

## What Counts As Pilot Success

- Real syslog lines flow into ATDR without manual file import.
- Alerts are explainable and tied to raw evidence.
- Analysts can triage, assign, note, resolve, and export reports.
- ML anomaly rows are reviewed before being trusted.
- Response actions are audited and safe.
- Any real enforcement connector is tested only after approval and rollback planning.

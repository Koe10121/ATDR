# ATDR v0.5 Real-Source Validation Plan

> Current status: real firewall/router hardware is not available yet. Use `docs/V0_5_SIMULATION_DEMO_PLAN.md` for the active v0.5 path. This document remains the future controlled hardware validation plan.

## Objective

Validate that ATDR behaves like a controlled lab SOC prototype when receiving logs from a real or simulated source. v0.5 does not claim production readiness. It keeps response simulated and analyst-approved, and it keeps ML as SOC triage decision support.

## Test Environment

- Backend: FastAPI on `127.0.0.1:8000`.
- Frontend: React dashboard on `127.0.0.1:5173`.
- Database: existing local SQLite database unless a command explicitly uses a temporary database.
- Source validation outputs: ignored `demo_exports/lab_validation_reports/`.
- Safe samples: `data/samples/` and `data/samples/scenarios/`.

Normal startup commands remain unchanged:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
cd frontend
npm.cmd run dev
```

## Supported Source Types

ATDR can validate these source paths:

1. Real router/firewall/syslog sender if controlled lab hardware is available.
2. Local UDP syslog simulation with `send_sample_syslog`.
3. Replay script direct import with a named source.
4. Replay script to the local syslog receiver.
5. Existing synthetic source scenario runner.

Source records track:

- source name
- source type: `firewall`, `router`, `syslog_udp`, `syslog_tcp`, `replay`, `sample`, `file_import`
- parser profile: `palo_alto`, `generic_syslog`, `raw_fallback`
- enabled/disabled state
- last seen and last log received timestamps
- logs received, parse success count, parse failure count
- latest error
- health status
- source-linked ingestion and detection run history

Disabling a source must never delete raw logs, normalized logs, alerts, cases, labels, audit records, or evidence.

## Expected Log Flow

1. Source sends or replays log lines.
2. ATDR stores raw evidence.
3. Parser normalizes fields when possible.
4. Source counters and parser quality update.
5. Detection runs source-scoped or globally.
6. Alerts are created or deduplicated.
7. Cases can be computed from related alerts.
8. Dashboard investigation can filter by source.
9. Response remains simulated and requires analyst approval.
10. Audit records show analyst/system actions without automatic firewall enforcement.

## Validation Commands

Register a controlled source:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.register_log_source --name lab-firewall-1 --source-type firewall --parser-profile palo_alto --host 192.0.2.10 --port 514 --pretty
```

Replay safe logs directly as a source:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --send-to direct --source-name lab-firewall-1 --source-type firewall --parser-profile palo_alto --limit 100 --rate 0 --run-detection --pretty
```

Validate an existing live/source path:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_live_source --source-name lab-firewall-1 --source-type firewall --parser-profile palo_alto --duration 60 --run-detection --pretty
```

Export a source validation report:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.export_lab_validation_report --source-name lab-firewall-1 --pretty
```

Run a safe scenario against a temporary database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --use-temp-db --run-detection --pretty
```

## Validation Checklist

- Source exists or is created intentionally.
- Source has the expected type and parser profile.
- Source is enabled unless testing disabled behavior.
- Logs received count increases during validation or prior source activity is visible.
- Raw logs are preserved.
- Normalized logs are created when parser profile can extract fields.
- Parser failures are counted and examples are visible.
- Detection run is source-linked when `--run-detection` is used.
- Alerts from the source are visible and filterable.
- Deduplication updates occurrence count and related log count for repeated patterns.
- Cases can be traced to source activity.
- No response action is automatically created.
- Simulated response still requires confirmation and justification.
- Protected IP response attempt is denied and audited.
- Dashboard remains fast and usable.

## Scenario Expectations

| Scenario | Expected Result |
| --- | --- |
| Normal allowed traffic | Logs import and parse; source healthy; no severe alerts. |
| Port-scan-like traffic | Alert created; Why flagged explains scanning-like evidence; case grouping works. |
| Malformed/generic syslog | Raw evidence preserved; parser warning visible; no crash. |
| Repeated replay | Raw evidence preserved; matching active alert deduplicates; occurrence count increases. |
| Simulated response | Requires justification and confirmation; protected IP denial is audited. |

## Success Criteria

- Controlled source validation command runs without reset or data deletion.
- Validation report is generated under ignored `demo_exports/lab_validation_reports/`.
- Source-scoped detection and dashboard source filters work.
- Parser fallback preserves raw evidence.
- Performance smoke has no local lab warnings.
- Release gate passes.

## Known Limitations

- Real router/firewall forwarding still needs controlled lab hardware validation.
- TCP syslog and vendor-specific setup are not fully validated.
- Response is simulated only.
- ML is decision support only.
- SQLite is suitable for local lab use, but larger shared lab deployments should validate PostgreSQL later.
- Full external OIDC/SSO remains future work.

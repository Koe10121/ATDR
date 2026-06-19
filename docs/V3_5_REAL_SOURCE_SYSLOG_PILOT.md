# ATDR v3.5 Controlled Real-Source Syslog Pilot

ATDR remains a controlled lab prototype. v3.5 adds a stronger, read-only pilot checklist for real or lab source validation. It does not change startup commands, database schema, detection logic, ML activation, response behavior, or firewall enforcement.

## Source Evidence

| Area | Evidence |
| --- | --- |
| FastAPI app and safety posture | `atdr/app/main.py`, `atdr/app/core/config.py` |
| Source model and source health | `atdr/app/db/models.py`, `atdr/app/services/source_service.py`, `atdr/app/routers/sources.py` |
| Raw/normalized log preservation | `atdr/app/services/log_service.py`, `atdr/app/parsers/paloalto_parser.py` |
| Syslog/replay workflow | `atdr/scripts/run_syslog_receiver.py`, `atdr/scripts/send_sample_syslog.py`, `atdr/scripts/replay_logs.py`, `atdr/scripts/register_log_source.py` |
| Source-scoped detection | `atdr/app/services/detection_service.py`, `atdr/app/services/operation_run_service.py` |
| v3.5 pilot checker and exporter | `atdr/scripts/run_v35_real_source_pilot_check.py`, `atdr/scripts/export_real_source_pilot_evidence.py` |
| Response safety | `atdr/app/services/response_service.py`, `atdr/tests/test_response_safety.py` |

## What v3.5 Adds

- A read-only source pilot checker:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v35_real_source_pilot_check --source-name lab-firewall-real-1 --expected-min-logs 100 --window-minutes 60 --pretty
```

- A safe pilot evidence exporter that prints JSON by default:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.export_real_source_pilot_evidence --source-name lab-firewall-real-1 --expected-min-logs 100 --pretty
```

- Optional write mode for ignored evidence output under `demo_exports/real_source_pilot/`:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.export_real_source_pilot_evidence --source-name lab-firewall-real-1 --expected-min-logs 100 --write --pretty
```

The exporter includes source metadata, counts, run IDs, alert IDs, case IDs, parser error IDs, checks, and warnings. It does not include full private raw log contents by default.

## Real Device Pilot Flow

1. Start the backend normally:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

2. Register the approved lab source:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.register_log_source --name lab-firewall-real-1 --source-type firewall --parser-profile palo_alto --host <device-or-forwarder-ip> --port 5514 --pretty
```

3. Start the UDP receiver on the approved host/port:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
```

Use `127.0.0.1` for local testing. Use a lab interface IP only after the network scope and host firewall rules are approved.

4. Send a local harmless sample first:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.send_sample_syslog --host 127.0.0.1 --port 5514 --count 3
```

5. Configure the firewall/router to forward syslog to the ATDR host and approved port. Vendor-specific screens are future documentation; for now, record the device model, source IP, protocol, port, and parser profile used.

6. Run source-scoped detection after logs arrive:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name lab-firewall-real-1 --source-type firewall --parser-profile palo_alto --run-detection --pretty
```

For real forwarded logs, run detection through the dashboard or API with the source filter, then run the v3.5 checker.

7. Run the v3.5 check and optional evidence export.

## Dashboard Validation Checklist

After source logs arrive and detection runs:

- Overview shows the source in the Log Sources panel.
- Source detail drawer opens and shows status, parser profile, quality, parser errors, and recent runs.
- Investigation / Log Explorer filters to the source and shows raw/normalized evidence.
- Alerts filter to the source.
- Alert detail shows "Why flagged?" and related log evidence.
- Case or alert grouping can be traced to source-linked alerts.
- Response & Audit shows no automatic response action.
- AI Governance still says decision support only and not production promoted.

## Status Wording

The v3.5 checker separates two states:

| Field | Meaning |
| --- | --- |
| `source_pipeline_validated` | ATDR source registration, ingestion, parsing, detection run history, and safety checks passed for the selected source. |
| `real_device_forwarding_validated` | The selected source appears to be a real/lab device source, not a replay/sample/scenario source, and the pipeline checks passed. |
| `simulated_or_replay_source` | Source name/type indicates sample, replay, scenario, demo, or test data. This validates the pipeline only, not hardware forwarding. |

Allowed language:

- controlled source pilot
- source pipeline validated
- real-device forwarding validated, only when true
- response automation disabled
- simulation response mode

Disallowed language:

- production ready
- automatic blocking enabled
- model production promoted
- certified detection accuracy

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Source is idle | Verify sender IP, receiver host/port, UDP/TCP protocol, host firewall, and whether `run_syslog_receiver` is still running. |
| Source warning | Review parser profile, unknown app rate, latest parser errors, and whether logs are generic syslog rather than Palo Alto CSV. |
| High parse failure rate | Switch to `generic_syslog` or `raw_fallback` for troubleshooting, preserve raw evidence, then add a vendor-specific parser later if needed. |
| High unknown app rate | Expected for some scan/incomplete traffic; confirm with action, port, rule, and behavior-window evidence. |
| No source-linked detection run | Run source-scoped detection through the dashboard/API or replay with detection enabled. |
| No alerts | Confirm logs are normalized, detection was run for the source, and the behavior meets alert thresholds. |
| Evidence export contains too little detail | Re-run with `--include-redacted-excerpts` only for safe local troubleshooting. Do not commit generated evidence. |

## Remaining Blockers

- Sustained real-device syslog forwarding must still be run with approved lab hardware.
- PostgreSQL/shared-lab database validation remains separate future work.
- External IAM callback flow is not implemented.
- TLS/reverse proxy and observability stack are future hardening.
- Response remains simulated and analyst-approved.
- ML remains decision support only.

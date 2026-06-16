# ATDR v3.2 No-Hardware Source Pilot

v3.2 provides a safe source-pipeline pilot when no real firewall or router is available. It simulates a named firewall/syslog source over time using safe synthetic samples.

This phase does not claim production readiness.

## Why This Exists

The v3.0 real-source validator correctly reports `real_device_forwarding_not_validated` when no real/lab source exists. v3.2 fills the gap by proving the ATDR source-management pipeline is ready for a future hardware pilot.

## Simulated Source vs Real Device

| Item | Simulated v3.2 Source | Future Real Device Pilot |
| --- | --- | --- |
| Hardware required | no | yes |
| Uses safe synthetic/sanitized logs | yes | maybe, depending on lab policy |
| Validates source registration | yes | yes |
| Validates raw and normalized log storage | yes | yes |
| Validates source health and parser quality | yes | yes |
| Validates source-scoped detection | yes | yes |
| Validates actual network forwarding from router/firewall | no | yes |
| Production-ready claim | no | no |

The v3.2 output intentionally reports:

```text
hardware_required=false
real_device_forwarding_validated=false
production_ready=false
response_automation_allowed=false
real_firewall_blocking_enabled=false
```

## What It Validates

- source exists and is enabled
- source receives logs
- `last_seen` and `last_log_received_at` update
- raw logs are preserved
- normalized logs are created where possible
- parser successes and failures are counted
- source health becomes `healthy` or `warning`
- source-scoped detection run is recorded
- alerts and cases trace back to source evidence
- no automatic response action is created
- real firewall blocking remains disabled

## What It Does Not Validate

- real router/firewall syslog forwarding
- network firewall rules, NAT, or routing path
- UDP packet loss behavior under load
- production security controls
- production model activation
- real response enforcement

## Register A Simulated Source

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.register_log_source --name lab-firewall-sim-1 --source-type firewall --parser-profile palo_alto --host 127.0.0.1 --port 5514 --pretty
```

This creates or updates the source only. It does not import logs, run detection, reset data, or create response actions.

## Run The Source Simulator

Dry-run first:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v32_syslog_source_simulator --source-name lab-firewall-sim-1 --source-type firewall --parser-profile palo_alto --host 127.0.0.1 --port 5514 --count 100 --rate 5 --scenario mixed_baseline --dry-run --pretty
```

Import safe synthetic rows as a simulated source:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v32_syslog_source_simulator --source-name lab-firewall-sim-1 --source-type firewall --parser-profile palo_alto --host 127.0.0.1 --port 5514 --count 100 --rate 5 --scenario mixed_baseline --pretty
```

The default implementation uses `simulated_source_import`, an in-process safe import path. It does not require a UDP receiver and does not claim real-device forwarding.

Supported scenarios:

- `mixed_baseline`
- `normal_web_dns`
- `port_scan_like_traffic`
- `malformed_mixed`
- `source_idle_recovery`
- `parser_quality_mixed`

## Run The Full No-Hardware Pilot

Temporary database validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v32_no_hardware_source_pilot --use-temp-db --pretty
```

Dashboard-visible validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v32_no_hardware_source_pilot --pretty
```

Expected result for the default mixed baseline:

- 100 safe synthetic rows generated
- about 97 parser successes
- about 3 parser failures
- source health `warning` because parser failures are intentionally included
- 1 source-linked port-scan alert
- 1 source-linked case summary
- no automatic response actions
- `real_device_forwarding_validated=false`
- `production_ready=false`

## Dashboard Checks

After running the dashboard-visible pilot:

1. Open React at `http://127.0.0.1:5173`.
2. Open Overview and confirm `lab-firewall-sim-1` appears in Log Sources.
3. Open the source detail drawer and review health, parser errors, and recent runs.
4. Open Investigation and filter by source.
5. Open Alerts and confirm the source-linked port-scan alert.
6. Open the alert detail and review Why flagged and related logs.
7. Open AI Governance and confirm:
   - Simulated source shows validated
   - Real device forwarding remains pending
   - Not Production Ready
   - Decision Support Only
   - Response Automation Disabled

## How To Explain This To A Professor

ATDR does not have a real firewall available yet, so v3.2 uses a controlled no-hardware source simulator. This proves the source registration, ingestion, parsing, health, source-scoped detection, alert/case traceability, and response-safety workflow. It does not prove actual router/firewall forwarding. The next real pilot would replace the simulator with a physical or virtual firewall forwarding syslog to ATDR.

## Replacing The Simulator With A Real Firewall Later

1. Register the real source name and parser profile.
2. Start the backend normally.
3. Start or configure the syslog receiver if needed.
4. Configure the firewall/router to forward syslog to the ATDR host and port.
5. Confirm the source receives logs.
6. Run source-scoped detection.
7. Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v30_real_source_pilot_validation --source-name <real-source-name> --expected-min-logs 100 --pretty
```

Real response automation and real firewall blocking must remain disabled unless a future approved governance change adds them.


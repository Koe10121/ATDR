# ATDR v3.0 Real-Device Syslog Pilot Plan

This plan validates ATDR with a real or lab-simulated router/firewall source without changing the normal local workflow.

## Safety Rules

- Do not reset or delete the current database.
- Do not enable automatic response.
- Do not enable real firewall blocking.
- Do not claim production readiness from this pilot alone.
- Keep real logs outside Git.

## Source Evidence

- UDP/syslog sender and receiver: `atdr/scripts/send_sample_syslog.py`, `atdr/scripts/run_syslog_receiver.py`
- Source registration and health: `atdr/app/routers/sources.py`, `atdr/app/services/source_service.py`
- Replay/direct import: `atdr/scripts/replay_logs.py`
- Pilot validator: `atdr/scripts/run_v30_real_source_pilot_validation.py`
- Source-scoped detection: `atdr/app/services/detection_service.py`

## Pilot Setup

1. Start backend normally:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

2. Register the lab source:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.register_log_source --name lab-firewall-real-1 --source-type firewall --parser-profile palo_alto --host 192.0.2.10 --port 514 --pretty
```

3. Start a local receiver if using ATDR's UDP receiver:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
```

4. Send a local test line first:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.send_sample_syslog --host 127.0.0.1 --port 5514 --count 3
```

5. Configure the real/lab device to forward syslog to the lab host and port. Vendor-specific steps are future work; this plan assumes the device can forward standard syslog or Palo Alto traffic logs.

## Validation Command

After logs arrive, run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v30_real_source_pilot_validation --source-name lab-firewall-real-1 --expected-min-logs 100 --window-minutes 60 --pretty
```

## Pass Criteria

- Source exists and is enabled.
- Source receives at least the expected number of logs.
- Raw logs are linked to source.
- Normalized logs are linked to source.
- Source health is `healthy` or explainable `warning`.
- Source-scoped detection run exists after detection is run.
- Alerts and cases trace back to source evidence.
- No automatic response actions are created.
- Response mode remains simulation.

## Dashboard Verification

- Overview shows the source in Log Sources.
- Source detail shows health, parser profile, quality, parser errors, and recent runs.
- Investigation can filter by source.
- Alerts can filter by source.
- Alert detail shows "Why flagged?" and source-linked evidence.
- Response & Audit shows no automatic response.

## Failure Handling

- Idle source: confirm device forwarding, firewall rules, receiver host/port, and UDP/TCP protocol.
- Warning source: review parser profile and source quality examples.
- Parse failures: preserve raw evidence and check whether the source needs `generic_syslog` or `raw_fallback`.
- No alerts: verify detection was run for the source and inspect Log Explorer first.

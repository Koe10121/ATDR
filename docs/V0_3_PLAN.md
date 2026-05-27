# ATDR v0.3 Phase 1 Plan

## Goal

Prepare ATDR for controlled real/live ingestion in a small-office or lab environment while preserving the existing local SQLite workflow.

## Added In Phase 1

- Lightweight log source management for file imports, replay, sample ingestion, UDP/TCP syslog, routers, and firewalls.
- Optional `source_id` linkage from raw logs to a source. Existing file imports still work without a source selection.
- Safe fallback source named `local_import` for normal manual imports.
- Source health states: `healthy`, `idle`, `warning`, `error`, and `disabled`.
- Source-level counters for logs received, parse successes, parse failures, last seen, last log received time, and latest error.
- API endpoints:
  - `GET /api/sources`
  - `GET /api/sources/{id}`
  - `POST /api/sources`
  - `PATCH /api/sources/{id}`
  - `GET /api/sources/{id}/health`
- React Overview **Log Sources** panel for compact source health and data-quality visibility.
- Replay and syslog ingestion now attach source metadata where available.
- Parser profile guidance for Palo Alto syslog CSV, generic syslog, and raw fallback behavior.

## Added In Phase 2

- Multi-source replay metadata:
  - `--source-name`
  - `--source-type`
  - `--source-host`
  - `--source-port`
  - `--parser-profile`
- Safe source onboarding helper:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.register_log_source --name lab-firewall-1 --source-type firewall --parser-profile palo_alto --host 192.0.2.10 --port 514 --pretty
```

- Source-aware API filters for logs, alerts, and computed cases:
  - `source_id`
  - `source_name`
  - `source_type`
  - `source_status`
- React Investigation and Alert Workbench source filters.
- React Overview source detail drawer with:
  - source status
  - parser profile
  - last seen / last log received
  - logs received
  - parse success/failure
  - unknown app rate
  - alert count
  - recent source-linked ingestion runs
  - recent source-linked detection runs when source-scoped detection is used
  - parser failure examples
  - troubleshooting hints
- Optional source-scoped detection through `POST /api/detection/run?source_id=<id>` and replay `--run-detection`, without changing the default unfiltered detection workflow.
- Parser profiles now have explicit runtime behavior:
  - `palo_alto` parses Palo Alto syslog CSV fields.
  - `generic_syslog` preserves generic wrapper/message metadata with limited normalized fields.
  - `raw_fallback` stores raw evidence and marks the row as a parser fallback/error.
- Source-level data-quality warnings for idle sources, parse failures, raw fallback profile, generic syslog mismatch, and high unknown/incomplete app rate.

## Added In Phase 3

- Synthetic source-aware validation samples in `data/samples/scenarios/`:
  - `normal_allowed_traffic.txt`
  - `port_scan_like_traffic.txt`
  - `repeated_dedup_traffic.txt`
  - `generic_syslog_mixed.txt`
  - `malformed_raw_fallback.txt`
- Safe scenario runner:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --use-temp-db --run-detection --pretty
```

- Temporary-database mode for expected-outcome validation without touching current local data.
- Dry-run mode for parser-only checks without database writes.
- Expected-outcome checks for:
  - normal traffic avoiding high/critical alerts
  - port-scan-like traffic creating source-scoped suspicious alerts
  - repeated traffic deduplicating into occurrence counts
  - generic syslog preserving evidence with limited structured fields
  - raw fallback preserving evidence and counting parser failures
  - no response actions being triggered by scenario output
- React smoke coverage for source detail warnings, parser fallback wording, and source filters in Investigation and Alert Workbench.
- Clearer source detail wording:
  - healthy sources received recent parseable logs
  - warning/error sources need parser or sender review
  - disabled sources preserve historical evidence
  - raw fallback preserves evidence while structured fields may be limited

## Compatibility Rules

- Normal backend command is unchanged.
- Normal React frontend command is unchanged.
- SQLite remains the default local mode.
- Docker/PostgreSQL remains optional.
- Existing imports do not require source selection.
- Missing or unknown source metadata never blocks ingestion.
- Disabling a source does not delete data.
- Source-aware filters are optional and do not change existing unfiltered API behavior.

## Source Health Interpretation

- `healthy`: logs arrived recently and parse failures are low.
- `idle`: source exists but no recent logs have arrived.
- `warning`: parser failures or latest source error should be reviewed.
- `error`: repeated parser failures indicate format or forwarding mismatch.
- `disabled`: administrator disabled the source.

## Real Syslog Lab Readiness

Start with local validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
.\.venv\Scripts\python.exe -m atdr.scripts.send_sample_syslog --host 127.0.0.1 --port 5514 --count 3
```

Then verify:

- source appears in Overview > Log Sources
- source detail drawer shows parser profile and health
- raw logs increased
- normalized logs increased
- parser failures are explainable
- detection can run on received logs
- alerts/cases update
- logs/alerts/cases can be filtered by source

For a real firewall/router, use an approved lab host, approved UDP/TCP port, and host firewall rules. Vendor-specific forwarding setup remains future lab validation.

## Scenario Validation Matrix

| Scenario | Parser profile | Detection | Expected result |
| --- | --- | --- | --- |
| `normal_allowed_traffic` | `palo_alto` | yes | Parses cleanly and creates no high/critical alerts. |
| `port_scan_like_traffic` | `palo_alto` | yes | Creates at least one source-scoped port-scan-style alert. |
| `repeated_dedup_traffic` | `palo_alto` | yes, twice | Preserves raw evidence and updates an active alert's occurrence count. |
| `generic_syslog_mixed` | `generic_syslog` | optional | Preserves raw evidence with limited generic syslog fields and source warning context. |
| `malformed_raw_fallback` | `raw_fallback` | optional | Records parser failures without crashing and keeps raw evidence available. |
 
Use `--use-temp-db` for proof runs and omit it only when you intentionally want the scenario source and alerts visible in the current React dashboard.

## What Remains Simulated

- Response actions remain simulated and analyst-approved.
- No real firewall enforcement is enabled.
- ML remains decision support only.
- ATDR is lab-ready, not certified production-ready.

## Next Recommended Work

- Add source detail management UI outside the compact Overview panel.
- Add TCP syslog receiver validation if needed for the lab device.
- Add source-level alert drill-downs and parser-error trend charts.
- Validate sustained ingestion on a Docker/PostgreSQL lab host.

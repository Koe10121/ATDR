# ATDR Lab Runbook

This runbook keeps the normal local workflow intact while adding optional lab-readiness checks. SQLite remains valid for local testing. Docker and PostgreSQL are optional lab-pilot targets, not required for daily development.

## Normal Local Workflow

Start the backend:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Start the React dashboard:

```powershell
cd frontend
npm.cmd run dev
```

Open:

```text
http://127.0.0.1:5173
```

This workflow must continue to support log import, detection, alert triage, ML Governance, reviewed CSV import, model retraining, simulated response actions, and audit review.

## Health Check

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Expected result: status `ok`, database `ok`, and response mode `simulation`.

## Safe Lab Scenario Runner

Dry run first:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_lab_scenario --dry-run --use-sample-data --pretty
```

Run against the safe sample file without resetting current data:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_lab_scenario --use-sample-data --no-ml --pretty
```

Run against an explicit private log path only when intended:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_lab_scenario --sample-path "C:/Users/User/Downloads/paloalto-firewall(1).log" --limit 5000 --pretty
```

Optional destructive demo reset is explicit:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_lab_scenario --reset-demo --use-sample-data --pretty
```

The runner never resets data unless `--reset-demo` is passed. It never imports private logs unless `--sample-path` is passed. Simulated response is skipped unless `--simulate-response` is passed.

The output includes import timing, detection timing, ML scoring timing when enabled, feature-generation timing, dashboard summary timing, top attack types, top source IPs, and audit presence.

## Import Logs Manually

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.import_logs "C:/Users/User/Downloads/paloalto-firewall(1).log" --limit 5000
```

Real or large logs should stay outside Git. Do not place private logs in the repository root.

## Run Detection

Through API after login, or from the dashboard Demo Controls. For CLI-style local validation, use the optional lab scenario runner. Detection remains rule-first, and ML remains assistive.

## Live Syslog Local Test

Terminal 1:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
```

Terminal 2:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.send_sample_syslog --host 127.0.0.1 --port 5514 --count 3
```

Verify:

- Raw logs increased.
- Normalized logs increased.
- AI Governance Data Quality shows latest ingestion time.
- Investigation page can find the new rows.
- Detection can be run after ingestion.
- Overview > Log Sources shows a `syslog_udp:<sender-ip>` source with recent activity.

The UDP receiver is local/lab only. Do not bind it to `0.0.0.0` unless host firewall rules and network scope are approved.

## Log Source Management

ATDR v0.3 tracks optional log sources/sensors so a lab operator can tell whether a file import, replay source, or syslog sender is healthy. Normal file import still works without choosing a source. If no source is provided, ATDR uses the safe default source `local_import`.

Source records include:

- name and source type
- host and port when available
- enabled or disabled state
- last seen and last log received time
- logs received, parse success count, and parse failure count
- latest parser/source error
- health status: `healthy`, `idle`, `warning`, `error`, or `disabled`
- parser profile: `palo_alto`, `generic_syslog`, or `raw_fallback`

Register or update a lab source:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.register_log_source --name lab-firewall-1 --source-type firewall --parser-profile palo_alto --host 192.0.2.10 --port 514 --pretty
```

Register a UDP syslog source before local validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.register_log_source --name syslog-localhost --source-type syslog_udp --parser-profile palo_alto --host 127.0.0.1 --port 5514 --pretty
```

List sources through the API:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/sources -Headers @{ Authorization = "Bearer <token>" }
```

Source health logic:

- `healthy`: recent logs were received and parse failures are low.
- `idle`: no logs have arrived recently.
- `warning`: parse failures, latest parser error, or format mismatch need review.
- `error`: repeated parser failures indicate the sender/parser profile should be checked.
- `disabled`: an administrator disabled the source; historical data remains intact.

Disabling a source never deletes raw logs, normalized logs, alerts, labels, or audit records.

Filter logs by source:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/logs?source_name=lab-firewall-1" -Headers @{ Authorization = "Bearer <token>" }
```

Filter alerts or cases by source:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/alerts?source_name=lab-firewall-1" -Headers @{ Authorization = "Bearer <token>" }
Invoke-RestMethod "http://127.0.0.1:8000/api/alerts/cases?source_name=lab-firewall-1" -Headers @{ Authorization = "Bearer <token>" }
```

In React, use source filters in **Investigation / Log Explorer** and **Alert Workbench**. Click a source card in Overview to inspect source health, quality warnings, recent source-linked runs, and parser examples.

Run detection for one source only when validating source-specific replay:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/detection/run?limit=1000&use_ml=true&source_id=<source_id>" -Method Post -Headers @{ Authorization = "Bearer <token>" }
```

The unfiltered detection command remains unchanged. Source-scoped detection is optional and useful for confirming that recent replay or syslog activity from one lab source can be traced into source-linked detection run history.

## v0.7 Controlled Detection Quality Validation

ATDR v0.7 validates defensive detection quality with safe synthetic/replayed logs. This is controlled small-subnet/lab-scale validation, not production certification and not an offensive test.

Run the expectation-based suite against a temporary database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_validation_suite --all --pretty
```

The suite reads `data/samples/scenarios/scenario_expectations.json`, imports each scenario, runs detection, compares actual results to expected outcomes, checks raw evidence preservation, checks evidence quality, verifies no response actions were created, and writes JSON/Markdown reports plus a risk-calibration report to ignored `demo_exports/detection_validation/`.

Current v0.7 scenarios:

- `normal_allowed_traffic`: clean allowed traffic, no high/critical alert.
- `normal_web_dns_quic_traffic`: routine web, DNS, and QUIC traffic, no noisy alert creation.
- `normal_high_volume_but_allowed_traffic`: approved moderate-volume business traffic below exfiltration threshold.
- `normal_repeated_same_service_traffic`: repeated allowed common-service access, no scan/beacon alert.
- `mixed_small_subnet_validation`: benign plus scan-like, brute-force-like, beacon-like, and odd rows in one source.
- `port_scan_like_traffic`: port-scan-style evidence from repeated ports.
- `brute_force_like_traffic`: repeated denied attempts against a service/authentication port.
- `malware_c2_like_beaconing`: repeated outbound destination behavior with risky/uncommon app context.
- `data_exfiltration_suspicion`: high outbound byte-volume pattern.
- `policy_violation_suspicious_app`: high-risk app and suspicious app characteristics.
- `ddos_or_connection_flood_like`: repeated connection flood-like behavior.
- `repeated_dedup_traffic`: repeated alert evidence updates occurrence count instead of creating endless duplicate alerts.
- `generic_syslog_mixed`: raw evidence preserved with limited generic parser fields.
- `malformed_raw_fallback`: raw evidence preserved and parser failures counted without crashing.

The Overview page reads the latest generated validation report through `/api/dashboard/validation-summary` and shows only safe metadata such as pass count and report filenames.

Only write validation rows to the current dashboard database when you intentionally want to inspect them in React:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_validation_suite --scenario port_scan_like_traffic --write-to-current-db --pretty
```

See `docs/V0_7_DETECTION_QUALITY_HARDENING.md` for the v0.7 scenario catalog, risk calibration behavior, and dashboard summary details.

## v0.8 Detection Generalization Validation

ATDR v0.8 checks whether detection behavior still holds when the safe scenario samples are varied. The suite generates synthetic defensive variants with shifted timestamps, safe IP changes, safe port changes, byte/session variation, and benign noise. It does not create offensive payloads, does not execute attacks, and does not create response actions.

Generate variants without importing them into the current dashboard database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.generate_detection_variants --scenario port_scan_like_traffic --variants 3 --pretty
```

Run the full generalization suite against a temporary database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_generalization_suite --all --variants 5 --pretty
```

Reports are written to ignored `demo_exports/detection_generalization/`; generated variant files are written to ignored `demo_exports/detection_variants/`. The Overview page shows a compact latest generalization status with pass count and false-positive/false-negative counts.

Use current-database mode only when you intentionally want to inspect generated variants in React:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_generalization_suite --scenario port_scan_like_traffic --variants 2 --write-to-current-db --pretty
```

See `docs/V0_8_DETECTION_GENERALIZATION.md` for report interpretation, safety boundaries, and known limits.

## v0.9 Layered Detection Validation

ATDR v0.9 compares detection layers across controlled scenarios:

- `rules_only`
- `anomaly_only`
- `supervised_only`
- `hybrid`

Run the full layered validation suite against a temporary database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_layered_detection_validation --all --variants 3 --pretty
```

The report explains what rules caught, where anomaly scoring contributed, where supervised SOC triage produced advisory signals, and how hybrid scoring combines the evidence. Reports are written to ignored `demo_exports/layered_detection/`. The Overview page shows a compact latest layered validation status.

Use current-database mode only when you intentionally want to inspect generated layered validation rows in React:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_layered_detection_validation --scenario port_scan_like_traffic --variants 1 --write-to-current-db --pretty
```

See `docs/V0_9_LAYERED_DETECTION_VALIDATION.md` for layer definitions, current results, and limitations.

## v1.0 End-to-End Workflow Validation

ATDR v1.0 validates the complete controlled SOC workflow: safe log ingestion, raw evidence preservation, parsing, source health, source-scoped detection, alert creation, **Why flagged?** explanation, investigation evidence links, case grouping, optional simulated response approval/denial, audit trail, and report generation.

Run the default end-to-end validation against a temporary database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_e2e_workflow_validation --pretty
```

Exercise simulated response safety as part of the workflow:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_e2e_workflow_validation --scenario port_scan_like_traffic --simulate-response --pretty
```

Reports are written to ignored `demo_exports/e2e_validation/`. The default temporary database mode does not modify your current dashboard data. Only use current-database mode when you intentionally want the validation source, logs, alerts, and audit rows visible in React:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_e2e_workflow_validation --scenario port_scan_like_traffic --source-name e2e-dashboard-check --write-to-current-db --simulate-response --pretty
```

Dashboard verification:

1. Open Overview and confirm the **E2E Workflow** validation card is visible.
2. Check Log Sources for the validation source when current-database mode is used.
3. Open Alerts and confirm **Why flagged?**, evidence count, attack type, and source context are visible.
4. Open Investigation and filter by the validation source to inspect normalized rows and raw evidence.
5. Open Response & Audit and confirm simulated response attempts are audited when `--simulate-response` was used.
6. Confirm no automatic response or real firewall blocking occurred.

See `docs/V1_0_E2E_WORKFLOW_VALIDATION.md` for report fields, safety defaults, and limitations.

## v1.1 Detection Reliability And Benchmarking

ATDR v1.1 adds reliability and benchmarking reports around the existing controlled validation suites. Reports are written to ignored `demo_exports/detection_reliability/`.

Run the full v1.1 reliability baseline against a temporary database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_reliability_baseline --pretty
```

Run a mapped CSV benchmark without committing the dataset:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_benchmark --csv-path C:\path\to\benchmark.csv --limit 1000 --pretty
```

Analyze controlled false positives/false negatives and risk calibration:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.analyze_detection_errors --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.calibrate_detection_risk --pretty
```

Generate ML/SOC triage reliability, drift, and stress reports:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_ml_reliability_report --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.monitor_detection_drift --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_stress_test --iterations 10 --pretty
```

The internal controlled benchmark manifest is:

```text
data/samples/benchmarks/internal_controlled_benchmark.json
```

The dashboard Overview page shows only compact reliability, benchmark, and drift indicators. Detailed evidence remains in reports. These reports do not execute real attacks, do not use offensive tooling, do not enable automatic response, do not perform real firewall blocking, and do not claim production readiness.

See `docs/V1_1_DETECTION_RELIABILITY_AND_BENCHMARKING.md`.

## v1.2 Realistic Benchmark And ML Strengthening

ATDR v1.2 separates larger benchmark-style data from the main local firewall-log database. Use it for public-style, synthetic, or approved benchmark CSVs. Do not commit benchmark CSVs, prepared snapshots, or generated reports.

Prepare a sanitized benchmark snapshot:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.prepare_benchmark_dataset `
  --input-csv "C:\path\to\benchmark.csv" `
  --mapping-config data\samples\benchmarks\example_firewall_mapping.json `
  --label-config data\samples\benchmarks\example_label_mapping.json `
  --limit 5000 `
  --sample-strategy balanced `
  --pretty
```

Run detection benchmark evaluation against the prepared snapshot:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_benchmark `
  --prepared-snapshot "demo_exports\benchmarks\benchmark_snapshot_<id>.json" `
  --detection-mode hybrid `
  --pretty
```

Run safe benchmark ML experiments without activating a model:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_benchmark_ml_experiment `
  --prepared-snapshot "demo_exports\benchmarks\benchmark_snapshot_<id>.json" `
  --split time `
  --test-size 0.3 `
  --pretty
```

Compare rule-only, anomaly-only, supervised-only, and hybrid behavior:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.compare_layered_benchmark_reliability `
  --prepared-snapshot "demo_exports\benchmarks\benchmark_snapshot_<id>.json" `
  --pretty
```

Outputs are ignored under `demo_exports/benchmarks/` and `ml_baseline_reviews/benchmark_ml_experiments/`. The dashboard shows only compact benchmark/readiness status. Benchmark metrics must not be described as production accuracy or mixed with local firewall-log metrics by default.

See `docs/V1_2_REALISTIC_BENCHMARK_AND_ML_STRENGTHENING.md`.

## v0.5 Controlled Replay Validation Archive

ATDR v0.5 uses controlled simulation and replay as the current validation path because real firewall/router hardware is not available yet. This validates source health, parser behavior, source-scoped detection, alert evidence, deduplication, case grouping, simulated response safety, and dashboard investigation flow. It does not validate real device forwarding or real firewall enforcement.

See `docs/V0_5_SIMULATION_DEMO_PLAN.md` for the advisor/demo script and scenario catalog. `docs/V0_5_REAL_SOURCE_VALIDATION_PLAN.md` is kept for future hardware validation.

Use this flow when proving ATDR can receive and investigate traffic from a controlled simulated lab source. It does not reset the database and it does not enable automatic response.

Validate a named source after replay/syslog activity:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_live_source --source-name lab-firewall-1 --source-type firewall --parser-profile palo_alto --duration 60 --run-detection --pretty
```

Useful flags:

- `--duration 0`: check current source state without waiting.
- `--require-activity`: fail validation if no new raw logs arrive during the validation window.
- `--run-detection`: run source-scoped detection and record alert/dedup counts.
- `--no-report`: skip writing the validation report.
- `--report-dir <path>`: write the report somewhere other than the default ignored report folder.

Export a source validation report without running detection:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.export_lab_validation_report --source-name lab-firewall-1 --pretty
```

Reports are written to:

```text
demo_exports/lab_validation_reports/
```

This folder is ignored by Git. A validation report includes source details, parser quality, ingestion and detection run summaries, alert and case summaries, response/audit summary, performance timings, and safety limitations. It explicitly states that response is simulated and ML is decision support only.

Recommended v0.5 dashboard verification:

1. Open Overview and confirm source health, latest ingestion run, latest detection run, and alert count are understandable.
2. Open the source detail drawer and inspect parser profile, quality warnings, parser errors, and recent runs.
3. Open Investigation, filter by source, and confirm raw/normalized evidence is visible.
4. Open Alerts, filter by source, and confirm evidence count, occurrence count, and **Why flagged?** are clear.
5. For repeated replay, confirm raw logs remain available while alerts deduplicate.
6. In Response & Audit, confirm response remains simulated, requires justification, and protected IP attempts are denied/audited.
7. In Admin / Settings, confirm External IAM remains not configured unless explicitly enabled later.

## Source Scenario Validation

ATDR includes small synthetic scenario files in `data/samples/scenarios/` for controlled source-aware validation. These files are safe examples, not private firewall logs.

Run every scenario against a temporary database when you want proof without touching current local data:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario normal_allowed_traffic --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario repeated_dedup_traffic --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario brute_force_like_traffic --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario malware_c2_like_beaconing --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario data_exfiltration_suspicion --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario ddos_or_connection_flood_like --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario generic_syslog_mixed --use-temp-db --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario malformed_raw_fallback --use-temp-db --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario policy_violation_suspicious_app --use-temp-db --run-detection --pretty
```

Expected outcomes:

- `normal_allowed_traffic`: imports and parses clean allowed traffic; no high or critical alerts should be created.
- `port_scan_like_traffic`: creates at least one suspicious/port-scan-style alert when detection runs.
- `repeated_dedup_traffic`: imports and detects the same pattern twice; raw evidence is preserved, while matching active alerts should update `occurrence_count` instead of flooding the queue.
- `brute_force_like_traffic`: creates a brute-force-like service-attempt alert from repeated denied service traffic.
- `malware_c2_like_beaconing`: creates a C2/beaconing-style alert from repeated outbound uncommon/risky app behavior.
- `data_exfiltration_suspicion`: creates a high outbound data-transfer alert.
- `ddos_or_connection_flood_like`: creates a connection flood-style alert from repeated same-target connections.
- `generic_syslog_mixed`: preserves raw evidence and minimal syslog wrapper fields; source health may show warning because firewall-specific fields are limited.
- `malformed_raw_fallback`: preserves raw evidence, counts parser failures, and does not crash.
- `policy_violation_suspicious_app`: creates at least one suspicious/policy-style alert from high app risk and suspicious app characteristics.

Dry-run a scenario without writing rows:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario malformed_raw_fallback --dry-run --pretty
```

Run a scenario against the current local database only when you intentionally want it visible in React:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name scenario-lab-firewall-1 --source-type firewall --parser-profile palo_alto --run-detection --pretty
```

Dashboard validation:

1. Open Overview and confirm the source appears in **Log Sources**.
2. Open the source detail drawer and check health, parser profile behavior, quality warnings, recent ingestion runs, and recent detection runs.
3. Filter **Investigation** by source and confirm raw evidence can be inspected.
4. Filter **Alerts** by source and open the alert evidence panel.
5. For repeated traffic, confirm `occurrence_count`, `related_log_count`, and dedup counts increase while raw logs remain available.
6. For generic/raw fallback traffic, treat warnings as parser-profile signals, not data loss.

If a scenario fails, check the runner's `expected_outcome.checks` output first. Then inspect source health, parser error examples, and whether detection was run with `--run-detection` for alert-producing scenarios.

## Controlled Real Syslog Lab Flow

For a real firewall/router lab test, keep the receiver bound to localhost until the host firewall and network scope are approved. For a device on the same lab network, configure the device to forward syslog to the ATDR host IP and approved UDP/TCP port. Vendor-specific forwarding screens differ, so treat the following as generic guidance:

1. Start the backend normally.
2. Start the UDP receiver:

   ```powershell
   .\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
   ```

3. Validate the path locally before using a device:

   ```powershell
   .\.venv\Scripts\python.exe -m atdr.scripts.send_sample_syslog --host 127.0.0.1 --port 5514 --count 3
   ```

4. Open React at `http://127.0.0.1:5173`.
5. Check Overview > Log Sources for a healthy or recently active source.
6. Check Investigation for the received raw and normalized log rows.
7. Run detection and verify alerts/cases update.
8. If the source is idle, confirm sender IP, receiver bind address, port, host firewall rules, and whether the device is sending UDP or TCP.
9. If the source is warning/error, inspect parse failure examples and confirm the parser profile matches the sender format.

TCP syslog and vendor-specific forwarding validation are future lab work unless explicitly configured and approved.

## Parser Profile Readiness

ATDR currently supports these parser-profile behaviors:

- Palo Alto syslog CSV: splits syslog timestamp and hostname first, then parses the Palo Alto CSV payload with `csv.reader`.
- Generic syslog: preserves the original raw line and minimal syslog wrapper/message metadata with a warning that normalized firewall fields are limited.
- Raw fallback: preserves the original raw line, marks a parser error, and keeps the row available for evidence review when the format is unknown.
- Unknown or incomplete Palo Alto fields: stores known normalized fields, stores the full parsed payload in `parsed_json`, and records missing-field warnings.

Parser failures are operational signals, not data loss. Raw evidence is always preserved.

## Safe Log Replay Mode

Replay mode simulates near-real-time ingestion from a sample log file. It never resets the database. Dry-run mode parses only and does not send syslog packets or write database rows.

Dry-run against the safe demo sample:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty
```

Replay the safe sample to the local UDP syslog receiver:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --send-to syslog --host 127.0.0.1 --port 5514 --limit 20 --rate 2 --pretty
```

Replay directly through the local import service when you do not want to run the UDP receiver:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --send-to direct --limit 20 --rate 0 --pretty
```

Replay directly as a specific lab firewall source:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --send-to direct --source-name lab-firewall-1 --source-type firewall --source-host 192.0.2.10 --source-port 514 --parser-profile palo_alto --limit 100 --rate 1 --pretty
```

Replay directly and run detection afterward:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --send-to direct --limit 20 --rate 0 --run-detection --pretty
```

Replay directly as a named source and run source-linked detection afterward:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --send-to direct --source-name lab-firewall-1 --source-type firewall --parser-profile palo_alto --limit 100 --rate 0 --run-detection --pretty
```

Replay a real/private log only when you explicitly provide the path:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --sample-path "C:/Users/User/Downloads/paloalto-firewall(1).log" --send-to syslog --limit 100 --rate 1 --pretty
```

Keep real and large logs outside Git.

## Near-Real-Time Ingestion Validation Flow

1. Start the backend normally.
2. If testing UDP, start the receiver:

   ```powershell
   .\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
   ```

3. Replay safe logs using `replay_logs`.
4. Open React at `http://127.0.0.1:5173`.
5. Verify Overview > System Health and Ingestion Quality Snapshot:
   - latest raw log time changed
   - latest normalized log time changed
   - parse success count increased
   - parse failure count remains explainable
   - source health changed from idle to healthy or warning
6. Open Investigation and search for the replayed source IP or destination port.
7. Filter Investigation by the source name or source status.
8. Run detection from Demo Controls or API.
9. Verify Alerts show related evidence and can be filtered by source.
10. Verify Active Case Grouping shows related alert/log counts, top destination ports, top actions, and recommended analyst focus.
11. Verify Audit Log contains import/syslog/detection activity.

Repeated replay is expected to preserve every raw log as evidence while deduplicating matching active alerts into occurrence counts instead of flooding the queue.

## Run History Checks

ATDR records lightweight run history for ingestion/import/replay/syslog work and detection work.

List latest ingestion runs:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/ingestion/runs -Headers @{ Authorization = "Bearer <token>" }
```

List latest detection runs:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/detection/runs -Headers @{ Authorization = "Bearer <token>" }
```

The React Overview page shows a compact **Operations Health** panel with:

- latest ingestion run status
- latest detection run status
- parser failures
- deduplicated alert count
- alert creation count
- runtime duration

Run history source names use safe labels such as filenames or `udp:host:port`; private full paths are not exposed in API output.

## Alert Deduplication Behavior

ATDR v0.2 deduplicates live/replayed alert noise by updating an active matching alert when these fields line up inside a short window:

- alert type/rule
- source pattern
- destination pattern
- destination port/service pattern
- event-time window

Deduplication updates the existing alert metadata:

- `occurrence_count`
- `related_log_count`
- first seen / last seen
- sample sources and destinations
- destination ports
- actions and protocols

Raw logs are never deleted. New evidence log IDs are linked to the existing alert, and an `alert_deduplicated` audit event is recorded.

Interpretation:

- `alerts_created`: new SOC alert groups created during the run.
- `alerts_deduplicated`: active alert groups updated instead of creating duplicates.
- `alerts_suppressed`: low-volume or explicitly suppressed groups.
- `occurrence_count`: repeated matching activity represented in one alert.
- `related_log_count`: distinct evidence logs linked to the alert.

## Performance Smoke

Run the read-only performance smoke report:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --feature-limit 20 --pretty
```

This does not import logs, reset data, run detection, score ML, or perform response actions. It times Overview summary, Operations Health run-history queries, alert list, case grouping, ML Governance lightweight summary, supervised report loading, and feature-generation reads.

Local lab budgets:

- Overview summary: ideally under `1s`.
- ML Governance lightweight summary: ideally under `2s`.
- Heavy supervised report/export: acceptable up to a few seconds because it is an explicit governance/reporting action.

If a timing warning appears, reduce page limits for the demo and review indexes/query shape before larger lab operation. For larger datasets, prefer PostgreSQL lab mode and keep ML Governance on the default cached view; use **Refresh ML Summary** after training, scoring, or label import.

Parser-error example extraction is intentionally lightweight for large local datasets. Full raw evidence is still retained and can be inspected through Log Explorer or specific alert/log details.

## Parser Failure Troubleshooting

Parser failures are preserved as raw evidence and visible in Overview/AI Governance data-quality panels.

Common causes:

- blank lines
- missing syslog timestamp / hostname / payload wrapper
- malformed CSV payload
- incomplete Palo Alto payload
- missing source IP, destination IP, action, or timestamp
- unknown or incomplete application values

For a bad row, inspect the parser error example, then compare it with the expected syslog wrapper:

```text
<syslog_timestamp> <hostname> <Palo Alto CSV payload>
```

## Triage And Simulated Response

1. Open Alerts.
2. Select an alert.
3. Review why flagged, evidence logs, ATT&CK-style mapping, and behavior-window evidence.
4. Assign to yourself or mark `Investigating`.
5. Add an analyst note.
6. Use simulated block only when evidence exists and the target is not protected internal infrastructure.
7. Confirm the action.
8. Open Response & Audit or Audit Trail and verify actor, action, target, and reason.

Response actions remain simulated. ATDR records denied response attempts too.

## Optional PostgreSQL/Docker Lab Workflow

Use this only on a Docker-capable host:

```powershell
Copy-Item .env.lab.example .env
.\.venv\Scripts\python.exe -m atdr.scripts.config_doctor --pretty
docker compose --profile postgres up -d postgres
docker compose --profile postgres run --rm migrate
docker compose --profile postgres up --build api dashboard
.\.venv\Scripts\python.exe -m atdr.scripts.lab_smoke_check
```

Docker/PostgreSQL is not required for normal local testing.

## Optional Reset And Seed

Do not reset the current local database unless you intend to clear demo data.

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.reset_demo --yes --path data/samples/paloalto-demo.txt --limit 5000
```

Use `--yes` only when you understand it clears local demo data.

## Troubleshooting

- API health check failed: confirm uvicorn is running on port `8000`.
- React shows failed fetch: confirm `VITE_API_BASE_URL` points to `http://127.0.0.1:8000`.
- Login fails: run `python -m atdr.scripts.seed_users`.
- Config Doctor warns about demo JWT secret: expected in local demo, unsafe for lab/prod.
- Config Doctor warns about missing sample path: set `DEMO_SAMPLE_LOG_PATH` in private `.env` or use `data/samples/paloalto-demo.txt`.
- Syslog test receives nothing: confirm receiver is running before sender and that both use the same host/port.

## Safety Rules

- Do not enable automatic response.
- Do not claim certified production readiness.
- Do not commit real logs, DB files, model artifacts, generated CSV/reports, `.env`, `ml_baseline_reviews/`, or `demo_exports/`.

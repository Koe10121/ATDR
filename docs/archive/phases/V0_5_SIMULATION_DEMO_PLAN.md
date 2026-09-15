# ATDR v0.5 Controlled Replay Validation Plan

## Objective

Make ATDR easy to validate without real firewall/router hardware. v0.5 uses controlled replay, safe source scenarios, dashboard evidence, and validation reports. This is honest lab-scale validation, not production certification and not real hardware validation.

## Current Validation Mode

- Current path: controlled replay / scenario validation.
- Hardware status: real router/firewall validation remains future work.
- Response status: simulated response only.
- ML status: SOC triage decision support only.
- IAM status: local login plus disabled-by-default OIDC groundwork.

## No Hardware Required

The validation flow can be run with:

- synthetic scenario files in `data/samples/scenarios/`
- `run_source_scenario`
- `replay_logs`
- `validate_live_source`
- `export_lab_validation_report`
- React dashboard evidence in Overview, Alerts, Investigation, AI Governance, Response & Audit, and Admin / Settings

## Scenario Catalog

| Scenario | Command Name | What It Proves | Expected Dashboard Result |
| --- | --- | --- | --- |
| Normal allowed traffic | `normal_allowed_traffic` | Clean allowed traffic parses without severe alert noise | Source is healthy; no high/critical alerts from the scenario. |
| Port-scan-like traffic | `port_scan_like_traffic` | Rule evidence, source-scoped detection, alert creation, case grouping | Possible port-scan alert with Why flagged and related logs. |
| Repeated dedup traffic | `repeated_dedup_traffic` | Replayed repeats preserve raw evidence but deduplicate alerts | Existing alert occurrence count and related log count increase. |
| Generic syslog mixed traffic | `generic_syslog_mixed` | Generic parser preserves raw evidence with limited fields | Source warning explains limited parser profile. |
| Malformed raw fallback traffic | `malformed_raw_fallback` | Parser failure handling without crashing | Raw evidence preserved; parse failures counted. |
| Policy/suspicious app traffic | `policy_violation_suspicious_app` | High app risk and suspicious app characteristics create explainable alert | Suspicious/policy alert with app-risk evidence. |

## Commands

Dry-run every scenario without writing database rows:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario normal_allowed_traffic --dry-run --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --dry-run --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario repeated_dedup_traffic --dry-run --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario generic_syslog_mixed --dry-run --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario malformed_raw_fallback --dry-run --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario policy_violation_suspicious_app --dry-run --pretty
```

Run scenarios against a temporary database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario repeated_dedup_traffic --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario policy_violation_suspicious_app --use-temp-db --run-detection --pretty
```

Run a scenario into the current dashboard intentionally:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name demo-port-scan-source --source-type firewall --parser-profile palo_alto --run-detection --pretty
```

Validate the source and export report:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_live_source --source-name demo-port-scan-source --source-type firewall --parser-profile palo_alto --duration 0 --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.export_lab_validation_report --source-name demo-port-scan-source --format both --pretty
```

## Dashboard Validation Flow

1. Open Overview.
2. Point out **Controlled Validation**:
   - controlled replay/scenario validation
   - source health
   - latest scenario run
   - latest detection result
   - simulated response
   - decision support only
3. Open **Log Sources** and click the scenario source.
4. Open **Investigation** and filter by the scenario source.
5. Open **Alerts** and filter by the scenario source.
6. Open alert detail and show:
   - Why flagged?
   - matched rules
   - behavior-window evidence
   - evidence log links
   - ATT&CK-style mapping
7. Open **AI Governance** and explain that ML is assistive, not production accuracy.
8. Open **Response & Audit** and show response requires approval and justification.
9. Export the validation report from CLI.

## What Is Validated

- Source registration/health.
- Raw evidence preservation.
- Parser success/failure handling.
- Source-scoped detection.
- Alert creation and deduplication.
- Case grouping.
- Dashboard source filters.
- Alert evidence explanations.
- Simulated response safety.
- Audit visibility.
- Performance smoke budgets.

## What Is Not Validated

- Real router/firewall forwarding.
- Real firewall blocking.
- Automatic response.
- Production IAM/SSO.
- Production accuracy of ML.
- Production scalability or HA.

## Success Criteria

- Scenario commands pass.
- Dashboard shows source, logs, alerts, evidence, and safety status clearly.
- Validation report writes JSON and Markdown under ignored `demo_exports/lab_validation_reports/`.
- Performance smoke has no warnings.
- Release gate passes.

## Safety Boundaries

- Do not commit generated reports.
- Do not commit real/private logs.
- Do not enable real firewall blocking.
- Do not enable automatic response.
- Do not claim production readiness.

# ATDR v0.3 Lab-Ready Release Candidate Status

ATDR v0.3 is a controlled lab-ready release candidate for small-office style firewall log monitoring. It preserves the normal local workflow while adding source management, parser profiles, source-scoped detection, scenario validation, alert deduplication, run history, and React dashboard investigation support.

## What Works

- FastAPI backend with JWT auth, RBAC, log import, log explorer, alerts, response simulation, audit, ML governance, source management, and dashboard summaries.
- React-first SOC dashboard at `http://127.0.0.1:5173`.
- Existing Streamlit dashboard remains available as a temporary demo/admin prototype.
- Palo Alto syslog CSV parsing with raw evidence preservation.
- Generic syslog and raw fallback parser profiles for controlled lab validation.
- Source management for file import, replay, syslog, router, firewall, and sample sources.
- Source health, source-level data quality, source filters, and source detail drawer.
- Rule-first detection, IsolationForest anomaly scoring, supervised ML decision support, hybrid risk scoring, and AI Governance.
- Alert lifecycle, analyst notes, timelines, case grouping, deduplication, evidence links, and ATT&CK-style mapping.
- Simulated response actions with confirmation, protected-IP safeguards, and audit trail.
- Ingestion and detection run history.
- Replay and scenario validation scripts.
- Performance smoke and release gate checks.

## Validated Scenarios

Safe synthetic files live under `data/samples/scenarios/`.

| Scenario | Expected Result | Current Validation |
| --- | --- | --- |
| `normal_allowed_traffic` | No high/critical alerts | Passed in temporary validation. |
| `port_scan_like_traffic` | Source-scoped port-scan-style alert | Passed; visible as `scenario-lab-firewall-1` when run against local DB. |
| `repeated_dedup_traffic` | Repeated evidence updates one alert | Passed; `occurrence_count` and `related_log_count` increase. |
| `generic_syslog_mixed` | Raw evidence preserved with source warning | Passed; visible as `scenario-router-generic`. |
| `malformed_raw_fallback` | Parser failures counted without crash | Passed; visible as `scenario-raw-fallback`. |

Scenario output does not trigger response actions.

## Current AI Status

- ML is analyst-review eligible and decision-support only.
- The model is not production-promoted.
- Threat-positive triage is strong, but suspicious vs malicious separation remains imperfect.
- Metrics are based on mixed weak and reviewed labels; do not claim production accuracy.
- Response automation remains disabled regardless of model output.

## Current Response Status

- Response actions remain simulated.
- Analyst/admin approval is required.
- High-impact actions require confirmation and justification.
- Protected internal/management IP ranges are guarded.
- Denied attempts are audited.
- No real firewall API enforcement is enabled.

## Live-Source Readiness

- Local file import, replay, direct replay, and UDP syslog lab paths are supported.
- Source-scoped detection can validate a specific replay/syslog source.
- Parser fallback preserves evidence for unmatched formats.
- Real device forwarding still needs controlled lab hardware validation and approved network/host firewall scope.

## Known Limitations

- SQLite is suitable for local lab/demo use; PostgreSQL should be used for shared lab deployment.
- A previous large local SQLite performance smoke showed budget warnings: Overview / ingestion summary around 10.7997s and ML Governance lightweight summary around 2.8009s. The final compliance rerun was healthy: Overview / ingestion summary 0.415s and ML Governance lightweight summary 1.3791s. Monitor for recurrence; do not reset or delete data to hide performance issues.
- Real firewall enforcement is not implemented.
- TCP syslog and vendor-specific device forwarding still need lab validation.
- Case grouping is computed rather than persisted as full incident records.
- Source scenario files are synthetic and prove behavior, not real network coverage.
- Supervised ML still needs more reviewed labels before any production-style claim.

## Recommended Next Phase

Move to v0.4 only after the v0.3 release candidate is stable in daily use. The strongest next options are:

- Docker/PostgreSQL lab deployment validation on a Docker-capable host.
- Real firewall/router syslog forwarding validation in a controlled lab.
- React dashboard polish based on actual analyst usage.
- More reviewed labels for suspicious/malicious boundary quality.

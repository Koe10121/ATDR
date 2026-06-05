# v0.6 Controlled Threat Detection Capability Validation

ATDR v0.6 validates defensive detection capability in a controlled small-subnet / lab-scale setting. It does not claim production readiness, does not execute attacks, and does not enable real firewall blocking.

For the newer detection-quality hardening pass, including negative controls, mixed traffic, evidence quality checks, and risk/severity calibration, see `docs/V0_7_DETECTION_QUALITY_HARDENING.md`.

## Scope

This phase proves that ATDR can:

- ingest safe synthetic or replayed firewall-style logs;
- preserve raw evidence;
- normalize logs into structured records;
- link activity to log sources;
- detect selected threat-like behavior patterns;
- generate explainable alerts;
- keep ML/SOC triage as decision support only;
- keep response actions simulated and analyst-approved;
- produce validation evidence reports.

Real production deployment and real router/firewall forwarding validation remain future work.

## Scenario Library

Safe samples are stored under `data/samples/scenarios/`.

| Scenario | Expected Result |
| --- | --- |
| `normal_allowed_traffic` | Logs ingest and parse; no high/critical alert. |
| `port_scan_like_traffic` | `port_scan` / `possible_port_scan` alert with multiple-port evidence. |
| `brute_force_like_traffic` | `brute_force` alert with repeated denied service-attempt evidence. |
| `malware_c2_like_beaconing` | `malware_c2` alert with repeated outbound destination evidence. |
| `data_exfiltration_suspicion` | `data_exfiltration_suspicion` alert with high outbound byte evidence. |
| `policy_violation_suspicious_app` | Suspicious/policy-style alert from high-risk app and risky app characteristics. |
| `ddos_or_connection_flood_like` | `dos_ddos` / connection-flood alert with repeated connection evidence. |
| `malformed_raw_fallback` | Raw evidence preserved, parse failures counted, no crash. |

Expectations are captured in `data/samples/scenarios/scenario_expectations.json`.

## Validation Suite

Run all scenarios safely against a temporary in-memory SQLite database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_validation_suite --all --pretty
```

Run one scenario:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_validation_suite --scenario port_scan_like_traffic --pretty
```

The default is safe:

- uses a temporary database;
- imports only safe scenario samples;
- runs defensive detection rules;
- checks expected versus actual results;
- checks parser success and raw evidence preservation;
- checks that no response actions were created;
- writes JSON and Markdown reports to ignored `demo_exports/detection_validation/`.

Only write scenario rows to the current local database when intentionally preparing a dashboard validation view:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_validation_suite --scenario port_scan_like_traffic --write-to-current-db --pretty
```

Do not use `--write-to-current-db` for routine testing unless you want the scenario to appear in the dashboard.

## Report Output

Reports include:

- scenario name;
- logs imported;
- parser success/failure;
- raw evidence preservation;
- detection result;
- expected versus actual checks;
- alert type, severity, and risk score;
- "Why flagged?" evidence summary;
- rule/anomaly/supervised/hybrid signal summary;
- safety status;
- limitations.

The correct wording is controlled small-subnet validation. This is not a production certification.

## Detection Improvements

v0.6 adds careful defensive rules for:

- brute-force-like repeated service attempts;
- beaconing-like repeated outbound behavior;
- high outbound byte volume;
- connection flood-like behavior.

The existing normal traffic scenario remains clean so the system does not turn every unusual event into a malicious alert.

## Dashboard Inspection

After intentionally writing a scenario to the current DB, inspect:

- Overview: Controlled Validation, source health, latest scenario activity, safety status;
- Alerts: alert type, severity, risk score, evidence count, Why flagged;
- Investigation: filter by source and review raw/normalized evidence;
- AI Governance: SOC triage decision-support wording;
- Response & Audit: simulated response only, justification required, audit trail retained.

## Safety Boundaries

- No real attacks.
- No offensive tools.
- No automatic response.
- No real firewall blocking.
- No production-readiness claim.
- No real/private logs in Git.
- ML remains SOC triage decision support unless future validation justifies more.

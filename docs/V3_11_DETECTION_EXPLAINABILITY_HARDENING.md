# v3.11 Detection Quality And Explainability Hardening

## Status

v3.11 strengthens ATDR's core advisor-facing requirement: parse logs, normalize them, detect suspicious activity with layered detection, and explain why an alert or log was triaged the way it was.

This pass does not change validated detection thresholds, ML promotion status, response behavior, database schema, or startup commands. ATDR remains a controlled lab prototype. ML remains decision support only, response automation remains disabled, and real firewall blocking is not enabled.

## Source Evidence

| Area | Evidence |
| --- | --- |
| Parser profiles and normalization | `atdr/app/parsers/paloalto_parser.py`, `atdr/app/services/log_service.py` |
| Rule/anomaly/supervised/hybrid detection | `atdr/app/detection/rules.py`, `atdr/app/detection/ml_detector.py`, `atdr/app/detection/supervised_detector.py`, `atdr/app/detection/hybrid_scoring.py` |
| Detection orchestration and deduplication | `atdr/app/services/detection_service.py`, `atdr/app/services/alert_service.py` |
| Alert and log explanations | `atdr/app/detection/explanations.py`, `atdr/app/routers/alerts.py`, `atdr/app/routers/logs.py` |
| Assistant read-only explanation support | `atdr/app/services/assistant_service.py` |
| Dashboard explanation display | `frontend/src/pages/AlertsTriage.tsx`, `frontend/src/pages/LogExplorer.tsx` |
| Validation CLI | `atdr/scripts/validate_detection_pipeline.py`, `atdr/scripts/run_detection_validation_suite.py` |
| Tests | `atdr/tests/test_parser.py`, `atdr/tests/test_detection_explanations.py`, `atdr/tests/test_detection_validation_suite.py`, `frontend/tests/smoke.spec.ts` |

## Detection Pipeline Map

| Stage | What Happens | Evidence / Output |
| --- | --- | --- |
| Raw ingestion | File import, replay, syslog, and source scenarios preserve the original raw line before parsing. | `RawLog.raw_line`, `raw_logs.source_id` |
| Parser selection | Source parser profile selects Palo Alto, generic syslog, or raw fallback behavior. Missing/unknown formats are not allowed to crash ingestion. | `parser_profile`, `parsed_json.parser_warnings`, `parsed_json.parser_error` |
| Normalization | Parser extracts timestamp, source IP, destination IP, ports, action, app, protocol, zones, bytes, packets, and parser metadata when available. | `NormalizedLog` fields |
| Parser failure handling | Malformed or unsupported lines preserve raw evidence and record limited parse status/errors. | `parse_status`, source quality counts, parser warnings |
| Rule detection | Deterministic rules flag known patterns such as port scans, brute-force-like behavior, deny/drop/reset patterns, possible exfiltration, policy violations, and unknown anomalies. | `RuleMatch`, alert type, matched rules |
| Anomaly scoring | IsolationForest marks unusual traffic as assistive evidence. It does not prove malicious activity by itself. | `is_anomaly`, anomaly score where available |
| Supervised scoring | Candidate supervised models provide analyst-review guidance. They are not production-promoted and cannot trigger response. | supervised prediction fields, ML Governance |
| Hybrid risk scoring | Rule, anomaly, supervised, and behavior-window signals contribute to SOC triage risk. | `hybrid_scoring.py`, alert `threat_score` |
| Alert creation | Detection creates alert records with evidence links to normalized logs. | `Alert`, `AlertEvidence` |
| Deduplication | Repeated similar alerts update occurrence count, first/last seen, related log count, and evidence links instead of deleting raw logs. | `occurrence_count`, `related_log_count` |
| Case grouping | Related alerts are grouped into lightweight cases for investigation. | case service / alert grouping |
| Explanation | Alert detail shows why flagged, matched rule/model context, ATT&CK-style mapping, behavior-window evidence, risk, and next analyst checks. | `build_detection_summary`, `explain_log_triage` |
| Analyst safety | Detection and assistant output are read-only decision support. Response actions require explicit analyst approval and remain simulated. | response service, audit log |

## What Changed

- Added a log-level triage explanation helper for the Investigation page.
- Added a "Why flagged?" / "Why not flagged?" style explanation payload to normalized log detail.
- Added parser warning and normalized-signal context to log detail explanations.
- Added explanation-completeness checks for validation reports.
- Added `python -m atdr.scripts.validate_detection_pipeline --pretty` to run safe synthetic scenario validation in a temporary database.
- Added assistant support for read-only log triage questions such as "why was log 123 not flagged?"
- Added frontend display for concise log-triage explanation, safety badges, parser notes, and analyst next-step context.

## Validation Report Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_detection_pipeline --pretty
```

Optional scoped run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_detection_pipeline --scenario normal_allowed_traffic --scenario port_scan_like_traffic --pretty
```

The report includes:

- logs attempted
- logs parsed
- parse failures
- expected alerts
- actual alerts
- missed expected alerts
- unexpected alerts
- dedup behavior
- explanation completeness score
- response actions created

## Safety Controls Preserved

- No database reset or deletion.
- No detection threshold tuning.
- No ML model activation or production promotion.
- No automatic response.
- No real firewall blocking.
- No raw-log sharing through the assistant by default.
- The validation command uses a temporary database and does not mutate the local dashboard DB.

## Known Limitations

- Explanation completeness checks confirm required fields exist; they do not prove that every explanation is semantically perfect.
- Lightweight ATT&CK-style mapping remains analyst context, not full MITRE technique attribution.
- Supervised ML explanations remain candidate decision support because labels and deployment validation are still limited.
- Parser profiles support Palo Alto, generic syslog, and raw fallback; additional vendor-specific parsers remain future work.

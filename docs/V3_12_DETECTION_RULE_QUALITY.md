# v3.12 Detection Rule Quality And Alert Noise Reduction

## Status

v3.12 improves alert quality by reducing duplicate/noisy alert rows in controlled scenario validation without weakening the underlying detection signals.

This pass does not change ML model status, retrain models, activate models, enable automatic response, enable real firewall blocking, reset the database, or change startup commands.

## Source Evidence

| Area | Evidence |
| --- | --- |
| Rule definitions | `atdr/app/detection/rules.py` |
| Grouping / detection orchestration | `atdr/app/services/detection_service.py` |
| Alert grouping / dedup metadata | `atdr/app/services/alert_service.py` |
| Scenario expectations | `data/samples/scenarios/scenario_expectations.json` |
| Validation CLI | `atdr/scripts/validate_detection_pipeline.py`, `atdr/scripts/run_detection_validation_suite.py` |
| Rule catalog | `docs/DETECTION_RULE_CATALOG.md` |
| Tests | `atdr/tests/test_detection_validation_suite.py` |

## Baseline Finding

Before v3.12, the validation suite passed but produced more alert rows than the minimum expected count:

| Metric | Before v3.12 |
| --- | ---: |
| Scenarios | 14 |
| Expected alert count | 8 |
| Actual alert count | 13 |
| Missed expected alerts | 0 |
| Explanation completeness | 1.0 |
| Response actions | 0 |

Extra alert rows were concentrated in:

- `mixed_small_subnet_validation`: repeated outbound beaconing split into two alert rows for one behavior.
- `policy_violation_suspicious_app`: three similar app-risk policy rows from multiple internal sources created three separate medium alerts.

Normal traffic scenarios stayed quiet. Port scan, brute force, malware/C2-like beaconing, exfiltration suspicion, DDoS/flood-like behavior, dedup behavior, generic syslog, and raw fallback remained valid.

## Changes Made

- Added explicit scenario expectation clarity:
  - expected primary attack type
  - allowed secondary attack types
  - minimum expected alert count
  - maximum acceptable alert count
  - unexpected attack type classification
- Adjusted grouping for app-risk policy rules so similar internal app-risk events are grouped into one SOC triage alert instead of one alert per source.
- Adjusted grouping for repeated destination behaviors so repeated outbound beaconing does not split by short time buckets.
- Adjusted grouping for port-scan multi-event patterns so safe synthetic variants do not split one scan into multiple port-scan alert rows.
- Improved explanation completeness so grouped alerts with sample source/destination metadata count as source/destination evidence.
- Added `docs/DETECTION_RULE_CATALOG.md`.

## After v3.12 Validation

| Metric | After v3.12 |
| --- | ---: |
| Scenarios | 14 |
| Expected alert count | 10 |
| Actual alert count | 10 |
| Missed expected alerts | 0 |
| Unexpected alert types | 0 |
| Deduplicated alert updates | 1 |
| Explanation completeness | 1.0 |
| Response actions | 0 |

The expected count increased from 8 to 10 because v3.12 now counts multi-behavior scenarios honestly. The alert count dropped from 13 to 10 because duplicate/noisy grouping was reduced.

## Rule Behavior Preserved

| Behavior | Status |
| --- | --- |
| Port scan-like traffic | Still detected |
| Brute-force-like traffic | Still detected |
| Malware/C2-like beaconing | Still detected |
| Data exfiltration suspicion | Still detected |
| DDoS/connection flood-like behavior | Still detected |
| Repeated dedup traffic | Still deduplicates |
| Normal allowed traffic | Still quiet |
| Generic syslog mixed input | Still preserves evidence and creates no alert |
| Raw fallback malformed input | Still records parse failures without crashing |

## Remaining Noisy Areas

- App-risk and suspicious application characteristics are still triage signals. They should be reviewed with business context.
- Real device validation may reveal new source-specific noise patterns.
- ML-assisted outputs remain decision support and are not production-promoted.

## Safety Controls Preserved

- No automatic response.
- No real firewall blocking.
- No model activation or promotion.
- No DB reset or deletion.
- No raw evidence deletion during grouping/deduplication.
- No production readiness claim.

# v3.44 Two-Stage SOC Queue Admission And Severity Separation

## Status

v3.44 is a diagnostic-only supervised ML phase. It does not write labels, activate models, write active model artifacts, enable automatic response, or change detection behavior.

## Purpose

v3.43 showed that evidence-first queue admission catches most review-worthy rows, but too many queued rows are counted as suspicious or malicious. v3.44 separates the two decisions:

1. Stage A decides whether a row should enter the SOC review queue.
2. Stage B classifies queued rows as unusual/needs-review, evidence-backed suspicious, or malicious high-confidence.

This lets ATDR test whether a row can be useful for analyst review without inflating threat-positive severity.

## Strategies Evaluated

- `deterministic_queue_ml_severity_extra_trees`
- `ml_queue_ml_severity_extra_trees`
- `hybrid_queue_ml_severity_extra_trees`
- `ml_queue_ml_severity_logistic_regression`
- `hybrid_queue_ml_severity_logistic_regression`

All strategies are evaluated across time, grouped/source-aware, and repeated random splits.

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Labels written: false
- Response automation allowed: false
- Real firewall blocking: false

## Expected Interpretation

v3.44 should be judged as a diagnostic candidate only. A useful result would improve the separation between queue recall and threat-positive false positives. It should remain `candidate_only` unless split stability, false-positive control, threat recall, and calibration are all acceptable.

## Current Result

Best diagnostic candidate:

- `ml_queue_ml_severity_logistic_regression`
- Readiness: `candidate_only`
- Checks passed: `7 / 10`
- Passing stability splits: `0 / 5`
- Queue recall min: `0.9218`
- Queue false-positive rate max: `0.9745`
- Threat-positive F1 min: `0.3913`
- Threat-positive false-positive rate max: `0.0759`
- Evidence-backed suspicious recall min: `0.2357`
- Malicious/high-confidence recall min: `0.0`
- Calibration: passed

Notable comparison:

- `ml_queue_ml_severity_extra_trees` kept better threat-positive F1 min (`0.7489`) and malicious recall min (`0.6606`), but threat-positive FPR max stayed too high (`0.4423`).
- Logistic regression controlled threat-positive FPR, but missed too many malicious/high-confidence rows.

## Interpretation

Two-stage queue/severity separation helped clarify the supervised design problem. It reduced threat-positive over-promotion compared with v3.43, but it did not produce a stable candidate:

- Queue admission still admits too many benign-like rows across some splits.
- Conservative severity thresholds reduce false positives but collapse malicious/high-confidence recall.
- ExtraTrees preserves more threat recall but remains too noisy.

The next meaningful phase should focus on better queue target quality and calibrated severity modeling rather than activation.

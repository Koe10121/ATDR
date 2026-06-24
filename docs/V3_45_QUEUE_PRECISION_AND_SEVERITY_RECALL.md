# v3.45 Queue Precision And Severity Recall Repair

## Status

v3.45 is a diagnostic-only supervised ML phase. It does not write labels, activate models, write active model artifacts, enable automatic response, or change detection behavior.

## Purpose

v3.44 proved that SOC queue admission and severity classification should be separated, but the tested variants still had unstable queue false positives and severity recall. v3.45 tests a stricter queue gate with evidence rescue:

- Low-signal web/utility traffic should not enter the queue from model probability alone.
- Rule/anomaly/scan-backed evidence can still rescue rows into the queue.
- Severity classification should keep malicious/high-confidence recall from collapsing.

## Strategies Evaluated

- `precision_queue_extra_trees_recall_severity_extra_trees`
- `precision_queue_extra_trees_recall_severity_logistic_regression`
- `precision_queue_logistic_regression_recall_severity_extra_trees`
- `precision_queue_logistic_regression_recall_severity_logistic_regression`

All strategies are evaluated across time, grouped/source-aware, and repeated random splits.

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Labels written: false
- Response automation allowed: false
- Real firewall blocking: false

## Expected Interpretation

v3.45 should remain `candidate_only` unless it improves queue false positives, threat false positives, malicious recall, and split stability at the same time. If the tradeoff remains unstable, the next phase should focus on label target quality and possibly a dedicated benchmark set rather than activation.

## Current Result

Best diagnostic candidate:

- `precision_queue_logistic_regression_recall_severity_extra_trees`
- Readiness: `candidate_only`
- Checks passed: `6 / 11`
- Passing stability splits: `0 / 5`
- Queue recall min: `0.3889`
- Queue false-positive rate max: `0.3265`
- Threat-positive F1 min: `0.5593`
- Threat-positive false-positive rate max: `0.3246`
- Evidence-backed suspicious recall min: `0.2214`
- Malicious/high-confidence recall min: `0.344`
- Calibration: passed

Notable comparison:

- `precision_queue_extra_trees_recall_severity_extra_trees` kept better queue recall min (`0.8786`) and malicious recall min (`0.6422`), but queue FPR max (`0.8138`) and threat FPR max (`0.7429`) were too noisy.
- Logistic queue variants controlled queue FPR better (`0.3265`) but queue recall collapsed to `0.3889`.

## Interpretation

v3.45 confirms that the next blocker is not a simple threshold issue:

- ExtraTrees can preserve threat recall but over-admits benign-like rows.
- Logistic queueing can reduce queue noise but suppresses too many review-worthy rows.
- Calibration is acceptable, but split stability remains `0 / 5`.

The next meaningful phase should inspect queue-target disagreement and feature separability directly. ATDR likely needs a cleaner queue training target, benchmark cases, or richer behavior-window features before a supervised SOC queue model can be stable.

# v3.49 Repaired Queue Severity Classification

## Status

v3.49 evaluated downstream severity classification after the stable v3.48 repaired queue admission model. It remains diagnostic only.

## Purpose

v3.48 showed that repaired queue admission is stable. v3.49 tests whether the queued rows can be separated into:

- `unusual_needs_review`
- `evidence_backed_suspicious`
- `malicious_high_confidence`

The evaluation compares:

- repaired queue + ExtraTrees severity
- repaired queue + Logistic Regression severity
- probability-only severity decisions
- evidence-guarded severity decisions

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Labels written: false
- Response automation allowed: false
- Real firewall blocking: false

## Result

Best diagnostic strategy:

- `repaired_queue_extra_trees_severity_logistic_regression_evidence_guarded`

Readiness:

- Decision: `candidate_only`
- Checks passed: `7 / 11`
- Passing severity splits: `0 / 5`
- Calibration: passed

Best strategy metric ranges across the standard split set:

| Metric | Min | Max |
| --- | ---: | ---: |
| Threat-positive precision | 0.7555 | 0.9382 |
| Threat-positive recall | 0.5496 | 0.9300 |
| Threat-positive F1 | 0.6545 | 0.9341 |
| Benign-like false-positive rate | 0.0458 | 0.1037 |
| Suspicious recall | 0.2286 | 0.7200 |
| Malicious recall | 0.4358 | 0.8403 |
| Macro F1 | 0.3293 | 0.5782 |
| Weighted F1 | 0.2658 | 0.5785 |
| Queue precision | 0.9886 | 1.0000 |
| Queue recall | 0.9559 | 0.9937 |
| Queue F1 | 0.9720 | 0.9969 |
| Queue false-positive rate | 0.0000 | 0.0467 |

Main blockers:

- Independent severity stability did not pass.
- Threat-positive F1 dropped below the target on some splits.
- Suspicious recall dropped as low as `0.2286`.
- Malicious recall dropped as low as `0.4358`.

Top severity confusions for the best diagnostic strategy:

- `evidence_backed_suspicious -> unusual_needs_review`: 271
- `malicious_high_confidence -> evidence_backed_suspicious`: 155
- `evidence_backed_suspicious -> malicious_high_confidence`: 123
- `malicious_high_confidence -> unusual_needs_review`: 107
- `unusual_needs_review -> evidence_backed_suspicious`: 103

## Interpretation

The repaired queue target is still the most stable supervised direction found so far. Queue admission remains strong across splits, with low false positives and high recall.

The downstream severity classifier is not stable enough to activate. It can decide which rows need SOC review, but it cannot yet reliably separate `unusual_needs_review`, `evidence_backed_suspicious`, and `malicious_high_confidence` across independent splits.

This suggests the next improvement should focus on severity target semantics, evidence feature support, and benchmark coverage for queued rows rather than additional threshold tuning or model activation.

## Expected Interpretation

ATDR should keep the stable queue model as a diagnostic admission layer and improve severity semantics before any activation discussion. The next phase should audit queued-row severity labels and evidence features so `unusual`, `suspicious`, and `malicious` are more learnable and better supported.

# v3.57 Queue-vs-Rule/Hybrid Agreement Diagnostic

## Status

Implemented as diagnostic-only supervised ML explainability work.

No model was activated, no model artifact was written, no labels were created or changed, no response actions were created, and response automation remains disabled.

## Purpose

v3.55 and v3.56 showed that the binary SOC review-queue target is more stable than exact severity classification. v3.57 checks whether that queue decision agrees with deterministic rule/anomaly/hybrid evidence.

This helps answer two analyst questions:

- When does ML agree with the rule/hybrid evidence?
- When does one side flag a row for review while the other side does not?

## What Changed

- Added `atdr/app/detection/v357_queue_rule_hybrid_agreement.py`.
- Added `atdr/scripts/run_v357_queue_rule_hybrid_agreement.py`.
- Added focused backend tests in `atdr/tests/test_v357_queue_rule_hybrid_agreement.py`.
- Generated ignored diagnostic outputs under `ml_baseline_reviews/`.

The diagnostic compares:

- queue model prediction: `needs_review` or `non_threat`
- deterministic evidence decision: `needs_review` or `non_threat`
- target queue label
- rule/anomaly/scan/high-risk/low-signal evidence snapshot

## Agreement Categories

- `queue_and_evidence_agree_review`
- `queue_only_review`
- `evidence_only_review`
- `queue_and_evidence_agree_non_review`

## Current Local Result

Latest local run:

- Evaluated splits: `5`
- Passing splits: `4`
- Queue F1 minimum: `0.9725`
- Queue recall minimum: `0.948`
- Queue precision minimum: `0.9907`
- Queue false-positive rate maximum: `0.04`
- Queue/evidence agreement minimum: `0.884`
- Calibration ECE maximum: `0.0137`
- Readiness: `diagnostic_only`

The queue model remains strong, but one split has evidence-only review rate above the current diagnostic budget.

Top evidence-only review patterns:

- `quic-base / allow / 443`
- `facebook-base / allow / 443`
- `ping / allow`
- other web/utility traffic with scan/diversity or rule context

## Interpretation

The supervised queue candidate is stable and low-noise, but deterministic evidence still identifies some rows that the queue model leaves as non-review. This is not a production blocker because no model is active, but it is important for future assistant and alert explanation quality.

Recommended next use:

- Keep the queue diagnostic candidate-only.
- Use disagreement examples to improve evidence explanations and future queue calibration.
- Do not auto-label disagreement rows.
- Do not activate or promote the queue model yet.

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Labels written: false
- Raw logs included: false
- Response automation allowed: false
- Real firewall blocking enabled: false

## Manual Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v357_queue_rule_hybrid_agreement --test-size 0.3 --min-samples 6 --pretty
```

Generated reports stay ignored in `ml_baseline_reviews/`.

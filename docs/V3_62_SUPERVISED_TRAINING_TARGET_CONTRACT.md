# v3.62 Supervised Training Target Contract

## Status

Implemented as diagnostic-only supervised ML safety infrastructure.

## Purpose

Recent supervised ML diagnostics showed that ATDR should not train or present exact suspicious/malicious/benign-like labels as active production classifier outputs. The stable path is a binary SOC review-queue target:

- `non_threat`
- `needs_review`

v3.62 makes that strategy reusable and testable by adding a safe training-target adapter. It maps current exact labels plus evidence features into a binary queue target while keeping exact labels as explanation/ranking context only.

## What Changed

- Added `atdr/app/detection/v362_supervised_training_target_contract.py`.
- Added `atdr/scripts/run_v362_supervised_training_target_contract.py`.
- Added focused tests in `atdr/tests/test_v362_supervised_training_target_contract.py`.
- The diagnostic writes ignored reports under `ml_baseline_reviews/`.

## Current Local Result

Latest run:

- Decision: `safe_queue_target_adapter_ready`
- Recommended target: `binary_soc_review_queue`
- Rows audited: `2672`
- Safe target distribution: `needs_review=2252`, `non_threat=420`
- Exact label policy: `explanation_or_ranking_only`
- Runtime activation allowed: `false`
- Production promotion allowed: `false`
- Response automation allowed: `false`
- Labels written: `false`
- Model runs written: `false`
- Response actions written: `false`

## Important Finding

The adapter found substantial label/evidence semantic tension:

- High-severity semantic issue rows: `1522`
- Weak/unreviewed high-severity semantic issue rows: `296`
- Main pattern: benign-like labels with threat evidence.
- Time split target-rate shift: up to `0.2193`

This supports the current policy: use supervised ML for SOC review prioritization, not exact production classification.

## Allowed And Blocked Targets

Allowed for diagnostic training:

- `binary_soc_review_queue`

Blocked:

- `flat_5class_exact_label`
- `exact_suspicious_vs_malicious_production_classifier`
- `ai_generated_human_review_label`

## Safety

v3.62 does not:

- reset or delete data
- write labels
- train or activate a model
- write active model artifacts
- promote a model
- enable automatic response
- enable real firewall blocking
- include raw logs in reports

## Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v362_supervised_training_target_contract --pretty
```

Generated outputs stay under `ml_baseline_reviews/` and remain ignored.

## Next Recommended Phase

Use the v3.62 adapter as the canonical target contract for future supervised diagnostics. The next ML work should evaluate a queue-only diagnostic model through this adapter and measure stability, calibration, and queue/evidence agreement without activating a model.

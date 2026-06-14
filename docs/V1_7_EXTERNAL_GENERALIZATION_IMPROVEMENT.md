# ATDR v1.7 External Generalization Improvement

v1.7 improves external/unseen benchmark behavior after v1.6 exposed a generalization gap. The work is still decision-support only. It does not activate a model, production-promote a model, enable automatic response, or enable real firewall blocking.

## What v1.6 Exposed

The v1.6 fixed unseen holdout used 320 safe synthetic/public-style rows across 5 sources and 14 scenarios. It showed that the internal benchmark was easier than the unseen holdout:

- Threat-positive F1: `0.7278`
- Benign-like false-positive rate: `0.3467`
- Suspicious recall: `0.3500`
- Malicious recall: `0.8889`
- Calibration: weak
- Readiness: `internal_benchmark_validated_candidate`

This is useful evidence: ATDR should not present internal benchmark results as production accuracy.

## What v1.7 Adds

Implementation evidence:

- `atdr/scripts/run_v17_external_generalization.py`
- `atdr/app/benchmarks/readiness.py`
- `atdr/app/routers/dashboard.py`
- `frontend/src/pages/MLGovernance.tsx`
- `frontend/src/pages/ExecutiveOverview.tsx`

The v1.7 script:

- analyzes external holdout false positives and false negatives
- compares external threshold/profile strategies
- tests confidence calibration buckets
- applies an overfitting guard
- exports an analyst review CSV for boundary rows
- writes ignored JSON/Markdown reports under `demo_exports/benchmarks/`
- writes ignored review CSV under `ml_baseline_reviews/`

## Current v1.7 Result

Latest run:

- Best profile: `hybrid_external_balanced`
- External threat-positive precision: `0.9533`
- External threat-positive recall: `0.8412`
- External threat-positive F1: `0.8937`
- Benign-like false-positive rate: `0.0467`
- Suspicious recall: `0.7875`
- Malicious recall: `0.7222`
- Macro F1: `0.8328`
- Calibration: weak, because max confidence/accuracy gap remains above the target
- External validation: not yet passed
- Readiness: `internal_benchmark_validated_candidate`

Compared with v1.6, v1.7 substantially reduces false positives and improves suspicious recall, but the model is still not externally validated because suspicious recall is just below target, external threat recall is just below target, calibration remains weak, and the internal-to-external gap is still flagged.

## Reports Generated

Generated reports are ignored and should not be committed:

- `demo_exports/benchmarks/v1_7_external_generalization_<timestamp>.json`
- `demo_exports/benchmarks/v1_7_external_generalization_<timestamp>.md`
- `demo_exports/benchmarks/v1_7_external_error_analysis_<timestamp>.md`
- `ml_baseline_reviews/v1_7_external_boundary_review_sample.csv`

The review sample targets rows such as:

- benign-like rows predicted as suspicious or malicious
- suspicious rows predicted as benign-like
- suspicious/malicious boundary rows
- rows where rule, supervised, and hybrid signals disagree
- QUIC/TLS, incomplete allow, unknown service, background UDP, and policy-violation boundaries

The export now includes `review_dataset_kind=external_holdout`, `review_import_workflow=benchmark_review`, and `benchmark_row_id`. It must use the dedicated benchmark review workflow rather than the normal reviewed-label importer because benchmark rows do not have `log_id` or `label_id`.

See [V1_7B_BENCHMARK_REVIEW_IMPORT.md](V1_7B_BENCHMARK_REVIEW_IMPORT.md).

## Run Command

```powershell
python -m atdr.scripts.run_v17_external_generalization --review-limit 300 --pretty
```

If the external holdout snapshot is missing, run v1.6 first:

```powershell
python -m atdr.scripts.run_external_benchmark_validation --holdout-from-current-data --pretty
```

After human review, import and apply the reviewed benchmark CSV:

```powershell
python -m atdr.scripts.import_benchmark_review_csv --input-csv "C:\path\to\v1_7_external_boundary_review_sample_REVIEWED.csv" --benchmark-kind external_holdout --pretty
python -m atdr.scripts.run_external_benchmark_validation --holdout-from-current-data --reviewed-benchmark-csv "C:\path\to\v1_7_external_boundary_review_sample_REVIEWED.csv" --pretty
python -m atdr.scripts.run_v17_external_generalization --review-limit 300 --pretty
```

## Safety Interpretation

- v1.7 is an external benchmark improvement workflow, not production certification.
- External benchmark metrics are separate from real firewall-log metrics.
- The selected profile is not activated automatically.
- ML remains SOC triage decision support.
- Response automation remains disabled.
- Every response action remains simulated and analyst-approved.

## Recommended Next Work

- Review the v1.7 boundary sample.
- Add more reviewed benign boundary rows and suspicious policy/unknown-service boundary rows.
- Improve calibration before trusting displayed confidence.
- Validate with controlled real router/firewall syslog forwarding.
- Keep readiness conservative until external validation, calibration, and real-source validation improve together.

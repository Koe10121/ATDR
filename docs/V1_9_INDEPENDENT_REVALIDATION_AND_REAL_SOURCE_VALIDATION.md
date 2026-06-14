# ATDR v1.9 Independent Revalidation And Controlled Real-Source Validation

## Purpose

v1.8 passed a reviewed synthetic external benchmark. v1.9 checks whether that
result transfers to a newly generated holdout with different source names,
scenario families, timing, and boundary patterns. It also validates the
source-aware ingestion and investigation workflow with safe replay/syslog-style
inputs.

This phase does not activate a model, enable automatic response, execute an
attack, or claim production readiness.

## Validation Layers

1. Internal benchmark: deterministic fixture used for architecture and pipeline
   checks.
2. External synthetic benchmark: reviewed v1.6-v1.8 holdout used for model
   generalization work.
3. Independent holdout: new seeded v1.9 data that is not used for model
   training or profile tuning.
4. Controlled real-source validation: safe source/replay/parser workflows that
   exercise ingestion, source health, detection, evidence, cases, response
   safety, and audit behavior.

Controlled real-source validation means the application follows the same source
management and ingestion path used for a lab sensor. It does not mean a real
router or firewall has completed vendor-specific forwarding validation.

## Commands

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.build_independent_holdout --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_controlled_real_source_validation --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v19_independent_revalidation --pretty
```

Generated CSVs, snapshots, and reports remain under ignored
`demo_exports/benchmarks/`.

## Independent Holdout

The default generator creates 500 synthetic rows with:

- six logical sources and sixteen scenario families;
- benign-like, suspicious, malicious, and needs-context rows;
- normal negative controls and near-threat benign traffic;
- low-and-slow scanning and credential boundaries;
- delayed DNS beaconing and gradual outbound transfer patterns;
- ambiguous rows intended for analyst review.

The report includes exact and near-duplicate counts and checks exact overlap
against existing prepared snapshots. Exact overlap must remain zero.

## Current Result

The selected v1.8 profile remains `external_recall_plus`.

| Metric | v1.8 external | v1.9 independent |
| --- | ---: | ---: |
| Threat precision | 0.9568 | 0.8679 |
| Threat recall | 0.9118 | 0.9346 |
| Threat F1 | 0.9338 | 0.9000 |
| Benign false-positive rate | 0.0467 | 0.1542 |
| Suspicious recall | 0.9375 | 0.9538 |
| Malicious recall | 0.8556 | 0.8769 |

Calibration passes using out-of-fold confidence calibration. The independent
holdout does not pass readiness v7 because its benign false-positive rate is
slightly above the 0.15 target. The final performance smoke is within the
current local budgets.

The correct status remains `external_benchmark_validated_candidate`, not
independently revalidated and not production promoted.

## Controlled Source Result

The isolated temporary-database workflow validates:

- Palo Alto-style replay and source health;
- generic syslog and malformed/raw fallback behavior;
- parser success and failure accounting;
- source-scoped detection, alert evidence, Why flagged, and case grouping;
- alert deduplication;
- protected-IP denial and audit entries;
- explicitly approved response remaining simulated;
- zero automatic response actions.

This controlled workflow passes, but real device forwarding and long-duration
source stability remain future lab work.

## Readiness v7

Readiness v7 can report:

- `analyst_review_eligible`
- `internal_benchmark_validated_candidate`
- `external_benchmark_validated_candidate`
- `independently_revalidated_candidate`
- `controlled_real_source_validated_candidate`

Every status remains decision-support only. The gate always reports production
promotion, model activation, response automation, and real firewall blocking as
disabled.

## Remaining Work

- reduce independent benign false positives without tuning directly on the
  independent holdout;
- generate another independent holdout after any model/profile change;
- validate UDP/TCP forwarding from a controlled router or firewall;
- continue long-duration drift and parser monitoring.

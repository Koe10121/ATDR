# v1.2 Realistic Benchmark And ML Strengthening

ATDR v1.2 adds a safe benchmark-intake and ML experiment workflow for larger public-style or synthetic labeled CSV data. The goal is to improve detection reliability evidence without importing benchmark labels into the main local `ml_labels` table by default.

ATDR remains a lab-ready defensive prototype. It does not execute attacks, does not enable automatic response, does not perform real firewall blocking, and does not claim production readiness.

## What v1.2 Adds

- Sanitized benchmark dataset preparation:
  - `atdr/scripts/prepare_benchmark_dataset.py`
  - output under ignored `demo_exports/benchmarks/`
- Example benchmark mapping configs:
  - `data/samples/benchmarks/example_firewall_mapping.json`
  - `data/samples/benchmarks/example_label_mapping.json`
- Larger benchmark detection evaluation:
  - `atdr/scripts/run_detection_benchmark.py`
  - supports prepared snapshots and modes `rules_only`, `anomaly_only`, `supervised_only`, and `hybrid`
- Safe benchmark ML experiment mode:
  - `atdr/scripts/run_benchmark_ml_experiment.py`
  - trains/evaluates candidate models in memory only
  - does not activate or promote any model
- Layered benchmark comparison:
  - `atdr/scripts/compare_layered_benchmark_reliability.py`
  - compares rule, anomaly, supervised, and hybrid behavior
- Model readiness gate v2:
  - `atdr/app/benchmarks/readiness.py`
  - reports candidate status only; production promotion stays disabled
- Dashboard summary:
  - Overview and AI Governance can show latest benchmark F1/readiness status when a report exists.

## Why Controlled Scenarios Are Not Enough

The v0.7-v1.1 validation suites prove that ATDR behaves correctly on controlled synthetic scenarios, negative controls, source-scoped replay, and end-to-end workflows. They do not prove broad deployment accuracy. Larger benchmark-style data helps evaluate:

- class imbalance
- false positives and false negatives across more rows
- attack-type coverage
- whether rules, ML, anomaly, and hybrid layers contribute differently
- whether model readiness gates remain honest under more data

Benchmark metrics remain separate from local firewall-log metrics.

## Prepare A Benchmark CSV

Use a public-style, synthetic, or approved local benchmark CSV. Do not commit the CSV. Map the CSV fields with the example configs:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.prepare_benchmark_dataset `
  --input-csv "C:\path\to\benchmark.csv" `
  --mapping-config data\samples\benchmarks\example_firewall_mapping.json `
  --label-config data\samples\benchmarks\example_label_mapping.json `
  --limit 5000 `
  --sample-strategy balanced `
  --pretty
```

The prepared snapshot is written under ignored `demo_exports/benchmarks/`. Private raw payload-like columns are excluded by default. The report includes missing field rates, label distribution, attack type distribution, time range, and class imbalance warnings.

## Run Detection Benchmark

Run against a prepared snapshot. Temporary DB mode is the default.

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_benchmark `
  --prepared-snapshot "demo_exports\benchmarks\benchmark_snapshot_<id>.json" `
  --detection-mode hybrid `
  --pretty
```

Supported modes:

- `rules_only`
- `anomaly_only`
- `supervised_only`
- `hybrid`

The report includes per-class metrics, per-attack metrics, confusion matrix, threat-positive precision/recall/F1, false positives, false negatives, alert volume, runtime, and response safety confirmation.

## Run Benchmark ML Experiment

This trains candidate models against the prepared snapshot but does not write or activate model artifacts.

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_benchmark_ml_experiment `
  --prepared-snapshot "demo_exports\benchmarks\benchmark_snapshot_<id>.json" `
  --split time `
  --test-size 0.3 `
  --pretty
```

Candidate families:

- RandomForest
- ExtraTrees
- LogisticRegression
- HistGradientBoosting
- binary threat-positive model
- three-class SOC triage model

Reports are written under ignored `ml_baseline_reviews/benchmark_ml_experiments/`.

## Compare Rule, ML, And Hybrid Reliability

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.compare_layered_benchmark_reliability `
  --prepared-snapshot "demo_exports\benchmarks\benchmark_snapshot_<id>.json" `
  --pretty
```

This writes `layered_benchmark_comparison_<timestamp>.md` under ignored `demo_exports/benchmarks/`.

## Readiness Gate v2

Readiness considers:

- benchmark/review label count
- class coverage
- threat-positive F1
- threat-positive recall
- macro or weighted F1
- benign-like false-positive rate
- drift warnings
- response automation disabled

Possible decisions:

- `candidate_only`
- `analyst_review_eligible`
- `benchmark_validated_candidate`

Production status remains `not_production_promoted`.

## Safety Rules

- Do not commit benchmark CSVs, snapshots, reports, DB files, model artifacts, `.env`, `ml_baseline_reviews/`, `demo_exports/`, or processed logs.
- Do not mix benchmark metrics into local firewall-log metrics by default.
- Do not describe benchmark metrics as real deployment accuracy.
- ML remains SOC triage decision support.
- Response actions remain simulated and analyst-approved.

## Verification Evidence

v1.2 adds tests in:

- `atdr/tests/test_benchmark_workflow_v12.py`
- `atdr/tests/test_api.py`
- `frontend/tests/smoke.spec.ts`

Run the full release gate before claiming the checkpoint is ready.

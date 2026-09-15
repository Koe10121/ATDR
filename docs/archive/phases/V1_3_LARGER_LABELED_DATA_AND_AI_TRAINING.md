# v1.3 Larger Labeled Data and AI Training

## Purpose

ATDR v1.3 strengthens supervised SOC-triage evaluation by auditing the current label set, defining class-specific review targets, exporting a larger active-learning batch, comparing candidate models, and applying a stricter readiness gate.

This phase does not activate a model, enable automatic response, or claim production accuracy.

## Evidence Rules

- Reviewed labels are stronger evidence than assisted weak labels.
- Time-split validation is the primary supervised evaluation.
- Random/grouped splits are diagnostic because repeated traffic can inflate results.
- Benchmark metrics stay separate from local firewall-log metrics.
- Threat-positive metrics do not replace suspicious and malicious per-class metrics.
- Every response remains simulated and analyst-approved.

## Audit Training Data

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.audit_training_data_quality --split time --test-size 0.3 --pretty
```

The ignored Markdown and JSON reports show reviewed and weak label counts, class and attack-type distributions, source/time coverage, duplicate patterns, missing feature rates, class overlap, and supervised training readiness.

## Generate Label Targets

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.generate_v13_label_target_plan --split time --test-size 0.3 --pretty
```

| Label | Minimum | Better |
| --- | ---: | ---: |
| benign | 300 | 500 |
| benign_unusual | 300 | 500 |
| suspicious | 300 | 500 |
| malicious | 150 | 250 |
| needs_context | 50 | 100 |

## Export a Larger Review Sample

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.export_v13_ai_training_review_sample --limit 500 --focus balanced --pretty
```

Supported focus modes are `balanced`, `threat_positive`, `benign_gap`, `boundary`, and `benchmark`.

Review `ml_baseline_reviews/v1_3_ai_training_review_sample.csv`, fill the `human_review_*` columns, and import it through React **AI Governance**. Do not overwrite protected manual labels without an explicit correction workflow.

## Train Candidate Models

After reviewed labels are imported:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.train_v13_supervised_candidates --split time --test-size 0.3 --min-samples 6 --pretty
```

The workflow compares Random Forest, Extra Trees, Logistic Regression, HistGradientBoosting, binary threat-positive SOC triage, three-class SOC triage, and hierarchical suspicious/malicious analysis. Candidate training is in-memory report generation and does not activate a model artifact.

An ignored prepared benchmark snapshot can be supplied with `--benchmark-snapshot`.

## Analyze Errors

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.analyze_v13_ml_errors --split time --test-size 0.3 --min-samples 6 --pretty
```

The report covers threat false negatives, benign-like false positives, suspicious/malicious boundary confusion, needs-context confusion, weak versus reviewed error evidence, common patterns, and the next recommended review focus.

## Benchmark CSV Intake

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.prepare_benchmark_dataset `
  --input-csv C:\path\benchmark.csv `
  --mapping-config data\samples\benchmarks\example_firewall_mapping.json `
  --label-config data\samples\benchmarks\example_label_mapping.json `
  --sample-strategy balanced `
  --limit 5000 `
  --pretty
```

Prepared snapshots exclude private raw payloads by default, are not imported into the main database, and remain ignored under `demo_exports/benchmarks/`.

## Readiness Gate v3

Possible candidate decisions:

- `candidate_only`
- `analyst_review_eligible`
- `benchmark_validated_candidate`

Production status remains `not_production_promoted`. The gate considers reviewed label counts, class and temporal coverage, benchmark size, threat-positive metrics, suspicious and malicious recall, benign-like false-positive rate, threat false-negative rate, calibration evidence, drift warnings, and disabled response automation.

## Known Limitations

- Labels can still reflect one narrow time range or source.
- Weak labels can bias exact-class metrics.
- Repeated traffic patterns can inflate random-split evaluation.
- Confidence calibration evidence is limited.
- Public benchmark results do not prove local deployment performance.
- Real-device and long-duration drift validation remain future work.

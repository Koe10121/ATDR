# v1.6 External / Unseen Benchmark Validation

## Purpose

v1.6 measures how an ATDR supervised candidate transfers from the deterministic v1.5 internal benchmark to a separate unseen holdout. The holdout uses different sources, scenarios, timestamps, and traffic patterns. It is safe synthetic validation data, not production traffic and not a production-accuracy claim.

The workflow never imports holdout labels into the main database, writes or activates a model artifact, enables response automation, or performs firewall enforcement.

## Source Evidence

- Holdout manifest: `data/samples/benchmarks/external_unseen_holdout_manifest.json`
- Holdout builder: `atdr/scripts/build_fixed_unseen_holdout.py`
- Snapshot preparation: `atdr/scripts/prepare_external_benchmark_snapshot.py`
- Cross-dataset validation: `atdr/scripts/run_external_benchmark_validation.py`
- Readiness gate v5: `atdr/app/benchmarks/readiness.py`
- Dashboard summary: `atdr/app/routers/dashboard.py`
- Regression tests: `atdr/tests/test_v16_external_benchmark.py`

## Fixed Holdout

The committed manifest generates 320 safe rows:

- 120 benign-like
- 80 suspicious
- 90 malicious
- 30 needs-context

It covers 14 scenarios across five synthetic source names. Scenarios include ordinary SaaS and QUIC traffic, normal incomplete connections, backup transfers, blocked background noise, slow scanning, policy violations, unknown services, credential probing, brute-force-like activity, C2-like beaconing, gradual exfiltration, connection flooding, and limited-context generic syslog.

## Commands

Preview the holdout without writing it:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.build_fixed_unseen_holdout --dry-run --pretty
```

Prepare the fixed safe holdout snapshot:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.prepare_external_benchmark_snapshot --holdout-from-current-data --pretty
```

Run the complete transfer evaluation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_external_benchmark_validation --holdout-from-current-data --pretty
```

`--holdout-from-current-data` is the backward-compatible CLI switch for the fixed safe unseen holdout. It does not copy private rows from the local database.

An approved external CSV can be supplied instead:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_external_benchmark_validation `
  --input-csv "C:\path\to\approved-benchmark.csv" `
  --mapping-config data\samples\benchmarks\example_firewall_mapping.json `
  --label-config data\samples\benchmarks\example_label_mapping.json `
  --pretty
```

Keep external datasets outside Git.

## Current Result

The June 7, 2026 run trained a three-class Random Forest candidate on the 240-row v1.5 internal fixture and evaluated it without retraining on the separate 320-row holdout.

| Metric | Internal fixture | Unseen holdout | Gap |
|---|---:|---:|---:|
| Threat-positive F1 | 1.0000 | 0.7278 | 0.2722 |
| Threat-positive recall | 1.0000 | 0.7471 | 0.2529 |
| Benign-like false-positive rate | 0.0000 | 0.3467 | 0.3467 |
| Suspicious recall | 1.0000 | 0.3500 | 0.6500 |
| Malicious recall | 1.0000 | 0.8889 | 0.1111 |

External macro F1 was `0.6117`, weighted F1 was `0.6292`, and calibration was weak:

- Brier score: `0.2198`
- expected calibration error: `0.1668`
- maximum confidence/accuracy gap: `0.2874`

The result shows a significant generalization gap. The internal deterministic fixture is materially easier than the unseen holdout, especially for suspicious-class separation and benign-like false positives.

## Readiness Gate v5

Current decision: `internal_benchmark_validated_candidate`.

The external gate passed 4 of 8 displayed checks and 3 of 7 required checks. External validation did not pass because:

- threat-positive F1 is below `0.85`
- threat-positive recall is below `0.85`
- benign-like false-positive rate is above `0.15`
- confidence calibration is weak

The 320-row count, controlled validation state, and disabled response automation checks passed.

## Safety And Limitations

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Response automation allowed: false
- Real firewall blocking enabled: false
- The fixed holdout is synthetic, not a public independent dataset.
- A truly external approved dataset and real-device long-duration validation remain future work.
- ATDR remains SOC-triage decision support with analyst-approved simulated response only.

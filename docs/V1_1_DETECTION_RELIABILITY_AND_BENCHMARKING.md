# ATDR v1.1 Detection Reliability And AI Benchmarking

ATDR v1.1 strengthens controlled detection validation with reliability baselines, generic benchmark adapters, false-positive/false-negative analysis, risk calibration, ML/SOC triage reliability reporting, drift monitoring, and safe stress testing.

This is still small-subnet/lab-scale validation. It does not execute real attacks, does not add offensive tools, does not enable automatic response, does not perform real firewall blocking, and does not claim production readiness.

## Why This Phase Exists

Scenario validation proves that known safe examples behave as expected. That is useful, but it is not enough by itself. v1.1 adds broader reliability evidence:

- scenario pass/fail aggregation
- synthetic generalization results
- layered rules/anomaly/supervised/hybrid contribution checks
- end-to-end workflow validation
- false-positive and false-negative analysis
- benchmark-style external CSV mapping
- risk/severity calibration review
- ML/SOC triage reliability summary
- drift monitoring groundwork
- synthetic stress/performance validation

## Reliability Baseline

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_reliability_baseline --pretty
```

Default mode uses temporary SQLite and writes reports to ignored:

```text
demo_exports/detection_reliability/
```

The report summarizes:

- v0.7 scenario validation
- v0.8 generalization validation
- v0.9 layered validation
- v1.0 end-to-end workflow validation
- false positives and false negatives
- alert volume
- severity/risk distribution
- detection layer contribution
- internal controlled benchmark manifest coverage
- safety limitations

Only use current-database mode intentionally:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_reliability_baseline --write-to-current-db --pretty
```

## Generic Benchmark Adapter

ATDR does not commit public/private benchmark datasets. The adapter maps an external CSV into ATDR normalized fields at runtime.

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_benchmark --csv-path C:\path\to\benchmark.csv --pretty
```

Optional mapping config:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_benchmark --csv-path C:\path\to\benchmark.csv --mapping-config C:\path\to\mapping.json --limit 1000 --pretty
```

Expected fields can be mapped to:

- `timestamp`
- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `protocol`
- `action`
- `app`
- `bytes`
- `packets`
- `label`
- `attack_type`

Benchmark metrics are separate from real firewall-log metrics and must not be presented as deployment accuracy.

## Internal Controlled Benchmark

The internal benchmark manifest lives at:

```text
data/samples/benchmarks/internal_controlled_benchmark.json
```

It combines safe normal, negative-control, threat-like, mixed, parser fallback, and deduplication scenario families. It documents expected label, attack type, severity/risk range, detection contribution, and no-automatic-response expectation.

## Error Analysis

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.analyze_detection_errors --pretty
```

The report highlights:

- false positives
- false negatives
- noisy normal patterns
- missed threat patterns
- over-triggered rules
- under-triggered rules
- risk calibration issues
- recommended rule/feature improvements

## Risk Calibration v2

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.calibrate_detection_risk --pretty
```

This reports risk/severity outliers and recommends whether thresholds should be reviewed. It does not mutate detection thresholds.

## ML/SOC Triage Reliability

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_ml_reliability_report --pretty
```

The report keeps ML wording honest:

- decision support only
- no production promotion claim
- no response automation
- reviewed/weak label context
- threshold profile notes
- reviewer workload estimate

## Drift Monitoring Groundwork

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.monitor_detection_drift --pretty
```

This read-only report compares recent local DB logs to older local rows:

- app distribution
- port distribution
- action distribution
- source/destination patterns
- alert rate
- unknown app rate
- parse failure rate
- anomaly score distribution when available

It is lightweight lab monitoring groundwork, not a production monitoring system.

## Stress/Performance Validation

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_stress_test --iterations 10 --pretty
```

Default mode uses temporary SQLite and safe synthetic scenarios. It reports ingestion time, detection time, alert query time, case query time, dashboard summary time, and warnings.

## Dashboard Impact

Overview shows concise indicators only:

- latest v1.1 reliability baseline
- latest mapped benchmark result
- latest drift warning count

AI Governance remains focused on SOC triage decision support. Long reliability details stay in generated reports and docs.

## Current Limitations

- Controlled synthetic/replay validation only.
- External benchmark quality depends on the provided mapping.
- Public benchmark metrics are separate from local firewall-log metrics.
- ML remains decision support only.
- No automatic response or real firewall blocking.
- Real router/firewall validation and production hardening remain future work.

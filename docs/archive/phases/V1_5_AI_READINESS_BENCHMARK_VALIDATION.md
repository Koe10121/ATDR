# v1.5 AI Readiness Benchmark Validation

## Purpose

v1.5 closes the missing benchmark-label check with a deterministic, safe, synthetic internal benchmark. It evaluates ATDR's detection layers and supervised SOC-triage candidates without importing benchmark labels into the main database, activating a model, or enabling response automation.

`benchmark_validated_candidate` means the candidate passed the internal benchmark decision-support gate. It is not production promotion, deployment certification, or permission to automate response.

## Source Evidence

- Manifest: `data/samples/benchmarks/internal_ai_readiness_benchmark_manifest.json`
- Builder: `atdr/scripts/build_internal_ai_readiness_benchmark.py`
- Snapshot adapter: `atdr/scripts/prepare_benchmark_dataset.py`
- Detection benchmark: `atdr/scripts/run_detection_benchmark.py`
- ML experiment: `atdr/scripts/run_benchmark_ml_experiment.py`
- Readiness gate: `atdr/app/benchmarks/readiness.py`
- Final runner: `atdr/scripts/run_v15_ai_readiness_validation.py`
- Tests: `atdr/tests/test_v15_ai_readiness.py`

## Benchmark Composition

The committed manifest generates 240 rows in an ignored output directory:

- 85 benign-like
- 55 suspicious
- 85 malicious
- 15 needs-context

The scenarios include normal QUIC/443, ordinary web/DNS, benign incomplete/allow/80 boundary traffic, port scanning, policy violations, brute-force-like access, C2-like beaconing, exfiltration suspicion, connection flooding, and malformed or limited-context rows.

All addresses and events are synthetic. No offensive tooling or real attack execution is used. Generated CSVs, snapshots, and reports remain ignored.

## Run

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.build_internal_ai_readiness_benchmark --dry-run --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v15_ai_readiness_validation --pretty
```

The runner:

1. Builds the safe benchmark CSV.
2. Prepares a sanitized snapshot under `demo_exports/benchmarks/`.
3. Compares rules-only, anomaly-only, supervised-only, and hybrid detection.
4. Compares three-class, binary, and hierarchical supervised candidates.
5. Reuses the latest v1.4c calibration evidence.
6. Checks the latest controlled v0.7-v1.1 validation reports.
7. Writes ignored final benchmark and AI-readiness reports.

## Readiness Gate v4

`benchmark_validated_candidate` requires:

- at least 100 benchmark labels
- benign-like, suspicious, and malicious benchmark support
- threat-positive F1 at least 0.85
- threat-positive recall at least 0.85
- benign-like false-positive rate at most 0.15
- confidence calibration passed
- controlled validations passed
- response automation disabled

Malicious recall is reported as an advisory exact-class metric. It is not a blocking threshold because ATDR's approved purpose remains threat-positive SOC triage, where suspicious versus malicious boundaries may require analyst context.

## Current Result

The June 7, 2026 validation used 240 benchmark labels and passed all eight v4 checks. The best benchmark three-class candidate achieved perfect metrics on this deterministic internal fixture. This result demonstrates pipeline correctness on the controlled benchmark; it must not be described as independent or production accuracy.

The latest local reviewed-label profile remains `malicious_recall_recovery`:

- benign-like false-positive rate: 0.0784
- threat-positive F1: 0.9187
- suspicious recall: 1.0000
- malicious recall: 0.6651
- calibration: passed

## Safety And Limitations

- Production promoted: false
- Model activated: false
- Response automation allowed: false
- Real firewall blocking enabled: false
- Benchmark data is synthetic and deterministic.
- Real-device forwarding, independent external benchmarks, long-duration drift, and production security validation remain future work.

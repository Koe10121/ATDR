# ATDR v1.8 External Benchmark Finalization

## Scope

v1.8 narrows the remaining v1.7 external holdout gaps without activating a
model or changing response behavior. It compares fixed candidate profiles,
adds behavior-window evidence for recurring external misses, evaluates
confidence calibration, and applies readiness gate v6.

The benchmark is a reviewed synthetic external holdout. Its metrics are
development evidence for SOC triage decision support, not production accuracy.

## Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v18_external_benchmark_finalization --pretty
```

Generated JSON and Markdown reports remain under ignored
`demo_exports/benchmarks/`.

## Remaining Miss Analysis

The v1.7 misses were concentrated in:

- slow multi-target incomplete connections consistent with horizontal scanning;
- repeated low-volume DNS activity consistent with beacon-like behavior;
- gradual repeated outbound TLS transfers;
- denied multi-target SSH/VNC probing that sat on the suspicious/malicious
  boundary.

v1.8 uses existing behavior-window features such as event count, unique
destinations, scanning score, packet/byte volume, app, action, and destination
port. Profile decisions do not use source names or scenario identifiers.

## Profile Result

The selected candidate is `external_recall_plus`.

| Metric | v1.7 | v1.8 |
| --- | ---: | ---: |
| Threat precision | 0.9533 | 0.9568 |
| Threat recall | 0.8412 | 0.9118 |
| Threat F1 | 0.8937 | 0.9338 |
| Benign-like FPR | 0.0467 | 0.0467 |
| Suspicious recall | 0.7875 | 0.9375 |
| Malicious recall | 0.7222 | 0.8556 |
| Macro F1 | 0.8328 | 0.9201 |
| Weighted F1 | 0.8440 | 0.9215 |

Recall-heavy profiles that raised benign FPR above `0.15` were rejected.

## Calibration

v1.8 compares:

- temperature scaling;
- sigmoid calibration;
- isotonic calibration;
- confidence bucket smoothing;
- an uncalibrated baseline.

The external calibration evidence uses stratified out-of-fold scoring. Each
row is scored by a confidence calibrator fitted on other rows. The selected
method is `bucket_smoothing`:

- ECE: `0.0118`
- threat-positive Brier score: `0.0607`
- maximum confidence/accuracy gap: `0.0418`
- status: `passed`

The calibration experiment does not write or activate a model artifact.

## Readiness v6

Current decision:

- readiness: `external_benchmark_validated_candidate`
- production promoted: `false`
- model activated: `false`
- response automation allowed: `false`
- real firewall blocking enabled: `false`

This status means the reviewed external benchmark gate passed for analyst
decision support. It is not a production promotion. Because v1.8 was informed
by the v1.7 miss analysis, a new independent holdout and controlled real-source
validation are still recommended before stronger deployment claims.

That follow-up is implemented in
`docs/V1_9_INDEPENDENT_REVALIDATION_AND_REAL_SOURCE_VALIDATION.md`. v1.9 keeps
the v1.8 result as external synthetic evidence and reports independent holdout
and controlled source results separately.

## Safety

- Response remains simulated and analyst-approved.
- ML output cannot create an automatic response action.
- Generated reports and benchmark snapshots remain ignored.
- Real logs, database files, model artifacts, `.env`, `ml_baseline_reviews/`,
  `demo_exports/`, and processed logs must not be committed.

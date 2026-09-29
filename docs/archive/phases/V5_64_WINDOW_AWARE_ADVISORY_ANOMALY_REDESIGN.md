# v5.64 Window-Aware Advisory Anomaly Redesign

Date: 2026-09-18

## Decision

v5.64 completed a private-safe, development-only comparison of eight declared
unsupervised anomaly strategies at four fixed queue targets. A dispatch defect
in the initial implementation made one declared strategy,
`empirical_percentile_calibration`, compute results byte-identical to
`robust_scaled_global_isolation_forest`; this is now fixed and disclosed in
code (`STRATEGY_KNOWN_DUPLICATES`, `duplicate_of_strategy` on each candidate
report) rather than presented silently. Seven strategies were methodologically
distinct. Correcting the defect does not change any reported number: the
duplicate combination never depended on `_candidate_gates`, `_rank`, or
`_improves_current`, so it could not have affected which candidate ranked
highest or whether any candidate qualified. No strategy passed every
unchanged v5.63.1 gate. No candidate was frozen, selected, installed, or
activated, and the existing ignored IsolationForest artifact remained
byte-for-byte unchanged.

Runtime authority is unchanged:

- deterministic rules: `active_authoritative`;
- IsolationForest and hybrid evidence: advisory only;
- supervised ML: `unqualified`;
- response: `simulation_only`;
- automatic response and real firewall blocking: disabled.

ATDR remains ready for a controlled advisor demonstration. This result makes
the anomaly limitation clearer; it does not reduce the verified rule,
explanation, Assistant, or simulated-response workflow.

## Locked Protocol

The protocol was fixed before candidate comparison:

| Role | Rows used |
| --- | ---: |
| Chronological fit window before cap | 27,435 |
| Fit after deterministic cap | 20,000 |
| Calibration | 7,337 |
| Development validation | 7,337 |
| Untouched candidate holdout | 7,317 |
| Boundary-family rows quarantined | 457 |

The private input contained 50,000 unique inspected rows, parsed at 100%, with
49,883 complete traffic rows. No supervised sealed evidence or private label
was accessed. Roles were chronological, and near-duplicate families crossing
a role boundary were removed from the later role.

Candidate selection used only fit, calibration, controlled synthetic
scenarios, and development validation. Because no candidate passed validation,
the untouched candidate holdout was not evaluated.

## Strategies Compared

Each strategy was evaluated at fixed 1%, 2%, 3%, and 5% queue targets:

1. current-feature global IsolationForest;
2. robust-scaled global IsolationForest;
3. chronological-window ensemble;
4. application/direction cohort normalization;
5. empirical percentile calibration (disclosed duplicate of strategy 2 — see
   Decision above; not a ninth distinct data point in the results below);
6. context-enriched IsolationForest;
7. context-enriched scoring with OOD abstention; and
8. global/cohort score ensemble.

Context features covered source event volume, destination and port diversity,
deny ratio, tuple and application repetition, destination load, interarrival
time, cadence jitter, bytes, duration, repeat count, application family,
direction, schema, and missingness. None encoded a rule decision as an anomaly
override.

## Results

The strongest nonqualified diagnostic was
`global_cohort_score_ensemble_q05`:

| Measure | Legacy artifact | Best v5.64 diagnostic |
| --- | ---: | ---: |
| Controlled benign anomaly rate | 17.78% | 0.00% |
| Suspicious scenario capture | 57.14% | 85.71% |
| Malicious scenario capture | 50.00% | 50.00% |
| Private development queue rate | 2.18% | 2.75% |
| Queue-rate range across four windows | 0.82 pp | 1.26 pp |

The best result improved controlled benign noise and suspicious capture while
keeping a stable private queue. It still missed both controlled C2-like
families and failed the fixed 75% malicious-scenario gate. The flood-like
suspicious scenario also stayed below its 95th-percentile queue threshold.

No strategy exceeded 50% malicious scenario capture. Several 5% variants also
exceeded the fixed 5% private queue ceiling. Zero of 32 declared strategy/target
combinations passed every gate; 28 of those 32 were methodologically distinct
and 4 were the disclosed empirical/robust-global duplicate.

## Root Causes

The evidence supports four concrete conclusions:

1. The legacy artifact is strongly affected by context mix. On development
   validation it queued 23.26% of network-control rows, 100% of the small
   deny/drop/reset cohort, and 10.83% of external-to-internal rows.
2. Chronological behavior drifts even when categorical application/schema
   mix is stable. Source event volume and destination diversity produced the
   largest robust median shifts: 0.64 in calibration, 0.79 in validation, and
   1.00 in the reserved future role.
3. Repeated low-volume C2-like cadence is not reliably distinguishable from
   routine repeated encrypted traffic in this one-source unlabeled corpus.
   The two missed C2 scenarios reached only 0.743 and 0.666 calibrated score.
4. Anomaly evidence is mostly redundant with deterministic rules. The best
   diagnostic queued 202 development-validation rows; 200 already had rule
   evidence. Its genuinely novel advisory contribution was two rows (0.99%).

Concept drift cannot be measured honestly without labels. The private queue
rate is not a false-positive rate, and controlled scenario capture is not
field accuracy.

## OOD And Privacy

The evaluator includes missing-feature and OOD abstention. The inspected
development-validation role required no abstentions; tests prove explicit
abstention for missing or materially out-of-distribution feature vectors.

The CLI accepts the private source only as an argument. Output contains no
source path, raw record, network address, identity, row fingerprint, provider
payload, credential, or secret. The generated aggregate JSON remains ignored
under `ml_baseline_reviews/`.

## Reproduce Safely

Write-free protocol preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v564_window_aware_anomaly_redesign `
  --sample-path "<private-log-file>" `
  --limit 50000 `
  --preflight-only `
  --pretty
```

Diagnostic comparison:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v564_window_aware_anomaly_redesign `
  --sample-path "<private-log-file>" `
  --limit 50000 `
  --pretty
```

There is deliberately no installation option.

## Safety Proof

The run created zero alerts, suppressions, labels, model runs, detection runs,
or response actions. It accessed no database and changed no artifact. Rule
authority, supervised state, and response policy stayed unchanged.

## Remaining Work

No further anomaly threshold tuning is justified on this evidence. The next
meaningful anomaly research requires a new source or a genuinely different
sequence representation, declared before evaluation. Supervised qualification
still requires completion of genuine protected review, a second physical
source, and a new untouched evaluation.

For the current controlled-lab product, one Codex-owned closure phase remains:
consolidate the final detection truth and advisor handoff. Supervised
qualification and field certification remain human/external phases.


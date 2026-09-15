# v3.52 Repaired Interface Severity Model Revalidation

## Status

v3.52 revalidates downstream severity modeling using the v3.51 queue/severity target interface repair. It is complete as a diagnostic-only pass.

## Purpose

v3.51 found that mapping queued `non_threat` rows to `unusual_needs_review` removed the downstream mismatch while retaining all review-queue rows. v3.52 tests whether that repaired interface improves downstream severity modeling compared with the baseline interface.

## Scope

The diagnostic compares:

- `baseline_current_interface`
- `map_non_threat_to_unusual`

For each interface, it evaluates:

- ExtraTrees queue model with ExtraTrees or Logistic Regression severity model
- probability-only severity decisions
- evidence-guarded severity decisions
- time, grouped/source-aware, and repeated random validation splits

## Safety

v3.52 must remain diagnostic-only:

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Labels written: false
- Response automation allowed: false
- Real firewall blocking: false

Generated reports are written under `ml_baseline_reviews/` and remain ignored.

## Result

- Best diagnostic strategy: `map_non_threat_to_unusual_extra_trees_severity_logistic_regression_probability_only`
- Readiness: `candidate_only`
- Checks passed: `8 / 12`
- Passing severity splits: `0 / 5`
- Queued non-threat mismatch: `0`
- Queue F1 minimum: `0.972`
- Benign-like FPR maximum: `0.1333`
- Threat-positive F1 minimum: `0.2296`
- Suspicious recall minimum: `0.2214`
- Malicious recall minimum: `0.0`
- Calibration: `passed`

## Interpretation

The v3.51 repaired interface worked for the specific mismatch it was designed to fix: queued rows no longer remain downstream `non_threat`.

However, the downstream severity model is still not stable. It keeps false positives under the configured budget and calibration passes, but suspicious and malicious recall collapse on some validation splits. This means the blocker has moved from target-interface mismatch to severity target separability and evidence-feature ambiguity.

The model must remain `candidate_only`. No activation or promotion is justified.

## Validation Gates

The candidate remains `candidate_only` unless all of these pass across independent splits:

- no test leakage during threshold selection
- queued non-threat mismatch is removed
- queue admission stays stable
- threat-positive F1 stays strong
- benign-like false-positive rate remains controlled
- suspicious recall remains stable
- malicious recall remains stable
- confidence calibration remains acceptable

## Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v352_repaired_interface_severity_model --test-size 0.3 --min-samples 6
```

## Next Phase

v3.53 should focus on severity target separability and feature ambiguity. The next work should analyze which suspicious and malicious rows collapse into `unusual_needs_review`, then add diagnostic features or target policy refinements before more classifier tuning.

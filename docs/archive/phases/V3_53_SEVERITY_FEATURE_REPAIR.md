# v3.53 Severity Target Separability And Evidence Feature Repair

## Status

v3.53 compares the current v337 evidence features with new severity-specific diagnostic features. It is complete as a diagnostic-only pass.

## Purpose

v3.52 proved that the v3.51 repaired target interface removes queued `non_threat` mismatch, but downstream severity classification still fails split stability. The remaining problem is severity target separability: the model struggles to separate `unusual_needs_review`, `evidence_backed_suspicious`, and `malicious_high_confidence`.

## Diagnostic Feature Candidates

v3.53 adds candidate features for evaluation only:

- `v353_scan_pressure_score`
- `v353_malicious_signal_score`
- `v353_suspicious_signal_score`
- `v353_low_risk_review_score`
- `v353_evidence_margin_score`
- `v353_severity_evidence_tier`
- `v353_service_family`

These features are not activated as a production model pipeline. They are tested only inside the diagnostic evaluation.

## Evaluation

The phase compares:

- `v337_current_features`
- `v353_severity_features`

Both use:

- repaired v3.51 interface: `map_non_threat_to_unusual`
- downstream severity models: ExtraTrees and Logistic Regression
- decision modes: probability-only and evidence-guarded
- the standard independent split suite

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Labels written: false
- Response automation allowed: false
- Real firewall blocking: false

Generated reports remain under `ml_baseline_reviews/` and are ignored.

## Result

- Best diagnostic strategy: `v337_current_features_map_non_threat_to_unusual_extra_trees_severity_logistic_regression_probability_only`
- Readiness: `candidate_only`
- Checks passed: `8 / 12`
- Passing severity splits: `0 / 5`
- Queue F1 minimum: `0.972`
- Benign-like FPR maximum: `0.1333`
- Threat-positive F1 minimum: `0.2296`
- Suspicious recall minimum: `0.2214`
- Malicious recall minimum: `0.0`
- Calibration: `passed`
- Rows analyzed for feature support: `2308`
- Strongest v353 candidate feature: `v353_scan_pressure_score`
- Strongest feature minimum pairwise effect size: `0.5012`

## Interpretation

v3.53 found useful severity signal, especially scan pressure:

- `v353_scan_pressure_score` separates severity targets better than the other new numeric candidates.
- `v353_suspicious_signal_score` helps separate unusual review rows from high-confidence malicious rows.
- `v353_service_family` shows that incomplete and unknown traffic families have clearer target tendencies than generic web/utility traffic.

However, the v353 feature set did not beat the existing v337 feature set as the best diagnostic candidate. The best strategy remains the v337 Logistic Regression severity candidate, and it still fails independent split stability. The root issue is now less about missing simple features and more about target/label ambiguity between `unusual_needs_review`, `evidence_backed_suspicious`, and `malicious_high_confidence`.

The model remains `candidate_only`. No activation or promotion is justified.

## Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v353_severity_feature_repair --test-size 0.3 --min-samples 6
```

## Next Phase

v3.54 should audit severity target semantics directly. The next phase should examine whether current labels and evidence rules are asking the model to learn distinctions that are not separable enough, especially suspicious versus malicious and unusual-review versus suspicious.

# v1.4 False Positive Reduction And Confidence Calibration

## Purpose

v1.4 evaluates candidate supervised strategies for a quieter SOC review queue. It addresses the post-v1.3 result where threat detection remained useful but benign-like traffic was frequently classified as suspicious or malicious.

This phase is diagnostic. It does not write or activate a model artifact, promote a model, enable response automation, or perform firewall enforcement.

## Command

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v14_false_positive_reduction --split time --test-size 0.3 --min-samples 6 --review-limit 200 --pretty
```

Generated outputs stay under ignored `ml_baseline_reviews/`:

- `v1_4_false_positive_analysis_<timestamp>.md`
- `v1_4_threshold_calibration_<timestamp>.md`
- `v1_4_model_strategy_comparison_<timestamp>.md`
- `v1_4_confidence_calibration_<timestamp>.md`
- `v1_4_false_positive_reduction_<timestamp>.md`
- `v1_4_false_positive_review_sample.csv`

## Evaluated Strategies

- Flat five-class ExtraTrees with current weighting
- Flat ExtraTrees with lower threat weighting
- Flat ExtraTrees with stronger benign-like weighting
- Calibrated Logistic Regression
- Binary benign-like versus threat-positive classifier
- Three-class SOC triage classifier
- Hierarchical threat gate followed by suspicious-versus-malicious classification

## Threshold Profiles

- `conservative`
- `balanced`
- `precision_focused`
- `recall_focused`
- `low_noise_soc_queue`

The v1.4 profiles use a hard threat gate. If suspicious plus malicious probability does not meet the profile threshold, prediction falls back only to `benign`, `benign_unusual`, or `needs_context`. This prevents a threat class from being selected merely because it has the largest individual probability below the gate.

## Calibration

The workflow reports:

- confidence buckets
- bucket accuracy
- confidence-versus-accuracy gap
- expected calibration error
- threat-positive Brier score

Calibration is marked `passed` only when confidence gaps remain within the conservative readiness tolerance. Missing benchmark labels and weak calibration remain explicit blockers.

## Review Sample

`v1_4_false_positive_review_sample.csv` prioritizes:

- benign-like rows predicted suspicious or malicious
- high-confidence false positives
- incomplete / allow / destination port 80 patterns
- repeated source or time-window patterns

The file includes the existing human-review columns and must be reviewed by an analyst before import.

## Safety

- Model activation: none
- Production promotion: false
- Response automation: disabled
- Real firewall blocking: disabled
- Metrics describe the current mixed/reviewed-label lab dataset, not production accuracy


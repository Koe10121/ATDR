# v3.30 Detection and ML Quality Revalidation

## Status

Implemented as a diagnostic, non-activating ML quality pass.

## Purpose

v3.30 returns focus from the SOC Assistant to detection and supervised ML quality. It evaluates the current labeled firewall-log dataset, compares threshold profiles, analyzes false-positive and false-negative patterns, checks confidence calibration, and exports a targeted review sample for analyst labeling.

This phase does not activate a model, promote a model, change response behavior, enable real firewall blocking, or claim production readiness.

## Source Evidence

- `atdr/app/detection/v330_detection_ml_quality.py`
- `atdr/scripts/run_v330_detection_ml_quality_revalidation.py`
- `atdr/tests/test_v330_detection_ml_quality.py`
- `atdr/app/routers/dashboard.py`
- `frontend/src/pages/MLGovernance.tsx`
- `frontend/tests/smoke.spec.ts`
- Generated ignored report: `ml_baseline_reviews/v3_30_detection_ml_quality_analysis_<timestamp>.md`
- Generated ignored review sample: `ml_baseline_reviews/v3_30_detection_quality_review_sample.csv`

## Current Diagnostic Result

Latest current-dataset revalidation:

- Total label rows: 2672
- Latest trainable labels: 2672
- Reviewed labels: 2235
- Weak/unreviewed assisted labels: 437
- Train/test rows: 1870 / 802
- Baseline weighted F1: 0.294
- Baseline macro F1: 0.3139
- Baseline suspicious precision/recall/F1: 0.2395 / 1.0 / 0.3864
- Baseline malicious precision/recall/F1: 1.0 / 0.6835 / 0.812
- Baseline threat-positive precision/recall/F1: 0.5067 / 0.9913 / 0.6706
- Baseline benign-like false-positive rate: 0.7211
- Calibration status: weak
- Readiness decision: candidate_only

The diagnostic result shows the model still catches most threat-positive rows, but it is too noisy on current labeled data. The main blocker is false-positive noise, especially benign `quic-base` / `allow` / port `443` traffic predicted as suspicious.

## Threshold Profile Comparison

- `balanced`: high threat recall but high benign-like false-positive rate.
- `low_noise_soc_queue`: lowers benign-like false-positive rate from 0.7211 to 0.024, but reduces threat recall and suspicious recall.
- `precision_focused`: lowers false positives compared with balanced but still does not solve the full class-separation problem.
- `threat_recall`: maximizes recall but makes false positives worse.
- `conservative`: slightly lower noise than balanced but still too noisy.

Best diagnostic profile: `low_noise_soc_queue`.

Important: this profile is not activated automatically. It is an analyst-review candidate only.

## Review Sample

Generated:

```text
ml_baseline_reviews/v3_30_detection_quality_review_sample.csv
```

The sample focuses on:

- high-confidence benign-like rows predicted as threat-positive
- benign `quic-base` / `allow` / port `443`
- `incomplete` / `allow` / port `80`
- suspicious/malicious boundary cases
- rule/ML/hybrid disagreement cases

The CSV includes review fields and does not include raw log text or private file paths.

## Dashboard Update

AI Governance now shows a compact `Detection Quality Revalidation` panel with:

- main blocker
- baseline false-positive rate
- best diagnostic profile
- threat-positive F1
- calibration status
- review sample count
- diagnostic safety state

The panel is summary-first. Detailed patterns are behind a collapsible section.

## Safety Controls

- ML remains decision support only.
- No model artifact is written.
- No model is activated.
- No model is production promoted.
- Response automation remains disabled.
- Real firewall blocking remains disabled.
- Generated reports and review CSVs stay ignored and must not be committed.

## Manual Test Flow

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v330_detection_ml_quality_revalidation --split time --test-size 0.3 --min-samples 6 --review-limit 200
```

Then open React:

```powershell
cd frontend
npm.cmd run dev
```

Go to `AI Governance` and verify:

- `Detection Quality Revalidation` appears.
- Main blocker is false-positive noise when current data is noisy.
- `low_noise_soc_queue` is shown as diagnostic-only.
- Production promoted is false.
- Model activated is false.
- Response automation remains false.

## Known Limitations

- This is a current-dataset diagnostic, not production accuracy.
- The current labeled dataset contains repeated time-window/source patterns that can distort the time split.
- Confidence calibration is weak.
- Better reviewed benign/benign_unusual and boundary labels are still needed.
- Real device validation and long-duration monitoring remain separate future work.

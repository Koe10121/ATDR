# ML Baseline Tuning Guide

ATDR uses IsolationForest as assistive anomaly scoring. It is not a verdict engine. A production-style workflow needs reviewed baseline traffic, analyst labels, and repeatable evidence exports before ML findings are used in SOC decisions.

## Recommended Lab Workflow

1. Import a representative firewall log window.
2. Run rule-based detection first.
3. Train the model with baseline-only filtering:

```powershell
python -m atdr.scripts.train_model --baseline-only --limit 20000
```

4. Apply scoring:

```powershell
python -m atdr.scripts.predict_anomaly --limit 50000
```

5. Export a baseline review package:

```powershell
python -m atdr.scripts.ml_baseline_review --anomaly-limit 200 --baseline-limit 200
```

The export is written to `ml_baseline_reviews/` and includes:

- `ml_baseline_summary.json`: model, dataset, drift, readiness, and recommendations.
- `anomaly_review.csv`: top anomaly rows with raw evidence excerpts and blank review columns.
- `baseline_candidate_sample.csv`: allowed low-risk candidate rows for baseline approval.
- `ML_BASELINE_REVIEW.md`: supervisor-readable summary and next actions.

## How To Review

Use `anomaly_review.csv` as the analyst labeling sheet.

Recommended labels:

- `true_positive`: suspicious enough to keep as an alert signal.
- `benign_unusual`: unusual but accepted in this network.
- `false_positive`: noisy or misleading for this environment.
- `needs_context`: cannot classify without owner or asset context.

Use `baseline_candidate_sample.csv` to confirm which rows are safe normal traffic. Do not include deny/drop events, app risk 4-5 traffic, unknown/incomplete apps, or previously flagged anomalies in the first baseline unless a security reviewer approves them.

## Acceptance Guidance

For lab-pilot confidence:

- Baseline candidates should be at least several hundred rows, preferably thousands.
- The anomaly rate should be explainable and stable across scoring runs.
- Top anomalous source IPs, applications, and ports should be reviewed.
- False positives should feed suppressions, watchlists, or threshold adjustments.
- ML should never trigger automatic containment without rule evidence and analyst approval.

## Current Limitation

Without labeled normal and malicious traffic, ATDR cannot claim ML accuracy in precision/recall terms. The honest production path is review, label, retrain, compare anomaly rate, then document model acceptance.

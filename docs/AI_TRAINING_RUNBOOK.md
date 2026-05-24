# ATDR Hybrid AI Training Runbook

This runbook explains the supervised AI workflow for the MFU ATDR senior project demo and small-office lab pilot. The AI layer is decision support only. Rule evidence, raw logs, and analyst approval remain required before any response action.

## 1. Start From A Clean Demo Baseline

```powershell
Copy-Item .env.example .env
python -m atdr.scripts.config_doctor --pretty
python -m atdr.scripts.seed_users
```

Start the API:

```powershell
uvicorn atdr.app.main:app --reload
```

Start either dashboard:

```powershell
streamlit run atdr/dashboard/streamlit_app.py --server.headless true --browser.gatherUsageStats false
```

or:

```powershell
cd frontend
npm.cmd run dev
```

## 2. Import Logs

```powershell
python -m atdr.scripts.import_logs ".\paloalto-firewall(1).log" --limit 5000
```

If the sample file is elsewhere, set `DEMO_SAMPLE_LOG_PATH` in `.env` or pass the absolute file path.

## 3. Run Rule-Based Detection

```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:8000/api/detection/run?limit=5000&use_ml=false"
```

Explain during presentation: rules are the first layer because they are auditable and easy to justify.

## 4. Train IsolationForest Baseline

```powershell
python -m atdr.scripts.train_model --limit 20000 --baseline-only
python -m atdr.scripts.predict_anomaly --limit 5000
```

Explain during presentation: IsolationForest finds unusual traffic patterns. It does not prove malicious intent.

## 5. Create A Review Queue

Export a prioritized queue for analyst labeling:

```powershell
Invoke-RestMethod -Headers @{Authorization="Bearer <token>"} "http://127.0.0.1:8000/api/ml/review-queue/export?limit=1000" -OutFile ".\ml-review-queue.csv"
```

The queue prioritizes high anomaly rows, high hybrid risk rows, unlabeled alert evidence, recent suspicious logs, and rule/ML disagreement.

## 6. Label Rows

Preferred demo workflow:

1. Open the React dashboard.
2. Go to **ML Governance**.
3. Review **Label Review Queue**.
4. Click a log ID to open **Log Explorer**.
5. Read raw evidence and normalized fields.
6. Save a label with attack type, confidence, and review note.

Allowed labels:

- `benign`
- `benign_unusual`
- `suspicious`
- `malicious`
- `needs_context`

Allowed attack types:

- `normal`
- `port_scan`
- `brute_force`
- `dos_ddos`
- `malware_c2`
- `policy_violation`
- `data_exfiltration_suspicion`
- `unknown_anomaly`

## 7. CSV Label Round Trip

Download a template:

```powershell
Invoke-RestMethod -Headers @{Authorization="Bearer <token>"} "http://127.0.0.1:8000/api/ml/labels/template" -OutFile ".\ml-label-template.csv"
```

Export current labels:

```powershell
Invoke-RestMethod -Headers @{Authorization="Bearer <token>"} "http://127.0.0.1:8000/api/ml/labels/export" -OutFile ".\ml-labels.csv"
```

Import edited labels through the **ML Governance** page. CSV import updates an existing `id` when present; otherwise it updates the latest label for a `log_id` or creates one.

## 8. Safe Synthetic Demo Labels

When you need enough labels for a supervised model demo without using private traffic, generate synthetic examples:

```powershell
python -m atdr.scripts.seed_demo_labels
```

To replace previous synthetic demo-label rows:

```powershell
python -m atdr.scripts.seed_demo_labels --force
```

These rows use documentation/example IP ranges and are marked as synthetic in `parsed_json`.

## 9. Assisted Labeling For Real Data

Assisted labels are weak labels. They are generated from rule evidence, IsolationForest anomaly flags, hybrid risk, normalized fields, and 5-minute behavior-window features. They are useful for bootstrapping a supervised demo, but they must be reviewed before claiming final model performance.

Dry-run a preview:

```powershell
python -m atdr.scripts.generate_assisted_labels --limit 1000 --dry-run --export-preview ml_baseline_reviews/assisted_label_preview.csv
```

Apply only labels with confidence 3 or higher:

```powershell
python -m atdr.scripts.generate_assisted_labels --limit 1000 --apply --reviewer codex_assisted --min-confidence 3
```

Export a balanced human review sample:

```powershell
python -m atdr.scripts.export_label_review_sample
```

Open `ml_baseline_reviews/assisted_label_human_review_sample.csv` and review approximately:

- 15 benign
- 10 benign unusual
- 15 suspicious
- 5 malicious if available
- 5 needs context

Presentation wording:

> Initial labels were generated using rule/ML-assisted labeling and a sample was manually reviewed for validation.

Do not say assisted labels are perfect ground truth.

## 10. Human Review Sample Import

The review sample is designed for a safe weak-label validation loop:

1. Export the sample from the React **ML Governance** page using **Human Review Sample**, or run:

```powershell
python -m atdr.scripts.export_label_review_sample
```

2. Open `ml_baseline_reviews/assisted_label_human_review_sample.csv`.
3. For each reviewed row, fill `human_review_decision` with one allowed label:
   `benign`, `benign_unusual`, `suspicious`, `malicious`, or `needs_context`.
4. Add analyst reasoning in `human_review_note`.
5. Import the corrected CSV from **ML Governance** using **Import Reviewed CSV**.

Import safety behavior:

- Imported review-sample rows are marked `reviewed=true`.
- Review-sample rows with empty `human_review_decision` and empty `human_review_note` are skipped.
- Existing assisted provenance such as `assisted_rule`, `assisted_ml`, or `assisted_hybrid` is preserved.
- The human reviewer and note are appended to `review_note`.
- Existing manual labels are protected and skipped by default.
- Manual labels are overwritten only when an explicit overwrite option is used through the API.

After importing reviewed labels, retrain the supervised model:

```powershell
python -m atdr.scripts.train_supervised_model --test-size 0.3 --min-samples 6
```

Senior project demo wording:

> Initial labels were generated using rule/ML-assisted labeling, and a sample was manually reviewed for validation. The supervised model is used as decision support, not as an automatic final authority.

## 11. Train The Supervised Model

```powershell
python -m atdr.scripts.train_supervised_model --test-size 0.3 --min-samples 6
```

The training script saves:

- model artifact
- metrics in `ml_model_runs`
- SHA-256 artifact hash
- Markdown model evaluation report beside the model artifact

## 12. Score And Explain

Use the API to inspect a supervised prediction for one log:

```powershell
Invoke-RestMethod -Headers @{Authorization="Bearer <token>"} "http://127.0.0.1:8000/api/ml/supervised/predict/1?rule_score=60"
```

The hybrid score combines:

- rule severity score
- IsolationForest anomaly signal
- supervised malicious probability
- optional asset/context weight

## 13. View AI Model Evaluation

Open **ML Governance** in the React dashboard. Show:

- IsolationForest status
- supervised label count
- training/test rows
- accuracy, precision, recall, F1
- label distribution
- assisted vs reviewed label counts
- review queue
- downloadable supervised model report

Presentation wording:

> The AI model helps prioritize analyst attention. It does not replace rule evidence or analyst approval.

## 14. Release Verification

```powershell
python -m atdr.scripts.verify_release --pretty
```

Optional local smoke check when API/dashboard are running:

```powershell
python -m atdr.scripts.verify_release --include-smoke --pretty
```

## 15. Real Data Demo Checklist

Use this flow when validating a real Palo Alto log file from a small-office or lab network. Keep the real log outside Git, for example in `Downloads`, `data/private/`, or `real_logs/`.

Run the helper from the repository root:

```powershell
.\scripts\run_ai_demo_pipeline.ps1 -LogPath "<REAL_LOG_PATH>" -Limit 50000
```

Example with a private local path:

```powershell
.\scripts\run_ai_demo_pipeline.ps1 -LogPath "C:/path/to/private/paloalto-firewall.log" -Limit 50000
```

The helper performs:

- Alembic migration upgrade
- demo user seed
- real log import
- rule-based detection
- IsolationForest baseline training
- anomaly scoring
- review queue CSV export
- validation summary
- supervised report Markdown export

After the script finishes, open:

- React dashboard: `http://127.0.0.1:5173`
- **ML Governance**: show IsolationForest status, anomaly rate, label distribution, and Label Review Queue.
- **Log Explorer**: open high-priority review rows, show raw evidence, normalized fields, and save analyst labels.
- **Alert Workbench**: show rule-based explanation and evidence log links.

Capture these screenshots/results for presentation:

- terminal validation summary from `run_ai_demo_pipeline.ps1`
- **ML Governance** AI Model Evaluation and Label Review Queue
- **Log Explorer** with raw evidence and analyst label form
- exported `ml_baseline_reviews/real_data_review_queue.csv`
- exported `ml_baseline_reviews/supervised_model_report.md`

After labeling enough rows across at least two classes, train the supervised model:

```powershell
python -m atdr.scripts.train_supervised_model --test-size 0.3 --min-samples 6
```

If you need bootstrapping labels before manual review:

```powershell
python -m atdr.scripts.generate_assisted_labels --limit 1000 --dry-run
python -m atdr.scripts.generate_assisted_labels --limit 1000 --apply --reviewer codex_assisted --min-confidence 3
python -m atdr.scripts.export_label_review_sample
```

Or rerun the helper with supervised training enabled:

```powershell
.\scripts\run_ai_demo_pipeline.ps1 -LogPath "<REAL_LOG_PATH>" -Limit 50000 -SkipImport -SkipDetection -SkipIsolationForest -TrainSupervised
```

Honest AI explanation:

- Rule-based detection is the primary evidence layer.
- IsolationForest identifies unusual behavior, not confirmed attacks.
- The supervised model only becomes meaningful after representative analyst labels exist.
- Assisted labels are weak labels and should be validated with a human review sample.
- Accuracy, precision, recall, and F1 should be presented as demo/lab metrics, not certified production performance.
- Response actions remain simulated and require analyst approval.

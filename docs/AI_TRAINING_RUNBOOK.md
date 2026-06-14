# ATDR Hybrid AI Training Runbook

This runbook explains the supervised AI workflow for the MFU ATDR senior project demo and small-office lab pilot. The AI layer is decision support only. Rule evidence, raw logs, and analyst approval remain required before any response action.

## Current Model Status

Current supervised ML status is `candidate_improved`: it is eligible for analyst review as decision support, but it is not production promoted. Threat-positive triage is strong, while exact suspicious-versus-malicious separation remains imperfect and suspicious recall is still below the project target. Automatic response remains disabled.

The latest external-holdout workflow is v1.8. It finalizes the reviewed
synthetic benchmark profile and out-of-fold confidence calibration while
keeping production promotion, model activation, and response automation
disabled.

Recommended demo wording:

> The model helps prioritize analyst attention. It is not a production-accuracy claim and it cannot trigger containment automatically. Response actions still require reviewed evidence and analyst approval.

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
python -m atdr.scripts.import_logs "C:/path/to/private/paloalto-firewall.log" --limit 5000
```

Keep real or large log files outside Git, for example in `Downloads`, `data/private/`, or `real_logs/`. Set `DEMO_SAMPLE_LOG_PATH` in `.env` or pass the absolute file path.

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

Compare supervised candidates without replacing the active model:

```powershell
python -m atdr.scripts.compare_supervised_models --test-size 0.3 --min-samples 6
```

This writes `ml_baseline_reviews/model_comparison_report.md`. The comparison includes Random Forest, Logistic Regression, gradient boosting, and a hybrid-score baseline. It does not overwrite the active supervised model artifact.

## 13. View AI Model Evaluation

Open **ML Governance** in the React dashboard. Show:

- IsolationForest status
- supervised label count
- training/test rows
- accuracy, precision, recall, F1
- feature importance
- data quality: parse success, missing fields, unknown apps, time range
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

## 16. Final Senior Project Demo Script

Use this compact story when presenting the hybrid AI workflow:

1. Import real Palo Alto firewall logs from a private local path.
2. Run rule-based detection and show that every alert includes score, severity, matched rules, and evidence log IDs.
3. Train and apply the IsolationForest anomaly detector to highlight unusual traffic patterns.
4. Generate assisted weak labels from rule evidence, anomaly flags, hybrid risk, normalized fields, and 5-minute behavior features.
5. Export the human review sample from **ML Governance**.
6. Review the CSV by filling `human_review_decision` and `human_review_note`.
7. Import the reviewed CSV through **ML Governance > Import Reviewed CSV**.
8. Retrain the supervised model.
9. Show **ML Governance** with label distribution, reviewed vs unreviewed assisted labels, model metrics, and the weak-label warning.
10. Open **Alert Workbench** and show rule evidence, raw evidence links, matched rules, and the recommended response.
11. Show that response actions such as block IP are simulated and require analyst/admin approval.
12. Open **Audit Log** to prove the workflow created traceable evidence.

Final presentation wording:

> The system uses rule-based detection, anomaly scoring, and assisted weak labeling to support analysts. Assisted labels are not treated as perfect ground truth. A human-reviewed sample is used to validate the labeling workflow, and all response actions remain analyst-approved.

Metric caveat:

- Current supervised metrics are based on a mixed dataset: mostly assisted weak labels plus the reviewed sample.
- Do not describe these numbers as final production accuracy.
- For a small-office lab pilot, the next maturity step is reviewing more representative labels from real baseline traffic before trusting supervised metrics operationally.

## 17. Dashboard Dropdown Manual QA Checklist

Before the final demo, verify that sorting and filter dropdowns close cleanly and never leave an invisible layer blocking the page:

1. Open **Log Explorer**, select a sort dropdown value, then click another filter/search input.
2. Open **Alert Workbench**, select severity/status/sort dropdown values, then open an alert detail or evidence link.
3. Open **Audit Log**, select table density or saved-view dropdown values, then click another filter/control.
4. Open **ML Governance**, use export/report/import controls after any available dropdown interaction.
5. Open **Threat Controls > Watchlists**, select the indicator-type dropdown, then click the indicator value input.
6. Confirm the page remains clickable, no raw HTML or error overlay is visible, and no dropdown menu remains open.

## 18. Active Learning And Safe Model Promotion

Use active learning when weak-label metrics look strong but reviewed coverage is still small:

```powershell
python -m atdr.scripts.export_active_learning_review_sample --limit 100
python -m atdr.scripts.train_supervised_model --split time --test-size 0.3 --min-samples 6
python -m atdr.scripts.compare_supervised_models --test-size 0.3 --min-samples 6
```

The active-learning CSV is written to `ml_baseline_reviews/active_learning_review_sample.csv`. Review the rows with the highest disagreement, low confidence, rare apps/ports, high hybrid risk, `needs_context`, or underrepresented classes. Fill `human_review_decision` and `human_review_note`, then import the reviewed CSV through **ML Governance > Import Reviewed CSV**.

Promotion rules:

- A higher weighted F1 score is not enough by itself.
- Reviewed-label support must be large enough to validate the result.
- Suspicious and malicious recall must not get worse.
- Minority classes must not collapse to zero recall.
- Metrics must be identified as weak-label, reviewed-label, or mixed-label.
- Response automation remains disabled; every containment action still requires analyst approval.

Recommended wording:

> Model comparison produced candidate models, but promotion is gated by reviewed-label coverage, class support, recall sanity checks, and analyst review. Current metrics are mostly weak-label or mixed-label indicators, not production accuracy.

## 19. Malicious-Class Coverage Improvement

If time-split evaluation shows `malicious recall = 0.0`, first check whether malicious examples exist in the training window:

```powershell
python -m atdr.scripts.export_class_temporal_coverage_report
```

Open `ml_baseline_reviews/class_temporal_coverage_report.md` and check:

- malicious train/test support
- suspicious train/test support
- earliest and latest timestamp per class
- warnings for classes that exist only in the test window

Then export review files designed for correction and re-import:

```powershell
python -m atdr.scripts.export_label_quality_issues --limit 1000
python -m atdr.scripts.export_active_learning_review_sample --limit 200 --focus malicious,suspicious,needs_context --output ml_baseline_reviews/active_learning_round3_malicious_focus.csv
```

Recommended review order:

1. Review `ml_baseline_reviews/label_quality_issues.csv` first. Correct inconsistent labels by filling `human_review_decision`, optional `human_review_attack_type`, optional `human_review_confidence`, and `human_review_note`.
2. Import the corrected quality CSV through **ML Governance > Import Reviewed CSV**.
3. Review `ml_baseline_reviews/active_learning_round3_malicious_focus.csv`, especially rows marked `training_window`.
4. Import the corrected active-learning CSV.
5. Retrain with time split:

```powershell
python -m atdr.scripts.train_supervised_model --split time --test-size 0.3 --min-samples 6
python -m atdr.scripts.tune_model_thresholds --split time --test-size 0.3 --min-samples 6
```

Presentation wording:

> Malicious-class validation is intentionally gated by time-window support. If malicious examples only appear in the newer test window, the model cannot learn that class yet. We improve this honestly by reviewing earlier malicious-like and suspicious examples, not by forcing promotion or claiming production accuracy.

## 20. Suspicious Recall And Boundary Improvement

After malicious training-window support reaches the minimum target, the next common blocker is suspicious recall. Use this workflow when threat-positive F1 is strong but exact suspicious-vs-malicious separation is weak:

```powershell
python -m atdr.scripts.analyze_suspicious_recall_errors --split time --test-size 0.3 --min-samples 6
python -m atdr.scripts.export_suspicious_recall_review_sample --limit 150
python -m atdr.scripts.tune_model_thresholds --split time --test-size 0.3 --min-samples 6
```

Review:

- `ml_baseline_reviews/suspicious_recall_error_report.md`
- `ml_baseline_reviews/suspicious_recall_review_sample.csv`
- `ml_baseline_reviews/threshold_tuning_report.md`

The suspicious recall sample prioritizes suspicious rows predicted as malicious, benign_unusual, benign, or needs_context, especially app=`incomplete`, action=`allow`, destination port `995`, and high threat-positive confidence rows with the wrong exact class. Fill `human_review_decision`, `human_review_attack_type`, `human_review_confidence`, and `human_review_note`, then import through **ML Governance > Import Reviewed CSV**.

Threshold profiles are candidate analysis only:

- `balanced`: default SOC triage policy.
- `suspicious_recall`: tries to recover suspicious rows without lowering malicious threshold.
- `malicious_recall`: catches more malicious rows but can increase suspicious/malicious boundary confusion.
- `threat_positive`: focuses on suspicious+malicious triage grouping, not exact class separation.

Recommended wording:

> The model is strong at threat-positive triage, but exact suspicious-versus-malicious separation is still being tuned. We use focused human review and threshold comparison to improve suspicious recall without enabling automatic response or claiming production accuracy.

## 21. Reproducible Supervised ML Pipeline

Use this workflow when you want a more professional supervised ML experiment without changing the current lab dashboard behavior.

Export a dataset snapshot:

```powershell
python -m atdr.scripts.export_supervised_dataset_snapshot --split time --test-size 0.3
```

This writes an ignored package under `ml_baseline_reviews/supervised_snapshots/` with metadata, feature schema, label distribution, reviewed/weak counts, class temporal coverage, train/test split information, and a feature CSV. Raw log text is excluded by default. Use `--include-raw` only for a controlled private review because raw payloads may contain sensitive data.

Train a model with explicit options:

```powershell
python -m atdr.scripts.train_supervised_model --split time --test-size 0.3 --min-samples 6 --model random_forest --class-weight balanced --threshold-profile balanced
```

Supported model options are:

- `random_forest`
- `hist_gradient_boosting`
- `logistic_regression`
- `extra_trees`

Run a comparison experiment without activating any model:

```powershell
python -m atdr.scripts.run_supervised_experiment --split time --test-size 0.3 --min-samples 6
```

This writes reports under `ml_baseline_reviews/supervised_experiments/` and compares rule/hybrid baseline, Random Forest, Logistic Regression, HistGradientBoosting, and ExtraTrees. Candidate metrics use the same probability-threshold decision path as supervised training when probabilities are available. Direct classifier metrics are kept separately in the JSON report for debugging.

Run a supervised sanity/debug report when experiment metrics look unexpectedly different from the active model:

```powershell
python -m atdr.scripts.supervised_sanity_report --split time --test-size 0.3 --min-samples 6
```

This writes `ml_baseline_reviews/supervised_sanity_report.md` and checks active-model evaluation, candidate comparison, label/probability mapping, feature preprocessing, and weighting behavior. It does not activate or promote any model.

Run safe tuning:

```powershell
python -m atdr.scripts.tune_supervised_model --split time --test-size 0.3 --min-samples 6
```

Tuning prioritizes threat-positive F1, suspicious recall, malicious recall, macro F1, and cost-sensitive score. Do not tune for accuracy alone.

Export error analysis:

```powershell
python -m atdr.scripts.analyze_supervised_errors --split time --test-size 0.3 --min-samples 6
```

This writes `ml_baseline_reviews/supervised_error_analysis.md` with suspicious/malicious false-negative and boundary-review guidance.

List model registry entries:

```powershell
python -m atdr.scripts.list_supervised_models
```

Activation is explicit and still means analyst decision support only:

```powershell
python -m atdr.scripts.activate_supervised_model --model-id <id>
python -m atdr.scripts.rollback_supervised_model
```

Activation never means production promotion. It does not enable automatic response. Response actions remain simulated and analyst-approved.

Recommended wording:

> We now snapshot the supervised dataset, version the feature pipeline, compare candidate models, tune thresholds with threat-focused metrics, and keep a model registry. The model remains decision support only; metrics are weak-label or mixed-label indicators unless separately validated with enough reviewed labels.

## 22. Supervised ML Recovery Workflow

Use this workflow when the active supervised artifact is unregistered/legacy or when current model metrics do not reproduce an older stronger run.

Export the current supervised dataset audit:

```powershell
python -m atdr.scripts.supervised_dataset_audit --split time --test-size 0.3
```

Run the full recovery workflow:

```powershell
python -m atdr.scripts.run_supervised_recovery_phase --split time --test-size 0.3 --min-samples 6 --review-limit 150
```

This creates ignored recovery artifacts under `ml_baseline_reviews/`, including:

- `current_supervised_dataset_audit.md`
- `current_supervised_error_analysis.md`
- `supervised_binary_threat_positive_experiment.md`
- `supervised_two_stage_experiment.md`
- `supervised_recovery_review_sample.csv`
- `supervised_label_target_plan.md`
- `supervised_recovery/latest_status.json`
- candidate-only registered baseline artifacts

The recovery command writes progress to the console and to `ml_baseline_reviews/supervised_recovery/latest_status.json`. On a large SQLite database, a terminal wrapper may time out even after intermediate reports are written. If that happens, inspect the latest `supervised_recovery_phase-*.json` file and the status file before rerunning.

Run individual recovery commands if you do not want the full workflow:

```powershell
python -m atdr.scripts.rebuild_supervised_baseline --split time --test-size 0.3 --min-samples 6
python -m atdr.scripts.run_binary_threat_experiment --split time --test-size 0.3 --min-samples 6
python -m atdr.scripts.current_supervised_error_analysis --split time --test-size 0.3 --min-samples 6
python -m atdr.scripts.export_supervised_recovery_review_sample --limit 150
python -m atdr.scripts.generate_supervised_label_target_plan --split time --test-size 0.3 --pretty
```

Recovery outputs are for diagnosis and active learning. They must not be committed and must not be presented as production accuracy. Rebuilt baselines are registered candidates only; activation and production promotion remain separate manual decisions, and response automation remains disabled.

## 23. Large-Pool Active Learning

Do not manually label all available logs. Use all logs for baseline statistics, source behavior, IsolationForest anomaly scoring, drift checks, and active-learning selection. Use reviewed labels for supervised model training and validation.

Export high-value review rows from the full normalized log pool:

```powershell
python -m atdr.scripts.export_large_pool_active_learning_sample --limit 300 --pretty
```

This writes `ml_baseline_reviews/large_pool_active_learning_sample.csv`. It prioritizes high anomaly score, high hybrid risk, rule/anomaly/model disagreement, unlabeled threat-positive predictions, rare apps/ports, repeated external-to-internal behavior, source-specific unusual behavior, and confusing `ssl`/`quic-base` allow/443 cases. The export is intentionally small, usually 200-500 rows, so humans review the most useful rows instead of random logs.

Use the label target plan to guide the next review batch:

```powershell
python -m atdr.scripts.generate_supervised_label_target_plan --split time --test-size 0.3 --pretty
```

Suggested reviewed-label targets:

- benign: 300
- benign_unusual: 300
- suspicious: 300
- malicious: 150
- needs_context: 50

Recommended wording:

> We use the full log pool to learn behavior baselines and select high-value examples for human review. The supervised model trains on reviewed labels, while weak labels remain bootstrap data and are not treated as perfect ground truth.

## 24. Balanced Supervised Recovery Review

Use this phase after malicious reviewed-label coverage is already above target and exact evaluation is unstable because the time split is class-imbalanced. The goal is to rebalance reviewed labels, not to chase another malicious-heavy review batch.

Generate a balanced recovery sample:

```powershell
python -m atdr.scripts.export_balanced_recovery_review_sample --limit 300 --pretty
```

This writes `ml_baseline_reviews/balanced_recovery_review_sample.csv`. The target composition is:

- 150 benign candidates
- 50 needs_context candidates
- 75 suspicious boundary candidates
- 25 miscellaneous rule/anomaly/model disagreement cases

The sample intentionally avoids malicious-heavy selection. It focuses on normal SSL/QUIC/DNS/web traffic, ambiguous rows with limited evidence, suspicious rows predicted benign-like, and benign/benign_unusual rows predicted threat-like.

Create split diagnostics:

```powershell
python -m atdr.scripts.evaluation_split_diagnostics --test-size 0.3 --min-samples 6 --pretty
```

This writes `ml_baseline_reviews/evaluation_split_diagnostics.md` and compares the primary time split with `grouped_stratified` as a diagnostic-only split. Time split remains the deployment-style validation. Grouped/stratified split may overestimate performance and must not be used to claim production accuracy.

Refresh the target plan:

```powershell
python -m atdr.scripts.generate_supervised_label_target_plan --split time --test-size 0.3 --pretty
```

When malicious target is met, the next review focus should be benign, needs_context, and suspicious boundary cleanup. ML remains decision support only, candidate-only unless future validation criteria are explicitly met, and response automation remains disabled.

## 25. Stage 1 Threat-Positive Recovery

Use this phase after balanced recovery if the two-stage/hierarchical candidate shows promising Stage 2 suspicious-versus-malicious separation but weak Stage 1 threat-positive recall. Stage 1 must first catch suspicious/malicious-like traffic before Stage 2 can classify it.

Generate the Stage 1 recall review sample:

```powershell
python -m atdr.scripts.export_stage1_threat_recall_review_sample --limit 300 --pretty
```

This writes `ml_baseline_reviews/stage1_threat_recall_review_sample.csv`. The target composition is:

- 120 threat-positive false negatives
- 80 benign candidates
- 50 benign versus benign_unusual boundary cases
- 30 needs_context candidates
- 20 miscellaneous rule/anomaly/model disagreement cases

The sample should not become malicious-heavy. Malicious and suspicious targets may already be met; use this sample to improve Stage 1 recall and complete benign/needs_context coverage.

Tune Stage 1 thresholds:

```powershell
python -m atdr.scripts.run_stage1_threshold_tuning --split time --test-size 0.3 --min-samples 6 --pretty
```

This writes `ml_baseline_reviews/stage1_threshold_tuning_report.md` and compares:

- conservative
- balanced
- recall_high
- recall_max_review_queue

Recall-heavy profiles catch more threat-positive rows but increase analyst review queue size. This is diagnostic only. Do not activate or promote a model from this report, and do not enable automatic response.

Recommended wording:

> Stage 2 suspicious-versus-malicious separation is promising, but Stage 1 threat-positive recall remains the blocker. The next review batch focuses on Stage 1 false negatives plus benign and needs_context coverage. The model remains candidate-only and decision support only.

## 26. Benign Class Recovery

Use this phase when malicious and suspicious reviewed targets are met but benign recall remains weak or `0.0`. Do not add another malicious-heavy batch. Focus on benign, needs_context, and benign/benign_unusual/suspicious boundary cleanup.

Write the benign debug report:

```powershell
python -m atdr.scripts.write_benign_class_debug_report --split time --test-size 0.3 --min-samples 6 --pretty
```

Run the benign recovery experiment:

```powershell
python -m atdr.scripts.run_benign_recovery_experiment --split time --test-size 0.3 --min-samples 6 --pretty
```

Export the final small review sample:

```powershell
python -m atdr.scripts.export_benign_needs_context_final_gap_sample --limit 100 --pretty
```

Expected outputs:

- `ml_baseline_reviews/benign_class_debug_report.md`
- `ml_baseline_reviews/benign_recovery_experiment.md`
- `ml_baseline_reviews/benign_needs_context_final_gap_sample.csv`

When the full supervised recovery phase runs, it also writes `ml_baseline_reviews/soc_triage_model_strategy_report.md`.

Interpretation:

- Benign recall near `0.0` usually means trusted benign training-window support is too small, benign overlaps with `benign_unusual`, or benign rows share features with weak suspicious rows.
- Threshold logic should be checked, but this phase must not activate or promote any model.
- SOC triage can use a `benign_like` versus `threat_positive` framing for analyst review while exact five-class separation remains future work.
- ML remains decision support only, production promotion remains false, and response automation remains disabled.

## 27. Final SOC Triage Recommendation

After the final benign/needs_context recovery pass, use the supervised model as SOC triage decision support rather than an exact automated classifier.

Write the final recommendation report:

```powershell
python -m atdr.scripts.write_soc_triage_final_recommendation --split time --test-size 0.3 --min-samples 6 --pretty
```

This writes `ml_baseline_reviews/soc_triage_final_recommendation.md`. The report compares:

- flat five-class supervised classification
- binary `benign_like` versus `threat_positive`
- three-class `benign_like` / `suspicious` / `malicious`
- hierarchical Stage 1 + Stage 2 candidate behavior
- conservative, balanced, and recall-high SOC review profiles

Export the final small label-gap sample only if another small review batch is useful:

```powershell
python -m atdr.scripts.export_final_small_label_gap_sample --limit 64 --pretty
```

This writes `ml_baseline_reviews/final_small_label_gap_sample.csv`. It targets the remaining benign and needs_context gaps plus a small benign/suspicious boundary set. It intentionally avoids another malicious-heavy batch.

Recommended wording:

> ATDR uses supervised ML as SOC triage decision support. Threat-positive triage is useful for analyst review, but the flat five-class model is not production-promoted. Benign and needs_context exact classification remain weak, and all response actions remain simulated and analyst-approved.

## 28. Benchmark-Style ML Experiment Mode

Use this phase when you have a safe public-style, synthetic, or approved benchmark CSV. Do not import benchmark labels into the main `ml_labels` table by default. Do not commit benchmark data, prepared snapshots, generated reports, model artifacts, or `ml_baseline_reviews/`.

Prepare a sanitized snapshot:

```powershell
python -m atdr.scripts.prepare_benchmark_dataset --input-csv "C:\path\to\benchmark.csv" --mapping-config data\samples\benchmarks\example_firewall_mapping.json --label-config data\samples\benchmarks\example_label_mapping.json --limit 5000 --sample-strategy balanced --pretty
```

Run an in-memory benchmark ML experiment:

```powershell
python -m atdr.scripts.run_benchmark_ml_experiment --prepared-snapshot "demo_exports\benchmarks\benchmark_snapshot_<id>.json" --split time --test-size 0.3 --pretty
```

The experiment compares RandomForest, ExtraTrees, LogisticRegression, HistGradientBoosting, binary threat-positive, and three-class SOC triage candidates. It writes reports only and does not activate a model.

Recommended wording:

> Benchmark experiments help evaluate model architecture and feature behavior on broader labeled data. They are not mixed with local firewall-log metrics by default, and they do not prove production accuracy. ATDR remains decision support only.

## 29. v1.3 Larger Reviewed-Label Workflow

```powershell
python -m atdr.scripts.audit_training_data_quality --split time --test-size 0.3 --pretty
python -m atdr.scripts.generate_v13_label_target_plan --split time --test-size 0.3 --pretty
python -m atdr.scripts.export_v13_ai_training_review_sample --limit 500 --focus balanced --pretty
```

After human review and React AI Governance import:

```powershell
python -m atdr.scripts.train_v13_supervised_candidates --split time --test-size 0.3 --min-samples 6 --pretty
python -m atdr.scripts.analyze_v13_ml_errors --split time --test-size 0.3 --min-samples 6 --pretty
```

See `docs/V1_3_LARGER_LABELED_DATA_AND_AI_TRAINING.md` for target definitions, focus modes, benchmark intake, readiness gate v3, and limitations. All outputs remain ignored, candidate-only, and unable to trigger response actions.

## 30. v1.4 False Positive Reduction And Calibration

Run the candidate-only comparison after v1.3 evaluation or reviewed-label import:

```powershell
python -m atdr.scripts.run_v14_false_positive_reduction --split time --test-size 0.3 --min-samples 6 --review-limit 200 --pretty
```

The workflow compares hard-gated threshold profiles, ExtraTrees weighting strategies, calibrated Logistic Regression, binary and three-class SOC triage, and a hierarchical candidate. It reports benign-like false-positive rate, threat-positive metrics, class recall, review queue size, calibration buckets, Brier score, and readiness checks.

No candidate is written to the model registry or activated. If generated, review `ml_baseline_reviews/v1_4_false_positive_review_sample.csv` before importing it through AI Governance.

See `docs/V1_4_FALSE_POSITIVE_REDUCTION_AND_CONFIDENCE_CALIBRATION.md`.

## 31. v1.4b Actionable False Positive Review

The original v1.4 diagnostic sample may contain protected labels. Use v1.4b for an importable review queue:

```powershell
python -m atdr.scripts.run_v14b_false_positive_mitigation --split time --test-size 0.3 --min-samples 6 --review-limit 200 --pretty
```

By default, protected manual and reviewed labels are excluded. The generated `v1_4b_actionable_false_positive_review_sample.csv` focuses on unlabeled and unreviewed assisted rows, especially normal QUIC/443 traffic predicted as threat-like.

Use `--include-manual` or `--include-reviewed` only for explicit diagnostics. These options do not disable import protection.

See `docs/V1_4B_FALSE_POSITIVE_MITIGATION.md`.

## 32. v1.4c Malicious Recall Recovery And Calibration

Run this after importing the v1.4b actionable false-positive review:

```powershell
python -m atdr.scripts.run_v14c_malicious_recovery --split time --test-size 0.3 --min-samples 6 --review-limit 150 --pretty
```

The workflow preserves the evidence-aware QUIC/443 safeguard while comparing malicious-recall, balanced low-noise, calibrated low-noise, and high-confidence triage profiles. Calibration methods are fit on held-out training-window rows and checked again on the chronological test window.

Review `ml_baseline_reviews/v1_4c_malicious_recall_review_sample.csv` only if the report identifies actionable unlabeled or unreviewed rows. Protected manual and reviewed labels remain excluded.

See `docs/V1_4C_MALICIOUS_RECALL_RECOVERY_AND_CALIBRATION.md`. No model artifact is activated, production promotion remains false, and response automation remains disabled.

## 33. v1.5 Internal Benchmark And Final Readiness

Preview the safe deterministic benchmark without writing output:

```powershell
python -m atdr.scripts.build_internal_ai_readiness_benchmark --dry-run --pretty
```

Run the complete isolated benchmark and readiness workflow:

```powershell
python -m atdr.scripts.run_v15_ai_readiness_validation --pretty
```

The committed manifest generates 240 synthetic labels across benign-like, suspicious, malicious, and needs-context scenarios. Generated CSVs, snapshots, and reports stay under ignored `demo_exports/benchmarks/` and `ml_baseline_reviews/`.

`benchmark_validated_candidate` means the internal benchmark gate passed for analyst decision support. It does not activate a model, promote it to production, enable response automation, or prove deployment accuracy.

See `docs/V1_5_AI_READINESS_BENCHMARK_VALIDATION.md`.

## 34. v1.6 External / Unseen Holdout Validation

Preview the 320-row fixed safe holdout:

```powershell
python -m atdr.scripts.build_fixed_unseen_holdout --dry-run --pretty
```

Run transfer evaluation without changing the active model:

```powershell
python -m atdr.scripts.run_external_benchmark_validation --holdout-from-current-data --pretty
```

The switch uses a separate synthetic holdout with different source names, timestamps, and scenarios. It does not extract private local database rows. An approved external CSV can be supplied with `--input-csv`, mapping, and label configuration.

The workflow compares internal and unseen metrics, checks per-class and per-attack performance, measures confidence calibration, and reports a generalization gap. Generated snapshots and reports remain under ignored `demo_exports/benchmarks/`.

Current readiness is `internal_benchmark_validated_candidate`, not external-benchmark validated. No model is written or activated, production promotion remains false, and response automation remains disabled.

See `docs/V1_6_EXTERNAL_BENCHMARK_VALIDATION.md`.

## 35. v1.7 External Generalization Improvement

Run the v1.7 profile comparison, error analysis, calibration check, and boundary review export:

```powershell
python -m atdr.scripts.run_v17_external_generalization --review-limit 300 --pretty
```

The script uses the latest v1.6 external holdout snapshot, rebuilds the safe internal benchmark snapshot, compares external profiles, applies an overfitting guard, and exports:

- `demo_exports/benchmarks/v1_7_external_generalization_<timestamp>.json`
- `demo_exports/benchmarks/v1_7_external_generalization_<timestamp>.md`
- `demo_exports/benchmarks/v1_7_external_error_analysis_<timestamp>.md`
- `ml_baseline_reviews/v1_7_external_boundary_review_sample.csv`

Current v1.7 evidence improves external threat-positive F1 and benign false-positive rate, but the model is still not externally validated or production-promoted. Use the boundary review sample to add human-reviewed evidence before another training pass.

See `docs/V1_7_EXTERNAL_GENERALIZATION_IMPROVEMENT.md`.

## 36. v1.7b Benchmark Review Import

The v1.7 external boundary CSV is benchmark review data keyed by `benchmark_row_id`. Do not import it through the normal reviewed-label importer, which requires database `log_id` or `label_id` values.

Import the completed benchmark review:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.import_benchmark_review_csv `
  --input-csv "C:\path\to\v1_7_external_boundary_review_sample_REVIEWED.csv" `
  --benchmark-kind external_holdout `
  --pretty
```

Then evaluate against the reviewed holdout labels:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_external_benchmark_validation `
  --holdout-from-current-data `
  --reviewed-benchmark-csv "C:\path\to\v1_7_external_boundary_review_sample_REVIEWED.csv" `
  --pretty
```

The reviewed benchmark artifact and reviewed snapshot remain under ignored storage. They never create or update `ml_labels`.

See `docs/V1_7B_BENCHMARK_REVIEW_IMPORT.md`.

## 37. v1.8 External Benchmark Finalization

Run the narrow external profile, miss-analysis, and calibration pass:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v18_external_benchmark_finalization --pretty
```

The workflow compares fixed external profiles, rejects candidates with benign
FPR above `0.15` or threat precision below `0.80`, and evaluates temperature,
sigmoid, isotonic, and confidence-bucket calibration. Confidence calibration is
stratified and out-of-fold, so a row is not calibrated by a fit that used that
same row.

Current v1.8 evidence selects `external_recall_plus` and reaches
`external_benchmark_validated_candidate`. This remains reviewed synthetic
benchmark evidence for analyst decision support. It does not production-promote
or activate a model, and it cannot enable response automation.

See `docs/V1_8_EXTERNAL_BENCHMARK_FINALIZATION.md`.

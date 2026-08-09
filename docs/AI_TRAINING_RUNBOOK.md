# ATDR Hybrid AI Training Runbook

This runbook explains ATDR's governed AI workflow for controlled lab and
shared-lab use. Deterministic rules are alert-authoritative. Anomaly,
supervised, hybrid, and assistant output are decision support only. Rule
evidence, source evidence, and analyst approval remain required before any
simulated response action.

## Current Model Status

Current supervised lifecycle status is `shadow_observation`. A governed v5.1
calibrated ExtraTrees binary SOC queue artifact exists, but v5.2 selected no new
candidate: no supervised strategy passed every temporal, source/proxy, random,
calibration, and external gate. Shadow scores cannot create or suppress alerts,
change severity, or authorize response.

v5.2 repaired the controlled layered matrix from 267/288 to 288/288 with zero
controlled false positives, false negatives, or response actions. This validates
the synthetic regression contract, not real-world accuracy. The locked external
benchmark and source-independent evidence requirements remain failed/open.

Recommended demo wording:

> Deterministic rules create explainable alerts. Supervised and anomaly layers
> remain shadow/advisory evidence because independent stability gates have not
> passed. They cannot trigger containment.

## 1. Start From A Clean Demo Baseline

```powershell
Copy-Item .env.example .env
python -m atdr.scripts.config_doctor --pretty
python -m atdr.scripts.seed_users
```

Start the API:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Start the main React dashboard in a second terminal:

```powershell
cd frontend
npm.cmd run dev
```

For the mandatory MFU outer-shell workflow, use the versioned team lifecycle
documented in `docs/TEAM_ONE_COMMAND_START.md`. Streamlit is legacy continuity,
not the primary dashboard.

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

## 38. v1.9 Independent Revalidation

Build a new seeded holdout that is separate from the v1.6-v1.8 reviewed
external benchmark:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.build_independent_holdout --pretty
```

Run the safe source/parser validation before calculating readiness v7:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_controlled_real_source_validation --pretty
```

Run the eight-profile independent comparison:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v19_independent_revalidation --pretty
```

The default holdout contains 500 synthetic rows across at least five logical
sources. The workflow reports exact overlap, near-duplicate families, per-class
metrics, calibration, internal/external/independent gaps, controlled-source
status, performance warnings, and readiness v7.

Do not tune a profile directly against this independent result and then describe
the same holdout as unseen. Any change informed by v1.9 requires another
independent holdout. Generated data and reports stay under ignored
`demo_exports/benchmarks/`.

See `docs/V1_9_INDEPENDENT_REVALIDATION_AND_REAL_SOURCE_VALIDATION.md`.

## 39. v1.9b Independent FPR Stabilization

Run the narrow identity-independent boundary comparison:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v19b_independent_fpr_stabilization --pretty
```

The runner compares the current v1.9 profile with four stabilization profiles
and two existing baselines. It rejects profiles that miss recall/FPR targets,
use source or scenario identity, or fail to preserve behavior-window evidence.

The selected `independent_fpr_stabilized` profile routes unresolved
`unknown-tcp` allowed high-port rows to analyst review only when rule and
behavior-window evidence are absent. It does not write or activate a model.

Current result:

- benign-like FPR: `0.0917`;
- threat F1: `0.9257`;
- suspicious recall: `0.9538`;
- malicious recall: `0.8769`;
- readiness v7b: `controlled_real_source_validated_candidate`;
- production promotion, model activation, response automation, and real
  firewall blocking: disabled.

Generated analysis and comparison reports remain under ignored
`demo_exports/benchmarks/`.

See `docs/V1_9B_INDEPENDENT_FPR_STABILIZATION.md`.

## 40. v2.0 Fresh Blind And Final Controlled Validation

Freeze the selected v1.9b policy before generating the new holdout:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.lock_v20_candidate --pretty
```

Generate the 700-row blind holdout:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.build_fresh_blind_holdout --pretty
```

Evaluate the frozen candidate once:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v20_fresh_blind_revalidation --pretty
```

Do not change thresholds, select another profile, or use source/scenario names
after inspecting this holdout. A failed check requires a separate future phase.

Run final controlled source acceptance:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_final_controlled_source_acceptance --pretty
```

Current fresh blind result:

- 700 rows, 7 sources, 16 scenarios;
- exact overlap: 0; near-pattern overlap: 335;
- threat F1: `0.9174`;
- threat recall: `0.9459`;
- benign-like FPR: `0.1303`;
- suspicious recall: `0.8556`;
- malicious recall: `0.9000`;
- no-fit raw-confidence calibration: passed;
- final readiness v8: `final_controlled_validation_candidate`.

Production promotion, model activation, automatic response, and real firewall
blocking remain disabled.

See `docs/FINAL_ENGINEERING_VALIDATION_SUMMARY.md`.

## v5.1 Governed Shadow Lifecycle

The current governed supervised model is a calibrated ExtraTrees binary SOC
review queue. It is operationally active in `shadow_observation`, not as an
alert-authoritative detector. Rules remain authoritative and response automation
remains disabled.

Inspect the current lifecycle:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.manage_supervised_lifecycle --status --pretty
```

Train, register, and request safe shadow activation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v51_supervised_shadow_activation --activation-mode shadow_observation --pretty
```

This command writes a versioned artifact only under the ignored
`atdr/models/supervised_candidates/` directory and generated reports only under
ignored `ml_baseline_reviews/`. It does not overwrite the unknown legacy
artifact. The run records latest eligible reviewed-row provenance, duplicate and
leakage isolation, fit/calibration/threshold/final partitions, five validation
views, locked external evidence, threshold, calibration, artifact checksum, and
latency.

Requesting `decision_support` uses the same command with
`--activation-mode decision_support`, but the lifecycle fails closed unless all
strict and external gates pass. The current result passes 0/5 strict splits, so
the allowed state is shadow only.

Disable governed inference:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.manage_supervised_lifecycle --disable --pretty
```

Rollback to the previous governed activation, or disable if no valid predecessor
exists:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.manage_supervised_lifecycle --rollback --pretty
```

These commands are audited and do not delete evidence or labels. See
`docs/V5_1_SUPERVISED_SHADOW_ACTIVATION.md` for metrics, private-file shadow
validation, and remaining gates.

## v5.3 Temporal Generalization And OOD Evaluation

Run the read-only temporal/OOD evaluator:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v53_temporal_generalization --pretty
```

The command freezes the current v5.2 dataset fingerprint and state, diagnoses
chronological drift, evaluates three disjoint future windows, fits OOD profiles
only on fit rows, and compares memory-only diagnostic strategies. It writes no
active model artifact, model activation, label, detection run, or response.

Current result: no candidate is selected. The leading diagnostic comparator has
temporal FPR `0.9976`; rolling FPR is `0.9923` to `1.0000`; source holdout fails
closed; and locked external evidence remains failed. OOD/unstable rows are
reported as `insufficient_model_evidence`, but abstentions remain counted in the
analyst queue so quality cannot be improved by hiding difficult rows.

Inspect the governed state after evaluation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.manage_supervised_lifecycle --status --pretty
```

It must remain `shadow_observation`, with production promotion, response
automation, and real blocking false. Generated v5.3 reports remain ignored
under `ml_baseline_reviews/`. See
`docs/V5_3_TEMPORAL_GENERALIZATION_AND_OOD.md`.

## v5.4 Temporal Evidence Preparation And Shadow Drift

Run the configured-database read-only evidence preparation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v54_temporal_evidence_preparation --pretty
```

Inspect a private PAN-OS file without importing it or returning private data:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v54_temporal_evidence_preparation `
  --sample-path "C:\Path\Outside\Git\firewall.log" `
  --preflight-only `
  --pretty
```

Run a bounded disposable validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v54_temporal_evidence_preparation `
  --sample-path "C:\Path\Outside\Git\firewall.log" `
  --use-temp-db `
  --limit 5000 `
  --pretty
```

The normal run validates the tracked v5.3 evidence lock, audits chronological
quality, writes an ignored development manifest and optional weak review pack,
and calculates aggregate shadow drift. Final/rolling/external labels remain
locked out of development. The private modes return no path, raw log, IP,
secret, or reusable fingerprint and make no accuracy claim.

The expected current status is `OOD Warning` and `shadow_observation`. Any
review-pack suggestion is assisted/weak, requires human confirmation, and is
not import-ready. See `docs/V5_4_TEMPORAL_EVIDENCE_AND_SHADOW_DRIFT.md`.

## v5.5 Development Model Repair And Anomaly Audit

Run the governed development-only evaluator:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v55_development_model_repair --pretty
```

To validate only the development boundary and freeze without reopening the
locked temporal-final role:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v55_development_model_repair `
  --skip-locked-final `
  --pretty
```

The command validates the v5.4 lock, compares five memory-only supervised
strategies across nested chronological development folds, freezes at most one
diagnostic leader, audits the existing IsolationForest read-only, and then
optionally runs one post-freeze locked-final regression. It writes only ignored
aggregate reports and never writes an active model artifact, label, detection
run, or response action.

Current result: the three-class ExtraTrees SOC queue is the diagnostic leader
but passes `0/3` strict development folds. Locked-final FPR improves to
`0.0773`, while F1 `0.4925`, suspicious recall `0.3824`, malicious recall
`0.4143`, and ECE `0.5405` fail the fixed gates. IsolationForest development
FPR is `0.2773` with threat capture `0.0818`. Lifecycle therefore remains
`shadow_observation`; rules remain alert-authoritative.

See `docs/V5_5_DEVELOPMENT_MODEL_REPAIR_AND_ANOMALY_AUDIT.md`.

## v5.6 Private PAN-OS Evidence And Assisted Model Repair

Run a boundary-only preflight against a private file outside Git:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v56_private_panos_model_repair `
  --sample-path "C:\Path\Outside\Git\firewall.log" `
  --use-temp-db `
  --preflight-only `
  --pretty
```

Run the governed bounded model comparison:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v56_private_panos_model_repair `
  --sample-path "C:\Path\Outside\Git\firewall.log" `
  --use-temp-db `
  --max-fit-rows 6000 `
  --max-calibration-rows 2400 `
  --max-threshold-rows 2800 `
  --max-future-rows 3500 `
  --pretty
```

`--use-temp-db` is an explicit safety acknowledgement. The command streams the
complete file into disposable SQLite, detects configured-DB overlap read-only,
predeclares chronological roles, applies the fixed non-human assisted policy,
compares diagnostic candidates, freezes one candidate, and only then opens the
private future labels once.

Generated reports and the optional candidate artifact remain ignored under
`ml_baseline_reviews/`. They do not replace the active model. The command must
return zero configured-DB, label, model-run, detection-run, alert, and response
writes.

Current result: 773,551 rows parsed with zero failures; 120,626 rows
quarantined; HistGradientBoosting is the diagnostic leader. Its private
future-policy F1/FPR are `0.9889/0.0211`, but maximum confidence gap is
`0.8143`, the source is one device, and labels are assisted. Lifecycle remains
`shadow_observation`. See
`docs/V5_6_PRIVATE_PANOS_EVIDENCE_AND_ASSISTED_MODEL_REPAIR.md`.

## v5.7 Independent Evidence And Blind Shadow Revalidation

v5.7 freezes the ignored v5.6 HistGradientBoosting diagnostic candidate as a
reproducible, threshold-only shadow evaluator. It records the feature,
preprocessing, sigmoid calibration, threshold, training-manifest, code, and
artifact contracts without replacing any active artifact.

The already analyzed private PAN-OS file is valid only for a disposable
preflight and reuse/leakage confirmation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v57_independent_shadow_revalidation `
  --sample-path "<PRIVATE_PAN_OS_FILE>" `
  --use-temp-db `
  --preflight-only `
  --pretty
```

Expected current result: `independent_evidence_required`. The file overlaps
v5.6 development evidence and must not be described as a new holdout.

For genuinely new evidence, first complete
`docs/detection/V5_7_INDEPENDENT_EVIDENCE_ACQUISITION.md` and the manifest
template. Use prediction and reveal as separate commands:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v57_independent_shadow_revalidation `
  --sample-path "<INDEPENDENT_PAN_OS_FILE>" `
  --evidence-manifest "<PRIVATE_EVIDENCE_MANIFEST>" `
  --use-temp-db `
  --predictions-only `
  --pretty

.\.venv\Scripts\python.exe -m atdr.scripts.run_v57_independent_shadow_revalidation `
  --sample-path "<INDEPENDENT_PAN_OS_FILE>" `
  --evidence-manifest "<PRIVATE_EVIDENCE_MANIFEST>" `
  --use-temp-db `
  --reveal-labels `
  --pretty
```

The prediction command is immutable and hides predictions from the review
pack. Reveal requires complete confirmed labels, allowed provenance, an
unchanged evidence contract, and advisor approval; it can run only once.
Assisted labels are never accepted as human ground truth.

If valid evidence is unavailable, do not lower gates, relabel reused rows, or
rerun opened final windows. Keep the lifecycle `shadow_observation`, rules
alert-authoritative, IsolationForest advisory, and response automation and
real blocking disabled.

## v5.8 Governed Shadow Scoring Runtime

The frozen v5.6/v5.7 HistGradientBoosting candidate can be observed through a
bounded read-only runtime. It remains disabled by default and is not an active
or promoted model.

Inspect status:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v58_governed_shadow_runtime --pretty
```

Run a one-process bounded evaluation without editing `.env`:

```powershell
$env:GOVERNED_SHADOW_SCORING_ENABLED="true"
$env:GOVERNED_SHADOW_BATCH_SIZE="100"
.\.venv\Scripts\python.exe -m atdr.scripts.run_v58_governed_shadow_runtime `
  --execute-shadow `
  --limit 100 `
  --pretty
```

The output is aggregate-only and must report unchanged database/artifact
state. Queue rate, drift, and rule disagreement are monitoring signals, not
accuracy. Never use this command to justify activation without the complete
v5.7 independent-evidence protocol.

Preflight genuinely new evidence only:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v58_governed_shadow_runtime `
  --sample-path "<NEW_PRIVATE_PANOS_PATH>" `
  --evidence-manifest "<APPROVED_MANIFEST_PATH>" `
  --preflight-only `
  --use-temp-db `
  --pretty
```

Reused evidence, invalid provenance, insufficient devices/periods, overlap,
or duplicate leakage must fail closed. No labels or blind accuracy are read
during preflight.

## v5.9 Longitudinal Shadow Observation

The v5.9 observation layer persists aggregate governed-shadow telemetry only.
It is disabled by default and does not change authoritative alerts, labels,
models, cases, or response state.

Inspect current status and aggregate history:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v59_longitudinal_shadow_observation --pretty

.\.venv\Scripts\python.exe -m atdr.scripts.run_v59_longitudinal_shadow_observation `
  --list `
  --pretty
```

Record one explicitly enabled, bounded observation:

```powershell
$env:GOVERNED_SHADOW_SCORING_ENABLED="true"
$env:GOVERNED_SHADOW_OBSERVATION_ENABLED="true"
.\.venv\Scripts\python.exe -m atdr.scripts.run_v59_longitudinal_shadow_observation `
  --execute-shadow `
  --source-id <SOURCE_ID> `
  --start-at "<ISO_TIMESTAMP>" `
  --end-at "<ISO_TIMESTAMP>" `
  --limit 250 `
  --pretty
```

Preview retention before any deletion:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v59_longitudinal_shadow_observation `
  --retention-preview `
  --pretty
```

Retention application is an explicit admin operation and affects only
expired aggregate observation rows. It creates an audit event.

Inspect a private file without importing it:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v59_longitudinal_shadow_observation `
  --sample-path "<PRIVATE_PANOS_PATH>" `
  --use-temp-db `
  --preflight-only `
  --pretty
```

The private output is aggregate-only. It must never return paths, raw rows,
IPs, fingerprints, or secrets. Reused unlabeled data can support parser/drift
monitoring but not accuracy claims. Follow
`docs/detection/V5_9_INDEPENDENT_EVIDENCE_ACQUISITION.md` for genuinely new
blind evidence.

## v5.10 Detection Operations And Shadow Acceptance

Inspect the safe bounded source/time plan:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v510_detection_operations_acceptance --pretty
```

Inspect aggregate acceptance from stored observations:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v510_detection_operations_acceptance `
  --acceptance-only `
  --pretty
```

Run the governed scopes explicitly:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v510_detection_operations_acceptance `
  --execute `
  --pretty
```

Execution enables governed scoring and observation for that process only.
Scopes are bounded and non-overlapping; outputs use opaque source labels and
exclude source IDs/names, raw logs, IPs, private paths, fingerprints, labels,
and secrets. Repeating the command reuses existing observation keys.

Interpret the result as operational telemetry only:

- `Stable`: aggregate behavior remains within the governed fit baseline.
- `Drift Warning`: a material distribution shift needs analyst attention.
- `OOD Warning`: evidence is materially outside the fit baseline; do not
  treat the queue as validated accuracy.
- `Insufficient Evidence`: the scope is retained but too small for a stable
  operational conclusion.

No v5.10 command activates or promotes a model, changes authoritative alerts,
or enables response. Profile the large-SQLite Governance path with:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.profile_ml_governance --pretty
```

## v5.11 Operational Drift And Shadow Monitoring

Inspect aggregate root causes, thresholds, hysteresis, and cadence status:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v511_shadow_monitoring --pretty
```

The output is operational telemetry only. It contains no accuracy, labels,
source identity, raw logs, IPs, private paths, fingerprints, or secrets.

Monitoring remains disabled by default. To use an approved external due-check
process, set all three values in the private runtime environment:

```text
GOVERNED_SHADOW_SCORING_ENABLED=true
GOVERNED_SHADOW_OBSERVATION_ENABLED=true
GOVERNED_SHADOW_MONITORING_ENABLED=true
```

Then request one due check:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v511_shadow_monitoring `
  --enqueue-if-due `
  --pretty
```

The due check is bounded, idempotent for its cadence bucket, retry-safe, and
cooperatively cancellable. It does not create an always-on scheduler.

Rehearse retention without touching the configured database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v511_shadow_monitoring `
  --retention-rehearsal `
  --pretty
```

The rehearsal uses disposable in-memory SQLite, previews before deletion,
removes only an expired aggregate observation, preserves logs, alerts,
labels, runs, users, and responses, and records an audit event. Do not apply
configured-database retention without an explicit admin review.

Interpret states conservatively:

- `Stable`: no material aggregate operating shift.
- `Drift Warning`: a sustained material shift after hysteresis.
- `OOD Warning`: an immediate large distribution/quality shift.
- `Insufficient Evidence`: fewer than 50 rows; it cannot clear a warning.

These states do not identify false positives or prove model accuracy. Keep
the lifecycle `shadow_observation` until independent governed evidence passes
the fixed blind gates.

## v5.12 Parser-Profile Baseline Repair

Inspect a private PAN-OS file without opening the configured database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v512_parser_profile_baseline_repair `
  --sample-path "<PRIVATE_PANOS_PATH>" `
  --preflight-only `
  --limit 120000 `
  --pretty
```

Run the read-only configured-database comparison plus disposable controlled
validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v512_parser_profile_baseline_repair `
  --sample-path "<PRIVATE_PANOS_PATH>" `
  --use-temp-db `
  --limit 120000 `
  --pretty
```

Interpret parser quality precisely:

- `parser_error_rate`: structural parsing failed.
- `parser_structural_warning_per_row`: parsing completed with structural
  compatibility/missing-field warnings.
- `unresolved_application_rate`: PAN-OS did not identify the application or
  the session lacked sufficient data; this is not automatically parser
  failure.
- `Insufficient Evidence`: too few rows or no comparable profile baseline;
  it must not be upgraded to stable.

Baselines use governed development-fit aggregates only. They never use labels,
accuracy, source identity, or locked-final evidence. The command must report
unchanged database entities, a matched v5.11 aggregate lock, and controlled
detection equivalence. It never authorizes model activation or response.

## v5.13 Runtime Parser Contract And Source Quality Operations

Future file imports, direct replay, UDP syslog, durable imports, and
controlled scenarios now write the same aggregate parser-quality contract.
No operator action is needed to backfill existing rows, and historical
evidence must not be reparsed automatically.

Interpret runtime source quality as follows:

- `parser_error`: structural parsing failed;
- `structural_warning`: parsing completed with a contract warning;
- `compatible`, `extended`, `partial`, and `unsupported`: layout
  compatibility states;
- `unresolved_application`: application identification is incomplete or
  unknown and is informational by itself;
- `absent_application`: the relevant record lacks an application value;
- `not_applicable`: the record type has no applicable application field;
- `generic_syslog`: raw evidence is preserved with limited structure; and
- `raw_fallback`: raw evidence is preserved without structured parsing and
  is not counted as an actual parser error.

Run a safe replay preview without persisting evidence:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs `
  --dry-run `
  --limit 20 `
  --rate 5 `
  --pretty
```

For an existing source, analysts and admins may open the read-only historical
contract preview in the source drawer or call:

```text
GET /api/sources/{source_id}/reparse-impact-preview
```

The preview reads only bounded stored normalized metadata. It does not read
raw logs, perform a reparse, or write to the database. Investigate
`parser_error_rate_increase`, unsupported layouts, structural drift, or
prolonged raw fallback as operational problems. Treat unresolved application
changes as context unless other evidence supports escalation.

Parser quality never changes alert authority, labels, model lifecycle, or
response behavior. Keep the supervised lifecycle in `shadow_observation`.

## v5.19 Independent Labeled Validation

Use only an officially acquired CTU-13 directory in ignored storage. Do not use
the private PAN-OS development file as independent ground truth.

Label-sealed preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v519_independent_labeled_validation `
  --dataset-path <IGNORED_CTU13_DIRECTORY> `
  --manifest-path <IGNORED_PRIVATE_MANIFEST> `
  --preflight-only `
  --pretty
```

One-shot execution for a fresh manifest/output state only:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v519_independent_labeled_validation `
  --dataset-path <IGNORED_CTU13_DIRECTORY> `
  --manifest-path <IGNORED_PRIVATE_MANIFEST> `
  --execute `
  --confirm `
  --pretty
```

The repository's completed v5.19 state is locked; a later preflight reports
`blind_validation_locked_complete`, and repeated execution fails closed. The
adapter-recovery mode exists only to preserve and diagnose the recorded
provider serialization mismatch. It is one-shot, cannot change predictions,
and must never be described as fresh blind evidence.

Interpret CTU-13 only as independent binary schema-transfer evidence. Do not
derive ATDR suspicious/malicious labels, train or tune against opened labels,
or claim full deterministic-rule coverage when PAN-OS action/application/zone
fields are absent. The measured v5.19 transfer failed; keep lifecycle
`shadow_observation` and rules alert-authoritative.

## v5.20 Schema-Aware Abstention Check

Run the read-only contract and v5.19 terminal-lock check with:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v520_schema_aware_abstention --pretty
```

The command does not access the configured database, reopen provider labels,
write a model artifact, or return private paths or fingerprints. A passing
result means unsupported schemas fail closed before supervised inference. It
does not mean the classifier is accurate or ready for activation.

During runtime, only compatible native PAN-OS evidence may receive a governed
supervised score. Treat `incompatible_schema`, `unknown_schema`,
`parser_error`, and `insufficient_evidence` as abstentions. Continue to use
deterministic rules as the authoritative alert path and keep lifecycle
`shadow_observation` until independent native evidence passes the fixed gates.

## v5.21 Native PAN-OS Evidence Program

Run the native evidence program only with an external private file and explicit
disposable-storage acknowledgement:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v521_native_panos_evidence `
  --sample-path "<private-panos-log>" `
  --use-temp-db `
  --review-limit 160 `
  --pretty
```

The command does not import the file into the configured database. It creates a
temporary derived-feature index, assigns chronological
`development_fit`/`calibration`/`threshold`/`untouched_future_validation`
roles, contains exact and near-duplicate families, and deletes the temporary
index on completion.

Generated local material under `ml_baseline_reviews/` is ignored:

- `v5_21_development_assisted_review_pack.csv` contains weak suggestions and
  requires human confirmation;
- `v5_21_blind_human_verification_pack.csv` contains no suggestions and must
  remain sealed during model development; and
- the manifest/report files contain private evidence locks and must not be
  committed.

Do not import either pack directly. Do not represent assisted suggestions as
human review. v5.22 may use only the three development roles for model
selection and must freeze its candidate before opening any human-confirmed
blind decision.

## v5.22 Native Supervised Rebuild

Run v5.21 first so the native role manifest exists, then run the diagnostic
rebuild with the private source supplied only as a CLI argument:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v522_supervised_model_rebuild `
  --sample-path <private-panos-path> --use-temp-db --pretty
```

The command reads configured governed labels without modifying them, rebuilds
the private source in disposable storage, and writes ignored aggregate reports
under `ml_baseline_reviews/`. It does not open the blind pack, serialize or
activate a model, create alerts, or change response authority. Treat private
assisted labels as weak evidence and the frozen candidate as shadow-only.

## v5.26 Native Blind Qualification

The full one-time qualification has already been consumed on the current
private evidence. Do not run it again. Use preflight only to verify that the
locks remain intact:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v526_native_blind_qualification `
  --sample-path "<private-panos-log>" `
  --use-temp-db `
  --preflight-only `
  --no-write `
  --pretty
```

The preflight returns aggregate eligibility only. It must not return the source
path, rows, IPs, identities, fingerprints, labels, or secrets.

The existing 40-row blind pack has zero genuine human decisions. Consequently,
its rule, anomaly, supervised, and hybrid queue rates are not accuracy metrics.
Do not calculate or present precision, recall, F1, false-positive rate,
calibration, or false-negative patterns until a qualified independent reviewer
completes the sealed decisions without seeing predictions.

After review, join decisions read-only to the already frozen private prediction
lock. Never rerun or tune against the consumed pack. Any repaired model must be
tested against a new preregistered blind corpus. Keep lifecycle
`shadow_observation`, rules alert-authoritative, and response automation and
real blocking disabled.

## v5.27 Independent Blind Review Intake

The evidence custodian keeps the sealed CSV immutable and creates a separate
ignored review copy with the v5.28 helper. Give the independent reviewer only
that working copy and `docs/detection/V5_27_BLIND_REVIEWER_GUIDE.md`. Never
provide the v5.26 prediction lock, per-row queue decisions, scores, or an
assisted pack.

After the human returns the completed working copy, run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v527_blind_review_evaluation --review-file ".\ml_baseline_reviews\v5_28_blind_human_review_working.csv" --pretty
```

The runner validates provenance, completeness, confirmation, token and lock
identity, blind-role integrity, and prediction exposure. It joins accepted
human decisions to existing frozen predictions without rerunning any detector.
It writes no labels or model artifacts. If support or class coverage is
insufficient, metrics remain withheld.

Never use the resulting blind errors for direct tuning. Any development-only
repair requires a new untouched blind pack before another final evaluation.

Run bounded real-record Gemini QA with:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v527_gemini_real_alert_quality --execute-provider --provider-interval-seconds 1 --pretty
```

This reads representative existing records, copies only bounded redacted
fields into disposable storage, excludes raw logs and IPs, verifies citations,
context, concision, fallback, latency/tokens, and authoritative immutability,
then removes the disposable database.

## v5.28 Deferred Human Review And Shadow Readiness

Prepare, resume, and inspect review progress only when a qualified human is
ready:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v528_blind_review_helper --prepare --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v528_blind_review_helper --interactive --reviewer "<institutional-id>" --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v528_blind_review_helper --status --pretty
```

The helper presents one structured row at a time, never displays detector or
AI suggestions, saves atomically, preserves protected evidence, keeps
`import_ready=false`, and never imports. Do not calculate or discuss blind
quality metrics from its progress output.

The label-independent readiness audit is safe while human review is deferred:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v528_supervised_readiness_audit --no-write --pretty
```

It checks the registered artifact, feature/calibration/schema contracts,
abstention, latency, drift, registry metadata, and zero-mutation state without
opening blind evidence or rerunning predictions. It cannot authorize model
activation or promotion.

## v5.29 Assistant Intent And Concision Validation

Run deterministic response-quality validation with:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.evaluate_assistant_qa --pretty
```

Expected result: 20/20 cases, 100% required citations, every intent-specific
word budget passed, raw-log context false, and no response/detection/model/
label/log/feedback side effect other than Assistant question audits.

When configured Gemini quota is available, run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v527_gemini_real_alert_quality --execute-provider --provider-interval-seconds 1 --pretty
```

Provider answers must retain the requested record and citation, stay within
the selected response contract, and never imply an executed action. An
unsupported record, missing requested coverage, lost primary citation,
secret-like content, or over-budget answer must fail closed to the concise
deterministic answer.

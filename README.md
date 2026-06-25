# MFU AI-Driven Log-Based Threat Detection and Response System

ATDR is a defensive senior-project lab prototype for AI-assisted firewall log monitoring. It imports Palo Alto firewall/syslog logs, preserves raw evidence, normalizes investigation fields, generates explainable SOC-style alerts, supports analyst review, and records simulated analyst-approved response actions with audit trails.

ATDR is lab-ready for controlled small-office validation. It is not certified production software, does not perform real firewall blocking, and does not trigger automatic response actions.

## Final Academic Checkpoint

- Readiness: `final_controlled_validation_candidate`
- Candidate: `independent_fpr_stabilized`
- Fresh blind validation: 700 rows, 7 sources, 16 scenarios
- Threat precision / recall / F1: `0.8906 / 0.9459 / 0.9174`
- Benign-like false-positive rate: `0.1303`
- Readiness v8: 22/22 checks
- Production promoted: false
- Model activated: false
- Response automation: disabled
- Real firewall blocking: disabled

This checkpoint validates controlled lab SOC triage behavior. It does not claim
production accuracy or deployment readiness.

## v3.0 Production-Readiness Track

The next track is real-source and lab-deployment hardening, not production approval. It adds:

- production-readiness gap assessment
- real-device/syslog pilot plan
- PostgreSQL lab validation plan
- observability and operations plan
- real-source ML monitoring plan
- conservative readiness gate v9
- v3.5 read-only real-source/syslog pilot checker and safe evidence export

Key docs:

- `docs/V3_0_PRODUCTION_READINESS_TRACK.md`
- `docs/V3_0_PRODUCTION_READINESS_GAP_ASSESSMENT.md`
- `docs/V3_0_REAL_DEVICE_SYSLOG_PILOT_PLAN.md`
- `docs/V3_0_POSTGRESQL_LAB_DEPLOYMENT_VALIDATION.md`
- `docs/V3_0_OBSERVABILITY_AND_OPERATIONS_PLAN.md`
- `docs/V3_0_REAL_SOURCE_ML_MONITORING_PLAN.md`
- `docs/V3_1_PERFORMANCE_STABILIZATION_PLAN.md`
- `docs/V3_1_POSTGRESQL_PERFORMANCE_VALIDATION_PLAN.md`
- `docs/V3_2_NO_HARDWARE_SOURCE_PILOT.md`
- `docs/V3_3_POSTGRESQL_SHARED_LAB_READINESS.md`
- `docs/V3_3_BACKUP_RESTORE_AND_RETENTION_PLAN.md`
- `docs/V3_3_DOCKER_POSTGRES_LAB_RUNBOOK.md`
- `docs/V3_4_SHARED_LAB_READINESS.md`
- `docs/V3_5_REAL_SOURCE_SYSLOG_PILOT.md`

Useful commands:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.production_readiness_doctor --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v30_real_source_pilot_validation --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.database_portability_audit --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_real_source_ml_monitoring --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v32_no_hardware_source_pilot --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v34_shared_lab_readiness --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_backup_restore_drill --dry-run --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.profile_dashboard_summary --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v35_real_source_pilot_check --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.export_real_source_pilot_evidence --pretty
```

These commands are non-destructive. They do not enable automatic response, real firewall blocking, model activation, or production promotion.

Final presentation material:

- `docs/PROGRESS_PRESENTATION_STATUS.md`
- `docs/PROGRESS_PRESENTATION_SCRIPT.md`
- `docs/PROGRESS_PRESENTATION_DEMO_FLOW.md`
- `docs/PROGRESS_PRESENTATION_REPO_TALKING_POINTS.md`
- `docs/FINAL_REPORT_OUTLINE.md`
- `docs/FINAL_REPORT_DRAFT.md`
- `docs/FINAL_PRESENTATION_SLIDE_CONTENT.md`
- `docs/FINAL_PRESENTATION_DESIGN_GUIDE.md`
- `docs/FINAL_SCREENSHOT_CAPTURE_PLAN.md`
- `docs/FINAL_REHEARSAL_CHECKLIST.md`
- `docs/FINAL_5_MINUTE_SCRIPT.md`
- `docs/FINAL_10_MINUTE_SCRIPT.md`
- `docs/FINAL_ONE_PAGE_SUMMARY.md`
- `docs/FINAL_SLIDE_ASSET_GUIDE.md`
- `docs/FINAL_DEMO_SCRIPT.md`
- `docs/FINAL_DEFENSE_QA.md`
- `docs/FINAL_EVIDENCE_CHECKLIST.md`
- `docs/SUPERVISOR_FINAL_STATUS_SUMMARY.md`
- `docs/FINAL_DEMO_RUNBOOK.md`
- `docs/FINAL_DEFENSE_TALKING_POINTS.md`
- `docs/FINAL_ACCEPTANCE_CHECKLIST.md`
- `docs/FINAL_SYSTEM_STATUS.md`
- `docs/FINAL_ENGINEERING_VALIDATION_SUMMARY.md`

## Current Lab Snapshot

- FastAPI backend with JWT auth, admin/analyst RBAC, SQLAlchemy/Alembic, and SQLite by default.
- Local account management supports username/password plus optional school-email fields, verified-email status, and email login for local users.
- React-first SOC dashboard with Overview, Alerts, Investigation / Log Explorer, AI Governance, Response & Audit, Threat Controls, Detection Tuning, User Admin, and Demo Controls.
- Palo Alto parser with raw evidence preservation, plus parser profiles for `palo_alto`, `generic_syslog`, and `raw_fallback`.
- Log source management with source health, source-level data quality, replay/syslog lab support, and source-scoped detection.
- Rule-based detection, alert deduplication, lightweight case grouping, ATT&CK-style mapping, and "Why flagged?" explanations.
- IsolationForest anomaly scoring and supervised ML decision support with AI Governance, labeling workflow, active learning, and model validation gates.
- Simulated response actions with confirmation, protected-IP safeguards, justification notes, and audit logs.
- External school-email IAM groundwork via disabled-by-default generic OIDC and MFU IAM/Google SSO adapter status. Local login remains the default; v3.14 adds disabled-by-default email verification/dev-outbox groundwork, and v3.15 improves account lifecycle/verification status UX. Real SMTP delivery, MFU IAM SDK login, Google callback login, and full school OIDC login remain future work.
- Supervisor-template IAM integration is tracked as controlled ATDR integration, not stack migration. See `docs/ATDR_TEMPLATE_MERGE_ANALYSIS.md` and `docs/security/ATDR_MFU_IAM_IMPLEMENTATION_PLAN.md`.
- SOC Assistant real-LLM provider adapters are documented in `docs/V3_63_REAL_LLM_ASSISTANT_ADAPTER.md` and `docs/security/ATDR_REAL_LLM_ASSISTANT_PLAN.md`; external LLM calls remain disabled by default.
- Safe synthetic scenario validation under `data/samples/scenarios/`.
- Release gate, performance smoke, onboarding docs, IAM/RBAC docs, PRD, traceability, and university workflow documentation.

## Safety And Scope

- Real or large firewall logs must stay outside Git, for example in `Downloads`, `data/private/`, or `real_logs/`.
- `.env`, DB files, model artifacts, generated CSVs/reports, `ml_baseline_reviews/`, and `demo_exports/` must not be committed.
- Response mode remains simulation unless a future approved connector is implemented.
- ML is analyst decision support only; weak-label metrics are not production accuracy.
- Docker/PostgreSQL is optional future/lab deployment work, not required for normal local testing.

## Quick Start

For a beginner-friendly Windows setup from a fresh clone or GitHub zip download, use:

- `docs/QUICKSTART_FOR_TEAM.md`

Minimum local flow:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\alembic.exe upgrade head
python -m atdr.scripts.seed_users
```

If your system uses `python` instead of the Windows launcher, replace `py -3.11` with `python`.

Default local demo users from `.env.example`:

```text
admin / admin123
analyst / analyst123
```

Replace demo secrets before shared lab or real deployment.

Environment templates:

- `.env.example` - normal local SQLite/demo setup.
- `.env.lab.example` - optional PostgreSQL/shared lab starting point.
- `.env.production.example` - future hardened deployment template, not a production guarantee.

If login fails with `Database unavailable` and logs mention host `postgres`, `.env` is using the optional Docker/PostgreSQL lab profile outside Docker. For normal local testing, switch back to SQLite:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.config_doctor --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.use_local_sqlite_config --dry-run --pretty
```

## Start The Backend

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

## Start The React Dashboard

Install Node.js 20.x LTS or newer. Node 16 may fail with the current Vite, ESLint, and Playwright toolchain.

```powershell
cd frontend
Copy-Item .env.example .env
npm.cmd install
npm.cmd run dev
```

Open:

```text
http://127.0.0.1:5173
```

Optional projector cleanup mode:

```powershell
$env:VITE_ATDR_PRESENTATION_MODE="true"
npm.cmd run dev
```

FastAPI must be running at:

```text
http://127.0.0.1:8000
```

Streamlit remains available only as legacy/demo continuity. React is the priority dashboard path. See `docs/DASHBOARD_PRODUCTION_PATH.md` for the historical dashboard migration context.

## Import Or Replay Logs

Keep private logs outside Git and pass an absolute path when importing real data:

```powershell
python -m atdr.scripts.import_logs "C:\Users\User\Downloads\paloalto-firewall.log" --limit 5000
```

Run detection:

```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:8000/api/detection/run?limit=5000&use_ml=false"
```

Safe replay dry-run:

```powershell
python -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty
```

Register a lab source and replay as that source:

```powershell
python -m atdr.scripts.register_log_source --name lab-firewall-1 --source-type firewall --parser-profile palo_alto --host 192.0.2.10 --port 514 --pretty
python -m atdr.scripts.replay_logs --send-to direct --source-name lab-firewall-1 --source-type firewall --source-host 192.0.2.10 --source-port 514 --limit 100 --rate 1 --pretty
```

## Controlled Threat Detection Validation

Synthetic scenario files live under `data/samples/scenarios/`. They validate normal traffic, negative controls, mixed small-subnet traffic, scanning-like traffic, brute-force-like service attempts, C2/beaconing-like activity, data exfiltration suspicion, connection flood behavior, deduplication, parser fallback, and policy/suspicious-app behavior without using private logs or offensive tooling.

Run the full v0.7 validation suite safely against a temporary database:

```powershell
python -m atdr.scripts.run_detection_validation_suite --all --pretty
```

The suite writes ignored JSON/Markdown reports plus a risk-calibration report under `demo_exports/detection_validation/`. The React Overview page shows a compact latest validation summary, but generated reports should not be committed.

Run the v0.8 generalization suite to generate safe synthetic variants and check for false positives/false negatives without touching the current database:

```powershell
python -m atdr.scripts.run_detection_generalization_suite --all --variants 5 --pretty
```

Generalization reports are written under ignored `demo_exports/detection_generalization/`, and generated variants are written under ignored `demo_exports/detection_variants/`.

Run the v0.9 layered detection validation suite to compare rules, anomaly scoring, supervised SOC triage, and hybrid scoring:

```powershell
python -m atdr.scripts.run_layered_detection_validation --all --variants 3 --pretty
```

Layered reports are written under ignored `demo_exports/layered_detection/`.

Run the v1.0 end-to-end workflow validation suite to prove safe ingestion, parsing, source health, detection, alert explanation, investigation evidence, optional simulated response checks, audit trail, and report generation:

```powershell
python -m atdr.scripts.run_e2e_workflow_validation --pretty
python -m atdr.scripts.run_e2e_workflow_validation --scenario port_scan_like_traffic --simulate-response --pretty
```

End-to-end reports are written under ignored `demo_exports/e2e_validation/`. The default mode uses a temporary database and does not modify current dashboard data.

Run the v1.1 detection reliability baseline to aggregate scenario validation, generalization, layered detection, E2E workflow, false-positive/false-negative counts, risk/severity distribution, and detection layer contribution:

```powershell
python -m atdr.scripts.run_detection_reliability_baseline --pretty
```

v1.1 reliability, benchmark, error-analysis, calibration, drift, ML reliability, and stress reports are written under ignored `demo_exports/detection_reliability/`.

For larger benchmark-style CSVs, v1.2 adds sanitized benchmark snapshot preparation, multi-mode detection benchmarking, benchmark ML experiments, layered rule/ML/hybrid comparison, and readiness gate v2:

```powershell
python -m atdr.scripts.prepare_benchmark_dataset --input-csv C:\path\to\benchmark.csv --mapping-config data\samples\benchmarks\example_firewall_mapping.json --label-config data\samples\benchmarks\example_label_mapping.json --limit 5000 --pretty
python -m atdr.scripts.run_detection_benchmark --prepared-snapshot demo_exports\benchmarks\benchmark_snapshot_<id>.json --detection-mode hybrid --pretty
python -m atdr.scripts.run_benchmark_ml_experiment --prepared-snapshot demo_exports\benchmarks\benchmark_snapshot_<id>.json --split time --test-size 0.3 --pretty
```

v1.2 reports are ignored under `demo_exports/benchmarks/` and `ml_baseline_reviews/benchmark_ml_experiments/`. Benchmark metrics stay separate from local firewall-log metrics and are not production accuracy.

Run the safe v1.5 internal AI-readiness benchmark:

```powershell
python -m atdr.scripts.build_internal_ai_readiness_benchmark --dry-run --pretty
python -m atdr.scripts.run_v15_ai_readiness_validation --pretty
```

The 240-row benchmark is generated from a small committed manifest. Generated data and reports remain ignored. A `benchmark_validated_candidate` result strengthens analyst-review evidence only; it does not activate or production-promote a model.

Run the v1.6 fixed unseen-holdout transfer check:

```powershell
python -m atdr.scripts.build_fixed_unseen_holdout --dry-run --pretty
python -m atdr.scripts.run_external_benchmark_validation --holdout-from-current-data --pretty
```

The 320-row holdout uses separate synthetic sources and scenarios. The original
v1.6 transfer result exposed a meaningful internal-to-unseen generalization
gap; v1.8 now reports the reviewed benchmark candidate separately. No model or
response action is activated.

Run the v1.7 external generalization improvement pass:

```powershell
python -m atdr.scripts.run_v17_external_generalization --review-limit 300 --pretty
```

v1.7 compares external profiles, reduces noisy benign false positives, exports a boundary review sample, and keeps readiness conservative. No model is activated and no response action is automated.

Reviewed v1.7 benchmark files use `benchmark_row_id`, not database log IDs. Import them through the dedicated workflow:

```powershell
python -m atdr.scripts.import_benchmark_review_csv --input-csv "C:\path\to\v1_7_external_boundary_review_sample_REVIEWED.csv" --benchmark-kind external_holdout --pretty
```

See `docs/V1_7B_BENCHMARK_REVIEW_IMPORT.md`.

Run the v1.8 external benchmark finalization and confidence calibration pass:

```powershell
python -m atdr.scripts.run_v18_external_benchmark_finalization --pretty
```

v1.8 uses behavior-window evidence and out-of-fold confidence calibration to
evaluate an external benchmark candidate. Passing the benchmark gate does not
activate or production-promote a model, and response automation stays disabled.

Run the v1.9 independent and controlled-source validation:

```powershell
python -m atdr.scripts.build_independent_holdout --pretty
python -m atdr.scripts.run_controlled_real_source_validation --pretty
python -m atdr.scripts.run_v19_independent_revalidation --pretty
```

v1.9 keeps the external benchmark, new independent holdout, and controlled
source evidence separate. Current readiness remains decision support only:
production promotion, model activation, automatic response, and real firewall
blocking are disabled.

Run the v1.9b identity-independent FPR stabilization comparison:

```powershell
python -m atdr.scripts.run_v19b_independent_fpr_stabilization --pretty
```

v1.9b routes unresolved allowed high-port services to analyst review only when
they lack rule and behavior-window threat evidence. The current candidate
passes readiness v7b, but it remains decision support and requires confirmation
on a fresh future holdout.

Run the v2.0 frozen-candidate blind and final controlled validation:

```powershell
python -m atdr.scripts.lock_v20_candidate --pretty
python -m atdr.scripts.build_fresh_blind_holdout --pretty
python -m atdr.scripts.run_v20_fresh_blind_revalidation --pretty
python -m atdr.scripts.run_final_controlled_source_acceptance --pretty
```

The 700-row fresh blind holdout passes without threshold tuning. Readiness v8
reports `final_controlled_validation_candidate`. This is controlled
decision-support evidence, not production promotion or deployment approval.

Run a scenario against a temporary database:

```powershell
python -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --use-temp-db --run-detection --pretty
```

Run a scenario into the current dashboard intentionally:

```powershell
python -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name scenario-lab-firewall-1 --run-detection --pretty
```

Validate a controlled replay source and export advisor-friendly JSON/Markdown reports:

```powershell
python -m atdr.scripts.validate_live_source --source-name scenario-lab-firewall-1 --source-type firewall --parser-profile palo_alto --duration 0 --run-detection --pretty
python -m atdr.scripts.export_lab_validation_report --source-name scenario-lab-firewall-1 --format both --pretty
```

Real firewall/router hardware validation remains future work. ATDR is intended for controlled small-subnet/lab-scale validation, not production certification.

## ML And AI Governance

ATDR combines:

- rule-based detection as the primary explainable signal
- IsolationForest anomaly scoring as assistive unsupervised ML
- supervised classifier output trained from reviewed/assisted labels
- hybrid risk scoring for analyst triage

The frozen candidate is a Final Controlled Validation Candidate for SOC triage decision support. It is Not Production Promoted, and Response Automation remains disabled regardless of model output.

Useful commands:

```powershell
python -m atdr.scripts.generate_assisted_labels --dry-run --limit 1000 --pretty
python -m atdr.scripts.export_active_learning_review_sample --limit 200
python -m atdr.scripts.train_supervised_model --split time --test-size 0.3 --min-samples 6
```

See `docs/AI_TRAINING_RUNBOOK.md` and `docs/ML_BASELINE_TUNING.md`.

## Verification

Backend:

```powershell
.\.venv\Scripts\python.exe -m compileall -q atdr migrations
.\.venv\Scripts\python.exe -m pytest atdr\tests -q
.\.venv\Scripts\alembic.exe check
```

Frontend:

```powershell
cd frontend
npm.cmd run lint
npm.cmd run build
npm.cmd run test:e2e
```

Release checks:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release
```

Equivalent release-gate command from an activated virtual environment:

```powershell
python -m atdr.scripts.verify_release
```

Optional browser smoke flag for legacy Python-driven dashboard smoke checks:

```powershell
$env:ATDR_RUN_PLAYWRIGHT="1"
```

## Documentation Map

Start here:

- `docs/QUICKSTART_FOR_TEAM.md` - Windows setup for teammates using clone or zip download.
- `docs/LAB_RUNBOOK.md` - lab operations, replay, syslog, source validation, and troubleshooting.
- `docs/FINAL_REPORT_OUTLINE.md` - complete ATDR-specific senior-project report structure.
- `docs/FINAL_REPORT_DRAFT.md` - academic draft covering architecture, detection, validation, limitations, and conclusion.
- `docs/FINAL_PRESENTATION_SLIDE_CONTENT.md` - slide-by-slide final defense content, visuals, and speaker notes.
- `docs/FINAL_PRESENTATION_DESIGN_GUIDE.md` - PowerPoint visual system, slide layouts, screenshot placement, and final QA.
- `docs/FINAL_SCREENSHOT_CAPTURE_PLAN.md` - slide-mapped, privacy-safe evidence capture instructions.
- `docs/FINAL_REHEARSAL_CHECKLIST.md` - presentation-day setup, timing, recovery, and cleanup checklist.
- `docs/FINAL_5_MINUTE_SCRIPT.md` - concise academic defense script.
- `docs/FINAL_10_MINUTE_SCRIPT.md` - expanded academic defense script.
- `docs/FINAL_ONE_PAGE_SUMMARY.md` - committee-ready project overview and final status.
- `docs/FINAL_SLIDE_ASSET_GUIDE.md` - recommended diagrams, screenshots, metrics, and local asset organization.
- `docs/FINAL_DEMO_SCRIPT.md` - exact commands, clicks, expected results, and spoken demonstration sequence.
- `docs/FINAL_DEFENSE_QA.md` - likely committee questions with concise, defensible answers.
- `docs/FINAL_EVIDENCE_CHECKLIST.md` - screenshot, metric, safety, verification, and submission evidence checklist.
- `docs/SUPERVISOR_FINAL_STATUS_SUMMARY.md` - concise final academic status for supervisor review.
- `docs/FINAL_DEMO_RUNBOOK.md` - final dashboard demonstration sequence and safe scenario.
- `docs/FINAL_DEFENSE_TALKING_POINTS.md` - academic defense narrative, architecture, metrics, safety, and limitations.
- `docs/FINAL_ACCEPTANCE_CHECKLIST.md` - final manual and automated sign-off checklist.
- `docs/FINAL_SYSTEM_STATUS.md` - concise v2.0 capability, metrics, safety, and future-work status.
- `docs/V0_6_THREAT_DETECTION_VALIDATION.md` - active controlled threat detection validation plan.
- `docs/V0_8_DETECTION_GENERALIZATION.md` - synthetic variant validation and anti-overfitting checks.
- `docs/V0_9_LAYERED_DETECTION_VALIDATION.md` - layered rules/anomaly/ML/hybrid contribution validation.
- `docs/V1_0_E2E_WORKFLOW_VALIDATION.md` - controlled ingestion-to-investigation workflow validation with optional simulated response/audit checks.
- `docs/V1_1_DETECTION_RELIABILITY_AND_BENCHMARKING.md` - reliability baselines, generic benchmark adapter, error analysis, risk calibration, drift, ML reliability, and stress testing.
- `docs/V1_2_REALISTIC_BENCHMARK_AND_ML_STRENGTHENING.md` - sanitized benchmark snapshots, benchmark detection/ML experiments, layered comparison, and readiness gate v2.
- `docs/V1_3_LARGER_LABELED_DATA_AND_AI_TRAINING.md` - reviewed-label audit, class targets, larger review samples, candidate training, error analysis, and readiness gate v3.
- `docs/V1_4_FALSE_POSITIVE_REDUCTION_AND_CONFIDENCE_CALIBRATION.md` - low-noise SOC queue experiments, hard-gated thresholds, confidence calibration, and targeted false-positive review.
- `docs/V1_4B_FALSE_POSITIVE_MITIGATION.md` - actionable review sampling and evidence-aware normal QUIC/443 false-positive mitigation.
- `docs/V1_4C_MALICIOUS_RECALL_RECOVERY_AND_CALIBRATION.md` - malicious-recall boundary analysis, low-noise recovery profiles, and held-out confidence calibration.
- `docs/V1_5_AI_READINESS_BENCHMARK_VALIDATION.md` - safe internal benchmark generation, layered/ML comparison, readiness gate v4, and final decision-support status.
- `docs/V1_6_EXTERNAL_BENCHMARK_VALIDATION.md` - unseen holdout transfer metrics, calibration, overfitting analysis, and readiness gate v5.
- `docs/V1_7_EXTERNAL_GENERALIZATION_IMPROVEMENT.md` - external boundary profiles, error analysis, calibration, and review sampling.
- `docs/V1_7B_BENCHMARK_REVIEW_IMPORT.md` - dedicated `benchmark_row_id` review import kept separate from `ml_labels`.
- `docs/V1_8_EXTERNAL_BENCHMARK_FINALIZATION.md` - external miss recovery, fixed profile comparison, out-of-fold calibration, and readiness v6.
- `docs/V1_9_INDEPENDENT_REVALIDATION_AND_REAL_SOURCE_VALIDATION.md` - new independent holdout, controlled source workflow, and readiness v7.
- `docs/V1_9B_INDEPENDENT_FPR_STABILIZATION.md` - identity-independent benign-boundary stabilization, profile comparison, and readiness v7b.
- `docs/FINAL_ENGINEERING_VALIDATION_SUMMARY.md` - v0.7-v2.0 evidence chain, fresh blind metrics, final controlled acceptance, safety posture, and remaining production work.
- `docs/V0_5_SIMULATION_DEMO_PLAN.md` - earlier controlled replay validation plan.
- `docs/V0_5_REAL_SOURCE_VALIDATION_PLAN.md` - future controlled hardware source validation plan.
- `docs/V0_3_RELEASE_CANDIDATE.md` - current release-candidate summary.
- `docs/V0_4_STATUS.md` - current dashboard/IAM/performance checkpoint.
- `docs/V0_3_STATUS.md` - detailed current v0.3 status.
- `docs/V0_3_PLAN.md` - v0.3 source-management and scenario-validation plan.
- `docs/V3_6_BACKGROUND_JOB_HARDENING.md` - operation job tracking and long-running operation visibility.
- `docs/V3_7_OPERATION_RETENTION_AND_JOB_RECOVERY.md` - stale job recovery and retention maintenance.
- `docs/V3_8_ANALYST_ASSISTANT_MVP.md` - read-only SOC Assistant MVP with external LLM disabled by default.
- `docs/V3_9_ASSISTANT_HARDENING.md` - assistant presets, audit-backed history, citations, and safe deterministic intents.
- `docs/V3_10_CONFIG_SAFETY_HARDENING.md` - local/shared-lab configuration safety and database diagnostics.
- `docs/V3_11_DETECTION_EXPLAINABILITY_HARDENING.md` - log-level triage explanations and validation checks.
- `docs/V3_12_DETECTION_RULE_QUALITY.md` - detection rule quality and alert-noise reduction.
- `docs/V3_13_SOC_ASSISTANT_ALERT_EXPLAINER.md` - alert explainer handoff for the read-only SOC Assistant.
- `docs/V3_14_EMAIL_VERIFICATION_AND_ACCOUNT_NOTIFICATIONS.md` - disabled-by-default local email verification and admin dev-outbox foundation.
- `docs/V3_15_ACCOUNT_LIFECYCLE_AND_EMAIL_VERIFICATION_UX.md` - account lifecycle and email verification status UX hardening.
- `docs/V3_63_REAL_LLM_ASSISTANT_ADAPTER.md` - disabled-by-default real LLM provider adapter with deterministic fallback and read-only safety.

Governance and university workflow:

- `docs/AI-DOCS-INDEX.md` - active ATDR documentation index and reference-only NewSystem boundary.
- `docs/ATDR_AI_WORKFLOW.md` - no-guessing, source-evidence, testing, PRD-update, safety, and handoff workflow.
- `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md` - how ATDR adapts the university NewSystem template without copying Node/Vue/Mongo implementation.
- `docs/ATDR_TEMPLATE_MANIFEST.json` - ATDR-specific template manifest with env keys, permission paths, validation commands, and safety constraints.
- `docs/prd/PRD-ATDR.md` - real ATDR PRD.
- `docs/tasks/README.md` - ATDR tasklist/progress-board rules.
- `docs/tasks/tasklist-progress.md` - canonical editable system progress board.
- `docs/tasks/tasklist-progress.html` - generated progress board view.
- `docs/security/ATDR_IAM_RBAC_MATRIX.md` - admin/analyst permission matrix and IAM limitations.
- `docs/security/ATDR_EXTERNAL_IAM_PLAN.md` - disabled-by-default OIDC groundwork for future school-email login.
- `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md` - safe MFU IAM / Google SSO adapter plan based on supervisor template guidance.
- `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md` - provider questions needed before real external IAM work.
- `docs/security/ATDR_PERMISSION_PATHS.md` - NewSystem-style ATDR permission path registry.
- `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md` - lab security review baseline and remaining hardening gaps.
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md` - source-backed mapping from requirements to code, tests, docs, and gaps.
- `docs/agents/ATDR_AGENT_OPERATING_MODEL.md` - ATDR agent roles and handoff responsibilities.
- `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` - ATDR change document template.
- `docs/changes/T1_T20_IAM_RBAC_COMPLIANCE.md` - completed change-document example.

Other useful docs:

- `docs/ACCEPTANCE_TEST_CHECKLIST.md`
- `docs/ARCHITECTURE.md`
- `docs/DEMO_DAY_RUNBOOK.md`
- `docs/DASHBOARD_PRODUCTION_PATH.md`
- `docs/ENVIRONMENT_GUIDE.md`
- `docs/DEPLOYMENT_GUIDE.md`
- `docs/OPERATIONS_RUNBOOK.md`
- `docs/LIMITATIONS_AND_FUTURE_WORK.md`

## Project Layout

```text
atdr/
  app/
    main.py
    core/
    db/
    parsers/
    detection/
    ml/
    routers/
    services/
    schemas/
  dashboard/        legacy Streamlit continuity
  scripts/
  tests/
data/samples/       safe synthetic/demo samples only
frontend/           React SOC dashboard
migrations/         Alembic migrations
docs/               runbooks, PRD, governance, status, release docs
```

## Current Limitations

- Real firewall blocking is not implemented.
- Automatic response is not enabled.
- Real router/firewall syslog forwarding still needs controlled lab validation.
- SQLite is convenient for local use; PostgreSQL is recommended later for shared/larger lab deployment.
- Supervised ML still needs more reviewed labels and live validation before stronger claims.
- Case grouping is lightweight and not a full incident-management/ticketing platform.

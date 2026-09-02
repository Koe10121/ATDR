# PRD: MFU ATDR

| Field | Value |
| --- | --- |
| Product | MFU AI-Driven Log-Based Threat Detection and Response System |
| Short name | ATDR |
| Current stage | v5.49b governed supervised revalidation published; v5.50 current-state truth lock in progress; external field/IAM/provider/deployment gates remain open |
| Production claim | None. ATDR is not certified production software. |
| Main workflow doc | `docs/ATDR_AI_WORKFLOW.md` |
| Agent model | `docs/agents/ATDR_AGENT_OPERATING_MODEL.md` |
| Change template | `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` |
| Docs index | `docs/AI-DOCS-INDEX.md` |
| Progress board | `docs/tasks/tasklist-progress.md`, `docs/tasks/tasklist-progress.html` |
| Current runbook | `docs/LAB_RUNBOOK.md` |

## Source Evidence

| Evidence | Repository Source |
| --- | --- |
| Product summary, startup commands, API highlights, CLI workflow | `README.md` |
| FastAPI app and mounted routers | `atdr/app/main.py` |
| Database entities and indexes | `atdr/app/db/models.py` |
| Backend routes | `atdr/app/routers/*.py` |
| React route/page truth | `frontend/src/App.tsx`, `frontend/src/pages/*` |
| Frontend scripts and dependencies | `frontend/package.json` |
| AI feature generation | `atdr/app/ml/features.py` |
| Detection and explanation services | `atdr/app/detection/*`, `atdr/app/services/detection_service.py` |
| Release gate | `atdr/scripts/verify_release.py` |
| Current status | `docs/FINAL_SYSTEM_STATUS.md` |
| Current source-backed state | `docs/CURRENT_SYSTEM_STATE_LOCK.md` |
| Current AI/ML product status | `docs/CURRENT_AI_ML_PRODUCT_STATUS.md` |
| Lab operations | `docs/LAB_RUNBOOK.md` |
| AI workflow | `docs/AI_TRAINING_RUNBOOK.md`, `docs/ML_BASELINE_TUNING.md` |
| IAM/RBAC permission matrix | `docs/security/ATDR_IAM_RBAC_MATRIX.md` |
| External IAM groundwork | `docs/security/ATDR_EXTERNAL_IAM_PLAN.md` |
| MFU IAM adapter plan | `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md`, `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md` |
| NewSystem template alignment and permission path registry | `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md`, `docs/ATDR_TEMPLATE_MANIFEST.json`, `docs/security/ATDR_PERMISSION_PATHS.md` |
| Tasklist/progress-board process | `docs/tasks/README.md`, `docs/tasks/tasklist-progress.md`, `docs/tasks/tasklist-progress.html`, `scripts/render-tasklist-progress-html.js`, `scripts/check-tasklist-progress-standard.js` |
| Requirement traceability | `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |
| v3.4 shared-lab readiness foundation | `docs/V3_4_SHARED_LAB_READINESS.md`, `atdr/scripts/run_v34_shared_lab_readiness.py`, `atdr/scripts/run_backup_restore_drill.py`, `atdr/scripts/profile_dashboard_summary.py` |
| v3.89 shared-lab persistence | `docs/V3_89_SHARED_LAB_PERSISTENCE_AND_BACKUP_RESTORE.md`, `atdr/app/services/persistence_service.py`, `atdr/scripts/backup_database.py`, `atdr/scripts/restore_database.py`, `atdr/scripts/validate_persistence_profile.py` |
| v3.93 resumable large-file ingestion | `docs/V3_93_RESUMABLE_LARGE_FILE_INGESTION.md`, `atdr/app/services/resumable_ingestion_service.py`, `atdr/app/services/staging_service.py`, `atdr/app/services/staged_input_retention_service.py`, `atdr/tests/test_v393_resumable_ingestion.py` |
| v3.97 large-file reliability validation | `docs/V3_97_LARGE_FILE_INGESTION_RELIABILITY.md`, `atdr/scripts/validate_large_ingestion.py`, `migrations/versions/b4c5d6e7f8a9_add_raw_log_content_fingerprint.py`, `atdr/tests/test_v397_large_ingestion.py` |
| v3.98 independent holdout validation | `docs/V3_98_INDEPENDENT_DETECTION_ML_HOLDOUT_VALIDATION.md`, `atdr/app/detection/v398_independent_holdout_validation.py`, `atdr/scripts/run_v398_independent_holdout_validation.py`, `atdr/tests/test_v398_independent_holdout_validation.py` |
| v3.99 multi-source frozen revalidation | `docs/V3_99_INDEPENDENT_MULTI_SOURCE_EVIDENCE_AND_FROZEN_REVALIDATION.md`, `atdr/app/detection/v399_multisource_frozen_revalidation.py`, `atdr/scripts/run_v399_multisource_frozen_revalidation.py`, `atdr/tests/test_v399_multisource_frozen_revalidation.py` |
| v3.5 source/syslog pilot readiness | `docs/V3_5_REAL_SOURCE_SYSLOG_PILOT.md`, `atdr/scripts/run_v35_real_source_pilot_check.py`, `atdr/scripts/export_real_source_pilot_evidence.py` |
| v3.6 background job hardening | `docs/V3_6_BACKGROUND_JOB_HARDENING.md`, `atdr/app/routers/jobs.py`, `atdr/app/services/job_service.py`, `atdr/tests/test_operation_jobs.py` |
| v3.7 operation retention and recovery | `docs/V3_7_OPERATION_RETENTION_AND_JOB_RECOVERY.md`, `atdr/scripts/maintenance_jobs.py`, `atdr/app/routers/jobs.py`, `atdr/app/services/job_service.py` |
| v3.8 analyst assistant MVP | `docs/V3_8_ANALYST_ASSISTANT_MVP.md`, `atdr/app/routers/assistant.py`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx` |
| v3.9 analyst assistant hardening | `docs/V3_9_ASSISTANT_HARDENING.md`, `docs/changes/T1_T20_V3_9_ASSISTANT_HARDENING.md`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` |
| v3.10 config safety hardening | `docs/V3_10_CONFIG_SAFETY_HARDENING.md`, `atdr/scripts/config_doctor.py`, `atdr/scripts/check_dev_environment.py`, `atdr/scripts/use_local_sqlite_config.py` |
| v3.13 SOC assistant alert explainer | `docs/V3_13_SOC_ASSISTANT_ALERT_EXPLAINER.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `frontend/src/pages/AlertsTriage.tsx` |
| v3.14 email verification foundation | `docs/V3_14_EMAIL_VERIFICATION_AND_ACCOUNT_NOTIFICATIONS.md`, `atdr/app/services/account_verification_service.py`, `atdr/app/services/email_service.py`, `frontend/src/pages/UserAdmin.tsx` |
| v3.15 account lifecycle UX | `docs/V3_15_ACCOUNT_LIFECYCLE_AND_EMAIL_VERIFICATION_UX.md`, `docs/changes/T1_T20_V3_15_ACCOUNT_LIFECYCLE_AND_EMAIL_VERIFICATION_UX.md`, `frontend/src/components/AppShell.tsx`, `frontend/src/pages/UserAdmin.tsx` |
| MFU IAM adapter planning | `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md`, `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md`, `atdr/app/routers/auth.py` |
| MFU IAM outer-shell secure handoff | `docs/V3_91_MFU_OUTER_SHELL_SECURE_HANDOFF.md`, `docs/security/ATDR_MFU_IAM_PREPROD_VALIDATION.md`, `atdr/app/routers/auth.py`, `atdr/app/services/mfu_iam_service.py` |
| Real LLM assistant adapter and probe | `docs/V3_63_REAL_LLM_ASSISTANT_ADAPTER.md`, `docs/security/ATDR_REAL_LLM_ASSISTANT_PLAN.md`, `docs/V3_65_MFU_IAM_AND_REAL_ASSISTANT_HARNESS.md`, `atdr/app/routers/assistant.py`, `atdr/app/services/assistant_service.py`, `atdr/app/services/assistant_llm.py`, `atdr/scripts/test_assistant_llm_provider.py` |
| v3.17 parser/detection explainability | `docs/V3_17_PARSER_DETECTION_EXPLAINABILITY_HARDENING.md`, `atdr/scripts/validate_parser_normalization.py`, `atdr/scripts/validate_detection_quality.py`, `atdr/app/detection/explanations.py` |
| v3.18 detection corpus and FP/FN QA | `docs/V3_18_DETECTION_CORPUS_AND_FP_FN_QA.md`, `data/samples/scenarios/scenario_expectations.json`, `atdr/tests/test_v318_detection_corpus.py` |
| v3.19 no-hardware soak and parser drift | `docs/V3_19_NO_HARDWARE_SOAK_AND_PARSER_DRIFT.md`, `atdr/scripts/run_no_hardware_soak.py`, `atdr/tests/test_v319_no_hardware_soak.py` |
| v3.21 SOC Assistant demo-quality upgrade | `docs/V3_21_SOC_ASSISTANT_DEMO_QUALITY.md`, `docs/changes/T1_T20_V3_21_SOC_ASSISTANT_DEMO_QUALITY.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` |
| v3.22 SOC Assistant evidence-grounded demo QA | `docs/V3_22_SOC_ASSISTANT_EVIDENCE_GROUNDED_DEMO_QA.md`, `docs/V3_22_ASSISTANT_DEMO_QUESTION_SET.md`, `docs/changes/T1_T20_V3_22_SOC_ASSISTANT_EVIDENCE_GROUNDED_DEMO_QA.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` |
| v3.23 Assistant context linking | `docs/V3_23_ASSISTANT_CONTEXT_LINKING.md`, `docs/changes/T1_T20_V3_23_ASSISTANT_CONTEXT_LINKING.md`, `frontend/src/pages/AssistantPage.tsx`, `frontend/src/pages/ExecutiveOverview.tsx`, `frontend/src/pages/MLGovernance.tsx`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` |
| v3.24 Assistant investigation context | `docs/V3_24_SOC_ASSISTANT_INVESTIGATION_CONTEXT.md`, `docs/changes/T1_T20_V3_24_SOC_ASSISTANT_INVESTIGATION_CONTEXT.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `frontend/src/pages/AlertsTriage.tsx`, `frontend/src/pages/LogExplorer.tsx`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` |
| v3.25 Assistant investigation brief builder | `docs/V3_25_SOC_ASSISTANT_INVESTIGATION_BRIEF_BUILDER.md`, `docs/changes/T1_T20_V3_25_SOC_ASSISTANT_INVESTIGATION_BRIEF_BUILDER.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` |
| v3.26 Assistant evaluation and end-to-end investigation QA | `docs/V3_26_ASSISTANT_QA_QUESTION_SET.md`, `docs/V3_26_SOC_ASSISTANT_EVALUATION_AND_INVESTIGATION_QA.md`, `docs/changes/T1_T20_V3_26_SOC_ASSISTANT_EVALUATION_AND_INVESTIGATION_QA.md`, `atdr/scripts/evaluate_assistant_qa.py`, `atdr/tests/test_assistant_qa_evaluator.py` |
| v3.27 Assistant feedback and answer quality review | `docs/V3_27_ASSISTANT_FEEDBACK_AND_ANSWER_QUALITY.md`, `docs/changes/T1_T20_V3_27_ASSISTANT_FEEDBACK_AND_ANSWER_QUALITY.md`, `atdr/app/routers/assistant.py`, `atdr/app/services/assistant_service.py`, `migrations/versions/d4e5f6a7b8c9_add_assistant_feedback.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py` |
| v3.28 Assistant feedback review dashboard and quality triage | `docs/V3_28_ASSISTANT_FEEDBACK_REVIEW.md`, `docs/changes/T1_T20_V3_28_ASSISTANT_FEEDBACK_REVIEW.md`, `atdr/app/services/assistant_service.py`, `atdr/app/routers/assistant.py`, `frontend/src/pages/AssistantPage.tsx`, `frontend/tests/smoke.spec.ts` |
| v3.29 SOC Assistant reasoning and triage quality | `docs/V3_29_SOC_ASSISTANT_REASONING_AND_TRIAGE_QUALITY.md`, `docs/changes/T1_T20_V3_29_SOC_ASSISTANT_REASONING_AND_TRIAGE_QUALITY.md`, `atdr/app/services/assistant_service.py`, `atdr/scripts/evaluate_assistant_qa.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py` |
| v3.30 Detection and ML quality revalidation | `docs/V3_30_DETECTION_ML_QUALITY_REVALIDATION.md`, `docs/changes/T1_T20_V3_30_DETECTION_ML_QUALITY_REVALIDATION.md`, `atdr/app/detection/v330_detection_ml_quality.py`, `atdr/scripts/run_v330_detection_ml_quality_revalidation.py`, `frontend/src/pages/MLGovernance.tsx`, `atdr/tests/test_v330_detection_ml_quality.py` |

## Product Overview

ATDR is a defensive cybersecurity monitoring platform for controlled
small-office or university lab validation. It ingests firewall/syslog logs,
preserves raw evidence, normalizes fields, runs explainable rule-based
detection, adds advisory anomaly and supervised scoring, groups alerts,
supports analyst investigation, and records simulated analyst-approved
response actions in audit logs.

ATDR does not currently perform real firewall blocking. It does not claim production readiness or production ML accuracy.

## System Purpose

ATDR exists to demonstrate and validate:

- Realistic firewall log ingestion and parsing.
- Raw evidence preservation for every investigation.
- Explainable alert generation.
- AI-assisted but analyst-controlled triage.
- Source health and parser profile visibility.
- Safe response simulation with audit trail.
- Lab-ready workflow with SQLite local operation, PostgreSQL compatibility and
  CI/scale qualification, plus explicit external gates for approved shared
  deployment and real-device syslog forwarding.

## Users And Roles

| Role | Purpose | Current Evidence |
| --- | --- | --- |
| Admin | Configure users, school-email account metadata, demo controls, source management, threat controls, response simulation actions | `atdr/app/routers/users.py`, `atdr/app/routers/demo.py`, `atdr/app/routers/response.py` |
| Analyst | Investigate alerts/logs, update alert status, review evidence, label logs, view audit and ML governance | `atdr/app/routers/alerts.py`, `atdr/app/routers/logs.py`, `atdr/app/routers/ml.py` |
| Supervisor/advisor | Review dashboard, evidence, runbooks, acceptance status, and lab-readiness claims | `docs/V0_3_STATUS.md`, `docs/ACCEPTANCE_TEST_CHECKLIST.md` |

The current role and permission matrix is documented in `docs/security/ATDR_IAM_RBAC_MATRIX.md`. Local accounts support optional school-email fields, email login, and disabled-by-default email verification/dev-outbox groundwork. v3.91 adds an optional MFU outer-shell secure handoff: a single-use code is exchanged server-to-server, external users default to analyst, and admin requires approved IAM group mapping. ATDR does not currently include a viewer/read-only role, real SMTP delivery, password reset email, direct ATDR-owned Google/MFU OAuth callback flow, or validated external IAM lifecycle synchronization.

## Current Capabilities

### Ingestion And Parsing

- Import log files through scripts and API.
- Replay logs to simulate near-real-time ingestion.
- Receive local UDP syslog in lab mode.
- Track log sources and source health.
- Support parser profiles: `palo_alto`, `generic_syslog`, `raw_fallback`.
- Preserve raw evidence even when parsing fails.

Evidence: `atdr/app/routers/logs.py`, `atdr/app/routers/sources.py`, `atdr/scripts/replay_logs.py`, `atdr/scripts/run_syslog_receiver.py`, `atdr/scripts/run_source_scenario.py`, `atdr/app/db/models.py`.

### Detection And Cases

- Rule-first detection.
- IsolationForest anomaly scoring.
- Supervised ML decision-support classifier.
- Hybrid risk scoring.
- Alert deduplication and occurrence counting.
- Case grouping for related alert patterns.
- ATT&CK-style mapping and "Why flagged?" explanations.

Evidence: `atdr/app/services/detection_service.py`, `atdr/app/detection/*`, `atdr/app/services/case_service.py`, `atdr/app/routers/alerts.py`.

### AI Governance

- `ml_labels` table with analyst-reviewed labels.
- Assisted weak-label generation.
- CSV review import/export.
- Active learning samples.
- Supervised model training, dataset snapshots, feature-set metadata, comparison experiments, tuning, error analysis, model registry, and evaluation reports.
- Promotion gate that keeps supervised lifecycle in `shadow_observation` with
  no selected candidate unless every predeclared readiness check passes and a
  separate human activation decision is approved.

Evidence: `atdr/app/db/models.py`, `atdr/app/routers/ml.py`, `atdr/app/detection/supervised_workflow.py`, `atdr/scripts/train_supervised_model.py`, `atdr/scripts/export_supervised_dataset_snapshot.py`, `atdr/scripts/run_supervised_experiment.py`, `atdr/scripts/tune_supervised_model.py`, `atdr/scripts/supervised_sanity_report.py`, `atdr/scripts/analyze_supervised_errors.py`, `atdr/scripts/generate_assisted_labels.py`, `docs/AI_TRAINING_RUNBOOK.md`.

Recovery workflow evidence: `atdr/app/detection/supervised_recovery.py`, `atdr/scripts/supervised_dataset_audit.py`, `atdr/scripts/rebuild_supervised_baseline.py`, `atdr/scripts/run_binary_threat_experiment.py`, and `atdr/scripts/run_supervised_recovery_phase.py`. Recovery outputs are candidate-only diagnostics and must not be treated as production accuracy.

### Dashboard

- React-first dashboard with protected routes.
- Overview, Alerts, Investigation/Log Explorer, SOC Assistant, AI Governance, Response & Audit, Threat Controls, Detection Tuning, User Admin, and Demo Controls.
- Admin-only route protection for user/demo controls.

Evidence: `frontend/src/App.tsx`, `frontend/src/pages/*`, `frontend/src/lib/api.ts`.

### Analyst Assistant

- Read-only assistant page and API for summarizing alerts, source health, operation jobs, ML Governance, and lab workflow.
- Deterministic local fallback answers work when no external LLM provider is configured.
- v3.9 adds broader deterministic intent coverage for alert lists, warning sources, failed jobs, recent changes, safe next steps, reviewed-label import help, safe scenario help, and model-promotion explanation.
- v3.9 adds grouped prompt presets and safe audit-backed assistant history in the React dashboard.
- v3.13 adds structured alert explanations with Summary, Why flagged, Evidence, ATT&CK mapping, Rule/model contribution, Analyst next steps, Safety note, and References.
- v3.13 adds a dashboard `Ask Assistant` handoff from alert detail to the SOC Assistant with alert context.
- v3.21 adds demo-quality prompt presets, recent detection-run summaries, import-log help, stronger unsafe-action refusal, and a visible `Simulation Mode` safety badge.
- v3.22 adds evidence-grounded answer sections, citation display, safe follow-up buttons, and an advisor demo question set.
- v3.23 adds dashboard handoff links for assistant citations, source-context handoff through `/assistant?source=<id>`, Overview source drawer linking, and read-only Ask Assistant links from source, operations, and AI Governance panels.
- v3.24 adds explicit alert/log/source/case assistant context, related-log citations, computed case/group summaries, and navigation-only Ask Assistant links from alert, log, and case investigation surfaces.
- v3.25 adds investigation brief presets and contextual `Generate Brief` support for alert, log, source, and computed case/group handoffs. Briefs are copyable, cited, and non-mutating.
- v3.26 adds a repeatable assistant QA evaluator that imports safe scenario data into a temporary database, runs detection, asks 15 investigation questions, verifies citations/safety wording, and confirms the assistant creates no response actions, detection runs, ML runs, labels, alerts, or logs.
- v3.27 adds answer-quality feedback so analysts can rate assistant answers as helpful, not helpful, incorrect, unsafe, or unclear. Feedback is audited, scoped by role, and cannot execute response, detection, label, data, email, or model actions.
- v3.28 adds filtered feedback review and quality triage for assistant answers. Admin users can review all feedback, analysts see their own feedback, and unsafe/incorrect feedback is highlighted for manual review only.
- v3.29 improves assistant reasoning quality with evidence strength, false-positive/noise caveats, missing-evidence notes, source/case risk summaries, and concrete analyst checklists.
- External LLM support is disabled by default and must be configured through `.env` only after review.
- v3.63 adds a real provider adapter for Gemini, OpenAI-compatible APIs, Claude/Anthropic, and a mock test provider. The deterministic local answer is still produced first and remains the fallback if the provider is disabled or unavailable.
- Real LLM provider configuration uses explicit disabled-by-default `ASSISTANT_LLM_*` settings. Gemini is preferred if MFU/Google access is approved; OpenAI-compatible or Claude providers remain alternatives. v3.65 adds `python -m atdr.scripts.test_assistant_llm_provider` for safe status/probe testing without exposing keys.
- Raw log context is disabled by default, IP redaction is enabled by default, and assistant questions are audited.
- Assistant cannot execute response actions, run detection, change labels, activate models, or promote ML models.

### v3.30 Detection and ML Quality Revalidation

- Current labeled firewall-log data can be revalidated with `python -m atdr.scripts.run_v330_detection_ml_quality_revalidation`.
- The diagnostic compares threshold profiles, calibration, false-positive and false-negative patterns, and rule/anomaly/supervised/hybrid disagreement.
- AI Governance shows a compact `Detection Quality Revalidation` panel when the v3.30 summary exists.
- The current diagnostic keeps the model as decision support only and does not activate, promote, or write model artifacts.
- Generated v3.30 reports and review CSVs stay under ignored review/report folders and must not be committed.

Evidence: `atdr/app/routers/assistant.py`, `atdr/app/services/assistant_service.py`, `atdr/app/schemas/assistant.py`, `frontend/src/pages/AssistantPage.tsx`, `docs/V3_8_ANALYST_ASSISTANT_MVP.md`, `docs/V3_9_ASSISTANT_HARDENING.md`.

### Email Verification And Account Notifications

- Disabled-by-default local email verification settings.
- Hashed verification-code tokens.
- Admin-only local dev outbox for verification-code testing.
- Authenticated self-service request/verify endpoints.
- Admin Send verification action in User Admin.
- Audit events for request, failure, local notification recording, and successful verification.
- Real SMTP delivery and full school OIDC/SSO login remain future work.

Evidence: `atdr/app/services/account_verification_service.py`, `atdr/app/services/email_service.py`, `atdr/app/routers/auth.py`, `atdr/app/routers/users.py`, `frontend/src/components/AppShell.tsx`, `frontend/src/pages/UserAdmin.tsx`, `docs/V3_14_EMAIL_VERIFICATION_AND_ACCOUNT_NOTIFICATIONS.md`, `docs/V3_15_ACCOUNT_LIFECYCLE_AND_EMAIL_VERIFICATION_UX.md`.

v3.15 adds account lifecycle and policy clarity: dashboard email verification badges, Admin/User Admin policy cards, status-only verification-required flags, and disabled verification actions when verification is not enabled. These are visibility and safety improvements only; they do not enforce login blocking.

### Response And Audit

- Simulated block/unblock response.
- Analyst/admin approval and justification.
- Protected IP safeguards.
- Denied and successful actions are audited.
- No real firewall connector is enabled.

Evidence: `atdr/app/routers/response.py`, `atdr/app/services/response_service.py`, `atdr/app/db/models.py`, `atdr/tests/test_response_safety.py`.

### Lab Operations

- Run history for ingestion and detection.
- Durable operation queue and separately launched worker for selected import, replay, detection, ML, and export tasks.
- Transactional chunk checkpoints, safe-boundary cancellation, verified-input resume, queue backpressure, and bounded private staging for queued file imports.
- Dry-run-first operation job maintenance for stale job recovery and old terminal job cleanup.
- Performance smoke checks.
- Release gate.
- Scenario runner with safe synthetic files.
- No-hardware soak validation for parser drift, source health, dedup, alert noise, and explanation completeness.
- Lab runbook and acceptance checklist.

Evidence: `atdr/app/db/models.py`, `atdr/app/routers/jobs.py`, `atdr/app/services/job_service.py`, `atdr/app/services/operation_worker.py`, `atdr/app/services/resumable_ingestion_service.py`, `atdr/app/services/staging_service.py`, `atdr/scripts/maintenance_jobs.py`, `atdr/scripts/performance_smoke.py`, `atdr/scripts/verify_release.py`, `docs/LAB_RUNBOOK.md`, `docs/ACCEPTANCE_TEST_CHECKLIST.md`.

## Functional Requirements

| ID | Requirement | Status |
| --- | --- | --- |
| FR-ATDR-001 | Import firewall/syslog logs without losing raw evidence | Implemented |
| FR-ATDR-002 | Normalize Palo Alto traffic fields for investigation and detection | Implemented |
| FR-ATDR-003 | Preserve malformed/unmatched lines through raw fallback behavior | Implemented |
| FR-ATDR-004 | Track log source identity, parser profile, health, and quality | Implemented |
| FR-ATDR-005 | Run explainable rule-based detection | Implemented |
| FR-ATDR-006 | Run IsolationForest anomaly scoring as assistive ML | Implemented |
| FR-ATDR-007 | Train and evaluate supervised classifier from labels | Implemented as decision support with dataset snapshots, feature-set metadata, candidate comparison, threshold tuning, error analysis, and explicit activation/rollback |
| FR-ATDR-008 | Keep ML outputs explainable and non-authoritative | Implemented |
| FR-ATDR-009 | Generate alert evidence, lifecycle, notes, timelines, and reports | Implemented |
| FR-ATDR-010 | Deduplicate repeated alert patterns without deleting raw logs | Implemented |
| FR-ATDR-011 | Group related alerts into lightweight cases | Implemented |
| FR-ATDR-012 | Simulate response actions with approval and audit | Implemented |
| FR-ATDR-013 | Prevent automatic response from ML output | Implemented constraint |
| FR-ATDR-014 | Provide React dashboard for SOC workflow | Implemented |
| FR-ATDR-015 | Provide lab scenario validation with expected outcomes | Implemented |
| FR-ATDR-016 | Provide release verification and performance smoke checks | Implemented |
| FR-ATDR-017 | Enforce JWT authentication and admin/analyst RBAC on protected workflows | Implemented for lab roles |
| FR-ATDR-018 | Support local school-email account metadata while preserving username/password login | Implemented for local lab accounts |
| FR-ATDR-019 | Provide non-destructive shared-lab readiness checks for PostgreSQL status, backup/restore readiness, operations health, and performance profiling | Implemented as v3.4 foundation; not a production claim |
| FR-ATDR-020 | Provide read-only controlled source/syslog pilot evidence without exporting private raw logs by default | Implemented as v3.5 source-pilot checker/exporter; not a production claim |
| FR-ATDR-021 | Provide job/status visibility for long-running lab operations without changing detection, ML, or response behavior | Implemented through v3.90-v3.93 as an opt-in durable queue, separately launched worker, leases, progress, and resumable queued imports; SQLite remains one-worker only |
| FR-ATDR-022 | Provide safe stale-job detection and explicit operation-job retention maintenance without deleting raw evidence | Implemented as dry-run-first maintenance and lease recovery; scheduled retention remains future deployment work |
| FR-ATDR-023 | Provide a safe read-only analyst assistant for alert/source/job/ML/workflow questions without response execution or raw-log sharing by default | Implemented as v3.9 hardened assistant with deterministic intents, prompt presets, safe audit-backed history, and citations; external LLM and raw-log context remain disabled by default |
| FR-ATDR-024 | Provide clear local/shared-lab configuration diagnostics and safe recovery from accidental PostgreSQL lab config on local machines | Implemented as v3.10 config safety hardening; normal local workflow remains SQLite and PostgreSQL remains optional |
| FR-ATDR-025 | Explain why alerts and selected logs were or were not flagged, and validate parser/detection/explanation completeness through safe scenarios | Implemented as v3.11 detection explainability hardening; no threshold, ML activation, response, or schema behavior changed |
| FR-ATDR-026 | Control deterministic rule alert noise with documented rule intent, expected/allowed scenario outcomes, and grouping that preserves evidence | Implemented as v3.12 rule quality hardening; no ML activation, automatic response, or production claim |
| FR-ATDR-027 | Provide structured read-only assistant explanations for alert evidence and analyst next steps | Implemented as v3.13 SOC Assistant alert explainer; no external LLM, raw-log context, response execution, or model activation |
| FR-ATDR-028 | Provide disabled-by-default local email verification and notification groundwork for school-email workflows | Implemented as v3.14 with hashed tokens, admin-only dev outbox, non-secret status API, and no real SMTP/OIDC by default |
| FR-ATDR-029 | Present account lifecycle, school-email policy, and verification status clearly in the dashboard without surprise enforcement | Implemented as v3.15 status/UX hardening; enforcement remains disabled by default |
| FR-ATDR-030 | Map supervisor-template MFU IAM/Google SSO/OTP/B2B requirements to ATDR without enabling external IAM | Implemented as safe adapter plan, provider checklist, disabled-by-default config placeholders, and non-secret status API |
| FR-ATDR-030A | Prepare MFU IAM SDK/token-introspection implementation path without copying secrets or enabling external login | Implemented as source-backed implementation plan and expanded non-secret status/config readiness |
| FR-ATDR-030B | Prepare real LLM assistant provider integration without enabling external LLM calls by default | Implemented as disabled-by-default `ASSISTANT_LLM_*` config/status groundwork and provider plan |
| FR-ATDR-030C | Provide an MFU school-email secure outer-shell handoff while preserving an explicit recovery profile | Implemented in v3.91 and made the normal fail-closed team profile in v4.3 with opaque one-time code, exact origin/return-path controls, server-side exchange, group-based role mapping, HttpOnly cookie session, audit, and explicit local recovery |
| FR-ATDR-030E | Validate MFU outer-shell handoff in approved preproduction without exposing credentials or changing SOC controls | Preproduction checklist and rollback are documented; live provider validation remains required |
| FR-ATDR-030D | Provide a safe real LLM provider probe without exposing API keys or raw logs | Implemented in v3.65 as `atdr/scripts/test_assistant_llm_provider.py` |
| FR-ATDR-031 | Validate parser normalization and controlled detection quality with source-backed, read-only reports | Implemented as v3.17 parser/detection validation and enriched explanation payloads; production accuracy is not claimed |
| FR-ATDR-032 | Maintain a safe controlled detection corpus with false-positive / false-negative scenario QA | Implemented as v3.18 expanded synthetic scenarios, explicit FP/FN reporting, rule-level QA summaries, and explanation completeness checks; scenario results are lab QA, not production accuracy |
| FR-ATDR-033 | Run no-hardware multi-source soak validation for parser drift, source health, deduplication, alert-noise stability, and explanation completeness | Implemented as v3.19 temp-DB/dry-run validation; real router/firewall forwarding and production accuracy remain future work |
| FR-ATDR-034 | Present SOC Assistant answers as evidence-grounded sections with citations and safe follow-up questions | Implemented as v3.22; answers remain read-only decision support and cannot execute response, detection, model, label, email, or data actions |
| FR-ATDR-035 | Link SOC Assistant citations to dashboard context without granting mutation or action capability | Implemented as v3.23; alert/log/source/job/detection/ML citations navigate to existing dashboard pages while docs/code citations remain text references |
| FR-ATDR-036 | Support read-only SOC Assistant investigation context for alerts, related logs, sources, and computed alert groups | Implemented as v3.24; assistant accepts alert/log/source/case context, summarizes evidence, cites related dashboard objects, strips raw logs by default, and cannot execute actions |
| FR-ATDR-037 | Generate read-only investigation briefs from existing alert/log/source/case context | Implemented as v3.25; brief presets and contextual generation produce structured, cited, copyable handoffs without writing notes, running detection, executing response, changing labels, or mutating data |
| FR-ATDR-038 | Validate SOC Assistant answers end to end against controlled investigation scenarios | Implemented as v3.26; evaluator uses a temporary database, safe scenario import, detection fixture, 15 assistant questions, citation checks, and no-side-effect checks without mutating the user's current database |
| FR-ATDR-039 | Record SOC Assistant answer-quality feedback without granting action capability | Implemented as v3.27; authenticated feedback endpoints, `assistant_feedback` table, dashboard feedback controls, scoped feedback summary, audit records, and no-side-effect tests |
| FR-ATDR-040 | Review assistant answer-quality feedback with filters and manual triage indicators | Implemented as v3.28; filtered feedback endpoints, unsafe/incorrect summary, needs-review counts, priority feedback cards, and dashboard review filters without automatic tuning or actions |
| FR-ATDR-041 | Improve SOC Assistant reasoning quality for professional triage | Implemented as v3.29; alert/log/source/case answers include evidence strength, false-positive caveats, missing-evidence notes, risk interpretation, concrete next checks, citations, and safety notes without external LLM or action execution |
| FR-ATDR-042 | Revalidate current supervised ML quality and false-positive noise without activating a model | Implemented as v3.30; diagnostic script, markdown report, compact dashboard summary, threshold profile comparison, calibration check, and targeted review CSV without production promotion or response automation |
| FR-ATDR-043 | Process queued large-file imports in transactional chunks with persisted progress, cooperative cancellation, verified-input resume, queue backpressure, and safe staged-input retention | Implemented as v3.93 for one verified staged input; separate re-imports are not claimed to be globally exactly-once, SQLite remains one-worker only, and PostgreSQL multi-worker runtime validation is pending |
| FR-ATDR-044 | Validate rule, anomaly, supervised SOC queue, and hybrid quality with frozen leakage-controlled holdouts and no model activation | Implemented as v3.98 internal unseen-data validation across temporal, source, and repeated fingerprint-grouped random splits; external provider-blinded or real-source independence remains required |
| FR-ATDR-045 | Generate source/time-separated synthetic evidence, quarantine overlap with reviewed data, and score it only after internal model/calibration/threshold roles are frozen | Implemented as v3.99 with three generated sources, four windows, exact/near/feature overlap controls, six strategy comparisons, non-importable expectation labels, and conservative `candidate_only` readiness; this is regression evidence, not external accuracy |
| FR-ATDR-046 | Provide portable teammate setup and lifecycle for the mandatory MFU shell plus ATDR services without machine-specific paths or committed secrets | Implemented in v4.3 with one setup command, one start command, preflight/check/stop commands, ignored runtime configuration, safe SQLite backup/migration, and explicit recovery profile |
| FR-ATDR-047 | Distribute the reviewed MFU shell as a sanitized, versioned, integrity-checked companion release | Implemented locally in v4.6 with deterministic packaging, secret/generated-file exclusions, contract-locked checksum and fingerprint, versioned ignored installation, package-integrity checks, and disposable clean-clone acceptance; provider-backed sign-in remains external |
| FR-ATDR-048 | Keep the large local SQLite Overview summary responsive without stale counts, prewarming, or cache-only masking | Implemented in v4.7 through indexed quality-count queries, recent-alert N+1 removal, one-statement freshness checks, repeatable five-run profiling, and cache/write correctness tests; no production SLA is claimed |

## Non-Functional Requirements

| Area | Requirement |
| --- | --- |
| Safety | No real firewall enforcement until a future approved connector, allowlist, rollback, and change approval exist. |
| Auditability | Auth, imports, detection, labels, response, and workflow actions must be auditable. |
| Explainability | Alerts and selected logs must show concise decision-support explanations, including "Why flagged?" or "Why not flagged?" context where available. |
| Alert quality | Deterministic rule alerts should be grouped and classified to reduce duplicate/noisy analyst workload without deleting raw evidence. |
| Assistant safety | Analyst assistant answers must be read-only, cite safe sources when available, exclude raw-log context by default, and never execute response or ML/model actions. |
| Account notification safety | Email verification must be disabled by default, avoid exposing SMTP secrets, store verification tokens as hashes, and use admin-only dev outbox for local testing only. |
| Lab performance | SQLite is acceptable for local testing; PostgreSQL is recommended for shared lab scale. |
| Reliability | Release gate and tests must pass before declaring a checkpoint. |
| Security | JWT auth and role checks are required for protected endpoints. Demo secrets must be replaced before shared lab use. |
| Data privacy | Real logs, databases, model artifacts, generated exports, and `.env` files must stay out of Git. |
| Shared-lab readiness | Backup/restore drills, PostgreSQL validation, performance profiling, and real-source pilot checks must be non-destructive and must not imply production readiness. |
| Team portability | Runtime paths must be discovered or supplied through ignored configuration; no developer username, workstation path, private shell file, or secret may be required from tracked source. |
| Authentication entry | The normal team profile must start at the approved MFU shell and fail closed when secure handoff is incomplete; direct local credentials require explicit recovery mode. |

## IAM / RBAC Constraints

ATDR adapts the university IAM requirement as local authentication, authorization, role-based access control, response-safety permissions, and auditability.

- JWT authentication is implemented for protected API routes.
- `admin` and `analyst` roles are implemented.
- Admin-only actions include user management, demo controls, log import, source create/update, ML model training/scoring, and simulated block/unblock response.
- Analyst/admin actions include alert investigation, log investigation, detection runs, label review/import/export, ML report viewing, source health viewing, blocked-IP viewing, and audit viewing.
- Frontend role-aware navigation and `AdminRoute` help the user experience, but backend route dependencies are the authority.

Current limitations:

- No full external SSO/OAuth/SAML/LDAP browser flow.
- No enterprise identity provider.
- MFU outer-shell secure handoff is implemented in source, but exact preproduction origins, group identifiers, provider lifecycle policy, and live validation still require approved private configuration.
- No viewer/read-only role.
- Demo JWT secret must be replaced before shared lab or real deployment.
- Current role model is suitable for lab prototype validation, not production IAM.
- Role permissions must be fully reviewed before real deployment or response connector implementation.
- v3.14 email verification does not block login by default and does not implement real SMTP or external school SSO.
- The v4.6 team profile installs a checksum-locked MFU shell companion release, selects it by default, and blocks direct local login. Real provider-backed MFU authentication, approved group mapping, provider-managed 2FA, recovery, and deprovisioning still require university environment acceptance.

## University Template Alignment

ATDR preserves selected NewSystem workflow, IAM, security, and manifest evidence
under `docs/reference/NewSystem/`, not as implementation truth. The unused
tracked Node/Vue/Mongo runtime copy is removed by the proposed v4.8.1 cleanup.
The separately distributed, checksum-locked MFU companion shell remains the
normal identity outer shell. The active ATDR adaptation is documented in:

- `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md`
- `docs/ATDR_TEMPLATE_MANIFEST.json`
- `docs/security/ATDR_PERMISSION_PATHS.md`
- `docs/security/ATDR_IAM_RBAC_MATRIX.md`
- `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md`
- `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md`
- `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md`
- `docs/reference/NewSystem/REFERENCE_SCOPE.md`

Template ideas adopted by ATDR:

- explicit environment keys and startup workflow
- permission path registry
- admin/analyst access matrix
- route-level authorization evidence
- audit logging expectation
- PRD and T1-T20 change gates
- tasklist/progress-board tracking and generated HTML progress evidence
- release/verification gate
- OWASP-style security review discipline

Template ideas not adopted by ATDR:

- Node.js backend migration
- Vue/Vuex frontend migration
- MongoDB migration
- external IAM/B2B SDK integration
- OAuth/SSO/SAML/LDAP
- real firewall enforcement
- production readiness claim

## Safety Constraints

- Response mode remains simulation.
- Response requires analyst/admin approval and justification.
- Protected IP ranges must not be blocked by simulation actions.
- Denied response attempts must be audited.
- ML cannot automatically trigger containment.
- Weak labels cannot be presented as production ground truth.
- The project must not add offensive tooling.

## AI Governance Constraints

- Rule evidence remains primary.
- IsolationForest is anomaly support, not proof of malicious behavior.
- Supervised ML is SOC triage decision support.
- Threat-positive triage can prioritize analyst review, but flat five-class predictions are not production-promoted.
- Benign and needs_context exact classification remain known weak spots until reviewed coverage and live validation improve.
- Model status must distinguish `candidate_only`, `candidate_improved`, `eligible_for_analyst_review`, and any future promotion state.
- Production promotion cannot be claimed while reviewed labels and live validation are limited.
- Assisted labels must be marked as weak unless reviewed.

## Source Management Requirements

- `source_id` is optional so existing imports keep working.
- Unknown imports must use safe fallback source behavior.
- Source health must show healthy, idle, warning, error, or disabled.
- Disabling a source must not delete historical data.
- Parser profile mismatch or high parse failure rates must be visible.

## Lab-Readiness Requirements

- Normal local workflow remains unchanged.
- Docker/PostgreSQL is optional for this stage.
- Scenario validation uses synthetic safe logs under `data/samples/scenarios/`.
- Real device syslog validation is future/lab work and must be scoped safely.
- Performance smoke should stay healthy for local DB testing.

## Known Limitations

- SQLite slows down with large imports and is not the recommended shared lab database.
- PostgreSQL compatibility, multi-worker coordination, scale qualification,
  and backup/restore are implemented and CI-tested; approved shared-host
  deployment, TLS, managed secrets, persistent monitoring, and measured RPO/RTO
  remain external.
- Real firewall blocking is not implemented.
- Real device forwarding needs controlled lab validation.
- Case grouping is lightweight and computed; it is not a full incident management system.
- Supervised ML currently has no qualified candidate. The consumed v5.49b
  result cannot be tuned; fresh development evidence, a second physical
  source, an untouched future evaluation, stable calibration, and separate
  human activation approval are required before stronger claims.

## PRD Update Rules

Update this PRD when a change affects:

- Product scope or user workflow.
- API route, request, response, auth, or RBAC.
- Database schema, migration, indexes, or retention.
- React route, page, table/filter/action flow, or dashboard wording.
- Parser profile, source health, ingestion, replay, or syslog behavior.
- Detection logic, alert lifecycle, deduplication, case grouping, or report output.
- ML labels, feature generation, model training, evaluation, promotion gate, or governance wording.
- Response safety, simulation mode, protected-IP handling, or audit behavior.
- Test/release gates, runbooks, status docs, or known limitations.
- Tasklist/progress-board requirements, evidence gates, or handoff workflow.

If no PRD update is needed, record the reason in T17 of the ATDR T1-T20 change document.
## v3.87 Real LLM SOC Assistant Requirement Addendum

- Real-provider assistant mode is optional and disabled by default.
- ATDR, not the external provider, owns authorization, evidence retrieval, context limits, redaction, citations, and audit policy.
- Provider answers must use a validated structured contract and fall back to deterministic ATDR output when unavailable, malformed, unsafe, or insufficiently grounded.
- Conversation context must be actor-scoped, bounded, resettable, and resistant to stale client identifiers.
- Raw log lines, secrets, credentials, private paths, and model paths must not be sent to the provider by default.
- The assistant remains read-only and cannot execute detection, response, labeling, model, user, source, email, firewall, or deletion operations.
- External-provider deployment requires approved privacy, key-custody, quota, cost, and data-sharing controls; implementation does not constitute production readiness.

## v3.88 Product Baseline Requirement Addendum

- A release checkpoint must classify every visible modified/untracked file before staging.
- Commit preparation must use an exact path allowlist; `git add .` is not acceptable for a worktree containing ignored private/runtime data.
- The supervisor template remains the optional external login/account shell; ATDR remains FastAPI/React/SQLAlchemy/Alembic.
- Local login and deterministic assistant fallback are required recovery paths.
- CI must run without private `.env`, real provider calls, MFU IAM availability, PostgreSQL, Docker, or the user's current database.
- Generated progress-board HTML may be tracked only because it is an intentional governance artifact generated from canonical Markdown.
- Checkpoint completion requires clean-config verification, full local release verification, secret/path hygiene evidence, rollback notes, and exact commit commands.
- No productization checkpoint may imply production certification.

## v3.90 Durable Operation Reliability Addendum

ATDR shall support an opt-in database-backed operation queue for selected long-running imports, replay, detection, ML, and report workflows. The API process shall not start a worker automatically. Queued work shall use role-based access, idempotency, lease/heartbeat visibility, safe cancellation, auditable lifecycle events, and private upload staging. The worker shall not execute response actions, real firewall changes, user/account changes, label changes, data deletion, external IAM/LLM calls, model activation, or model promotion. SQLite remains suitable for a single local worker; PostgreSQL/multi-worker validation remains future shared-lab work.

## v3.92 Operational Observability Addendum

- API requests shall have a bounded correlation ID returned as `X-Request-ID` and included in structured logs.
- Process liveness shall not depend on the database; readiness shall fail cleanly for unavailable DB, migration drift, or unsafe configuration.
- Metrics shall use bounded dimensions and shall not expose request/run/job IDs, paths, actors, email addresses, IP addresses, credentials, raw evidence, or secrets.
- Operations Health shall warn on stale workers/jobs, backlog, repeated failures, database/migration/configuration failures, and unexpected response-mode changes without triggering actions.
- SQLite shall reject concurrent fresh operation workers. The API shall not auto-start a worker.
- Audit retention shall default to report-only, require an explicit confirmed apply, honor a minimum, preserve IAM/denied/response security events, and never delete raw log evidence.
- PostgreSQL multi-worker supervision, an external monitoring stack, scheduled retention, and paging remain future deployment work.

## v3.93 Resumable Ingestion Addendum

- Durable file imports shall stream input and atomically commit raw/normalized evidence, source/run counters, progress/checkpoint state, lease renewal, and worker heartbeat per chunk.
- Resume shall continue only after the last committed byte/line checkpoint and only when the ignored staged input still matches its recorded size and SHA-256 fingerprint.
- Running cancellation shall be cooperative and acknowledged only at a safe chunk boundary; committed evidence shall remain available.
- Queue and staging limits shall fail clearly without exposing paths or credentials. Staged cleanup shall be dry-run by default and shall protect active or still-resumable inputs.
- The guarantee is transactional chunk replay protection for one verified staged input, not global exactly-once ingestion across separate jobs.
- PostgreSQL multi-worker operation, shared staged storage, and managed worker deployment remain future environment-backed validation.

## v3.94 PostgreSQL Multi-Worker And Managed Deployment Addendum

- SQLite remains the default local profile and shall run at most one operation worker.
- PostgreSQL queue claims and expired-lease recovery shall lock rows with skip-locked behavior so concurrent workers do not select the same available job.
- Ownership-sensitive job updates shall require a private lease token and current worker identity; stale owners shall fail closed.
- Shared file jobs shall use a relative staged-object key plus a deployment storage identity. A worker shall not claim an import from inaccessible or mismatched storage.
- Resumable imports shall respond to managed shutdown at a committed chunk boundary, persist their checkpoint, release ownership, and remain available to a replacement worker.
- PostgreSQL backup shall coordinate with ATDR workers and refuse while mutating operation jobs remain active. Restore validation shall use a separate empty target.
- Managed service examples shall use an unprivileged account, explicit environment files, failure restart policy, graceful termination, and separately managed API/worker processes.
- Ephemeral PostgreSQL CI or an approved host must execute the concurrency and backup drills before environment-backed multi-worker validation is claimed.
- These controls do not establish global exactly-once ingestion, production readiness, automatic response, real firewall blocking, or model promotion.

## v3.95 Deployment Security, Monitoring, And Recovery Addendum

- Normal localhost startup shall remain unchanged; reverse proxy, Prometheus, systemd timers, and managed secret services are optional deployment components.
- Forwarded client/protocol headers shall be ignored by default and accepted only from explicit trusted direct proxy addresses.
- Deployment metrics and alerts shall cover service/database readiness, queue/worker health, repeated failures, ingestion/detection failures, staging pressure, and unexpected response-mode changes without sensitive or high-cardinality dimensions.
- Scheduled audit retention and staged-input cleanup shall remain report-only. Destructive modes require a separate explicit operator command and confirmation; raw evidence shall never be deleted automatically.
- A load-test utility shall be GET-only by default, bounded, token-safe, and body-free. Any future write-load test requires a disposable isolated database and separate approval.
- Backup verification shall check manifest, checksum, age, revision, and recorded counts without restoring. Recovery drills shall restore only to a separate target and shall never overwrite the configured database.
- Planning assumptions are RPO 24 hours and RTO 4 hours until measured deployment drills establish evidence. They are not service guarantees.
- TLS certificates, external alert routing, secret-manager integration, environment-sized recovery evidence, and remote PostgreSQL CI remain deployment gates. v3.95 does not claim production readiness.

## v3.96 Controlled Preproduction Acceptance Addendum

- A secret-safe preproduction gate shall reject acceptance unless an approved shared-lab/preproduction Linux host, PostgreSQL at Alembic head, HTTPS/DNS/TLS, scoped trusted proxy, explicit CORS, protected shared staging, fresh verified backup, Prometheus, managed secrets, multi-worker profile, and MFU secure handoff are evidenced together.
- A production profile shall not be used as a substitute for the controlled preproduction rehearsal.
- Preflight output shall expose no secret, connection URL, private path, token, raw log, email, or IP value. Database probing requires an exact operator confirmation and remains read-only.
- Monitoring shall include bounded database-pool and backup-freshness state without high-cardinality or sensitive labels.
- Controlled load shall remain GET-only, body-free, token-safe, bounded, and remote-confirmed. Local SQLite measurements do not establish PostgreSQL capacity or an SLA.
- Recovery evidence shall distinguish isolated synthetic timing from approved-host RPO/RTO. A measured synthetic RTO shall not be presented as deployment RTO, and RPO remains unmeasured without a real failure/backup point.
- Operational acceptance remains blocked when approved environment evidence is unavailable. This status is not an application-test failure and is not a production-readiness claim.

## v3.97 Large-File Ingestion Reliability Addendum

- Queued large-file imports shall preserve transactional chunk checkpoints, monotonic committed progress, lease renewal, cooperative cancellation, and changed-input fail-closed behavior.
- Duplicate accounting shall use bounded indexed fingerprint lookups followed by exact raw-line comparison. Duplicate evidence shall remain stored; a fingerprint must never replace or delete raw evidence.
- Raw and normalized rows shall flush at chunk boundaries rather than once per record, keeping memory bounded and preserving one normalized row for each successfully parsed input record.
- Operations Health and metrics shall expose safe cumulative import, parse, failure, duplicate, checkpoint-age, and stalled-job signals without raw content, paths, fingerprints, actors, IPs, or other high-cardinality labels.
- Large-file acceptance shall use synthetic data and a disposable database only. The validator must refuse to run without its explicit temporary-database flag and must prove that the configured database was unchanged.
- The validated local baseline is 100,000 synthetic generic-syslog rows, 200 chunk commits, one forced resume, zero resume duplicates, zero unsafe side effects, 724.45 rows/second, and 8.71 MiB peak traced Python memory.
- SQLite remains a one-worker local profile. The result is not an SLA, real-device proof, shared-storage proof, PostgreSQL capacity result, or production-readiness claim.

## v3.98 Independent Detection/ML Holdout Validation Addendum

- Detection/ML quality validation shall keep fit, probability calibration, threshold selection, and final-test partitions separate. Final-test labels shall not influence fitting, calibration, feature selection, candidate selection, or threshold selection.
- Exact raw-evidence fingerprints, near behavior fingerprints, used-feature fingerprints, normalized-log identities, label history, source identity, and time-window overlap shall be audited. Unacceptable overlap shall fail closed or quarantine the affected behavior group.
- Required diagnostic views shall include strict temporal holdout, source-disjoint holdout, and repeated fingerprint-grouped random splits.
- Evaluation shall compare deterministic rules, fresh in-memory IsolationForest, the repaired binary SOC review queue, a rule/anomaly/supervised hybrid, Logistic Regression, and a majority baseline without writing an active model artifact.
- Reports shall include queue precision/recall/F1, benign-like FPR, suspicious/malicious diagnostic recall, macro/weighted F1, calibration, Brier score, ECE, confidence buckets, bootstrap intervals, operational queue size, and errors by source/application/action/port.
- Internal reviewed-label holdout evidence shall not be described as an external independent benchmark or production accuracy. External real-source/provider-blinded validation remains a separate gate.

## v3.99 Synthetic Multi-Source Evidence Addendum

- Generated evidence shall declare source identity/type, parser profile, collection windows, provenance, scenario/category, evidence kind, expected-label provenance, and duplicate/overlap status.
- Deterministic scenario expectations shall remain `human_reviewed=false` and `import_ready=false`; they shall not be inserted into the supervised label store automatically.
- Exact raw fingerprints, normalized near-pattern fingerprints, and used-feature fingerprints shall be compared with existing reviewed evidence before scoring. Overlap shall be quarantined and minimum evidence requirements shall fail closed.
- Existing reviewed evidence may be used for fit, calibration, and threshold selection. Generated v3.99 evidence may be used only as final evaluation evidence after those roles are frozen.
- Synthetic multi-source/time performance shall be described as reproducible regression evidence, not provider-blinded, real-device, externally reviewed, or production accuracy.
- Model activation, artifact writing, production promotion, automatic response, and real firewall blocking remain prohibited regardless of v3.99 metrics.
- v3.98 shall not create labels, activate or promote models, execute response actions, enable automatic response, or enable real firewall blocking. Readiness remains `candidate_only` unless every documented internal gate passes, and passing internal gates alone cannot authorize production promotion.

## v4.0 Provider-Blinded External Evidence Addendum

- External benchmark acquisition shall use an official primary source with documented publisher, version, terms, citation, checksum, fields, label provenance, and limitations.
- Sampling and feature mapping shall not consult final provider label values. Predictions and their checksum shall be frozen before provider labels are read for scoring.
- External rows shall contribute zero rows to model fitting, probability calibration, feature/guard selection, and threshold selection.
- Provider benchmark labels shall remain non-human ATDR evidence with `human_reviewed=false` and `import_ready=false`; they shall never be inserted automatically into the operational label store.
- Benchmark adapters shall map only available fields. Missing IP, action, application, zone, source-port, and risk fields shall be reported unavailable rather than fabricated.
- Rules whose required fields are unavailable shall report `unavailable`; partial rule results shall not be presented as full ATDR rule-engine accuracy.
- Exact, near-pattern, and used-feature overlap shall be quarantined against internal reviewed and prior synthetic evidence before scoring.
- External classification, calibration, bootstrap, stability, and error results shall be reported even when they fail. No final-label tuning is permitted after the prediction freeze.
- The v4.0 CSE-CIC-IDS2018 sample is locked final evidence. Its FPR `1.0000` and weak calibration are blockers requiring schema-aware redesign on separate development evidence and validation on a new untouched benchmark.
- v4.0 cannot activate or promote a model, write an active artifact, import labels, execute response actions, enable automatic response, or enable real firewall blocking. Readiness remains `candidate_only` regardless of metrics.

## v4.1 Schema-Aware Diagnostic Addendum

- ATDR shall distinguish Palo Alto, generic syslog, provider-flow, and raw-fallback evidence schemas. It shall expose field availability and missingness rather than fabricate unavailable source/destination identity, action, application, zone, risk, or behavior-window fields.
- A rule shall report unavailable when its required fields are absent. Unavailable evidence shall not be treated as a negative detection signal or as full rule-engine coverage.
- v4.0 public-provider files and manifests are locked final evidence and shall not be used for v4.1 feature engineering, fitting, calibration, threshold selection, or candidate selection. Separate provider development data remains non-human and non-importable.
- Schema-aware model evaluations shall report time, source-aware, repeated random, and schema-held-out diagnostics where evidence supports them, including calibration. Strong random-split results alone shall not authorize promotion.
- v4.1 results remain `candidate_only`: no model activation/promotion, active-artifact write, response automation, real firewall blocking, or automatic label import is permitted. A separately governed untouched benchmark and authorized multi-source real firewall/syslog validation are required before activation can even be reconsidered.

## v4.2 Evidence-Grounded Assistant Addendum

- Every assistant answer shall expose the ATDR record, service, run, or documentation references actually used. Missing record-specific evidence shall be stated rather than fabricated.
- Optional Gemini use shall be limited to explanation and summarization of bounded, structured, redacted ATDR context. Gemini shall not be treated as a source of database facts.
- The assistant shall remain read-only and shall not expose controls for response, detection, labels, models, users, deletion, or firewall state.
- Assistant route navigation shall preserve a whitelisted session-scoped investigation snapshot without resending the question. Raw logs, secrets, access tokens, private paths, and arbitrary technical payloads shall not be persisted.
- Clear Context, logout, and session expiry shall clear assistant context. Malformed browser storage shall fail safely.
- Default answers shall prioritize a concise summary, evidence, analyst next steps, one safety line, and compact citations. Secondary detail shall use progressive disclosure.
- Provider labels shall be truthful: **Gemini Assisted** applies only to an answer that actually used Gemini and passed ATDR guards.
- MFU visual alignment shall use shared burgundy/gold presentation tokens while preserving React, accessibility, ATDR routes, and SOC identity.
## v4.4 MFU Authentication Stabilization Addendum

- The separately supplied MFU Vue/Node shell is the required normal authentication entry; ATDR does not implement a parallel direct Google login.
- Local shell login uses exactly `http://localhost:8080` and requires one university-approved OAuth Web client configured identically as private `VUE_APP_CLIENTID` and `GOOGLE_CLIENT_ID` values.
- Missing, mismatched, placeholder, or legacy fallback configuration must fail closed before normal startup.
- The shell-to-ATDR boundary remains a short-lived one-time code exchanged server-to-server, followed by an HttpOnly ATDR cookie.
- New approved external users default to analyst. Admin requires an explicitly approved IAM group mapping; email address alone is insufficient.
- Local credentials are an explicit recovery profile only and must never be selected automatically after provider failure.
- Provider tokens, one-time codes, client values, secrets, raw provider responses, and private environment content must not appear in URLs, API status, logs, audit details, or committed files.
- Real MFU authentication acceptance requires an approved OAuth client, authorized origins/domain/account policy, and successful live account/handoff evidence. Source-level readiness alone is not production acceptance.

## v4.7 Large-SQLite Overview Performance Addendum

- The Overview summary shall preserve exact counts and data-quality semantics across empty, small, and current large databases.
- Application caching shall not substitute for repairing an expensive uncached query, and TTL/prewarming shall not be used to hide regressions.
- Cache freshness shall account for raw/normalized growth, alert changes, ingestion/detection completion, audited mutations, suppression state, and watchlist state.
- Performance profiling shall be read-only and report application-cache cold/warm distributions, query counts, payload consistency, database dialect, and safe query-plan evidence.
- Shared service SQL shall remain SQLite/PostgreSQL portable. SQLite-only inspection is allowed only in the profiler's guarded diagnostic path.
- Current local targets are cold application-cache median `<=2.0s`, p95 `<=3.0s`, and warm cache `<=0.05s`; these are regression budgets, not production SLAs.
- No performance optimization may reset/delete data, change detection/ML/IAM/assistant/response behavior, activate a model, or enable response automation or real blocking.

## v4.8 End-to-End Acceptance Addendum

- **FR-ATDR-049:** ATDR shall provide a fail-closed integrated acceptance command that can target only a newly created disposable database and refuses configured-database execution.
- The acceptance path shall apply existing Alembic migrations and exercise real source, durable-job, ingestion, parser, detection, alert deduplication, case, explanation, assistant, metrics, dashboard-summary, and persistence services.
- It shall validate graceful interruption, cooperative cancellation/resume, monotonic progress, stale mutating-job lease failure, and useful failure diagnostics.
- It shall preserve raw evidence, parser failure status, source linkage, source health, and exact raw/normalized count accounting.
- It shall prove source-scoped detection and investigation traceability using safe synthetic scenarios without ML activation or response actions.
- Assistant acceptance shall remain read-only, exclude raw logs, redact IPs, cite actual ATDR records, preserve follow-up context, and fall back deterministically when an injected external provider failure occurs.
- Backup/restore acceptance shall use only the disposable source and a second empty disposable target, verify checksum/counts/revision, and refuse overwrite of the active source.
- Public output shall omit raw evidence, secrets, private paths, credentials, and connection values.
- Synthetic SQLite acceptance is regression evidence only. It does not satisfy real-device, approved-host PostgreSQL, provider-backed IAM, independent detection/ML, or production-response requirements.

## v4.9 Detection and ML Reliability Addendum

- **FR-ATDR-050:** Deterministic detection rules shall have stable IDs, semantic versions, required fields, source/window scope, confidence, false-positive guidance, references, explanation templates, and claim boundaries in a machine-readable catalog.
- Repeated-behavior rules and behavior-window features shall be source-scoped and event-time bounded. Future rows and cross-source address collisions shall not contribute to the current row's features.
- Generic vendor THREAT, application risk, application characteristics, and directionless byte/packet outliers shall not be promoted to C2, exfiltration, or DoS claims without the required supporting evidence.
- Supervised evaluation shall preserve original label source, require explicit eligible/reviewed status, disclose assisted-source counts, and never present AI-generated labels as human-reviewed.
- Fit, calibration, threshold-selection, and final-test roles shall remain separate. Exact/near/feature duplicate groups and normalized-log identities shall not cross partitions.
- Required reliability views shall include temporal holdout, a source/group proxy where true device holdout is unavailable, and repeated random splits. Proxy evidence must be labeled honestly.
- Strict gates are FPR `<=0.10`, threat-positive F1 `>=0.85`, suspicious recall `>=0.80`, malicious recall `>=0.80`, ECE `<=0.10`, and max confidence/accuracy gap `<=0.15` on every required split.
- A locked final external benchmark shall not be used to engineer features, select candidates, calibrate probabilities, or tune thresholds.
- The active artifact and diagnostic candidates shall be displayed separately. Unknown active metadata must not be guessed, and candidate diagnostics must not be shown as active/promoted models.
- v4.9 remains `candidate_only`; it shall not write labels, model runs, active artifacts, response actions, or real firewall configuration.

## v5.1 Governed Supervised Lifecycle Addendum

- **FR-ATDR-051:** ATDR shall register reproducible supervised SOC queue artifacts with model/feature versions, dataset fingerprint, label provenance, code revision, split metrics, calibration, threshold, checksum, timestamp, readiness, and lifecycle state.
- Governed states are `inactive`, `shadow_observation`, and gated `decision_support`. `production_promoted` is not implemented and shall be rejected.
- Shadow inference may expose queue probability and provenance but shall not create or suppress alerts, change severity, alter labels, start detection, execute response, or enable firewall action.
- Rules remain alert-authoritative. A missing, corrupt, incompatible, or slow model shall fail safely to rule-only operation.
- `decision_support` shall be denied unless every required split and locked external gate meets the v4.9 FPR, F1, suspicious/malicious recall, ECE, maximum-gap, leakage, and safety targets.
- Activation, disable, and rollback shall be admin-controlled and audited. Disable/rollback shall preserve logs, labels, alerts, and evidence.
- The unknown legacy artifact shall remain unselected unless it can be tied to complete governed registry metadata; v5.1 shall not overwrite it silently.
- Private-file shadow validation shall use disposable storage, return safe aggregates only, and distinguish operational queue volume from labeled accuracy.
- v5.1 remains `shadow_observation`: strict quality passes 0/5, external transfer fails, production promotion is false, and response automation is disabled.

## v5.2 Shadow Reliability And Layered Detection Addendum

- **FR-ATDR-052:** Deterministic rule matches shall be the sole authority for
  alert eligibility, score, severity, and primary attack type. IsolationForest,
  supervised, and hybrid evidence shall remain advisory and shall not suppress
  a strong deterministic rule.
- Controlled layered validation shall preserve scenario cadence and report a
  machine-readable FP/FN failure matrix with rule, anomaly, supervised, and
  hybrid evidence components.
- Field-poor parser/fallback anomaly evidence shall retain its raw anomaly score
  while using bounded uncertainty language rather than an unsupported attack
  claim.
- Supervised selection shall include temporal, source-disjoint (or fail-closed),
  network-zone proxy, and random-seed views with separated fit, calibration,
  threshold, and final-test roles.
- No candidate shall be selected unless every required internal view passes the
  fixed FPR/F1/recall/calibration/leakage/safety gates. Locked external labels
  shall never be used for feature, model, calibration, or threshold selection.
- Shadow telemetry may persist only aggregate model version, inference/failure,
  latency, missingness, score-distribution, queue-rate, and drift fields. It
  shall exclude raw logs, IPs, labels, private paths, and secrets.
- v5.2 selects no supervised candidate and remains `shadow_observation`.
  Production promotion, automatic response, and real blocking remain false.

## v5.3 Temporal Generalization And OOD Addendum

- **FR-ATDR-053:** Supervised reliability evaluation shall include leakage-safe
  rolling chronological windows in addition to temporal, source, network-proxy,
  and repeated random views.
- Fit, calibration, threshold-selection, and final roles shall remain separate.
  Final and rolling-future labels shall contribute zero rows to tuning.
- OOD state shall be derived from fit-only schema, missingness, categorical,
  numeric-range, and confidence evidence. Unfamiliar or unstable rows shall be
  reported as `insufficient_model_evidence`, not forced into a confident claim.
- Abstention shall remain visible in analyst queue and FPR accounting; it shall
  not improve reported quality by silently dropping difficult rows.
- Locked external aggregate evidence shall fail closed when row-level frozen
  predictions are unavailable. Provider labels shall not be reopened for v5.3
  feature, model, calibration, threshold, or strategy tuning.
- AI Governance shall expose aggregate temporal drift, OOD, abstention,
  coverage, calibration, and blocker information without raw logs, identifiers,
  labels, private paths, or secrets.
- v5.3 selects no candidate and remains `shadow_observation`. Rules remain
  alert-authoritative; production promotion, automatic response, and real
  firewall blocking remain false.

## v5.4 Temporal Evidence And Shadow Drift Addendum

- **FR-ATDR-054:** Every governed supervised evidence role shall have a stable
  aggregate fingerprint and shall fail closed if fit, calibration, threshold,
  final, rolling, external, or artifact state changes unexpectedly.
- Locked temporal-final, rolling-future, external-final, and duplicate
  quarantine evidence shall contribute zero rows to development or tuning.
- Development manifests shall preserve provenance, time role, schema profile,
  pseudonymous source/group identity, duplicate group, and exclusion reason
  without exporting raw evidence or private identifiers.
- Rule-, ML-, and hybrid-assisted suggestions shall never be represented as
  human-reviewed and shall remain non-import-ready until a human confirms them.
- Private-file inspection shall be read-only, aggregate-only, disposable, and
  unable to return a path, raw row, IP address, secret, or reusable fingerprint.
- Shadow drift shall report `Stable`, `Drift Warning`, `OOD Warning`, or
  `Insufficient Evidence` against the governed fit baseline.
- v5.4 remains `shadow_observation`; it selects no candidate and changes no
  model, label, response, detection authority, or active artifact.

## v5.5 Development Model Repair And Anomaly Reliability Addendum

- **FR-ATDR-055:** Supervised model repair shall use only evidence roles
  explicitly designated for development by the governed v5.4 lock.
- Nested development validation shall preserve chronological order, isolate
  duplicate groups, separate fit/calibration/threshold/final roles, and use
  provenance-aware sampling without changing label provenance.
- Locked temporal-final labels may be read exactly as a post-freeze,
  read-only regression and shall not influence feature engineering, strategy
  ranking, calibration, threshold selection, or repeated tuning.
- Diagnostic comparison shall include calibrated tree, linear, three-class
  SOC queue, and hierarchical strategies. A best diagnostic leader is not an
  activated or promotion-eligible model.
- IsolationForest shall be evaluated separately for benign noise, threat
  capture, application/schema/time distributions, controlled benign traffic,
  and queue stability. Its output remains advisory.
- Fixed readiness gates remain FPR `<=0.10`, queue F1 `>=0.85`, suspicious
  recall `>=0.80`, malicious recall `>=0.80`, ECE `<=0.10`, and maximum
  confidence/accuracy gap `<=0.15` across every required development view.
- AI Governance may expose aggregate v5.5 metrics and blockers only. It shall
  not expose raw evidence, private identifiers, labels, paths, or secrets.
- v5.5 remains `shadow_observation`: no model is activated/promoted, no active
  artifact is written, rules remain alert-authoritative, and response
  automation and real blocking remain disabled.

## v5.6 Private PAN-OS Evidence And Assisted Repair Addendum

- **FR-ATDR-056:** Private real-source files shall be processed through
  bounded, disposable storage without importing them into the configured
  database or returning paths, raw rows, IPs, secrets, or reusable row
  fingerprints.
- Configured-database overlaps and duplicate families shall be quarantined.
  Exact and near families shall remain wholly within one chronological role.
- Development fit, calibration, threshold, and untouched future roles shall be
  declared before assisted labels are calculated. Future labels shall remain
  sealed until a diagnostic candidate is frozen.
- AI, rule, vendor, and weak-supervision decisions shall use explicit
  provenance and `human_reviewed=false`. Ambiguous evidence shall remain
  `needs_context` or quarantine and shall not enter training.
- Genuinely human-reviewed development evidence shall remain distinct and have
  greater sample weight than assisted evidence.
- Supervised repair shall compare calibrated tree, linear, three-class,
  hierarchical, and weighted strategies across nested chronological
  development views. A strong result against assisted future labels shall be
  described as policy agreement, not independent accuracy.
- IsolationForest alternatives shall be fitted only on high-confidence benign
  development evidence and remain advisory.
- Sparse chronological calibration roles that lack a fitted model class shall
  fail closed to an explicit uncalibrated diagnostic instead of crashing.
- AI Governance may expose only aggregate v5.6 counts, metrics, safety state,
  and blockers.
- v5.6 remains `shadow_observation`: the ignored diagnostic candidate is not
  activated/promoted, active artifacts are unchanged, rules remain
  alert-authoritative, and response automation and real blocking remain
  disabled.

## v5.7 Independent Evidence And Blind Revalidation Addendum

- **FR-ATDR-057:** The v5.6 diagnostic candidate shall be reproducibly frozen
  with model family, feature contract, preprocessing, calibration, threshold,
  training-manifest, code-contract, and artifact identities before any new
  independent labels are available.
- v5.3 fit/calibration/threshold/final/rolling/external roles and v5.4-v5.6
  development/future roles shall remain fingerprinted, immutable, and
  ineligible as fresh independent evidence.
- Independent evidence shall require a compatible PAN-OS schema, at least two
  real devices, at least two independent collection periods, sufficient
  parsed chronological rows, owner/license permission, zero configured-DB
  overlap, and a documented local fingerprint/duplicate-family overlap audit.
- Predictions shall be frozen before labels are revealed. The first valid
  prediction freeze shall be immutable, the review pack shall omit
  predictions, and a successful label reveal shall be one-time and sealed.
- Human-reviewed, advisor-approved human review, and compatible provider
  ground truth are the only allowed blind labels. AI, rule, vendor-assisted,
  Codex-assisted, and weak-supervision decisions shall not be accepted as
  human ground truth.
- Blind readiness gates are threat/SOC queue F1 `>=0.85`, benign-like FPR
  `<=0.05`, suspicious recall `>=0.80`, malicious recall `>=0.80`, ECE
  `<=0.10`, maximum confidence/accuracy gap `<=0.15`, zero evidence leakage,
  zero actual-threat suppression by post-prediction guards, and valid
  independent source/time evidence.
- The frozen v5.6 candidate uses calibrated threshold-only decisions and no
  post-prediction suppression guard.
- IsolationForest shall be audited on the same independent evidence only after
  valid labels are revealed and shall remain advisory.
- AI Governance shall expose only aggregate candidate, evidence, validation,
  lifecycle, rule-authority, and response-safety status. It shall not expose
  private paths, raw logs, IP addresses, row values/fingerprints, labels, or
  secrets.
- When valid independent evidence is unavailable, the required outcome is
  `independent_evidence_required`; blind metrics shall remain hidden and the
  lifecycle shall remain `shadow_observation`.

## v5.8 Governed Shadow Runtime Addendum

- **FR-ATDR-058:** The frozen v5.6/v5.7 candidate may be evaluated only by a
  disabled-by-default, bounded, read-only shadow runtime.
- The runtime shall fail closed if artifact identity, code contract, feature
  contract, model family, calibration, classes, threshold, inactivity,
  response-safety, or rule-authority fields are absent or mismatched. It shall
  never silently select another model.
- Shadow scoring shall accept only normalized logs, preserve chronological
  order and optional source/time scope, enforce batch/timeout limits, and
  produce idempotent aggregate results without persistent evaluation writes.
- Telemetry may include aggregate queue, score, confidence, drift,
  source/time stability, rule/ML agreement, and separately identified
  persisted IsolationForest values. It shall not include raw logs, IPs,
  paths, hashes, feature names, row fingerprints, labels, or secrets.
- Shadow output shall not create, suppress, prioritize, or modify
  authoritative alerts; change cases, labels, runs, users, or model state; or
  trigger response.
- Governed evidence intake shall validate manifest/schema/chronology,
  devices/periods, permission/provenance, checksums, overlap, and duplicate
  containment. Reused v5.3-v5.7 evidence shall be rejected.
- Accuracy/calibration metrics shall not be calculated without sealed,
  independently governed labels.
- The lifecycle remains `shadow_observation`; rules are alert-authoritative,
  IsolationForest is advisory, production promotion is false, response
  automation is disabled, and real blocking is disabled.

## v5.9 Longitudinal Shadow Observation Addendum

- **FR-ATDR-059:** ATDR may persist append-only aggregate observations from
  the exact frozen governed shadow candidate only when both scoring and
  observation features are explicitly enabled.
- Every observation shall be source/time/row bounded, chronologically
  reproducible, and idempotent for the same candidate contract and scope.
- Persisted/API/job/UI output shall exclude raw logs, IP addresses, private
  paths, row/file fingerprints, feature lists, labels, and secrets.
- Durable observation jobs shall be admin-only, retry-safe, and cooperatively
  cancellable before aggregate persistence.
- Retention shall be explicit, previewable, admin-only, audited, and limited
  to the aggregate observation table.
- AI Governance may show only aggregate count, drift, queue,
  rule-disagreement, and bounded trend telemetry with rule-authority and
  response-safety state.
- Private source inspection shall use disposable storage, shall not access the
  configured database, and shall report aggregate drift/parser quality only.
- Reused unlabeled development evidence shall never support accuracy,
  false-positive, recall, F1, or calibration claims.
- Independent model advancement still requires new compatible multi-device,
  multi-period evidence, prediction-before-label, allowed human/provider
  ground truth, fixed blind gates, and advisor approval.
- The lifecycle remains `shadow_observation`; no model activation/promotion,
  authoritative alert influence, response automation, or real blocking is
  authorized.

## v5.10 Detection Operations And Shadow Acceptance Addendum

- **FR-ATDR-060:** ATDR shall plan bounded, non-overlapping historical
  source/time scopes from existing normalized evidence for aggregate
  operational shadow acceptance.
- Public scope, API, CLI, job, and dashboard output shall use opaque source
  labels and exclude source identity, raw logs, IPs, private paths,
  fingerprints, labels, and secrets.
- Every operational scope shall be marked reused development operational
  evidence and shall not be described as independent validation.
- A frozen-candidate contract mismatch shall fail before observation
  persistence; cancellation shall not leave partial observations.
- Repeated execution of the same candidate/scope contract shall reuse the
  existing observation key rather than create a duplicate.
- Acceptance shall report queue, rule/shadow disagreement, drift,
  data-quality, persisted IsolationForest, runtime, and operational gate
  aggregates without calculating unlabeled accuracy.
- The AI Governance dashboard shall expose operational warnings and safety
  state but shall not expose analyst execution controls.
- The large-SQLite Governance path shall preserve cold/warm response
  equivalence and remain within the local smoke budget.
- Rules remain alert-authoritative, IsolationForest remains advisory, the
  lifecycle remains `shadow_observation`, and activation, promotion,
  automatic response, and real blocking remain prohibited.

## v5.27 Blind Review And Real-Record Assistant Quality Addendum

- **FR-ATDR-075:** ATDR shall validate independent blind-review decisions
  against the existing frozen prediction lock without rerunning prediction.
- A valid blind review shall require a real reviewer identity, timezone-aware
  timestamp, explicit reviewed/confirmed flags, allowed decision, confidence,
  and meaningful notes.
- Assisted, weak, AI-, rule-, heuristic-, model-generated, incomplete, token-
  mismatched, or prediction-exposed reviews shall be rejected and shall never
  count as human ground truth.
- Blind metrics shall remain unavailable until at least 20 legitimate reviews
  and both queue classes exist. A consumed blind pack shall never be used for
  tuning or candidate selection.
- Locked evaluation may report confusion counts, queue metrics, class recall,
  macro/weighted F1, calibration, and aggregate error patterns without
  returning row tokens, fingerprints, reviewer identity, paths, raw evidence,
  IP addresses, or secrets.
- **FR-ATDR-076:** ATDR shall support bounded Assistant quality evaluation over
  representative existing dashboard records copied into disposable storage.
- The bounded snapshot shall replace raw log values, IPs, source names, user
  fields, and private metadata before provider execution.
- Assistant acceptance shall check citations, active-record continuity,
  evidence relevance, unsupported IDs, concision, safe recommendations,
  latency/token use, deterministic fallback, privacy, and zero authoritative
  side effects.
- Automated Assistant checks shall not be represented as proof of universal
  semantic accuracy. Human semantic/privacy acceptance and provider operations
  governance remain required.
- Rules remain alert-authoritative; supervised ML remains
  `shadow_observation`; Gemini remains read-only; automatic response and real
  firewall blocking remain disabled.

## v5.26 Native Blind Qualification Addendum

- **FR-ATDR-075:** ATDR shall support a one-time native PAN-OS blind
  qualification that freezes unchanged rule, anomaly, supervised-shadow, and
  hybrid predictions before accessing human-decision fields.
- The qualification shall validate chronological role, duplicate-family,
  blind-pack, source, and frozen-candidate locks and fail closed on mismatch.
- Blind evidence shall not be used for fit, calibration, threshold selection,
  candidate selection, or post-result tuning.
- Only independently human-reviewed blind decisions with reviewer and review
  evidence may count as ground truth. Assisted, weak, rule-derived, model, or
  AI suggestions shall never be represented as human labels.
- Precision, recall, F1, false-positive rate, calibration, and error-pattern
  claims shall be withheld when legitimate support or class coverage is
  insufficient. Queue rate shall remain explicitly distinct from accuracy.
- The private source shall be accepted only by CLI argument, processed in
  disposable storage, and excluded from the configured database and tracked
  repository.
- Public output shall exclude private paths, raw evidence, IP addresses,
  source identities, fingerprints, labels, credentials, and secrets.
- A successful protocol run shall not activate/promote a model, create an
  artifact, alter authoritative alerts, or enable automatic/real response.
- Full qualification shall be one-shot. Any future repaired candidate shall
  use a new preregistered untouched blind corpus.

## v5.25 Integrated Acceptance Addendum

- **FR-ATDR-071:** ATDR shall provide one disposable, aggregate-only acceptance
  path across collection, normalization, recovery, local transport, rule
  detection, advisory ML, investigation, Assistant evidence, simulated
  analyst response, and audit.
- Integrated acceptance shall require exact raw/normalized accounting,
  source/evidence traceability, alert deduplication, case/explanation evidence,
  missing-justification and protected-target denial, and configured-database
  preservation.
- Gemini acceptance may use a fresh bounded provider run or a validated
  immutable v5.24 quality lock. Deterministic fallback shall not be counted as
  provider quality evidence.
- Startup, teammate setup, RBAC, responsive UI, privacy, performance, and
  release gates remain independently verifiable; one aggregate result shall
  not hide a failed subsystem.
- Local product-closure status shall list non-loopback transport, real device,
  independent human labels, MFU preproduction, approved host, and provider
  governance as separate external gates.
- Rules remain alert-authoritative; supervised ML remains
  `shadow_observation`; Assistant remains read-only; response remains simulated
  and analyst-approved; production readiness is not claimed.

## v5.24 Investigation And Gemini Quality Addendum

- **FR-ATDR-074:** Alert and log investigation shall present what happened,
  why evidence was flagged or not flagged, evidence strength, missing context,
  and bounded analyst checks before technical model telemetry.
- Technical rule/anomaly/supervised/hybrid and raw diagnostic structures shall
  remain available through progressive disclosure without horizontal overflow.
- Runtime navigation and empty states shall use operational SOC terminology,
  not classroom, advisor, presentation, or demo language.
- External assistant answers shall use bounded structured output and only
  citations supplied by the trusted ATDR context builder. A primary trusted
  citation shall be attached to record-specific answers.
- Assistant quality shall be measured across alert, log, source, case, and
  follow-up workflows for context retention, grounding, citation correctness,
  unsupported identifiers, concision, latency, token use, provider failure,
  privacy, and authoritative side effects.
- Raw logs shall remain excluded from external context and IP redaction shall
  remain enabled. The assistant shall remain read-only and shall not mutate
  alerts, detection, labels, models, users, sources, or responses.
- Passing a bounded provider contract does not establish universal answer
  correctness, production readiness, or authority to act.

## v5.23 Live-Source Acceptance Addendum

- **FR-ATDR-068:** ATDR shall provide a disposable acceptance path covering
  direct file import, authenticated multipart API import, durable queued
  import, backpressure, committed-chunk recovery, and replay through a real UDP
  socket.
- Acceptance shall verify source health, parser quality, source-scoped
  detection history, alert deduplication, case/evidence linkage, why-flagged
  explanations, analyst recommendations, and audit history.
- Local-loopback, external second-laptop, and real firewall/router evidence
  shall be reported as distinct classes. Loopback success shall not complete
  the external transport gate or imply device validation.
- Public results shall exclude private paths, raw rows, sender/source/destination
  addresses, fingerprints, staging paths, database URLs, credentials, and
  secrets.
- The configured database shall never be an acceptance target; disposable
  storage shall be removed after each run.
- Rules shall remain alert-authoritative. No acceptance run may create labels,
  model activations/promotions, response actions, automatic response, or real
  firewall blocking.

## v5.22 Supervised Model Rebuild Requirement Update

ATDR shall select supervised review-queue candidates only from predeclared
fit, calibration, threshold, and development-evaluation evidence. Human
authorship must be determined from approved provenance, not a generic reviewed
flag. Weak/rule/vendor-assisted labels shall remain lower-weight development
evidence and shall never be presented as independent ground truth.

The current frozen configuration is diagnostic-only hierarchical two-stage
ExtraTrees at threshold `0.40`. It is not an active artifact. Suspicious recall,
calibration, source independence, and blind human confirmation remain mandatory
gates. Rules remain alert-authoritative and response automation remains
disabled.

## v5.20 Schema-Aware Abstention Addendum

- **FR-ATDR-062:** Governed supervised inference shall validate evidence
  compatibility before model execution.
- The current supervised contract expects native `palo_alto` evidence with a
  timestamp, source/destination IP presence, destination port, protocol,
  action, and application.
- Incompatible, unknown, parser-failed, or incomplete evidence shall abstain
  and shall not return a supervised queue probability.
- Historical rows without explicit parser-profile metadata may use ATDR's
  established Palo Alto default only when every required field is present.
- Abstention shall not create, suppress, reprioritize, or reduce a deterministic
  rule alert. Rules remain alert-authoritative.
- Alert explanations and AI Governance shall expose privacy-safe schema status,
  reason codes, missing field names, and aggregate abstention counts.
- v5.19 terminal evidence shall remain immutable and shall not be reopened for
  tuning or a new blind claim.
- The lifecycle remains `shadow_observation`; model activation/promotion,
  automatic response, and real firewall blocking remain prohibited.

## v5.21 Native PAN-OS Evidence Program Addendum

- **FR-ATDR-069:** ATDR shall prepare private native PAN-OS evidence through an
  explicit disposable-storage CLI without opening or writing the configured
  database.
- Evidence roles shall be assigned chronologically before any assisted
  decision: development fit, calibration, threshold selection, and untouched
  future validation.
- Exact and near-duplicate families shall not cross evidence roles.
- Development suggestions shall remain weak/assisted, require human
  confirmation, and remain not import-ready.
- Untouched-future evidence shall contain no rule, model, or AI suggestion and
  shall stay sealed during model development.
- Public output shall exclude raw rows, source/destination addresses, private
  paths, reusable fingerprints, database details, and secrets.
- Official PAN-OS field semantics shall guide evidence interpretation. TRAFFIC
  action/application/port context, THREAT records, and application risk shall
  not be converted automatically into human-reviewed labels.
- The complete private source may support diagnostic native-schema rebuilding,
  but one device and absent independent labels shall remain insufficient for
  activation, production promotion, or source-generalization claims.
- Rules remain alert-authoritative; model activation/promotion, automatic
  response, and real firewall blocking remain prohibited.

## v5.19 Independent Labeled Validation Addendum

- **FR-ATDR-063:** ATDR shall support a one-shot, prediction-before-label
  evaluation against authoritative independent network-security evidence.
- Evidence selection shall use primary publisher/university sources and record
  provenance, license, schema, label meaning, collection limitations, and
  development-overlap decisions.
- The private evidence manifest shall be immutable and remain outside Git.
- Feature mapping, taxonomy, ambiguity handling, duplicate containment,
  candidate identity, calibration, threshold, metrics, and gates shall be
  frozen before final labels are read.
- Sampling, features, and predictions shall not access provider labels.
- Provider taxonomy shall not be expanded into unsupported ATDR classes.
- Repeated final-label execution shall fail closed.
- A post-blind adapter diagnostic shall preserve the original failed record,
  retain frozen predictions, and remain ineligible for activation.
- Public output shall exclude paths, checksums, raw rows, IPs, database URLs,
  secrets, and private evidence identifiers.
- Independent transfer failure shall retain `shadow_observation`; it shall not
  trigger model tuning, alert authority, automatic response, or blocking.

## v5.14 Large-File Runtime Acceptance Addendum

- **FR-ATDR-064:** ATDR shall provide a fail-closed, disposable acceptance
  path for large private PAN-OS files that composes the production runtime
  staging, durable job, transactional import, source, parser-quality,
  detection, alert, case, and dashboard read services.
- Runtime acceptance shall refuse configured-database processing and shall
  preserve an unchanged configured SQLite marker when one is available.
- Full-file preflight shall return aggregate record types, schema classes,
  parser quality, application-resolution quality, chronological coverage, and
  duplicate counts without returning paths, raw rows, IPs, row fingerprints,
  source identities, or secrets.
- One physical source may be partitioned into simulated logical windows for
  source-scoped runtime checks only. Such windows shall never be represented
  as independent physical devices.
- Acceptance shall validate bounded chunks, monotonic committed progress,
  checkpoint interruption/resume, cooperative cancellation, idempotent
  enqueue, lock waiting, and staged-input cleanup.
- Exact repeated log rows shall remain preserved evidence. Duplicate
  accounting shall be distinct from checkpoint-resume idempotency.
- Source counters, last-seen state, parser quality, ingestion/detection
  history, alert evidence, and computed case grouping shall remain
  traceable.
- Detection totals shall be described as operational output, not labeled
  accuracy. Rules remain alert-authoritative; supervised and anomaly ML
  remain advisory/shadow.
- Acceptance shall create no labels, model runs, activation, promotion,
  response actions, automatic response, or real firewall blocking.
- Local SQLite throughput and dashboard timings are measured evidence, not
  an approved-host capacity SLA or production certification.

## v5.16 Full-Scale Memory And Query Stabilization Addendum

- **FR-ATDR-066:** ATDR shall provide a fail-closed, disposable full-scale
  profiling path that measures process memory, ORM identity state, query
  counts/plans, throughput, database growth, integrity, privacy, and cleanup
  without targeting the configured database.
- Full-scale acceptance shall keep whole-process peak memory below 8 GiB or
  demonstrate at least 40 percent reduction from the governed baseline.
- At 773,551 rows, cold Overview and source detail shall remain below three
  seconds and cached Overview below 0.1 seconds in the measured local profile.
- Ingestion and deterministic-detection throughput shall not regress by more
  than ten percent from the corresponding governed baseline.
- Bounded detection may use scalar projections, batched evidence persistence,
  exact scalar case counting, and stage-local memory release only when
  ingestion, parser, rule, alert, dedup, case, source, audit, and API semantics
  remain unchanged.
- Query changes shall be measurement-driven. A scan-based consolidation shall
  not replace a faster indexed query, and schema/index changes require
  independent evidence and Alembic.
- Query profiling shall return aggregate counts and plan steps only; private
  paths, raw rows, IPs, fingerprints, SQL parameters, and secrets are
  prohibited.
- Rules remain alert-authoritative; supervised ML remains
  `shadow_observation`; no label/model/response/activation/promotion write is
  permitted.
- Local SQLite evidence is not an approved-host PostgreSQL concurrency or
  production-capacity SLA.

## v5.17 PostgreSQL Multi-Worker Capacity And Recovery Addendum

- **FR-ATDR-067:** ATDR shall provide a fail-closed PostgreSQL acceptance path
  that refuses SQLite, the configured database identity, unsafe database
  names, unavailable targets, and missing backup/restore tools.
- The gate shall use at least two workers and verify skip-locked distinct
  claims, private lease fencing, committed checkpoints, evidence-mutating
  stale recovery, cancellation/resume, shared staging identity, exact source
  counters, and concurrent idempotency containment.
- PostgreSQL detection alert/dedup writes shall be transactionally coordinated
  so concurrent same-scope runs cannot commit duplicate alert evidence from
  the same pre-commit view. Coordination shall be bounded and shall not change
  rule meaning, thresholds, grouping, severity, or response policy.
- Capacity evidence shall include aggregate throughput, process memory, pool
  use, chunk commit interval percentiles, database growth, dashboard/query
  latency, query counts, lock state, and privacy-safe plan node types.
- Backup shall produce a checksum/count/revision manifest and restore only
  into a second empty disposable PostgreSQL database. Both disposable
  databases, staging, and backup artifacts shall be removed.
- The gate shall return no database URL, credential, private path, raw row,
  IP, fingerprint, or secret.
- Missing PostgreSQL infrastructure shall return `blocked_by_environment`;
  SQLite shall never be substituted as a passing result.
- Rules remain alert-authoritative, supervised ML remains
  `shadow_observation`, and no labels, model runs, activation, promotion,
  automatic response, or real blocking may be created.
- Ephemeral CI evidence is repository regression evidence. Multi-host storage,
  approved-host capacity, real devices, and production SLA evidence remain
  separate gates.

## v5.18 Approved-Host PostgreSQL Scale Qualification Addendum

- **FR-ATDR-068:** ATDR shall provide an explicit approved-host scale gate
  that qualifies 100,000 rows before allowing a 250,000-row PostgreSQL run.
- Preflight shall require two distinct empty disposable PostgreSQL databases,
  PostgreSQL 16 or newer, `plpgsql`, compatible `psql`/`pg_dump`/`pg_restore`,
  sufficient memory/disk, connection headroom for the requested workers, and
  an exact execution confirmation.
- The gate shall run 2-worker and 4-worker profiles and reconcile exact raw,
  normalized, parser, source, detection, alert, evidence, and case counts.
- Fixed SLOs shall cover throughput, ingestion runtime, chunk p99, full-stage
  RSS, database growth, pool timeouts, lock waiters, and cold/cached Overview,
  alert, case, and source-detail queries.
- Alert list and case summary paths may use exact aggregate evidence counts
  with bounded ID samples. When IDs are truncated, the API shall expose that
  fact explicitly; count and source traceability must remain exact.
- The gate shall validate lease fencing, stale recovery, committed-boundary
  cancellation/resume, concurrent idempotency, source-scoped detection/dedup
  consistency, checksum/revision/count backup, isolated restore, configured
  database preservation, and disposable cleanup.
- A passed single-host qualification closes only the measured PostgreSQL
  capacity gate. It does not establish multi-host behavior, a production SLA,
  real-device acceptance, independent Detection/ML accuracy, or provider and
  deployment security readiness.
- Rules remain alert-authoritative, supervised ML remains
  `shadow_observation`, and no label, model activation/promotion, automatic
  response, or real blocking write is permitted.

## v5.15 Long-Duration Runtime Soak Addendum

- **FR-ATDR-065:** ATDR shall provide a fail-closed disposable runtime-soak
  path that validates progressive 250,000-row, 500,000-row, and complete-file
  checkpoints without writing to the configured database.
- The soak shall measure aggregate input/resource state first and require at
  least three times estimated temporary-storage headroom before processing.
- Fault injection shall occur only after committed chunk boundaries and shall
  cover repeated worker handoff, cancellation/resume, stale-lease
  fail-closed recovery, explicit resume, and bounded database lock wait.
- Progress, line checkpoints, byte checkpoints, source counters,
  ingestion-run counters, raw/normalized counts, and staging retention shall
  reconcile after every recovery.
- Disposable SQLite integrity, foreign keys, normalized/raw/source links,
  alert evidence, database growth, and cleanup shall be verified.
- Source-scoped rule detection, alert evidence, and computed cases shall
  remain traceable. Operational detector totals shall not be described as
  labeled accuracy.
- Runtime evidence shall include ingestion/parsing/detection throughput,
  chunk/resume/cancellation/lock latency, traced memory, database growth,
  dashboard read timings, and cleanup duration.
- The soak shall return no private path, raw row, IP, fingerprint, source
  identity, database, secret, or generated evidence file.
- Rules remain alert-authoritative; ML remains advisory/shadow; labels, model
  activation/promotion, automatic response, and real blocking remain
  prohibited.
- The measured 12 GiB traced-memory peak is a capacity warning. Approved-host
  PostgreSQL/shared-staging and memory optimization remain required before
  production-scale claims.

## v5.13 Runtime Parser Contract And Source Quality Addendum

- **FR-ATDR-063:** ATDR shall apply the versioned parser-quality contract to
  every future file import, direct replay, UDP syslog batch, durable import,
  and controlled scenario without automatically reparsing historical
  evidence.
- Runtime source quality shall distinguish actual parser errors, structural
  warnings, compatible/extended/partial/unsupported layouts, unresolved,
  absent, and not-applicable applications, generic syslog, and raw fallback.
- Unknown or incomplete PAN-OS application values shall remain informational
  unless independent structural or behavioral evidence indicates a problem.
- Source aggregates shall retain a fixed supported baseline and a bounded
  latest window so parser-error increases and structural drift are measured
  rather than inferred from cumulative totals alone.
- Operational alerts and dashboard output shall be aggregate and privacy-safe;
  they shall not expose raw evidence, IP addresses, source identities, private
  paths, labels, secrets, or model artifacts.
- Historical contract coverage may be previewed from stored normalized
  metadata through an authenticated read-only route. The preview shall not
  read raw evidence, mutate rows, or perform a reparse.
- Rules remain alert-authoritative, IsolationForest and supervised ML remain
  advisory, and parser quality shall not trigger labels, model changes,
  automatic response, or real firewall blocking.

## v5.12 Parser-Profile Baseline Repair Addendum

- **FR-ATDR-062:** ATDR shall identify the parser contract, compatibility
  state, parser profile, and application-resolution state for newly parsed
  evidence.
- PAN-OS unresolved application values shall be represented as data-quality
  evidence, not as parser failure unless structural parsing actually fails.
- TRAFFIC, THREAT, and SYSTEM mappings shall remain type-specific; SYSTEM
  records shall not inherit traffic-only fields.
- Generic syslog and raw fallback shall preserve raw evidence and report
  limited/unstructured compatibility without crashing.
- Operational parser baselines shall use governed development-fit aggregates
  only, require minimum support, and fall back conservatively for compatible
  profiles.
- Baseline selection shall not use labels, accuracy, locked-final evidence,
  or source identity and shall not create per-device baselines that hide
  drift.
- Private parser audit shall be bounded, aggregate-only, disposable, and
  exclude paths, raw rows, IPs, source identity, fingerprints, and secrets.
- Historical normalized evidence shall not be reparsed automatically.
- AI Governance may expose concise parser contract, profile-baseline
  provenance, structural quality, unresolved-application rate, and aggregate
  drift only.
- Rules remain alert-authoritative, IsolationForest remains advisory, the
  lifecycle remains `shadow_observation`, and activation, promotion,
  automatic response, and real blocking remain prohibited.

## v5.11 Operational Drift And Shadow Monitoring Addendum

- **FR-ATDR-061:** ATDR shall diagnose longitudinal shadow warnings from
  aggregate operational evidence without reading labels or calculating
  accuracy.
- Diagnostics shall distinguish application-distribution shift,
  schema/missingness shift, parser-profile limitations, parser-quality shift,
  source-volume imbalance, sparse windows, candidate score/queue movement,
  rule/shadow disagreement movement, and IsolationForest variation.
- Fixed drift thresholds and state hysteresis shall not alter the model,
  prediction threshold, rule engine, alert authority, or response behavior.
- Public output shall use opaque source/time labels and exclude source
  identifiers, raw logs, IPs, private paths, fingerprints, labels, and
  secrets.
- Operational cadence shall be disabled by default, bounded, idempotent,
  retry-safe, and cooperatively cancellable through the existing durable job
  infrastructure.
- No always-on scheduler shall be enabled implicitly. An approved external
  operator or scheduler must invoke due checks after scoring, observation,
  and monitoring are explicitly enabled.
- Retention rehearsal shall use disposable storage. Any configured-database
  retention remains a separate explicit, previewed, audited admin action
  limited to aggregate shadow observations.
- AI Governance may expose aggregate root cause, drift, queue,
  disagreement, anomaly, quality, and runtime diagnostics without execution
  controls.
- Rules remain alert-authoritative, IsolationForest remains advisory, the
  lifecycle remains `shadow_observation`, and activation, promotion,
  automatic response, and real blocking remain prohibited.

## v5.28 Blind Review And Assistant Operations Addendum

- **FR-ATDR-077:** Independent blind review shall occur in a separate ignored
  working copy while the sealed evidence pack, review tokens, protected
  evidence, ordering, and frozen predictions remain immutable and separately
  controlled.
- The review workflow shall never reveal rule, IsolationForest, supervised,
  hybrid, Codex, or Gemini suggestions and shall never classify assisted
  decisions as human ground truth.
- Review progress shall expose human completion and class support only. Blind
  accuracy metrics shall remain unavailable until at least 20 legitimate
  reviews and both ground-truth queue classes exist.
- The locked evaluator shall use sealed evidence plus human fields from the
  working copy, shall never rerun predictions, and shall never import labels
  automatically.
- **FR-ATDR-078:** External Assistant providers shall use configurable output
  budgets, bounded retries/timeouts, typed failure handling, circuit breaking,
  and deterministic fallback.
- Assistant operational telemetry shall remain aggregate and content-free; it
  may contain call/failure/fallback counts, latency, tokens, estimated cost,
  and health state but no prompts, answers, raw logs, IPs, private paths, or
  secrets.
- Assistant provider output shall remain read-only decision support and shall
  not create responses, detections, labels, models, users, or deletions.
- Rules remain alert-authoritative, supervised ML remains
  `shadow_observation`, and model promotion, automatic response, and real
  firewall blocking remain prohibited without separate governed evidence and
  approval.

## v5.29 Intent-Aware Assistant Addendum

- **FR-ATDR-079:** The SOC Assistant shall classify each question into an
  explicit response mode and return only the content needed for that intent.
- Routine facts, explanations, next steps, linked-log summaries, source
  health, ranked lists, procedures, governance answers, and explicit
  investigation briefs shall use separate response contracts and hard word
  limits.
- The provider guard shall validate entity scope, requested coverage,
  citations, safety, secrets, and response budget. It shall not reject an
  accurate short answer merely because deterministic context is long.
- Follow-up questions shall retain the active alert, log, source, or case but
  answer only the new question and shall not repeat the complete prior report.
- Detailed evidence and provider/citation information shall remain available
  behind collapsed dashboard controls; the direct answer shall be primary.
- The visible response state shall retain `Read Only`, `Decision Support Only`,
  and `Response Automation Disabled`.
- The Assistant shall not create responses, detection runs, labels, model
  runs, users, deletions, or any other authoritative state change.

## v5.32 Analyst Product Acceptance Addendum

- **FR-ATDR-080:** The primary React Overview shall expose a compact detection
  operations projection using existing governed records only.
- The projection shall include primary-rule alert volume, distinct
  source-linked alert volume, analyst dispositions, unique alerts, grouped
  occurrences, deduplication updates, parser context, and recent detection-run
  counts.
- Repeated evidence rows shall not inflate source-linked alert counts.
- Alert volume, occurrence counts, deduplication, parser quality, and analyst
  dispositions shall be described as workload or operational evidence, not
  model accuracy.
- When independent labeled accuracy evidence is unavailable, the operational
  view shall display `Insufficient Evidence` and direct quality claims to AI
  Governance.
- **FR-ATDR-081:** Safe SOC Assistant conversation and active entity context
  shall persist across supported React navigation, explicit entity IDs shall
  replace stale context, and broad/latest requests shall clear stale entity
  context.
- Assistant answers shall remain concise, citation-backed, provider-truthful,
  redacted, read-only, and unable to mutate response, detection, label, model,
  user, or data state.
- Rules remain alert-authoritative, supervised ML remains
  `shadow_observation`, and automatic response and real firewall blocking
  remain disabled.

## v5.33 Independent Detection And Assistant Human Acceptance Addendum

- **FR-ATDR-082:** ATDR shall validate the existing sealed native blind review
  pack without rerunning predictions, exposing predictions to reviewers, or
  calculating final metrics before fixed review and evidence gates pass.
- Review status shall distinguish missing working copy, incomplete human
  review, invalid human input, and evaluation-ready state without exposing
  reviewer identities, private evidence, paths, IPs, or fingerprints.
- Fixed supervised gates shall be recorded before blind labels are opened and
  shall cover false-positive rate, queue precision/recall/F1, suspicious and
  malicious recall, calibration, class support, source/time stability, and
  zero development overlap.
- **FR-ATDR-083:** ATDR shall support a separate integrity-protected human
  acceptance worksheet for representative alert, log, source, case, ML-
  governance, and safe-response Assistant questions.
- Automated Assistant contract checks and human semantic acceptance shall be
  reported separately. AI-generated reviewer identities shall not satisfy the
  human gate, and the worksheet shall never be import-ready.
- Gemini operations shall expose aggregate provider readiness, timeout,
  fallback, bounded tokens, optional configured-rate cost, and local rate
  limits without prompts, answers, secrets, raw logs, or IPs.
- Provider account quota, key rotation, privacy, and retention approval remain
  external institutional responsibilities.
- Rules remain alert-authoritative; supervised ML remains
  `shadow_observation`; Gemini remains read-only; model promotion, automatic
  response, and real blocking remain disabled.

## v5.34 Assistant Concision And Provider Reliability Addendum

- **FR-ATDR-084:** Deterministic and external-provider Assistant answers shall
  use the same mode-specific presentation contract before being returned to
  the dashboard.
- Direct answers shall not exceed 80 words, alert explanations shall not
  exceed 120 words, and investigation briefs shall not exceed 160 words.
- Evidence, assessment, recommendations, and limitations shall be compact and
  semantically deduplicated. Citations shall remain visible and restricted to
  supplied ATDR references.
- Case handoff shall be a dedicated read-only response mode, not a generic
  list or persisted incident operation.
- **FR-ATDR-085:** Provider timeout, quota, rate limit, malformed output,
  citation rejection, safety rejection, grounding/quality rejection,
  availability, and circuit-breaker outcomes shall be classified without
  returning provider payloads or secrets.
- Provider availability and automated answer quality shall be reported as
  separate contracts. A safe deterministic fallback may pass answer-quality
  checks while provider operations remain degraded.
- Conversation IDs and active alert/log/source/case context shall survive
  supported React navigation; explicit new IDs and clear-context actions shall
  replace stale context.
- Human acceptance shall remain separate and incomplete until a genuine
  reviewer scores the protected worksheet.
- The Assistant remains read-only; raw logs remain excluded; redaction stays
  enabled; no detection, label, model, user, deletion, response, or firewall
  authority is added.

## v5.35 Large-SQLite Overview Performance Requirements

- **NFR-ATDR-035:** On the current supported local dataset, uncached Overview
  shall complete within `1.0s`, cached Overview within `0.05s`, ingestion
  summary within `2.0s`, alert and case summaries within `0.25s`, and
  lightweight ML Governance within `2.0s` under the documented measurement
  method.
- Overview cache misses shall use no more than 35 SQL statements and valid
  cache hits no more than one freshness statement.
- Source-scoped alert volume shall remain an exact distinct-alert count and
  shall use index-covered evidence-to-source lookup hops on large SQLite data.
- ML Governance anomaly distributions by source IP, destination IP, and
  protocol shall remain index-covered on the supported large local dataset.
- Optimization shall preserve all API fields, counts, source/status/severity
  semantics, cache invalidation, and empty-dataset behavior.
- Any index migration shall be additive, preserve existing application rows,
  and compile for both SQLite and PostgreSQL.
- Performance work shall never change detection, parser, deduplication, ML,
  IAM, Assistant, response, or audit authority and shall not hide a warning
  unless its measured cause is repaired.
- These are controlled local acceptance targets, not production or shared-host
  SLAs. OS disk-cache state and deployment capacity must be reported honestly.

## v5.36 Independent Evidence And Activation Requirements

- **FR-ATDR-086:** ATDR shall provide one canonical read-only supervised
  activation-decision command that reuses the sealed prediction lock, strict
  human-review validator, registered artifact audit, fixed quality gates, and
  Assistant/provider acceptance records.
- Blind prediction values and row-level errors shall remain hidden until the
  prediction-before-label, seal, identity, duplicate, provenance, schema,
  minimum-human-support, and binary-class contracts pass.
- Frozen rule, IsolationForest, supervised, and hybrid metrics shall be
  reported only after strict intake permits them and shall never be used to
  select a threshold or tune the candidate against the consumed blind pack.
- Configured-data shadow diagnostics shall remain visibly separate from
  independent evidence and shall disclose source/time/training-overlap limits.
- Eligibility shall require every predeclared evidence and quality gate. An
  eligible result shall permit only a separate explicit manual activation
  review; the audit shall never write or activate an artifact.
- **FR-ATDR-087:** Assistant automated contracts, human semantic acceptance,
  provider availability, and institutional provider governance shall be
  reported as separate states.
- Gemini telemetry shall contain only bounded aggregate call, latency, token,
  cost-status, timeout, retry, rate, and fallback information. It shall expose
  no prompt, answer, provider payload, secret, raw log, IP, or private path.
- The Assistant shall remain read-only and shall execute no detection, label,
  model, user, data, response, or firewall action.
- **NFR-ATDR-036:** The activation audit shall prove configured raw,
  normalized, alert, detection, label, model, response, user, and audit counts
  unchanged and shall fail closed when any required external evidence is
  absent.
- Rules remain alert-authoritative, supervised lifecycle remains
  `shadow_observation` until separately approved, and automatic response and
  real firewall blocking remain disabled.

## v5.37 Blind Evidence Review Requirements

- **FR-ATDR-088:** ATDR shall provide an authenticated `/evidence-review`
  workspace for the existing sealed detection and protected Assistant human
  acceptance contracts.
- Review evidence shall be available only to the assigned analyst/admin
  reviewer. Non-owner admins and analysts may view aggregate progress only.
- Detection review shall expose only the v5.28 approved structured fields and
  shall withhold predictions, model/rule scores, expected labels, review
  tokens, fingerprints, private paths, IPs, raw logs, and hidden truth.
- Detection decisions shall map `benign_like`, `needs_context`, and
  `threat_positive` to the existing valid five-class contract, require
  confidence `1-100`, rationale, attack type where applicable, authenticated
  reviewer provenance, timezone-aware timestamp, and explicit confirmation.
- **FR-ATDR-089:** Assistant acceptance shall expose only protected v5.33
  questions, answers, citations, and context type; require eight `1-5` scores
  and accept/revise/reject; and make no external provider call during review.
- Completed decisions shall be immutable through the API. Pack and protected
  content changes, stale revisions, malformed rows, and automated reviewer
  identities shall fail closed.
- Review persistence shall remain isolated from trainable labels and model
  state. No save or completion shall import, train, tune, activate, run
  detection, create alerts, or execute responses.
- **NFR-ATDR-037:** Review lifecycle audit records shall exclude evidence,
  questions, answers, notes, tokens, predictions, raw logs, paths,
  fingerprints, IPs, and secrets.
- File-backed reviewer ownership is accepted for this controlled private-pack
  workflow; distributed multi-reviewer production operation remains future
  work.

## v5.38 Product Reliability And Failure-Mode Requirements

- **FR-ATDR-090:** ATDR shall provide one canonical disposable acceptance
  command for the supported ingest, normalize, source, detection, deduplication,
  case, Why Flagged, Assistant, evidence-review, simulated-response, audit, and
  recovery workflow.
- The command shall refuse configured-database execution, preserve the
  configured database, remove temporary artifacts, and return concise gate
  results without raw evidence, private paths, IPs, provider payloads, or
  secrets.
- **FR-ATDR-091:** Critical failure behavior shall cover malformed and
  duplicate input, interrupted/cancelled resume, stale workers, malformed
  review evidence, provider failure, missing references, database
  unavailability, frontend query failure, RBAC denial, and supported
  navigation continuity.
- Launcher metadata shall identify a tracked process using both PID and
  recorded start time so that PID reuse cannot falsely block startup.
- Overview, AI Governance, and Response & Audit shall expose concise
  page-level primary-query failure state without implying that a response or
  model operation occurred.
- **NFR-ATDR-038:** The eight primary React routes shall fit supported
  projector, laptop, and mobile viewports without incoherent horizontal
  overflow.
- Product acceptance shall prove zero label/model activation, zero real
  response action, read-only Assistant behavior, response simulation, and
  deterministic-rule authority.
- Passing local synthetic acceptance is not production readiness and shall
  not replace genuine human, real-device, MFU-provider, shared-host, privacy,
  or disaster-recovery evidence.

## v5.41 Governed Blind Evidence Requirements

- **FR-ATDR-092:** ATDR shall revalidate the consumed v5.39 evidence boundary
  and v5.40 development cutoff before accepting future supervised evidence.
- Private candidate logs shall be parsed only in disposable storage and shall
  never be imported into the configured database by the v5.41 workflow.
- Qualification shall require events strictly after the cutoff, a genuine
  human physical-source attestation, source independence, and zero configured,
  consumed, exact, near, temporal, or custody overlap.
- Human review shall remain closed until at least two independently verified
  physical sources, three disjoint windows, and 240 isolated rows exist.
- Frozen predictions shall be stored in a separate ignored seal. Reviewer-
  visible evidence shall contain no prediction, score, suggestion, answer key,
  fingerprint, raw-log, or IP column.
- Protected collection, candidate, prediction, and review content shall be
  integrity-bound and fail closed on alteration or partial state.
- AI Governance shall expose aggregate readiness only: Designed, Collecting,
  Insufficient Sources, Ready For Human Review, Review Complete, or Ready For
  Frozen Evaluation.
- Frozen metrics shall remain unavailable until genuine human review and fixed
  support targets pass. The review pack shall never become import-ready
  automatically.
- Rules remain alert-authoritative; supervised lifecycle remains
  `shadow_observation`; no model/label/detection/alert/response write, automatic
  response, or real firewall action is permitted.

## v5.42 Development Candidate Freeze Requirements

- **FR-ATDR-093:** ATDR shall revalidate the v5.39 consumed-evidence boundary,
  v5.40 development population, and v5.41 custody state before any candidate
  freeze evaluation.
- Candidate selection shall use exactly the predeclared five-strategy set and
  development-only fit, calibration, threshold, and nested temporal evaluation
  roles with duplicate-group isolation.
- Every fold shall satisfy fixed precision, recall, F1, benign-FPR,
  suspicious-recall, malicious-recall, ECE, confidence-gap, and no-leakage
  gates; review-queue spread shall also satisfy a fixed stability ceiling.
- No gate may be weakened after results are observed to force a candidate.
- At most one diagnostic artifact may be frozen. Its contract and artifact
  shall be immutable, private, ignored, inactive, not production-promoted, and
  unable to create or suppress authoritative alerts.
- Conflicting, partial, or tampered freeze state shall fail closed.
- v5.39 labels/predictions and v5.41 blind evidence shall not be used for
  training, thresholding, calibration, ranking, or diagnosis.
- AI Governance shall expose aggregate candidate readiness only and shall not
  expose paths, digests, row identifiers, fingerprints, source identities,
  blind predictions, raw logs, or secrets.
- Failure to satisfy every gate shall preserve `shadow_observation`,
  deterministic-rule authority, disabled response automation, and disabled
  real blocking.

## v5.43 Temporal Stability Repair Requirements

- **FR-ATDR-094:** ATDR shall support a fixed development-only repair protocol
  that revalidates v5.39-v5.42 custody before fitting.
- The protocol shall compare exactly the predeclared baseline, inverse
  duplicate weighting, temporal/provenance weighting, stronger assisted-label
  down-weighting, and compact stable-feature hierarchical variants.
- It shall use only duplicate-isolated development fit, calibration, threshold,
  and evaluation roles and shall preserve the unchanged v5.42 gates.
- Feature analysis shall report aggregate missingness, drift, redundancy,
  constant/source-specific behavior, and possible label-derived names without
  returning private rows or identifiers.
- At most one ignored inactive diagnostic candidate may be frozen, and only
  when all fold and queue-stability gates pass.
- AI Governance shall expose authenticated aggregate temporal-stability status
  with no training, activation, promotion, alert, or response control.
- A failed repair shall keep supervised lifecycle in `shadow_observation`,
  preserve deterministic-rule alert authority, and create no automatic
  response or real firewall action.

## v5.44 Chronological Evidence Expansion Requirements

- **FR-ATDR-095:** ATDR shall inspect private PAN-OS development evidence only
  through an explicit CLI path and disposable storage, without importing it
  into the configured database.
- The workflow shall revalidate v5.39-v5.43 custody and exclude configured,
  consumed, exact, near, temporal, and candidate-family overlap before any
  assisted decision is calculated.
- Chronological fit, calibration, threshold, and untouched-future roles shall
  be assigned before label assistance and shall contain duplicate families in
  exactly one role.
- The untouched-future role shall remain sealed during development evidence
  coverage and anomaly diagnosis.
- Assisted decisions shall retain non-human provenance, never overwrite an
  existing label, and never produce an import-ready review file automatically.
- Public output shall contain aggregates only and exclude private paths,
  filenames, raw logs, IP addresses, source identities, reusable
  fingerprints, predictions, and secrets.
- A private ignored custody lock shall bind collection, protected-boundary,
  and assisted-policy summaries and fail closed on conflict or tamper.
- Development evidence sufficiency shall be distinct from candidate-freeze,
  independent-validation, activation, and production claims.
- v5.44 shall preserve `shadow_observation`, deterministic-rule authority,
  disabled response automation, and disabled real firewall blocking.

## v5.45 Development-Only Supervised Repair Requirements

- **FR-ATDR-096:** ATDR shall revalidate v5.39-v5.44 custody and use only the
  locked development-fit, calibration, and threshold roles for supervised
  repair, calibration, threshold selection, and candidate ranking.
- The workflow shall prevent exact, propagation, and broader candidate-near
  family leakage without inspecting reserved-future labels.
- Manual/reviewed labels shall remain distinct from assisted evidence, and
  assisted aggregate sample weight shall never exceed manual-anchor weight.
- The comparison shall include calibrated ExtraTrees,
  HistGradientBoosting, Logistic Regression, binary queue, three-class queue,
  and hierarchical two-stage strategies.
- Every mandatory view shall use the unchanged v5.42 gates. Optional views
  lacking required class support shall be excluded transparently rather than
  counted as automatic failures.
- ATDR may freeze at most one inactive diagnostic recipe only when every gate
  and queue-stability requirement passes. It shall not write an active model
  artifact in this workflow.
- IsolationForest shall be evaluated separately and remain advisory unless
  fixed FPR and sensitivity gates pass.
- AI Governance shall expose an authenticated aggregate v5.45 status without
  private rows, paths, identities, predictions, fingerprints, or secrets.
- A failed decision shall preserve `shadow_observation`, deterministic-rule
  alert authority, disabled response automation, and disabled real blocking.

## v5.46 Manual-Anchor Transfer Requirements

- **FR-ATDR-097:** ATDR shall diagnose manual-versus-assisted transfer using
  aggregate development evidence without opening reserved-future labels.
- Transfer features shall be derivable at runtime and shall not use provenance,
  source identity, private fingerprints, or reviewer identity as predictors.
- Manual/reviewed anchors shall retain greater aggregate effective weight than
  assisted evidence, and no label shall be rewritten by the evaluator.
- Calibration and thresholds shall use dedicated development partitions only;
  evaluation labels shall not influence their selection.
- The comparison shall include provenance-balanced, manual-prioritized,
  calibrated linear/tree, binary, three-class, hierarchical, and conservative
  ensemble strategies under unchanged v5.42 gates.
- A failed transfer shall freeze no recipe or active artifact and shall not
  create labels, runs, alerts, response actions, or firewall actions.
- The authenticated dashboard shall expose only aggregate transfer status,
  manual-anchor metrics, calibration state, and safety/lifecycle state.
- Further tuning against the same evidence shall stop when transfer worsens;
  the next decision shall require new prediction-blind human anchors and
  broader genuine-source evidence.

## v5.47 Prediction-Blind Manual-Anchor Acquisition Requirements

- **FR-ATDR-098:** ATDR shall create a sealed development-only review pack
  without exposing model predictions, model scores, or assisted labels to the
  reviewer.
- Selection shall use only eligible development roles and shall exclude
  quarantined, reserved-future, duplicate, and existing manual-anchor families.
- The pack shall cover known error boundaries including unknown transport,
  incomplete/allow/80, scan-like behavior, low-signal suspicious cases,
  QUIC/443 controls, high-risk context, and routine benign controls.
- Raw logs, IP addresses, source/device identities, private paths,
  fingerprints, predictions, and assisted labels shall not appear in the pack
  or public status.
- Review shall require a genuine human identity, supported decision,
  confidence, rationale, timestamp, and explicit confirmation. Automated
  reviewer identities shall be rejected.
- The workspace shall remain non-import-ready. ATDR shall not automatically
  create labels, train, freeze, activate, promote, create alerts, or execute
  responses from review progress.
- Fixed revalidation shall remain blocked until every selected row is validly
  reviewed and minimum benign-like, suspicious, and malicious support is met.
- The authenticated dashboard shall expose aggregate coverage and review
  readiness only. One-device evidence shall not be represented as source
  generalization or independent activation evidence.

## v5.48 Protected Manual-Anchor Review And Fixed Revalidation Requirements

- **FR-ATDR-099:** ATDR shall lock the eligible roles, deterministic
  partitions, feature schema, candidate strategies, calibration/threshold
  policy, and unchanged quality gates before the first v5.47 review decision.
- Manual-anchor rows shall be accessible only to an authenticated assigned
  human reviewer through a dedicated protected workspace.
- The workspace shall enforce owner isolation, optimistic revision control,
  supported decisions, confidence, rationale, explicit human confirmation,
  complete-review validation, and immutable formal closure.
- Predictions, model scores, assisted labels, raw logs, IP addresses, source
  identities, fingerprints, private paths, reviewer identities, and secrets
  shall not be returned by its API or UI.
- Protocol, sealed-pack, working-copy, or review-state binding conflicts shall
  fail closed.
- Fixed revalidation shall require complete valid review, minimum class
  support, formal closure, and explicit operator confirmation. It may execute
  at most once against the predeclared development protocol.
- The workflow shall not import labels, write an active artifact, activate or
  promote a model, change alert authority, or create a response action.
- One-source development evidence shall not be represented as independent
  source-generalization evidence or production readiness.

## v5.49 Fixed Revalidation And Candidate Decision Requirements

- **FR-ATDR-100:** ATDR shall execute the locked v5.48 development protocol at
  most once and only after proven complete human review, minimum class support,
  formal closure, valid custody, and explicit operator confirmation.
- The execution shall be atomically claimed before evaluation-label access;
  an interrupted or conflicting claim shall fail closed without automatic
  retry.
- The decision report shall contain all eight locked strategies and their
  precision, recall, F1, benign-like FPR, suspicious and malicious recall,
  macro/weighted F1, queue rate, calibration diagnostics, and fixed-gate checks.
- Missing, duplicate, reordered, changed-gate, or authority-mutating result
  data shall fail integrity validation.
- At most one result may qualify as an inactive diagnostic candidate. No
  candidate shall be activated or promoted by this workflow.
- The workflow shall write no labels, configured model runs, detection runs,
  alerts, response actions, active artifacts, or firewall actions.
- Independent second-source and untouched-future validation shall remain
  mandatory after any passing development result.

## v5.49a Supplemental Evidence Requirements

When a closed protected review does not meet honest class-support
preconditions, ATDR shall fail closed rather than request relabeling or use
machine predictions as human truth. It shall support a separate prediction-
blind supplemental workspace selected only from deterministic parser, rule,
and correlation evidence.

The workspace shall exclude original anchors, duplicate families, quarantined
rows, prior protected manual families, and locked final/future/external roles.
It shall be authenticated, owner-isolated, revision-safe, immutable after
closure, and expose only approved normalized evidence. Class targets and
combined support shall remain hidden until closure.

Supplemental closure may produce only a proposal for a newly versioned fixed
protocol when honest combined support passes. It shall not execute evaluation,
write labels, train or activate models, change alert authority, enable response
automation, or perform real blocking. A second genuine source and untouched
future validation remain prerequisites for any activation decision.

## v5.49b Immutable Combined Revalidation Requirements

- **FR-ATDR-101:** ATDR shall bind the closed original and supplemental review
  workspaces to a new immutable combined protocol before evaluation-label
  access.
- The protocol shall preserve the v5.48 feature schema, eight strategies,
  calibration/threshold policy, duplicate isolation, and fixed quality gates.
- Execution shall require combined support of at least `20` benign-like, `15`
  suspicious, and `10` malicious decisions and explicit operator confirmation.
- An atomic claim shall be written before any evaluation-label access. A
  claimed, interrupted, completed, or tampered protocol shall not be retried.
- Public status shall expose aggregate custody, metrics, gate outcomes, and
  safety state only. Private rows, identities, paths, fingerprints,
  predictions, and digests shall remain withheld.
- A diagnostic candidate may be named only when every fixed gate passes. The
  workflow shall never activate, promote, or write an active artifact.
- The workflow shall not write labels, configured model runs, detection runs,
  alerts, response actions, or firewall actions.
- Consumed evaluation evidence shall not be used for tuning. A failed result
  shall require fresh development evidence and a newly versioned protocol.

## v5.50 Current-State Truth Lock Requirements

- **FR-ATDR-102:** ATDR shall maintain one active source-backed truth lock that
  identifies the published commit, CI result, current runtime authority,
  supervised lifecycle, and remaining external gates without exposing private
  evidence.
- Current documentation shall distinguish implemented controlled-lab behavior
  from field acceptance, provider approval, shared deployment, and production
  certification.
- Historical candidate results and registry artifacts shall not be presented
  as a qualified current supervised model.
- Only aggregate v5.49b facts may be documented. Protected rows, decisions,
  identities, paths, fingerprints, predictions, claims, digests, and provider
  secrets remain private and ignored.
- v5.50 changes documentation and governance only. It shall not rerun consumed
  evaluation, write labels or models, change detection authority, activate a
  candidate, or enable automatic response or real blocking.

## v5.51 Detection Field Qualification Requirements

- **FR-ATDR-103:** ATDR shall provide a disposable, fail-closed field
  qualification workflow for transport, parser fields, deterministic rules,
  and fresh evidence without modifying configured application data.
- The workflow shall distinguish local loopback, second-laptop transport, and
  truthfully attested physical firewall/router evidence.
- Human source attestation and field expectations shall use versioned private
  contracts. Automated or assisted identities shall not satisfy human gates.
- Rule FP/FN metrics shall remain unavailable until every sealed review row is
  completed prediction-blind with confidence, rationale, and required attack
  type. No automatic label import is permitted.
- Fresh evidence shall start at the public post-v5.49b boundary, exclude
  missing/pre-boundary timestamps and exact duplicates, and keep each
  near-duplicate family in one fixed chronological role.
- The untouched future role shall remain label-closed until a separately
  approved one-shot evaluation protocol.
- Public API/UI status shall use only `ready`, `hardware_required`,
  `reviewer_required`, `insufficient_evidence`, or `failed` and shall expose no
  raw row, IP address, private path, identity, fingerprint, seal, or secret.
- v5.51 shall not access v5.49b protected evidence, train/activate/promote a
  model, create or suppress an alert, change severity, or execute response.

## v5.52 Analyst Experience And SOC Assistant Closure Requirements

- **FR-ATDR-104:** ATDR shall maintain one explicit primary alert, log, source,
  or case context for Assistant follow-ups and shall start a clean conversation
  when the analyst resets context or explicitly switches entities.
- Generic `ID` text shall never be interpreted as an alert ID. Entity IDs shall
  require explicit entity wording or an alert `#` reference.
- Related citations shall remain evidence and shall not silently replace the
  primary conversational entity.
- **FR-ATDR-105:** ATDR shall persist at most four sanitized conversation turns
  in the current browser tab across dashboard navigation. Persistence shall be
  bounded, exclude raw logs/secrets, and clear on logout or explicit reset.
- **FR-ATDR-106:** Every Assistant answer shall expose whether it is ATDR
  deterministic analysis or external-LLM synthesis, its safe evidence scopes,
  citation count, deterministic-rule authority, advisory-ML status, and raw-log
  exclusion.
- **FR-ATDR-107:** Assistant response contracts shall remain intent-specific,
  enforce 55-120 word limits and at most two follow-ups, preserve deterministic
  fallback, and reject ungrounded, unsafe, over-budget, or unsupported provider
  output.
- Provider checks shall never expose API keys or provider payloads and shall
  verify raw-log exclusion, redaction, structured output, fallback, and zero
  label/model/detection/response side effects.
- The Assistant shall remain read-only. Rules remain alert-authoritative, ML
  remains advisory, and automatic response and real blocking remain disabled.

## v5.53 MFU IAM And Shared Deployment Readiness Requirements

- **FR-ATDR-108:** ATDR shall expose an authenticated admin-only aggregate
  readiness view for MFU IAM, shared deployment, Assistant-provider governance,
  teammate runtime, and repository security without exposing configuration
  values, credentials, private paths, identities, raw evidence, or provider
  payloads.
- Configuration shall not count as acceptance. Real acceptance shall require
  expiring, environment-bound private evidence contracts; absent, malformed,
  unsafe, replayed, or expired evidence shall fail closed.
- **FR-ATDR-109:** Normal template-shell mode shall validate explicit origins,
  callbacks and return paths, HTTPS requirements outside development, secure
  cookie expectations, analyst-default role mapping, explicit admin groups, and
  disabled mock behavior outside development. Wildcard CORS policy is forbidden.
- **FR-ATDR-110:** ATDR shall provide a disposable teammate-machine acceptance
  runner that validates an approved shell source and rehearses setup, startup,
  health, shutdown, and cleanup only after an exact confirmation. The runner
  shall not self-approve a physical-machine acceptance contract.
- **FR-ATDR-111:** Repository verification shall include high-confidence secret
  and forbidden-path scanning, Python and npm dependency auditing, a CycloneDX
  source SBOM, and scheduled Python/JavaScript CodeQL analysis. Scan output shall
  never include matched secret values.
- Local SQLite shall remain supported. Shared deployment evidence shall cover
  PostgreSQL, migrations, durable workers, HTTPS, managed secrets, monitoring,
  backup/restore, measured recovery, rollback, and disaster recovery on an
  approved host before a shared-deployment claim is allowed.
- v5.53 shall not alter detector authority, activate/promote a model, allow raw
  log provider context, enable automatic response, or enable real blocking.

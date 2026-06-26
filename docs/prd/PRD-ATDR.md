# PRD: MFU ATDR

| Field | Value |
| --- | --- |
| Product | MFU AI-Driven Log-Based Threat Detection and Response System |
| Short name | ATDR |
| Current stage | v3.65 MFU IAM and real assistant harness |
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
| Lab operations | `docs/LAB_RUNBOOK.md` |
| AI workflow | `docs/AI_TRAINING_RUNBOOK.md`, `docs/ML_BASELINE_TUNING.md` |
| IAM/RBAC permission matrix | `docs/security/ATDR_IAM_RBAC_MATRIX.md` |
| External IAM groundwork | `docs/security/ATDR_EXTERNAL_IAM_PLAN.md` |
| MFU IAM adapter plan | `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md`, `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md` |
| NewSystem template alignment and permission path registry | `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md`, `docs/ATDR_TEMPLATE_MANIFEST.json`, `docs/security/ATDR_PERMISSION_PATHS.md` |
| Tasklist/progress-board process | `docs/tasks/README.md`, `docs/tasks/tasklist-progress.md`, `docs/tasks/tasklist-progress.html`, `scripts/render-tasklist-progress-html.js`, `scripts/check-tasklist-progress-standard.js` |
| Requirement traceability | `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |
| v3.4 shared-lab readiness foundation | `docs/V3_4_SHARED_LAB_READINESS.md`, `atdr/scripts/run_v34_shared_lab_readiness.py`, `atdr/scripts/run_backup_restore_drill.py`, `atdr/scripts/profile_dashboard_summary.py` |
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
| MFU IAM implementation planning and token harness | `docs/security/ATDR_MFU_IAM_IMPLEMENTATION_PLAN.md`, `docs/ATDR_TEMPLATE_MERGE_ANALYSIS.md`, `docs/V3_64_MFU_IAM_TEMPLATE_ADAPTER.md`, `docs/V3_65_MFU_IAM_AND_REAL_ASSISTANT_HARNESS.md` |
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

ATDR is a defensive cybersecurity monitoring prototype for controlled small-office or university lab validation. It ingests firewall/syslog logs, preserves raw evidence, normalizes fields, runs explainable rule-based detection, adds ML-assisted anomaly and supervised scoring, groups alerts, supports analyst investigation, and records simulated analyst-approved response actions in audit logs.

ATDR does not currently perform real firewall blocking. It does not claim production readiness or production ML accuracy.

## System Purpose

ATDR exists to demonstrate and validate:

- Realistic firewall log ingestion and parsing.
- Raw evidence preservation for every investigation.
- Explainable alert generation.
- AI-assisted but analyst-controlled triage.
- Source health and parser profile visibility.
- Safe response simulation with audit trail.
- Lab-ready workflow that can later be validated with PostgreSQL, Docker, and real device syslog forwarding.

## Users And Roles

| Role | Purpose | Current Evidence |
| --- | --- | --- |
| Admin | Configure users, school-email account metadata, demo controls, source management, threat controls, response simulation actions | `atdr/app/routers/users.py`, `atdr/app/routers/demo.py`, `atdr/app/routers/response.py` |
| Analyst | Investigate alerts/logs, update alert status, review evidence, label logs, view audit and ML governance | `atdr/app/routers/alerts.py`, `atdr/app/routers/logs.py`, `atdr/app/routers/ml.py` |
| Supervisor/advisor | Review dashboard, evidence, runbooks, acceptance status, and lab-readiness claims | `docs/V0_3_STATUS.md`, `docs/ACCEPTANCE_TEST_CHECKLIST.md` |

The current role and permission matrix is documented in `docs/security/ATDR_IAM_RBAC_MATRIX.md`. Local accounts now support optional school-email fields, email login for local users, and v3.14 disabled-by-default email verification/dev-outbox groundwork. v3.65 adds a disabled-by-default MFU IAM token-login harness that can map verified school-email identities to local ATDR users when explicitly configured. ATDR does not currently include a viewer/read-only role, real SMTP delivery, password reset email, full Google/MFU OAuth callback flow, or external IAM group synchronization.

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
- Promotion gate that keeps the model in analyst-review / candidate status unless readiness checks pass.

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
- Synchronous operation job history for long-running import, replay, detection, ML, and export tasks.
- Dry-run-first operation job maintenance for stale job recovery and old terminal job cleanup.
- Performance smoke checks.
- Release gate.
- Scenario runner with safe synthetic files.
- No-hardware soak validation for parser drift, source health, dedup, alert noise, and explanation completeness.
- Lab runbook and acceptance checklist.

Evidence: `atdr/app/db/models.py`, `atdr/app/routers/jobs.py`, `atdr/app/services/job_service.py`, `atdr/scripts/maintenance_jobs.py`, `atdr/scripts/performance_smoke.py`, `atdr/scripts/verify_release.py`, `docs/LAB_RUNBOOK.md`, `docs/ACCEPTANCE_TEST_CHECKLIST.md`.

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
| FR-ATDR-021 | Provide job/status visibility for long-running lab operations without changing detection, ML, or response behavior | Implemented as v3.6 synchronous operation job tracking; true async workers remain future work |
| FR-ATDR-022 | Provide safe stale-job detection and explicit operation-job retention maintenance without deleting raw evidence | Implemented as v3.7 dry-run-first maintenance; true async workers and automatic retention remain future work |
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
| FR-ATDR-030C | Provide a disabled-by-default MFU school-email token-login harness while preserving local login | Implemented in v3.65 with public readiness status, token-login route, allowed-domain enforcement, explicit admin email mapping, audit, and login/Admin UI readiness |
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
- MFU token-login harness exists but real provider token introspection still requires private `.env` configuration and live provider validation.
- No viewer/read-only role.
- Demo JWT secret must be replaced before shared lab or real deployment.
- Current role model is suitable for lab prototype validation, not production IAM.
- Role permissions must be fully reviewed before real deployment or response connector implementation.
- v3.14 email verification does not block login by default and does not implement real SMTP or external school SSO.
- MFU IAM status and token-login harness are disabled by default. They do not make external network calls during normal startup or change local login.

## University Template Alignment

ATDR uses `NewSystem/` as a university reference template, not as implementation truth. The active ATDR adaptation is documented in:

- `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md`
- `docs/ATDR_TEMPLATE_MANIFEST.json`
- `docs/security/ATDR_PERMISSION_PATHS.md`
- `docs/security/ATDR_IAM_RBAC_MATRIX.md`
- `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md`
- `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md`
- `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md`

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

Template ideas not adopted in v0.3:

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
- PostgreSQL/Docker validation still needs a Docker-capable host.
- Real firewall blocking is not implemented.
- Real device forwarding needs controlled lab validation.
- Case grouping is lightweight and computed; it is not a full incident management system.
- Supervised ML still needs more reviewed labels and live validation before stronger claims.

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

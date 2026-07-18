# ATDR University Compliance Checklist

This checklist maps the university AI/project workflow rules to ATDR-specific evidence and remaining gaps.

## Source Evidence

| Evidence | Repository Source |
| --- | --- |
| ATDR workflow adaptation | `docs/ATDR_AI_WORKFLOW.md` |
| ATDR PRD | `docs/prd/PRD-ATDR.md` |
| Agent operating model | `docs/agents/ATDR_AGENT_OPERATING_MODEL.md` |
| Change template | `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` |
| AI docs index | `docs/AI-DOCS-INDEX.md` |
| Tasklist/progress board | `docs/tasks/README.md`, `docs/tasks/tasklist-progress.md`, `docs/tasks/tasklist-progress.html` |
| Tasklist renderer/checker | `scripts/render-tasklist-progress-html.js`, `scripts/check-tasklist-progress-standard.js` |
| v3.4 shared-lab foundation | `docs/V3_4_SHARED_LAB_READINESS.md`, `atdr/scripts/run_v34_shared_lab_readiness.py`, `atdr/scripts/run_backup_restore_drill.py`, `atdr/scripts/profile_dashboard_summary.py` |
| v3.5 real-source/syslog pilot | `docs/V3_5_REAL_SOURCE_SYSLOG_PILOT.md`, `atdr/scripts/run_v35_real_source_pilot_check.py`, `atdr/scripts/export_real_source_pilot_evidence.py` |
| v3.6 background job hardening | `docs/V3_6_BACKGROUND_JOB_HARDENING.md`, `atdr/app/routers/jobs.py`, `atdr/app/services/job_service.py`, `atdr/tests/test_operation_jobs.py` |
| v3.7 operation retention/recovery | `docs/V3_7_OPERATION_RETENTION_AND_JOB_RECOVERY.md`, `atdr/scripts/maintenance_jobs.py`, `atdr/app/routers/jobs.py`, `atdr/tests/test_operation_jobs.py` |
| v3.8 analyst assistant MVP | `docs/V3_8_ANALYST_ASSISTANT_MVP.md`, `atdr/app/routers/assistant.py`, `atdr/app/services/assistant_service.py`, `atdr/tests/test_assistant.py` |
| v3.9 analyst assistant hardening | `docs/V3_9_ASSISTANT_HARDENING.md`, `docs/changes/T1_T20_V3_9_ASSISTANT_HARDENING.md`, `atdr/app/routers/assistant.py`, `frontend/src/pages/AssistantPage.tsx` |
| v3.10 config safety hardening | `docs/V3_10_CONFIG_SAFETY_HARDENING.md`, `atdr/scripts/config_doctor.py`, `atdr/scripts/check_dev_environment.py`, `atdr/scripts/use_local_sqlite_config.py` |
| v3.11 detection explainability hardening | `docs/V3_11_DETECTION_EXPLAINABILITY_HARDENING.md`, `atdr/scripts/validate_detection_pipeline.py`, `atdr/app/detection/explanations.py`, `atdr/tests/test_detection_explanations.py` |
| v3.12 detection rule quality | `docs/V3_12_DETECTION_RULE_QUALITY.md`, `docs/DETECTION_RULE_CATALOG.md`, `atdr/app/services/detection_service.py`, `atdr/tests/test_detection_validation_suite.py` |
| v3.13 SOC assistant alert explainer | `docs/V3_13_SOC_ASSISTANT_ALERT_EXPLAINER.md`, `docs/changes/T1_T20_V3_13_SOC_ASSISTANT_ALERT_EXPLAINER.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `frontend/src/pages/AlertsTriage.tsx` |
| v3.21 SOC Assistant demo-quality upgrade | `docs/V3_21_SOC_ASSISTANT_DEMO_QUALITY.md`, `docs/changes/T1_T20_V3_21_SOC_ASSISTANT_DEMO_QUALITY.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` |
| v3.22 SOC Assistant evidence-grounded demo QA | `docs/V3_22_SOC_ASSISTANT_EVIDENCE_GROUNDED_DEMO_QA.md`, `docs/V3_22_ASSISTANT_DEMO_QUESTION_SET.md`, `docs/changes/T1_T20_V3_22_SOC_ASSISTANT_EVIDENCE_GROUNDED_DEMO_QA.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` |
| v3.23 Assistant context linking | `docs/V3_23_ASSISTANT_CONTEXT_LINKING.md`, `docs/changes/T1_T20_V3_23_ASSISTANT_CONTEXT_LINKING.md`, `frontend/src/pages/AssistantPage.tsx`, `frontend/src/pages/ExecutiveOverview.tsx`, `frontend/src/pages/MLGovernance.tsx`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` |
| v3.24 Assistant investigation context | `docs/V3_24_SOC_ASSISTANT_INVESTIGATION_CONTEXT.md`, `docs/changes/T1_T20_V3_24_SOC_ASSISTANT_INVESTIGATION_CONTEXT.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `frontend/src/pages/AlertsTriage.tsx`, `frontend/src/pages/LogExplorer.tsx`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` |
| v3.25 Assistant investigation brief builder | `docs/V3_25_SOC_ASSISTANT_INVESTIGATION_BRIEF_BUILDER.md`, `docs/changes/T1_T20_V3_25_SOC_ASSISTANT_INVESTIGATION_BRIEF_BUILDER.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` |
| v3.26 Assistant evaluation and end-to-end investigation QA | `docs/V3_26_ASSISTANT_QA_QUESTION_SET.md`, `docs/V3_26_SOC_ASSISTANT_EVALUATION_AND_INVESTIGATION_QA.md`, `docs/changes/T1_T20_V3_26_SOC_ASSISTANT_EVALUATION_AND_INVESTIGATION_QA.md`, `atdr/scripts/evaluate_assistant_qa.py`, `atdr/tests/test_assistant_qa_evaluator.py` |
| v3.27 Assistant feedback and answer-quality review | `docs/V3_27_ASSISTANT_FEEDBACK_AND_ANSWER_QUALITY.md`, `docs/changes/T1_T20_V3_27_ASSISTANT_FEEDBACK_AND_ANSWER_QUALITY.md`, `atdr/app/routers/assistant.py`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py` |
| v3.28 Assistant feedback review and quality triage | `docs/V3_28_ASSISTANT_FEEDBACK_REVIEW.md`, `docs/changes/T1_T20_V3_28_ASSISTANT_FEEDBACK_REVIEW.md`, `atdr/app/services/assistant_service.py`, `atdr/app/routers/assistant.py`, `frontend/src/pages/AssistantPage.tsx`, `frontend/tests/smoke.spec.ts` |
| v3.29 Assistant reasoning and triage quality | `docs/V3_29_SOC_ASSISTANT_REASONING_AND_TRIAGE_QUALITY.md`, `docs/changes/T1_T20_V3_29_SOC_ASSISTANT_REASONING_AND_TRIAGE_QUALITY.md`, `atdr/app/services/assistant_service.py`, `atdr/scripts/evaluate_assistant_qa.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py` |
| v3.30 Detection and ML quality revalidation | `docs/V3_30_DETECTION_ML_QUALITY_REVALIDATION.md`, `docs/changes/T1_T20_V3_30_DETECTION_ML_QUALITY_REVALIDATION.md`, `atdr/app/detection/v330_detection_ml_quality.py`, `atdr/scripts/run_v330_detection_ml_quality_revalidation.py`, `frontend/src/pages/MLGovernance.tsx`, `atdr/tests/test_v330_detection_ml_quality.py` |
| v3.14 email verification foundation | `docs/V3_14_EMAIL_VERIFICATION_AND_ACCOUNT_NOTIFICATIONS.md`, `docs/changes/T1_T20_V3_14_EMAIL_VERIFICATION_AND_ACCOUNT_NOTIFICATIONS.md`, `atdr/app/services/account_verification_service.py`, `frontend/src/pages/UserAdmin.tsx` |
| v3.15 account lifecycle and email verification UX | `docs/V3_15_ACCOUNT_LIFECYCLE_AND_EMAIL_VERIFICATION_UX.md`, `docs/changes/T1_T20_V3_15_ACCOUNT_LIFECYCLE_AND_EMAIL_VERIFICATION_UX.md`, `frontend/src/components/AppShell.tsx`, `frontend/src/pages/UserAdmin.tsx` |
| IAM/RBAC permission matrix | `docs/security/ATDR_IAM_RBAC_MATRIX.md` |
| External IAM groundwork plan | `docs/security/ATDR_EXTERNAL_IAM_PLAN.md` |
| MFU IAM adapter plan and provider checklist | `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md`, `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md` |
| MFU IAM implementation plan | `docs/security/ATDR_MFU_IAM_IMPLEMENTATION_PLAN.md` |
| MFU IAM template adapter readiness | `docs/V3_64_MFU_IAM_TEMPLATE_ADAPTER.md`, `atdr/app/services/mfu_iam_service.py` |
| Historical MFU IAM token-login harness | `docs/V3_65_MFU_IAM_AND_REAL_ASSISTANT_HARNESS.md` (superseded by v3.91; route removed) |
| v3.91 secure MFU outer-shell handoff | `docs/V3_91_MFU_OUTER_SHELL_SECURE_HANDOFF.md`, `docs/security/ATDR_MFU_IAM_PREPROD_VALIDATION.md`, `atdr/app/routers/auth.py`, `atdr/app/services/mfu_iam_service.py` |
| Real LLM assistant plan | `docs/security/ATDR_REAL_LLM_ASSISTANT_PLAN.md` |
| v3.63 Real LLM assistant adapter | `docs/V3_63_REAL_LLM_ASSISTANT_ADAPTER.md`, `docs/changes/T1_T20_V3_63_REAL_LLM_ASSISTANT_ADAPTER.md`, `atdr/app/services/assistant_llm.py` |
| v3.65 Real LLM provider probe | `atdr/scripts/test_assistant_llm_provider.py`, `docs/V3_65_MFU_IAM_AND_REAL_ASSISTANT_HARNESS.md` |
| Template merge analysis | `docs/ATDR_TEMPLATE_MERGE_ANALYSIS.md` |
| v3.17 parser/detection explainability hardening | `docs/V3_17_PARSER_DETECTION_EXPLAINABILITY_HARDENING.md`, `atdr/scripts/validate_parser_normalization.py`, `atdr/scripts/validate_detection_quality.py` |
| v3.18 detection corpus and FP/FN QA | `docs/V3_18_DETECTION_CORPUS_AND_FP_FN_QA.md`, `atdr/scripts/validate_detection_quality.py`, `atdr/tests/test_v318_detection_corpus.py`, `data/samples/scenarios/scenario_expectations.json` |
| v3.19 no-hardware soak and parser drift | `docs/V3_19_NO_HARDWARE_SOAK_AND_PARSER_DRIFT.md`, `atdr/scripts/run_no_hardware_soak.py`, `atdr/tests/test_v319_no_hardware_soak.py` |
| v3.20 supervisor-template comparison and school-email IAM readiness audit | `docs/ATDR_TEMPLATE_COMPARISON_AND_GAP_AUDIT.md`, `docs/security/ATDR_SCHOOL_EMAIL_IAM_READINESS_AUDIT.md`, `docs/changes/T1_T20_TEMPLATE_COMPARISON_AND_IAM_READINESS_AUDIT.md` |
| NewSystem template alignment | `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md` |
| ATDR template manifest | `docs/ATDR_TEMPLATE_MANIFEST.json` |
| ATDR permission path registry | `docs/security/ATDR_PERMISSION_PATHS.md` |
| ATDR OWASP lab security review | `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md` |
| Requirement traceability | `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |
| Current product/run commands | `README.md` |
| Release gate | `atdr/scripts/verify_release.py` |
| Current status | `docs/V0_3_STATUS.md` |
| Repo hygiene | `.gitignore` |

## Compliance Matrix

| University Rule / Expectation | ATDR Current Satisfaction | Evidence | Gap / Next Action | Owner |
| --- | --- | --- | --- | --- |
| No guessing; inspect source first | Satisfied for future work through source discovery rule and T3 evidence requirement | `docs/ATDR_AI_WORKFLOW.md`, `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` | Enforce in every future change handoff | Orchestrator |
| Source evidence required | Satisfied by ATDR workflow and T1-T20 T3 section | `docs/ATDR_AI_WORKFLOW.md`, `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` | Future change docs must cite paths and findings | All agents |
| Source truth order defined | Satisfied with ATDR-specific truth order | `docs/ATDR_AI_WORKFLOW.md` | Keep updated if architecture changes | Orchestrator |
| T1-T20 change document required | Satisfied by ATDR template | `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` | Store completed change docs under `docs/changes/` for major work | Orchestrator |
| Tasklist/progress-board workflow | Satisfied by canonical ATDR tasklist Markdown, generated HTML, and validation scripts | `docs/tasks/README.md`, `docs/tasks/tasklist-progress.md`, `docs/tasks/tasklist-progress.html`, `scripts/render-tasklist-progress-html.js`, `scripts/check-tasklist-progress-standard.js` | Future non-trivial work must update progress Markdown and regenerate/check HTML | Orchestrator / Release-Ops |
| Docs index | Satisfied by ATDR-specific docs index | `docs/AI-DOCS-INDEX.md` | Keep active docs and reference-only docs separated | Orchestrator |
| PRD update gate | Satisfied by ATDR PRD and workflow update rule | `docs/prd/PRD-ATDR.md`, `docs/ATDR_AI_WORKFLOW.md` | PRD must be updated when behavior/API/UI/data/ML/safety changes | Product Owner |
| Testing gate | Satisfied by release gate and documented test commands | `atdr/scripts/verify_release.py`, `frontend/package.json`, `atdr/tests/*` | Full verification remains required for code-risk changes | QA/UAT |
| Backend route truth | Satisfied by FastAPI route source order | `atdr/app/main.py`, `atdr/app/routers/*.py` | Keep README API highlights aligned with mounted routes | Backend/API |
| Frontend route truth | Satisfied by React route source order | `frontend/src/App.tsx`, `frontend/src/pages/*` | Keep dashboard docs aligned when routes change | Frontend |
| Data model/migration control | Satisfied by SQLAlchemy/Alembic source truth | `atdr/app/db/models.py`, `migrations/versions/*` | Add Alembic migration for future schema changes | Data Model |
| AI safety | Satisfied: ML is decision support only; weak labels are not production ground truth | `docs/prd/PRD-ATDR.md`, `docs/AI_TRAINING_RUNBOOK.md`, `docs/V0_3_STATUS.md` | Continue reviewed-label expansion before stronger claims | AI/ML Governance |
| Response safety | Satisfied: response remains simulated, approval/audit required | `docs/prd/PRD-ATDR.md`, `atdr/app/routers/response.py`, `atdr/tests/test_response_safety.py` | Real blocking remains future approved work only | Security / Response Safety |
| Repo hygiene | Satisfied by `.gitignore` and workflow rules | `.gitignore`, `docs/ATDR_AI_WORKFLOW.md` | Check `git status --short` before handoff | Release/Ops |
| Lab readiness documentation | Satisfied for current local workflow and source scenarios | `docs/LAB_RUNBOOK.md`, `docs/V0_3_STATUS.md`, `README.md` | Real device syslog forwarding still needs controlled lab hardware validation | Release/Ops |
| Production claim control | Satisfied: docs state lab-ready prototype, not certified production | `README.md`, `docs/V0_3_STATUS.md`, `docs/prd/PRD-ATDR.md` | Keep wording honest in future presentation/docs | Product Owner |
| Docker/PostgreSQL validation | Partially satisfied: optional docs/config exist, but local Docker validation is not required | `docker-compose.yml`, `docs/LAB_RUNBOOK.md`, `docs/DEPLOYMENT_GUIDE.md` | Validate on Docker-capable lab host later | Release/Ops |
| Shared-lab readiness foundation | Satisfied for non-destructive local readiness checks; not a production claim | `docs/V3_4_SHARED_LAB_READINESS.md`, `atdr/scripts/run_v34_shared_lab_readiness.py`, `atdr/tests/test_v34_shared_lab_readiness.py` | Execute PostgreSQL and real-device validation on appropriate lab host/hardware | Release/Ops |
| Controlled real-source/syslog pilot workflow | Partially satisfied: v3.5 checker/exporter validates source pipeline and separates simulated/replay evidence from real-device forwarding evidence | `docs/V3_5_REAL_SOURCE_SYSLOG_PILOT.md`, `atdr/scripts/run_v35_real_source_pilot_check.py`, `atdr/tests/test_v35_real_source_pilot.py` | Run sustained approved router/firewall forwarding and export evidence after real logs arrive | Release/Ops |
| Long-running operation visibility | Satisfied for opt-in durable queue, leases/heartbeats, scoped queue API, retry/cancel policy, and a separately launched worker | `docs/V3_90_DURABLE_BACKGROUND_JOBS.md`, `atdr/app/routers/jobs.py`, `atdr/app/services/operation_worker.py`, `atdr/tests/test_v390_durable_operation_jobs.py` | Multi-worker/PostgreSQL runtime evidence and worker supervision remain future work | Backend / Release-Ops |
| Operation job maintenance and retention | Satisfied for dry-run-first stale-job recovery, old terminal job cleanup, and fail-closed lease recovery | `docs/V3_7_OPERATION_RETENTION_AND_JOB_RECOVERY.md`, `docs/V3_90_DURABLE_BACKGROUND_JOBS.md`, `atdr/scripts/maintenance_jobs.py`, `atdr/tests/test_operation_jobs.py` | Automatic retention, run-history archival, and resumable large imports remain future work. Raw evidence is protected. | Release/Ops |
| Read-only analyst assistant | Satisfied for v3.9 local deterministic assistant with prompt presets, safe history, citations, and broader read-only analyst intents | `docs/V3_8_ANALYST_ASSISTANT_MVP.md`, `docs/V3_9_ASSISTANT_HARDENING.md`, `atdr/app/routers/assistant.py`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` | External LLM provider integration and raw-log context require future privacy/security review. Assistant cannot execute response actions or mutate data. | Backend / Frontend / Security |
| Local/shared-lab config safety | Satisfied for v3.10 local SQLite diagnostics, optional PostgreSQL lab guidance, secret redaction, and DB-unavailable response clarity | `docs/V3_10_CONFIG_SAFETY_HARDENING.md`, `atdr/scripts/config_doctor.py`, `atdr/scripts/check_dev_environment.py`, `atdr/app/main.py` | PostgreSQL validation still requires a running lab database/Docker service. | Release/Ops |
| Detection explainability hardening | Satisfied for v3.11 parser validation, log-level triage explanation, explanation completeness checks, and temporary-database detection validation | `docs/V3_11_DETECTION_EXPLAINABILITY_HARDENING.md`, `atdr/scripts/validate_detection_pipeline.py`, `atdr/app/detection/explanations.py`, `frontend/src/pages/LogExplorer.tsx` | Explanation completeness is structural and remains analyst decision support. Real-source validation and production claims remain future work. | Backend / Detection / QA |
| Detection rule quality and alert-noise control | Satisfied for v3.12 controlled scenario expectations, expected/allowed/unexpected alert classification, rule catalog, and grouping-noise reduction | `docs/V3_12_DETECTION_RULE_QUALITY.md`, `docs/DETECTION_RULE_CATALOG.md`, `atdr/scripts/validate_detection_pipeline.py` | Real-source traffic may reveal new noise patterns; production accuracy is not claimed. | Detection / QA |
| Parser normalization and detection-quality validation | Satisfied for v3.18 expanded safe corpus, controlled FP/FN scenario report, enriched log/alert explanations, and no-response validation | `docs/V3_17_PARSER_DETECTION_EXPLAINABILITY_HARDENING.md`, `docs/V3_18_DETECTION_CORPUS_AND_FP_FN_QA.md`, `atdr/scripts/validate_parser_normalization.py`, `atdr/scripts/validate_detection_quality.py`, `atdr/app/detection/explanations.py` | Validation is controlled and sample-based. Scenario FP/FN counts are not production metrics. Real-source parser drift and production accuracy remain future work. | Backend / Detection / QA |
| No-hardware soak and parser drift validation | Satisfied for v3.19 controlled multi-source temp-DB soak, parser drift reporting, dedup/noise reporting, source health checks, explanation completeness, and no-response validation | `docs/V3_19_NO_HARDWARE_SOAK_AND_PARSER_DRIFT.md`, `atdr/scripts/run_no_hardware_soak.py`, `atdr/tests/test_v319_no_hardware_soak.py` | No-hardware soak is still synthetic/replay validation. Real router/firewall forwarding and production reliability remain future work. | Backend / Detection / QA / Release-Ops |
| SOC assistant alert explainer | Satisfied for v3.13 structured read-only alert explanations, safe alert context, and dashboard alert-to-assistant handoff | `docs/V3_13_SOC_ASSISTANT_ALERT_EXPLAINER.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AlertsTriage.tsx`, `atdr/tests/test_assistant.py` | External LLM and raw-log context remain disabled by default. Assistant remains decision support and cannot execute actions. | Backend / Frontend / Security |
| SOC assistant demo-quality analyst guidance | Satisfied for v3.21 deterministic alert/source/detection/ML/how-to answers, advisor-friendly presets, Simulation Mode badge, and unsafe-action refusals | `docs/V3_21_SOC_ASSISTANT_DEMO_QUALITY.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` | External LLM, raw-log context, command execution, response action execution, detection execution, label mutation, and model activation remain disabled/out of scope. | Backend / Frontend / Security |
| SOC assistant evidence-grounded demo QA | Satisfied for v3.22 structured answer sections, citations, safe follow-up buttons, and advisor demo question set | `docs/V3_22_SOC_ASSISTANT_EVIDENCE_GROUNDED_DEMO_QA.md`, `docs/V3_22_ASSISTANT_DEMO_QUESTION_SET.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` | Assistant remains deterministic/read-only. It does not execute actions, call external providers by default, or include raw logs by default. | Backend / Frontend / Security |
| SOC assistant dashboard handoff | Satisfied for v3.23 navigation-only citation links and source-context handoff | `docs/V3_23_ASSISTANT_CONTEXT_LINKING.md`, `frontend/src/pages/AssistantPage.tsx`, `frontend/src/pages/ExecutiveOverview.tsx`, `frontend/tests/smoke.spec.ts` | Handoffs are dashboard navigation only. Dedicated job/run detail routes, external LLMs, raw logs, and action execution remain future reviewed work. | Frontend / Security |
| SOC assistant investigation context | Satisfied for v3.24 read-only alert/log/source/case context summaries and dashboard handoffs | `docs/V3_24_SOC_ASSISTANT_INVESTIGATION_CONTEXT.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AlertsTriage.tsx`, `frontend/src/pages/LogExplorer.tsx`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` | Computed case/group summaries are not persisted incident records. Assistant still cannot execute response, detection, label, model, source, user, email, or data actions. | Backend / Frontend / Security |
| SOC assistant investigation brief builder | Satisfied for v3.25 read-only structured brief generation and copyable dashboard handoff | `docs/V3_25_SOC_ASSISTANT_INVESTIGATION_BRIEF_BUILDER.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` | Briefs are deterministic handoff text only. They do not create incidents, notes, reports, response actions, detection runs, model changes, label changes, or raw-log sharing. | Backend / Frontend / Security |
| SOC assistant end-to-end QA | Satisfied for v3.26 controlled assistant evaluator and question set | `docs/V3_26_ASSISTANT_QA_QUESTION_SET.md`, `docs/V3_26_SOC_ASSISTANT_EVALUATION_AND_INVESTIGATION_QA.md`, `atdr/scripts/evaluate_assistant_qa.py`, `atdr/tests/test_assistant_qa_evaluator.py` | Evaluation uses a safe temporary scenario and validates assistant answers/side effects. It does not prove production accuracy or add persisted notebooks, external LLM, raw-log sharing, or action execution. | Backend / QA / Security |
| SOC assistant feedback and answer-quality review | Satisfied for v3.27 authenticated feedback controls, feedback summary, audit trail, and no-side-effect tests | `docs/V3_27_ASSISTANT_FEEDBACK_AND_ANSWER_QUALITY.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py` | Feedback is answer-quality metadata only. It does not retrain/tune the assistant, persist full chat transcripts, expose raw logs, call external providers by default, or execute actions. | Backend / Frontend / Security / QA |
| SOC assistant feedback review dashboard | Satisfied for v3.28 filtered feedback review, unsafe/incorrect quality summary, and manual triage indicators | `docs/V3_28_ASSISTANT_FEEDBACK_REVIEW.md`, `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` | Feedback review is manual. It does not create a feedback status lifecycle, automatically tune assistant answers, expose raw logs, call external providers by default, or execute actions. | Backend / Frontend / Security / QA |
| SOC assistant reasoning and triage quality | Satisfied for v3.29 deterministic evidence strength, false-positive caveats, missing-evidence notes, source/case risk summaries, and analyst checklists | `docs/V3_29_SOC_ASSISTANT_REASONING_AND_TRIAGE_QUALITY.md`, `atdr/app/services/assistant_service.py`, `atdr/scripts/evaluate_assistant_qa.py`, `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` | Assistant reasoning is professional decision support only. It does not autonomously classify truth, tune models, execute response, call external providers by default, or include raw logs by default. | Backend / Frontend / Security / QA |
| Real LLM assistant adapter | Satisfied for v3.63 as disabled-by-default provider adapter with safe fallback, bounded context, redaction-aware prompting, and provider-used audit | `docs/V3_63_REAL_LLM_ASSISTANT_ADAPTER.md`, `atdr/app/services/assistant_llm.py`, `atdr/app/services/assistant_service.py`, `atdr/tests/test_assistant.py` | Real provider keys and school data-sharing approval remain required before real external use. External LLM calls are not enabled by default and the assistant cannot execute actions. | Backend / Frontend / Security / QA |
| Email verification and account notification foundation | Satisfied for disabled-by-default local email verification, hashed tokens, admin-only dev outbox, non-secret status reporting, and v3.15 dashboard lifecycle clarity | `docs/V3_15_ACCOUNT_LIFECYCLE_AND_EMAIL_VERIFICATION_UX.md`, `atdr/app/services/account_verification_service.py`, `atdr/tests/test_email_verification.py`, `frontend/tests/smoke.spec.ts` | Real SMTP delivery, password reset email, full OIDC/SSO school login, and enforced verified-email policy remain future work. | Security / Backend / Frontend |
| Real device validation | Partially satisfied: local replay/syslog and source scenarios exist | `docs/LAB_RUNBOOK.md`, `atdr/scripts/run_source_scenario.py`, `data/samples/scenarios/*` | Test with actual firewall/router forwarding in controlled lab | Release/Ops |
| IAM/RBAC adaptation | Satisfied for admin/analyst roles with local JWT fallback and optional v3.91 secure MFU outer-shell handoff | `docs/security/ATDR_IAM_RBAC_MATRIX.md`, `docs/V3_91_MFU_OUTER_SHELL_SECURE_HANDOFF.md`, `atdr/app/core/security.py`, `atdr/app/services/mfu_iam_service.py`, `frontend/src/components/AdminRoute.tsx`, `frontend/src/pages/LoginPage.tsx` | Preproduction identity lifecycle, IAM group evidence, provider-managed 2FA/session evidence, SMTP invite email, and viewer role remain future work | Security / Response Safety |
| MFU IAM / Google SSO adapter planning | Satisfied for safe planning: supervisor-template IAM concepts are mapped to ATDR, provider details are listed, and disabled-by-default non-secret status placeholders exist | `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md`, `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md`, `atdr/app/routers/auth.py` | Real MFU IAM SDK, Google callback flow, token introspection, B2B client auth, and external network calls remain disabled until approved | Security / Response Safety |
| MFU IAM template env compatibility | Satisfied for v3.64: ATDR reads supervisor `IAM_SDK_*`, `IAM_ADMIN_*`, and `PROJECT_PERMISSION_*` env names for non-secret readiness/status and displays them in Admin | `atdr/app/core/config.py`, `atdr/app/services/mfu_iam_service.py`, `frontend/src/pages/UserAdmin.tsx`, `docs/V3_64_MFU_IAM_TEMPLATE_ADAPTER.md` | User-facing school-email login, callback/token exchange, external group-role mapping, and 2FA enforcement remain future reviewed work | Security / Backend / Frontend |
| MFU IAM school-email handoff | Source implementation complete in v3.91: template-owned school sign-in, opaque single-use code, form POST, server-side exchange, analyst default, group-based admin mapping, audit, and local-login fallback | `atdr/app/routers/auth.py`, `atdr/app/services/mfu_iam_service.py`, `atdr/app/core/security.py`, `frontend/src/pages/LoginPage.tsx`, `atdr/tests/test_mfu_iam_handoff.py`, `docs/V3_91_MFU_OUTER_SHELL_SECURE_HANDOFF.md` | Preproduction origins, IAM group identifiers, provider-managed 2FA/session evidence, recovery, deprovisioning, and HTTPS routing remain operational validation work | Security / Backend / Frontend |
| Supervisor template comparison and school-email IAM readiness audit | Satisfied for v3.20: supervisor IAM/process evidence was compared to ATDR, completed/partial/missing areas were documented, and real school-email login was correctly marked blocked until provider details are approved | `docs/ATDR_TEMPLATE_COMPARISON_AND_GAP_AUDIT.md`, `docs/security/ATDR_SCHOOL_EMAIL_IAM_READINESS_AUDIT.md`, `docs/changes/T1_T20_TEMPLATE_COMPARISON_AND_IAM_READINESS_AUDIT.md` | Advisor/provider must still provide provider choice, issuer/base URL, client ID/secret delivery method, redirect URLs, domains, group-role mapping, token validation, OTP policy, and audit/privacy rules | Security / Product Owner |
| NewSystem template adaptation | Satisfied: ATDR maps template concepts to FastAPI/React/SQLAlchemy equivalents and documents what was intentionally not copied | `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md`, `docs/ATDR_TEMPLATE_MANIFEST.json` | Keep this updated if external IAM, PostgreSQL/Docker, or real response connectors become approved scope | Orchestrator |
| Permission path registry | Satisfied: ATDR has a NewSystem-style permission path registry backed by current FastAPI and React sources | `docs/security/ATDR_PERMISSION_PATHS.md`, `docs/security/ATDR_IAM_RBAC_MATRIX.md` | Future external IAM can register these paths if approved | Security / Response Safety |
| OWASP/security review discipline | Satisfied for lab baseline: security posture, controls, and gaps are documented without production claim | `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md` | Add dependency scanning and stronger auth hardening before shared lab/production | Security / Response Safety |
| Requirement traceability | Satisfied for major v0.3 capabilities | `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | Keep updated when routes, data model, UI, ML, response, or source workflows change | Orchestrator |

## Current Compliance Status

ATDR now has ATDR-specific workflow governance, PRD, agent operating model, change template, completed change example, IAM/RBAC matrix, requirement traceability, and release evidence. The old template-style university docs can remain as historical references, but future ATDR work should use the ATDR-specific documents listed above.

| Compliance Item | Current Status | Evidence |
| --- | --- | --- |
| No-guessing/source evidence rule | Satisfied | `docs/ATDR_AI_WORKFLOW.md`, T3 in `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` |
| ATDR PRD exists | Satisfied | `docs/prd/PRD-ATDR.md` |
| Agent operating model exists | Satisfied | `docs/agents/ATDR_AGENT_OPERATING_MODEL.md` |
| T1-T20 template exists | Satisfied | `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` |
| Tasklist/progress board exists | Satisfied | `docs/tasks/tasklist-progress.md`, `docs/tasks/tasklist-progress.html` |
| Tasklist renderer/checker exists | Satisfied | `scripts/render-tasklist-progress-html.js`, `scripts/check-tasklist-progress-standard.js` |
| ATDR docs index exists | Satisfied | `docs/AI-DOCS-INDEX.md` |
| Completed T1-T20 example exists | Satisfied | `docs/changes/T1_T20_IAM_RBAC_COMPLIANCE.md` |
| IAM/RBAC matrix exists | Satisfied | `docs/security/ATDR_IAM_RBAC_MATRIX.md` |
| MFU IAM adapter plan exists | Satisfied | `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md` |
| MFU IAM implementation plan exists | Satisfied | `docs/security/ATDR_MFU_IAM_IMPLEMENTATION_PLAN.md` |
| MFU IAM provider checklist exists | Satisfied | `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md` |
| Secure MFU outer-shell handoff design and preproduction checklist exist | Satisfied | `docs/V3_91_MFU_OUTER_SHELL_SECURE_HANDOFF.md`, `docs/security/ATDR_MFU_IAM_PREPROD_VALIDATION.md` |
| Real LLM assistant provider plan exists | Satisfied | `docs/security/ATDR_REAL_LLM_ASSISTANT_PLAN.md` |
| Controlled template merge analysis exists | Satisfied | `docs/ATDR_TEMPLATE_MERGE_ANALYSIS.md` |
| NewSystem template alignment exists | Satisfied | `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md` |
| ATDR template manifest exists | Satisfied | `docs/ATDR_TEMPLATE_MANIFEST.json` |
| Permission path registry exists | Satisfied | `docs/security/ATDR_PERMISSION_PATHS.md` |
| OWASP lab security review exists | Satisfied | `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md` |
| Requirement traceability exists | Satisfied | `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |
| Release gate exists | Satisfied | `atdr/scripts/verify_release.py` |
| Acceptance checklist exists | Satisfied | `docs/ACCEPTANCE_TEST_CHECKLIST.md` |
| Lab runbook exists | Satisfied | `docs/LAB_RUNBOOK.md` |
| AI safety documented | Satisfied | `docs/prd/PRD-ATDR.md`, `docs/AI_TRAINING_RUNBOOK.md`, `docs/V0_3_STATUS.md` |
| Response safety documented | Satisfied | `docs/prd/PRD-ATDR.md`, `docs/security/ATDR_IAM_RBAC_MATRIX.md`, `atdr/tests/test_response_safety.py` |
| Repo hygiene documented | Satisfied | `.gitignore`, `docs/ATDR_AI_WORKFLOW.md`, `docs/QUICKSTART_FOR_TEAM.md` |
| Read-only assistant safety documented | Satisfied | `docs/V3_8_ANALYST_ASSISTANT_MVP.md`, `docs/V3_9_ASSISTANT_HARDENING.md`, `docs/LAB_RUNBOOK.md` |
| Config safety documented | Satisfied | `docs/V3_10_CONFIG_SAFETY_HARDENING.md`, `docs/QUICKSTART_FOR_TEAM.md`, `docs/LAB_RUNBOOK.md` |
| Detection explainability documented | Satisfied | `docs/V3_11_DETECTION_EXPLAINABILITY_HARDENING.md`, `docs/changes/T1_T20_V3_11_DETECTION_EXPLAINABILITY_HARDENING.md` |
| Detection rule catalog documented | Satisfied | `docs/DETECTION_RULE_CATALOG.md`, `docs/V3_12_DETECTION_RULE_QUALITY.md` |
| Parser/detection quality validation documented | Satisfied | `docs/V3_17_PARSER_DETECTION_EXPLAINABILITY_HARDENING.md`, `docs/V3_18_DETECTION_CORPUS_AND_FP_FN_QA.md`, `docs/changes/T1_T20_V3_18_DETECTION_CORPUS_AND_FP_FN_QA.md` |
| No-hardware soak validation documented | Satisfied | `docs/V3_19_NO_HARDWARE_SOAK_AND_PARSER_DRIFT.md`, `docs/changes/T1_T20_V3_19_NO_HARDWARE_SOAK_AND_PARSER_DRIFT.md` |
| Supervisor template comparison documented | Satisfied | `docs/ATDR_TEMPLATE_COMPARISON_AND_GAP_AUDIT.md`, `docs/changes/T1_T20_TEMPLATE_COMPARISON_AND_IAM_READINESS_AUDIT.md` |
| School-email IAM readiness audited | Satisfied | `docs/security/ATDR_SCHOOL_EMAIL_IAM_READINESS_AUDIT.md`, `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md` |
| SOC assistant alert explainer documented | Satisfied | `docs/V3_13_SOC_ASSISTANT_ALERT_EXPLAINER.md`, `docs/changes/T1_T20_V3_13_SOC_ASSISTANT_ALERT_EXPLAINER.md` |
| SOC assistant demo-quality upgrade documented | Satisfied | `docs/V3_21_SOC_ASSISTANT_DEMO_QUALITY.md`, `docs/changes/T1_T20_V3_21_SOC_ASSISTANT_DEMO_QUALITY.md` |
| SOC assistant evidence-grounded demo QA documented | Satisfied | `docs/V3_22_SOC_ASSISTANT_EVIDENCE_GROUNDED_DEMO_QA.md`, `docs/V3_22_ASSISTANT_DEMO_QUESTION_SET.md`, `docs/changes/T1_T20_V3_22_SOC_ASSISTANT_EVIDENCE_GROUNDED_DEMO_QA.md` |
| SOC assistant context linking documented | Satisfied | `docs/V3_23_ASSISTANT_CONTEXT_LINKING.md`, `docs/changes/T1_T20_V3_23_ASSISTANT_CONTEXT_LINKING.md` |
| SOC assistant investigation context documented | Satisfied | `docs/V3_24_SOC_ASSISTANT_INVESTIGATION_CONTEXT.md`, `docs/changes/T1_T20_V3_24_SOC_ASSISTANT_INVESTIGATION_CONTEXT.md` |
| SOC assistant investigation brief builder documented | Satisfied | `docs/V3_25_SOC_ASSISTANT_INVESTIGATION_BRIEF_BUILDER.md`, `docs/changes/T1_T20_V3_25_SOC_ASSISTANT_INVESTIGATION_BRIEF_BUILDER.md` |
| SOC assistant evaluation and investigation QA documented | Satisfied | `docs/V3_26_ASSISTANT_QA_QUESTION_SET.md`, `docs/V3_26_SOC_ASSISTANT_EVALUATION_AND_INVESTIGATION_QA.md`, `docs/changes/T1_T20_V3_26_SOC_ASSISTANT_EVALUATION_AND_INVESTIGATION_QA.md` |
| SOC assistant feedback and answer-quality review documented | Satisfied | `docs/V3_27_ASSISTANT_FEEDBACK_AND_ANSWER_QUALITY.md`, `docs/changes/T1_T20_V3_27_ASSISTANT_FEEDBACK_AND_ANSWER_QUALITY.md` |
| SOC assistant feedback review dashboard documented | Satisfied | `docs/V3_28_ASSISTANT_FEEDBACK_REVIEW.md`, `docs/changes/T1_T20_V3_28_ASSISTANT_FEEDBACK_REVIEW.md` |
| SOC assistant reasoning and triage quality documented | Satisfied | `docs/V3_29_SOC_ASSISTANT_REASONING_AND_TRIAGE_QUALITY.md`, `docs/changes/T1_T20_V3_29_SOC_ASSISTANT_REASONING_AND_TRIAGE_QUALITY.md` |
| Email verification foundation documented | Satisfied | `docs/V3_14_EMAIL_VERIFICATION_AND_ACCOUNT_NOTIFICATIONS.md`, `docs/changes/T1_T20_V3_14_EMAIL_VERIFICATION_AND_ACCOUNT_NOTIFICATIONS.md` |
| Account lifecycle/email verification UX documented | Satisfied | `docs/V3_15_ACCOUNT_LIFECYCLE_AND_EMAIL_VERIFICATION_UX.md`, `docs/changes/T1_T20_V3_15_ACCOUNT_LIFECYCLE_AND_EMAIL_VERIFICATION_UX.md` |
| Durable background-job safety documented | Satisfied | `docs/V3_90_DURABLE_BACKGROUND_JOBS.md`, `docs/changes/T1_T20_V3_90_DURABLE_BACKGROUND_JOBS.md`, `atdr/tests/test_v390_durable_operation_jobs.py` |
| Remaining gaps documented | Satisfied | Remaining Gaps section below |

## Large SQLite Performance Monitoring Note

Earlier compliance runs showed that the cached dashboard was fast while a true cold Overview/ingestion summary could exceed nine seconds on the current large database. v4.7 profiled and repaired the dominant uncached query shape without resetting data, increasing TTL, prewarming, or adding an ad hoc index. Keep the inherited cold-disk evidence as a monitoring item because operating-system cache and local contention still affect SQLite timing.

| Metric | Historical Warning | v4.7 Result | Local Budget |
| --- | ---: | ---: | --- |
| Overview application-cache miss | 9.341s true cold-disk observation | median 0.129154s; p95 0.156620s | median <=2.0s; p95 <=3.0s |
| Overview warm cache | 0.0062s | p95 0.010919s; one query | <=0.05s |
| ML Governance lightweight summary | 2.8009s historical warning | 1.1921s | <=2.0s |

Do not reset or delete data to hide performance issues. If warnings recur, run the read-only five-pass profiler, inspect query plans and query counts, and validate on PostgreSQL for shared-host capacity. Do not mask a regression through cache TTL or prewarming.

## Remaining Gaps

- Real device syslog forwarding validation is not complete.
- Local supervisor-template school-email session handoff is implemented and exercised, with local JWT login retained as fallback.
- Direct ATDR-owned Google/OIDC callback login and B2B token introspection are not required for the current outer-shell architecture, but remain optional future alternatives.
- Preprod/production identity routing, external group synchronization, provider-managed 2FA evidence, recovery, deprovisioning, and operational IAM approval remain incomplete.
- The supervisor template contains IAM patterns and env names, but ATDR still lacks approved provider choice, issuer/base URL, client registration, redirect URLs, allowed domains, group-role mapping, token validation rules, OTP policy, and audit/privacy requirements.
- Real SMTP email delivery and password reset email are not implemented; v3.14 adds local/dev verification groundwork only.
- Viewer/read-only role is not implemented.
- Demo JWT secrets must be replaced before shared lab or real deployment.
- Real firewall/router validation is pending.
- Real response enforcement is not implemented.
- External LLM assistant adapter exists as v3.63 disabled-by-default groundwork; real provider use still needs approved key handling, school data-sharing policy, and prompt-injection/privacy testing.
- Real Gemini assistant calls are implemented and locally validated through private configuration; calls remain disabled by default in examples/CI, raw logs remain excluded, deterministic fallback remains active, and organizational privacy/quota/key-custody approval remains a deployment gap.
- v3.13 assistant alert explanations are decision support only and require analyst judgment.
- v3.21 assistant demo guidance remains deterministic/read-only. External LLM integration and raw-log sharing remain future reviewed work only.
- v3.22 assistant evidence sections improve trust and demo clarity, but the assistant remains deterministic decision support rather than an autonomous SOC agent.
- v3.26 assistant QA validates controlled investigation questions and side effects, but it remains synthetic scenario QA, not production SOC certification.
- v3.27 assistant feedback records quality-review metadata, but it does not automatically retrain/tune the assistant or create a full incident notebook.
- v3.28 assistant feedback review highlights answer-quality issues, but status lifecycle and automatic remediation are intentionally future work.
- v3.29 assistant reasoning improves triage quality, but it remains deterministic decision support and does not replace analyst judgment or production validation.
- Docker/PostgreSQL lab deployment validation is still optional/future on a Docker-capable host.
- PostgreSQL host `postgres` requires Docker/PostgreSQL lab service; normal local workflow should use SQLite.
- Detection explanations are structural decision-support aids and still require analyst review.
- Detection rule quality is validated through controlled scenarios; real-source noise tuning remains future work.
- No-hardware soak validation is synthetic/replay only; sustained real router/firewall syslog forwarding remains future work.
- Production security hardening is pending.
- Final report/slides are not finalized.
- Future non-trivial changes should update `docs/tasks/tasklist-progress.md`, regenerate `docs/tasks/tasklist-progress.html`, and create completed T1-T20 change records like `docs/changes/T1_T20_IAM_RBAC_COMPLIANCE.md`.
- More human-reviewed suspicious/malicious labels are needed before stronger ML claims.
- Large local SQLite DB performance should be monitored; investigate if the Overview/ML Governance warnings recur.
- v3.90 provides an opt-in durable worker, leases, heartbeat, queue-backed retry/cancel controls, and fail-closed recovery. Multi-worker supervision, PostgreSQL concurrency validation, resumable large imports, and automatic retention remain future work.

## Required Pre-Handoff Checks For Future Work

```powershell
git status --short
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release
```

For docs-only changes, at minimum verify the docs exist, links are correct, and ATDR docs do not introduce stale template-specific commands or production claims.
## v3.87 Real LLM Assistant Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| Source-grounded AI output | Satisfied for bounded ATDR context and validated structured citations | `atdr/app/services/assistant_llm.py`, `atdr/app/services/assistant_service.py`, `atdr/tests/test_assistant.py` | Analyst judgment and real-traffic validation remain required. |
| AI safety and no action execution | Satisfied | Full chat probe reports zero response, detection, label, and model side effects | No autonomous actions are permitted. |
| Privacy and secret handling | Satisfied for implementation defaults | Raw logs disabled, IP redaction enabled, secret/path filtering, safe status/probe output | Organizational provider data-sharing and key-custody approval remain open. |
| Change workflow | Satisfied | `docs/changes/T1_T20_V3_87_REAL_LLM_SOC_ASSISTANT.md`, tasklist and generated board | Keep verification evidence current after future provider changes. |
| Production claim discipline | Satisfied | v3.87 docs retain decision-support and non-production wording | Provider availability, quota, privacy, and operational monitoring are not production-certified. |

## v3.88 Baseline Consolidation Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| Source evidence and no guessing | Satisfied | Git/source/CI/external-template audits and `docs/changes/T1_T20_V3_88_PRODUCT_BASELINE_CHECKPOINT.md` | Repeat the audit if status changes before staging. |
| Change classification and repo hygiene | Satisfied | `docs/V3_88_CHANGESET_MANIFEST.md`, `.gitignore`, tracked/ignored path scans | Commit/push are not automatic. |
| PRD/traceability/docs gate | Satisfied | PRD, state lock, roadmap, traceability, compliance, index, runbook, tasklist, and README reconciled | Keep future phase docs current. |
| Testing/release gate | Satisfied | Full backend `473 passed, 1 skipped`; Playwright `19 passed, 1 skipped`; clean-config simulation, Alembic, dependency audit, replay, performance, and release gate passed | Repeat after future runtime changes. |
| AI/response safety | Satisfied | Assistant remains read-only; raw logs disabled; response automation and real blocking disabled | Organizational provider and deployment review remain open. |
| Production claim discipline | Satisfied | v3.88 explicitly remains a productization checkpoint, not certification | PostgreSQL, workers, observability, IAM lifecycle, real hardware, and security operations remain incomplete. |

## v3.89 Shared-Lab Persistence Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| Database migration control | Satisfied for SQLite and CI-designed PostgreSQL isolation | `migrations/env.py`, `migrations/versions/*`, `atdr/app/db/engine.py`, Alembic checks | Remote PostgreSQL job or approved host still needs to run. |
| Safe backup/restore | Satisfied for isolated local SQLite validation | `atdr/app/services/persistence_service.py`, `atdr/scripts/backup_database.py`, `atdr/scripts/restore_database.py`, `atdr/tests/test_v389_persistence.py` | Encryption, off-host retention, and operational recovery drill remain open. |
| Secret-safe diagnostics | Satisfied | `atdr/app/db/engine.py`, `atdr/scripts/config_doctor.py`, `atdr/scripts/check_dev_environment.py`, persistence tests | Continue secret scans before every commit. |
| Local workflow preservation | Satisfied | `.env.example`, `atdr/app/db/database.py`, local validator, quickstart/runbook | PostgreSQL remains optional; do not replace SQLite for teammates. |
| Production claim discipline | Satisfied | v3.89 docs explicitly mark PostgreSQL runtime validation pending | Passing CI is not production certification. |

## v3.90 Durable Background Jobs Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| Explicit execution control | Satisfied | `atdr/scripts/run_operation_worker.py`, `OPERATION_WORKER_ENABLED=false` defaults | A managed worker/service supervisor is not yet part of ATDR. |
| Data/evidence safety | Satisfied | Lease expiry fails evidence-mutating jobs closed; staged imports are removed after attempt; raw evidence remains protected | Resumable large-file import design remains future work. |
| RBAC and auditability | Satisfied | Scoped `/api/jobs` routes, lifecycle `AuditLog` events, and `atdr/tests/test_v390_durable_operation_jobs.py` | Fine-grained per-job-type permission policy can be expanded later. |
| AI/response safety | Satisfied | Worker dispatcher has no response, activation/promotion, IAM, LLM, label, or account action handlers | Human approval and broader deployment governance remain required. |
| Production claim discipline | Satisfied | v3.90 documents local/shared-lab limits explicitly | PostgreSQL/multi-worker runtime evidence and operational monitoring are still pending. |

## v3.96 Preproduction Rehearsal Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| Source evidence / no guessing | Satisfied | Environment audit, strict preflight, v3.96 report/checklist/change record | Required external resources are recorded as unavailable, not inferred. |
| Approval and destructive-action boundary | Satisfied | DB probe confirmation, remote-load confirmation, separate-target restore, no deploy/commit/push | Approved-host execution still requires explicit operator approval. |
| Secret and privacy safety | Satisfied in source/local rehearsal | Boolean-only preflight, body-free load report, low-cardinality metrics, secret tests | Managed-secret runtime and rotation drill remain pending. |
| Verification and traceability | Satisfied for repository/local scope | Focused tests, CI dry preflight, PRD/traceability/task-board updates | Final approved-host acceptance evidence remains open. |
| IAM/AI/response safety | Satisfied in controls | MFU handoff is fail-closed; assistant raw logs/actions disabled; response simulated; no model activation | Provider-backed MFU session lifecycle remains unvalidated. |
| Production claim discipline | Satisfied | Operational acceptance is explicitly blocked | Linux/TLS/DNS/PostgreSQL/monitoring/recovery evidence is required before any stronger claim. |

## v3.97 Large-File Ingestion Reliability Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| Source evidence / no guessing | Satisfied | v3.93 ingestion source, pre-change profile, v3.97 migration/service/tests, and measured 100,000-line validator output | Real-device and approved-host load evidence remains unavailable. |
| Database and evidence safety | Satisfied for implementation validation | Additive fingerprint migration, exact raw-line collision check, retained duplicate evidence, disposable migration and acceptance databases | The current user DB was not migrated; the operator must run the documented additive migration before updated ingestion. |
| Verification and traceability | Satisfied for repository/local scope | PRD addendum, traceability rows, T1-T20 record, task board, targeted tests, frontend checks, and isolated acceptance | PostgreSQL/shared-storage and sustained concurrent acceptance remain external. |
| Privacy and operational metrics | Satisfied | Low-cardinality job/checkpoint metrics and compact dashboard counters expose no paths, fingerprints, raw logs, IPs, actors, or secrets | Persistent metrics and alert routing require an approved deployment. |
| AI/response safety | Satisfied | Validator confirms zero detection, label, model, and response side effects; response automation and real blocking remain disabled | No dangerous behavior is authorized by this phase. |
| Production claim discipline | Satisfied | 100k result is explicitly local synthetic evidence, not an SLA or production certification | Approved-host capacity, recovery, IAM, monitoring, and real-source evidence remain open. |

## v3.98 Independent Detection/ML Holdout Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| Source evidence / no guessing | Satisfied | Current rule/anomaly/supervised/hybrid source audit, reviewed latest-label provenance, v3.98 evaluator, and generated ignored reports | No external provider-blinded or real-device labeled corpus was supplied. |
| Frozen evaluation and leakage control | Implemented fail-closed | Four isolated partitions; exact/near/feature/log-ID grouping; source and temporal checks; deterministic seeds | Current labels cannot support a source split and the temporal final window lacks both classes. |
| Honest metric/readiness reporting | Satisfied | Split ranges, worst-split metrics, calibration, bootstrap intervals, error patterns, and `candidate_only` decision | Worst random FPR is unstable and sparse confidence buckets fail calibration. |
| AI/response/data safety | Satisfied | Before/after DB and artifact checks; no label/model/detection/response writes; raw lines and IPs absent from reports | No future phase may convert these diagnostics into activation without a separate approved gate. |
| Change workflow and traceability | Satisfied | Canonical v3.98 doc, T1-T20 record, PRD, traceability, state lock, roadmap, tests, and task board | Final verification evidence must stay current with the exact worktree. |
| Production claim discipline | Satisfied | Internal unseen holdout is explicitly distinguished from external independence and production accuracy | Independent real-source, multi-source, temporal-support, drift, deployment, and governance evidence remain open. |

## v3.99 Synthetic Multi-Source Frozen Revalidation Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| Source evidence / no guessing | Satisfied for the generated pack | Versioned generator, evidence manifest, source/parser/time/provenance fields, deterministic seed, and measured ignored output | The pack is generated synthetic evidence, not provider-blinded or real-device data. |
| Label provenance integrity | Satisfied | Every expectation is marked deterministic synthetic, `human_reviewed=false`, and `import_ready=false`; no labels are imported | Independent human/provider review is still missing. |
| Frozen evaluation and leakage control | Satisfied for v3.99 | Internal fit/calibration/threshold roles freeze before external scoring; exact/near/feature overlap is quarantined; five final views pass isolation checks | Existing internal model-development evidence remains single-source and narrow-window. |
| Honest metric/readiness reporting | Satisfied | Full metrics, bootstrap intervals, calibration buckets, source/app/action/port errors, worst split, and `candidate_only` decision | Calibration fails all five splits; synthetic separability can overstate real performance. |
| AI/response/data safety | Satisfied | Disposable DB counts and artifact metadata unchanged; no labels, model runs, artifacts, detection runs, or responses created; reports exclude raw lines/IPs/secrets | No activation or response authority is granted. |
| Change workflow and traceability | Satisfied | Canonical guide, T1-T20 record, exact manifest, tests, PRD, traceability, state lock, roadmap, runbook, and task board | Approved real-source evidence acquisition remains a future separately governed phase. |
| Production claim discipline | Satisfied | Documentation calls results synthetic regression evidence and preserves `candidate_only` | Provider-blinded/real-source validation, calibration repair on development evidence, drift, deployment, IAM, monitoring, and recovery evidence remain open. |

## v4.0 Provider-Blinded External Validation Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| No guessing / official source evidence | Satisfied | Official UNB and AWS pages, fixed S3 object metadata, byte counts, SHA-256 values, version, terms, citation, and known limitations | Only two published days are sampled; no authorized real-device evidence exists. |
| Provider-label integrity | Satisfied | Label-independent feature sample; predictions hashed before labels are read; provider labels remain `human_reviewed=false`, `import_ready=false`, and outside the DB | Provider labels are dataset ground truth, not independent ATDR analyst review. |
| Frozen evaluation and leakage control | Satisfied | Internal `random_seed_42` roles frozen; external fit/calibration/threshold rows `0/0/0`; exact/near/feature overlap zero after quarantine | Missing provider fields create cross-schema shift that leakage controls cannot solve. |
| Honest result and blocker reporting | Satisfied | FPR `1.0000`, weak calibration, all-benign false-positive count, bootstrap intervals, split range, and unsupported rules are reported without post-label tuning | A separate development corpus and new untouched final benchmark are required. |
| AI/response/data safety | Satisfied | Disposable DB and active artifact unchanged; zero label/model/detection/response writes; provider data and reports ignored | No activation, promotion, automatic response, or real blocking is authorized. |
| T1-T20, traceability, and task board | Satisfied | Canonical v4.0 guide, completed change record, exact manifest, focused tests, PRD, traceability, compliance, and task-board updates | Final command evidence must remain synchronized with the exact worktree. |
| Production claim discipline | Satisfied | Result remains `candidate_only` and is explicitly a failed external gate | Real-device drift, schema-aware generalization, approved-host deployment, MFU IAM lifecycle, and operations acceptance remain open. |

## v4.1 Schema-Aware SOC Queue Redesign Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| No guessing / source evidence | Satisfied | Official CSE-CIC-IDS2018 and UNSW-NB15 references, checksum-verified development files, explicit schema contracts, and source-backed evaluator | Authorized multi-source real firewall/syslog data is still needed. |
| v4.0 evidence lock and label integrity | Satisfied | Seven v4.0 file/hash records are checked before/after each v4.1 run; development/provider labels remain non-human and non-importable | A future untouched benchmark must remain separate from v4.1 development work. |
| Honest schema-aware evaluation | Satisfied | Missing fields remain unavailable; unsupported rules are unavailable rather than negative; time/source/random/schema-held-out diagnostics are reported | Provider source/time and cross-schema transfer remain unstable. |
| Calibration and readiness discipline | Satisfied | Weak calibration and failed held-out views are reported; readiness stays `candidate_only` | No candidate meets activation/promotion criteria. |
| AI/response/data safety | Satisfied | Disposable DB/artifact/session state unchanged; zero label/model/detection/response writes; automation and real blocking disabled | No automatic model or response authority is permitted. |
| Change workflow and traceability | Satisfied | Canonical guide, T1-T20 record, changeset manifest, traceability addendum, task board, and focused tests | Full repository verification evidence must remain synchronized with this checkpoint. |

## v4.2 Presentation-Ready SOC Assistant Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| Source evidence and no guessing | Satisfied for assistant output | `details.grounding` and **Grounded In** derive from returned ATDR citations; unavailable evidence is stated | Analyst verification is still required for incident conclusions. |
| AI safety | Satisfied for v4.2 scope | Gemini is optional summarization over bounded redacted context; deterministic fallback and output guards remain active | Provider privacy approval, quota monitoring, and key rotation remain deployment work. |
| Response safety | Satisfied for v4.2 scope | Assistant has no action controls; automation and real blocking remain disabled | Any future action integration requires a separate approved design. |
| Browser privacy | Satisfied for local implementation | Raw-log context is rejected, arbitrary details are excluded, and persistence is whitelisted/session scoped | Formal shared-device policy remains future operations work. |
| Change workflow | Satisfied | v4.2 canonical status, T1-T20 record, traceability, tests, and task board | Closure evidence must match the final worktree. |
| UI/template adaptation | Satisfied as an ATDR-specific adaptation | React keeps its runtime; MFU colors come from official template visual sources without Node/Vue/MongoDB migration | Formal brand approval remains external. |

## v4.3 Portable MFU Shell Runtime Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| Supervisor shell as normal entry | Satisfied for local/team runtime | `ATDR_AUTH_MODE=template_shell`, backend enforcement, fail-closed React login, portable launcher | Real MFU provider acceptance still requires an approved university environment. |
| No machine-specific runtime path | Satisfied | Shell root is supplied to setup and stored only in ignored runtime configuration; active runtime source has no developer path | The external shell must still be distributed through the approved channel. |
| Secret/repository hygiene | Satisfied in implementation | `.env.shell.example` contains placeholders; setup generates private values; check/status output exposes booleans and field names only | Operational secret rotation and managed storage remain deployment work. |
| Database preservation | Satisfied | No reset/seed path; setup backs up existing SQLite before additive Alembic migration | Shared PostgreSQL acceptance remains separate. |
| Authentication/role safety | Satisfied for handoff contract | One-time code, server exchange, HttpOnly cookie, analyst default, approved-group admin mapping, local recovery isolation | Provider 2FA, recovery, deprovisioning, and approved group identifiers need live evidence. |
| AI/response safety | Unchanged and satisfied | Assistant remains read-only; raw-log context disabled; response simulation true; no model promotion | No production or autonomous-response claim is authorized. |
| Change workflow | Satisfied | v4.3 guide, T1-T20 record, PRD, traceability, quickstart, runbook, task board, and tests | Final verification evidence must remain synchronized with the exact worktree. |

## v4.6 Versioned MFU Shell Distribution Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| Reproducible supervisor shell | Satisfied locally | Contract v2 locks release, archive checksum, source fingerprint, required files, and sanitization policy | The approved archive still needs an authorized distribution channel or release asset. |
| Secret/repository hygiene | Satisfied | Deterministic builder excludes private environments, credentials, uploads, DB/log/model/generated content; package and runtime remain ignored | Private provider files require managed delivery and rotation outside Git. |
| Teammate installation | Satisfied on disposable Windows clone | Fresh path-with-spaces setup installed all dependencies and migrated disposable SQLite; repeat setup reused the verified release | Legacy shell dependencies make first setup slow and emit upstream deprecation warnings. |
| Authentication safety | Satisfied locally / provider pending | Shell remains normal entry; startup fails closed with one provider blocker; local login remains explicit recovery | University OAuth Web client, domains/groups, 2FA, and real-account acceptance remain external. |
| Database/safety controls | Satisfied | No configured DB copy/reset; clean-room used new disposable SQLite; response simulation, no blocking, and no model promotion remain enforced | Approved-host and real-source validation remain separate product gates. |
| Change workflow | Satisfied | v4.6 status, T1-T20 record, hygiene report, exact allowlist, task board, tests, and verification evidence | Commit/push require explicit owner approval of the exact allowlist. |

## v4.7 Large-SQLite Performance Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| Source evidence / no guessing | Satisfied | SQLAlchemy timings, five-run before/after distributions, response fingerprints, and SQLite query plans are recorded in the v4.7 status | True OS-cold reproduction remains platform-dependent. |
| Database preservation | Satisfied | Profiler and smoke are read-only; no reset, copy, migration, index, or configured-DB write occurred | Shared PostgreSQL capacity remains external. |
| Correctness and freshness | Satisfied | Fixed-time full payload equality and raw/alert/run cache invalidation tests pass | Future summary fields must keep the freshness signature synchronized. |
| Portability/concurrency | Satisfied for locally controllable scope | PostgreSQL dialect compilation and concurrent file-SQLite reads pass | Approved-host PostgreSQL load/lock evidence remains pending. |
| AI/response safety | Unchanged and satisfied | Tests confirm zero ML model runs and response actions from summary/profile reads | No production, promotion, automation, or blocking claim is authorized. |
| Change workflow | Satisfied | v4.7 status, T1-T20 record, exact allowlist, PRD, traceability, runbook, task board, tests, and verification evidence | Commit/push require explicit owner approval of the exact allowlist. |

## v4.8 End-to-End Product Acceptance Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| No guessing / source evidence | Satisfied | v4.8 composes actual ATDR source, job, parser, detection, assistant, metrics, and persistence services; measured checks identify exact contracts | Synthetic behavior does not prove unobserved real-device/provider behavior. |
| Database preservation | Satisfied | runner requires `--use-temp-db`, migrates a unique disposable SQLite DB, refuses active restore target, compares configured DB markers, and removes temp state | Approved-host PostgreSQL acceptance remains external. |
| Testing gate | Satisfied for implemented scope | ten focused tests, a passing 50,000-log run, full backend `612 passed, 1 skipped`, no Alembic drift, replay/performance checks, and a green release gate | Frontend was unchanged; approved-host/provider/real-device acceptance remains external. |
| Requirement/PRD/docs gate | Satisfied | v4.8 status, T1-T20, PRD, traceability, compliance, runbook, task board, and cumulative exact allowlist | Future behavior changes must update the same source-of-truth chain. |
| AI and assistant safety | Satisfied | no model runs/labels; assistant excludes raw context, redacts IPs, uses cited records, and falls back locally on injected provider failure | Real LLM privacy, quota, rotation, and answer-quality acceptance remain external. |
| Response safety | Satisfied | zero response actions, automation false, real blocking false | Any real response connector requires a separately approved design and validation. |
| Repo hygiene | Satisfied by design | generated DB/backups/staging remain under ignored temporary storage and are deleted; public report omits private paths/raw evidence/secrets | Continue pre-commit tracked-file checks. |
| Change workflow | Satisfied | cumulative v4.7/v4.8 17-path boundary is documented because shared files contain both phases | Commit/push require a new explicit repository-owner instruction. |

## v4.4 MFU Authentication Stabilization Compliance Status

| Rule | Current Status | Evidence | Remaining Gap |
| --- | --- | --- | --- |
| Source evidence / no guessing | Satisfied locally | Private fields were inspected as configured/not-configured only; source fallback evidence and exact runtime origins are recorded without credential values | University provider policy still requires administrator confirmation. |
| Google configuration safety | Satisfied locally | Matching frontend/backend private client preflight, secret-free doctor, legacy fallback removal, safe backend 503 | Approved OAuth Web client has not yet been supplied. |
| Handoff and role safety | Satisfied in source/tests | Exact origins, one-time server exchange, HttpOnly cookie, analyst default, explicit group-based admin, conflict/domain rejection | Real provider account, group, 2FA, expiry, logout, and deprovisioning evidence remain. |
| Recovery safety | Satisfied | Normal profile fails closed; local password login requires explicit `local_recovery` | Recovery authorization/operations policy requires environment owner approval. |
| Secret/repo hygiene | Satisfied locally | Status uses booleans/codes, backups are ignored, no `.env` value is copied or returned | Managed secret delivery remains deployment work; any administrator credential disclosed outside the approved channel must be revoked and rotated. |
| AI/response safety | Unchanged | Detection/ML behavior is untouched; assistant is read-only; automation and real blocking remain disabled | No autonomous action authority is approved. |
| Change workflow | Locally verified | v4.4 status, T1-T20, PRD, traceability, compliance, regenerated task board, `584 passed, 1 skipped`, React/external-shell checks, and release gate `ok: true` | Live provider acceptance must be recorded after MFU administrator configuration. |

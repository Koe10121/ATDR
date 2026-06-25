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
| Real LLM assistant plan | `docs/security/ATDR_REAL_LLM_ASSISTANT_PLAN.md` |
| v3.63 Real LLM assistant adapter | `docs/V3_63_REAL_LLM_ASSISTANT_ADAPTER.md`, `docs/changes/T1_T20_V3_63_REAL_LLM_ASSISTANT_ADAPTER.md`, `atdr/app/services/assistant_llm.py` |
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
| Long-running operation visibility | Satisfied for synchronous lab operations | `docs/V3_6_BACKGROUND_JOB_HARDENING.md`, `atdr/app/routers/jobs.py`, `atdr/tests/test_operation_jobs.py` | True async workers, retry queues, and durable cancellation remain future work | Backend / Release-Ops |
| Operation job maintenance and retention | Satisfied for dry-run-first stale-job recovery and old terminal operation-job cleanup | `docs/V3_7_OPERATION_RETENTION_AND_JOB_RECOVERY.md`, `atdr/scripts/maintenance_jobs.py`, `atdr/tests/test_operation_jobs.py` | Automatic retention, run-history archival, and async worker recovery remain future work. Raw evidence is protected. | Release/Ops |
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
| IAM/RBAC adaptation | Satisfied for local lab roles: JWT auth, admin/analyst RBAC, school-email account metadata, frontend guards, response permission checks, and audit requirements are documented | `docs/security/ATDR_IAM_RBAC_MATRIX.md`, `atdr/app/core/security.py`, `frontend/src/components/AdminRoute.tsx` | Full external login provider, SMTP invite email, and viewer role are future work; OIDC status/config groundwork is now documented | Security / Response Safety |
| MFU IAM / Google SSO adapter planning | Satisfied for safe planning: supervisor-template IAM concepts are mapped to ATDR, provider details are listed, and disabled-by-default non-secret status placeholders exist | `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md`, `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md`, `atdr/app/routers/auth.py` | Real MFU IAM SDK, Google callback flow, token introspection, B2B client auth, and external network calls remain disabled until approved | Security / Response Safety |
| MFU IAM template env compatibility | Satisfied for v3.64: ATDR reads supervisor `IAM_SDK_*`, `IAM_ADMIN_*`, and `PROJECT_PERMISSION_*` env names for non-secret readiness/status and displays them in Admin | `atdr/app/core/config.py`, `atdr/app/services/mfu_iam_service.py`, `frontend/src/pages/UserAdmin.tsx`, `docs/V3_64_MFU_IAM_TEMPLATE_ADAPTER.md` | User-facing school-email login, callback/token exchange, external group-role mapping, and 2FA enforcement remain future reviewed work | Security / Backend / Frontend |
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
| Remaining gaps documented | Satisfied | Remaining Gaps section below |

## Large SQLite Performance Monitoring Note

During compliance closure, large local SQLite performance smoke runs showed that cached dashboard summaries remain fast, but a cold Overview/ingestion summary can still exceed the local budget on the current large database. Keep this note as a monitoring item because local SQLite timing can vary with concurrent backend/dashboard activity and DB lock contention.

| Metric | Recent Warning Run | Latest Tasklist Pass | Local Budget |
| --- | ---: | ---: | --- |
| Overview / ingestion summary | 10.7997s | 12.216s cold, 0.0126s cached | 1.0s for Overview, 2.0s for ingestion summary |
| ML Governance lightweight summary | 2.8009s | 3.3442s | 2.0s |

Do not reset or delete data to hide performance issues. If warnings recur, recommended next action is to profile the Overview/ingestion summary query path on the current large SQLite DB and consider a targeted cache/query/index improvement or PostgreSQL lab validation later.

## Remaining Gaps

- Real device syslog forwarding validation is not complete.
- Full external IAM provider login is not implemented. ATDR currently uses local JWT auth and admin/analyst RBAC; v0.4 adds disabled OIDC config/status groundwork only, and the MFU IAM adapter plan adds disabled status/config placeholders only.
- MFU IAM SDK integration, Google SSO callback login, B2B token introspection, and external group synchronization are not implemented.
- MFU IAM implementation readiness is improved with token/introspection/profile path placeholders, but real school-email login is still disabled until approved `.env` values, callback flow, role mapping, and provider testing are complete.
- v3.64 closes the supervisor env compatibility gap for readiness/status, but real school-email login still requires an approved front-channel Google/MFU Mail or IAM token flow.
- The supervisor template contains IAM patterns and env names, but ATDR still lacks approved provider choice, issuer/base URL, client registration, redirect URLs, allowed domains, group-role mapping, token validation rules, OTP policy, and audit/privacy requirements.
- Real SMTP email delivery and password reset email are not implemented; v3.14 adds local/dev verification groundwork only.
- Viewer/read-only role is not implemented.
- Demo JWT secrets must be replaced before shared lab or real deployment.
- Real firewall/router validation is pending.
- Real response enforcement is not implemented.
- External LLM assistant adapter exists as v3.63 disabled-by-default groundwork; real provider use still needs approved key handling, school data-sharing policy, and prompt-injection/privacy testing.
- Real LLM assistant configuration is documented and status-visible, but external provider calls remain disabled by default until API key handling, data-sharing policy, and adapter tests are approved.
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
- True async background workers, queue-backed retries, and durable cancellation are future work; v3.7 adds safe job maintenance only.

## Required Pre-Handoff Checks For Future Work

```powershell
git status --short
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release
```

For docs-only changes, at minimum verify the docs exist, links are correct, and ATDR docs do not introduce stale template-specific commands or production claims.

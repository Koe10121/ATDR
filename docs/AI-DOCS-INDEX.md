# ATDR AI Docs Index

This index defines the active ATDR documentation set for AI/Codex-assisted work. It adapts the university template documentation pattern to ATDR without making NewSystem, Node, Vue, MongoDB, or full external IAM implementation truth.

## Active Control Documents

| Document | Purpose |
| --- | --- |
| `docs/ATDR_AI_WORKFLOW.md` | Active no-guessing, source-evidence, testing, PRD, tasklist, safety, and handoff workflow. |
| `docs/prd/PRD-ATDR.md` | Active ATDR product requirements and safety constraints. |
| `docs/tasks/README.md` | ATDR tasklist/progress-board rules. |
| `docs/tasks/tasklist-progress.md` | Canonical editable system progress board. |
| `docs/tasks/tasklist-progress.html` | Generated progress board view. |
| `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` | ATDR T1-T20 change/handoff template. |
| `docs/templates/PROJECT-TASKLIST-TEMPLATE.md` | ATDR feature/change tasklist template. |
| `docs/templates/PROJECT-SYSTEM-PROGRESS-TEMPLATE.md` | ATDR system progress template. |
| `docs/agents/ATDR_AGENT_OPERATING_MODEL.md` | ATDR agent roles, responsibilities, and verification responsibilities. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | Requirement-to-source/test/docs/gap traceability. |
| `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md` | University process compliance status and remaining gaps. |
| `docs/ATDR_TEMPLATE_COMPARISON_AND_GAP_AUDIT.md` | Supervisor-template comparison showing what ATDR has completed, what is partial, and what remains future work. |
| `docs/CURRENT_SYSTEM_STATE_LOCK.md` | Current-state anchor before major productization work, including architecture, safety boundaries, limitations, verification commands, and protected local artifacts. |
| `docs/PRODUCTIZATION_TEMPLATE_GAP_ANALYSIS.md` | Phase 1 comparison between ATDR and the official supervisor template with keep/adapt/do-not-copy guidance and safe cleanup plan. |
| `docs/ATDR_PRODUCTIZATION_ROADMAP.md` | Phase 2 SaaS-like productization roadmap covering target backend/frontend/database/IAM/assistant/detection/deployment/testing/security direction. |
| `docs/ATDR_REPO_CLEANUP_PLAN.md` | Phase 3 repository cleanup classification covering keep/update/move/delete/ignore decisions without deleting files. |
| `docs/DETECTION_ML_PRODUCTIZATION_PLAN.md` | Source-backed plan for productizing rule detection, anomaly scoring, supervised SOC queue output, model registry, drift monitoring, and promotion gates without activating models or response automation. |
| `docs/detection/ATDR_RULE_PACK_CONTRACT.md` | Versioned deterministic detection rule-pack contract aligned to implemented rule IDs and SOC analyst checks. |
| `docs/detection/ATDR_SCENARIO_CORPUS_CONTRACT.md` | Controlled scenario-corpus contract for parser, detection, deduplication, explanation, and response-safety validation. |
| `docs/V3_72_UNIFIED_DETECTION_ML_EVALUATION.md` | Read-only unified detection/ML productization evaluator covering rule/scenario contracts, optional temp-DB scenario quality, latest supervised policy artifacts, and safety invariants. |
| `docs/V3_95_DEPLOYMENT_SECURITY_MONITORING_AND_RECOVERY.md` | Optional reverse-proxy, monitoring, scheduled maintenance, secret, read-only load, and isolated recovery operating guide. |
| `docs/V3_94_RELEASE_COMMIT_ALLOWLIST.md` | Exact v3.89-v3.94 path boundary and safe staging warning for the cumulative worktree. |
| `docs/V3_95_RELEASE_MANIFEST.md` | Approval-gated cumulative v3.89-v3.95 staging, commit, push, CI, exclusion, and rollback boundary. |

## Security And IAM Documents

| Document | Purpose |
| --- | --- |
| `docs/security/ATDR_IAM_RBAC_MATRIX.md` | Current admin/analyst role matrix and access-control evidence. |
| `docs/security/ATDR_PERMISSION_PATHS.md` | NewSystem-style ATDR permission path registry for future IAM mapping. |
| `docs/security/ATDR_EXTERNAL_IAM_PLAN.md` | Disabled-by-default generic OIDC/school-email IAM plan. |
| `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md` | Safe mapping from supervisor MFU IAM/Google SSO/OTP/B2B guidance to ATDR without enabling external IAM. |
| `docs/security/ATDR_MFU_IAM_IMPLEMENTATION_PLAN.md` | Source-backed implementation path for MFU IAM SDK/token introspection and school-email role mapping, still disabled by default. |
| `docs/V3_64_MFU_IAM_TEMPLATE_ADAPTER.md` | Supervisor-template IAM env compatibility and non-secret readiness status for ATDR. |
| `docs/V3_65_MFU_IAM_AND_REAL_ASSISTANT_HARNESS.md` | Historical MFU token-login harness (retired by v3.91) and safe real LLM provider probe. |
| `docs/V3_74_MFU_IAM_VALIDATION_HARNESS.md` | Safe MFU IAM configuration/probe harness for private `.env` validation without exposing secrets or enabling external login by default. |
| `docs/V3_77_MFU_IAM_CONFIG_DOCTOR_VISIBILITY.md` | Historical pre-v3.91 MFU IAM readiness visibility; current handoff readiness is documented by v3.91. |
| `docs/ATDR_TEMPLATE_SHELL_INTEGRATION_PLAN.md` | Historical source-backed plan for template-shell integration. Its browser-token material is superseded by the v3.91 opaque-code handoff. |
| `docs/V3_79_TEMPLATE_TO_ATDR_HANDOFF_RECEIVER.md` | Historical frontend receiver/change record; v3.91 now rejects credential-like URLs and consumes only an opaque form-posted code. |
| `docs/V3_80_SUPERVISOR_TEMPLATE_RUNTIME_BRIDGE.md` | Historical source-contract validator; v3.91 validates the safe handoff-status contract rather than template browser-token evidence. |
| `docs/V3_81_TEMPLATE_ATDR_LAUNCHER_HELPER.md` | Dry-run-first helper for adding an `Open ATDR SOC Dashboard` launcher to the official supervisor template registry page. |
| `docs/V3_82_TEMPLATE_LAUNCHER_APPLIED_RUNTIME_PREP.md` | Status after applying the ATDR launcher to the external supervisor template copy, including backup path and runtime test steps. |
| `docs/V3_83_TEMPLATE_SHELL_SESSION_ADAPTER.md` | ATDR-side adapter that validates the supervisor template session through the template backend profile endpoint and maps the verified school email into an ATDR user. |
| `docs/V3_84_TEMPLATE_SHELL_RUNTIME_VALIDATION.md` | Non-mutating CLI validation for static bridge state, private template-shell IAM config, and optional live ATDR/template reachability. |
| `docs/V3_85_TEMPLATE_SHELL_CONFIG_HELPER.md` | Dry-run-first helper for preparing private `.env` template-shell handoff settings with backup-on-write behavior. |
| `docs/V3_86_TEMPLATE_SHELL_LIVE_RUNTIME_CHECK.md` | Local runtime validation record showing ATDR and the supervisor template running together with the protected profile endpoint detected. |
| `docs/security/ATDR_REAL_LLM_ASSISTANT_PLAN.md` | Real LLM assistant provider plan with Gemini/OpenAI/Claude options, disabled by default and read-only. |
| `docs/security/ATDR_SCHOOL_EMAIL_IAM_READINESS_AUDIT.md` | School-email IAM readiness audit explaining why real MFU/Google/OIDC login remains disabled until provider details are approved. |
| `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md` | Advisor/provider questions required before real MFU IAM or Google SSO implementation. |
| `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md` | Lab security review baseline and production-hardening gaps. |

## Runbooks And Readiness Documents

| Document | Purpose |
| --- | --- |
| `README.md` | Short project overview, startup commands, verification commands, and doc map. |
| `docs/QUICKSTART_FOR_TEAM.md` | Windows setup for teammates using clone or zip download. |
| `docs/LAB_RUNBOOK.md` | Local/lab operations, replay, syslog, sources, scenarios, and troubleshooting. |
| `docs/ACCEPTANCE_TEST_CHECKLIST.md` | Manual acceptance workflow. |
| `docs/FINAL_SYSTEM_STATUS.md` | Current final controlled academic status. |
| `docs/V3_0_PRODUCTION_READINESS_TRACK.md` and related v3 docs | Future production-readiness planning without production claim. |
| `docs/V3_4_SHARED_LAB_READINESS.md` | Current shared-lab foundation checks for PostgreSQL status, backup/restore drill, performance profiling, source pilot checklist, operations health, and config hardening. |
| `docs/V3_5_REAL_SOURCE_SYSLOG_PILOT.md` | Controlled real-source/syslog pilot checklist, source-pipeline-vs-real-device wording, and safe evidence-export workflow. |
| `docs/V3_6_BACKGROUND_JOB_HARDENING.md` | Synchronous operation job tracking for import, replay, detection, ML, and export visibility without changing core runtime behavior. |
| `docs/V3_7_OPERATION_RETENTION_AND_JOB_RECOVERY.md` | Dry-run-first stale job recovery and operation-job retention maintenance without deleting raw evidence. |
| `docs/V3_8_ANALYST_ASSISTANT_MVP.md` | Read-only SOC assistant MVP with deterministic local fallback, external LLM disabled by default, raw-log context disabled by default, and audit logging. |
| `docs/V3_9_ASSISTANT_HARDENING.md` | Read-only assistant hardening with presets, audit-backed history, citations, and broader safe deterministic intents. |
| `docs/V3_10_CONFIG_SAFETY_HARDENING.md` | Local/shared-lab configuration safety for SQLite defaults, optional PostgreSQL lab config, and clear DB-unavailable diagnostics. |
| `docs/V3_11_DETECTION_EXPLAINABILITY_HARDENING.md` | Parser/detection/explanation hardening with log-level triage explanations and safe detection-validation reporting. |
| `docs/V3_12_DETECTION_RULE_QUALITY.md` | Detection rule quality and alert-noise reduction with expected/allowed/unexpected scenario validation. |
| `docs/V3_13_SOC_ASSISTANT_ALERT_EXPLAINER.md` | Read-only SOC Assistant alert explainer with structured evidence, ATT&CK mapping, analyst next steps, and safe alert-detail handoff. |
| `docs/V3_14_EMAIL_VERIFICATION_AND_ACCOUNT_NOTIFICATIONS.md` | Disabled-by-default local email verification, hashed-token, and admin-only dev outbox foundation. |
| `docs/V3_15_ACCOUNT_LIFECYCLE_AND_EMAIL_VERIFICATION_UX.md` | Account lifecycle and school-email verification UX hardening with status-only verification policy flags. |
| `docs/V3_17_PARSER_DETECTION_EXPLAINABILITY_HARDENING.md` | Parser/normalization validation, controlled detection-quality validation, and enriched explanation payloads. |
| `docs/V3_18_DETECTION_CORPUS_AND_FP_FN_QA.md` | Expanded safe detection corpus, false-positive / false-negative scenario QA, rule-level QA, and explanation completeness validation. |
| `docs/V3_19_NO_HARDWARE_SOAK_AND_PARSER_DRIFT.md` | No-hardware multi-source soak validation for parser drift, alert-noise stability, source health, deduplication, and explanation completeness. |
| `docs/V3_21_SOC_ASSISTANT_DEMO_QUALITY.md` | SOC Assistant demo-quality upgrade with deterministic alert/source/detection/ML/how-to answers and read-only guardrail refusals. |
| `docs/V3_22_SOC_ASSISTANT_EVIDENCE_GROUNDED_DEMO_QA.md` | Evidence-grounded SOC Assistant demo QA with structured answer sections, citation display, safe follow-ups, and advisor demo question set. |
| `docs/V3_22_ASSISTANT_DEMO_QUESTION_SET.md` | Advisor/team demo questions for alert, source, operations, ML, workflow, and unsafe-request refusal checks. |
| `docs/V3_23_ASSISTANT_CONTEXT_LINKING.md` | Assistant citation-to-dashboard handoff polish for alert, log, source, job, detection, and ML context without adding action capability. |
| `docs/V3_24_SOC_ASSISTANT_INVESTIGATION_CONTEXT.md` | Assistant investigation-context upgrade for alert, related-log, source, and computed case/group summaries while staying read-only. |
| `docs/V3_25_SOC_ASSISTANT_INVESTIGATION_BRIEF_BUILDER.md` | Assistant investigation brief builder for structured, cited, copyable alert/log/source/case handoffs while staying read-only. |
| `docs/V3_26_ASSISTANT_QA_QUESTION_SET.md` | Controlled question set for validating assistant alert/log/source/job/ML/brief/unsafe-request behavior. |
| `docs/V3_26_SOC_ASSISTANT_EVALUATION_AND_INVESTIGATION_QA.md` | End-to-end assistant QA using a temporary database, safe scenario import, detection fixture, citation checks, and no-side-effect checks. |
| `docs/V3_27_ASSISTANT_FEEDBACK_AND_ANSWER_QUALITY.md` | SOC Assistant answer-quality feedback workflow with authenticated ratings, scoped summary, audit, and no action capability. |
| `docs/V3_28_ASSISTANT_FEEDBACK_REVIEW.md` | SOC Assistant feedback review dashboard and quality-triage workflow with filters, unsafe/incorrect summary, and no automatic tuning. |
| `docs/V3_29_SOC_ASSISTANT_REASONING_AND_TRIAGE_QUALITY.md` | SOC Assistant reasoning upgrade with false-positive awareness, missing-evidence notes, source/case risk summaries, analyst checklists, and no action capability. |
| `docs/V3_30_DETECTION_ML_QUALITY_REVALIDATION.md` | Current-dataset detection and supervised ML quality revalidation with false-positive analysis, threshold comparison, calibration, and diagnostic review export. |
| `docs/V3_56_SOC_QUEUE_DIAGNOSTIC_INTEGRATION.md` | ML Governance/API integration for the stable v3.55 binary SOC review-queue diagnostic, kept candidate-only with exact severity as explanation/ranking. |
| `docs/V3_57_QUEUE_RULE_HYBRID_AGREEMENT.md` | Diagnostic-only queue-vs-rule/hybrid evidence agreement analysis for the stable SOC review-queue candidate. |
| `docs/V3_58_QUEUE_EVIDENCE_VISIBILITY.md` | Read-only ML Governance and SOC Assistant visibility for the latest v3.57 queue-vs-rule/hybrid agreement diagnostic. |
| `docs/V3_59_SUPERVISED_OUTPUT_POLICY_CONTRACT.md` | Diagnostic-only supervised output policy contract: queue score is decision support, exact severity labels remain explanation/ranking only. |
| `docs/V3_60_SUPERVISED_POLICY_DASHBOARD_ASSISTANT_ALIGNMENT.md` | Dashboard and SOC Assistant alignment with the v3.59 supervised output policy contract. |
| `docs/V3_61_SOC_ASSISTANT_PRESENTATION_HARDENING.md` | Presentation-ready SOC Assistant preset and fallback hardening while preserving read-only, no-action behavior. |
| `docs/V3_63_REAL_LLM_ASSISTANT_ADAPTER.md` | Disabled-by-default real LLM provider adapter for Gemini, OpenAI-compatible APIs, Claude, and mock testing while preserving deterministic fallback and read-only safety. |
| `docs/V3_62_SUPERVISED_TRAINING_TARGET_CONTRACT.md` | Diagnostic-only safe training target adapter: exact labels are mapped to a binary SOC review-queue target while exact severity remains explanation/ranking only. |
| `docs/V3_66_SOC_ASSISTANT_CONTEXT_HARDENING.md` | SOC Assistant follow-up context hardening so typed IDs override stale context and active alert/log/source/case context is clearer. |
| `docs/V3_67_CI_AND_ASSISTANT_STABILITY.md` | CI hardening for backend no-`.env` checks and React dashboard lint/build/e2e coverage after assistant context stabilization. |
| `docs/V3_68_REAL_LLM_ASSISTANT_QUALITY_GUARD.md` | Real LLM assistant quality guard so weak or unsafe provider wording cannot replace ATDR's deterministic evidence-grounded answer. |
| `docs/V3_69_REAL_LLM_PROMPT_QUALITY_CONTRACT.md` | Real LLM prompt-quality contract that asks providers for professional, evidence-preserving SOC answer sections while keeping v3.68 guardrails active. |
| `docs/V3_70_ASSISTANT_PROVIDER_TELEMETRY.md` | SOC Assistant dashboard telemetry that clearly shows local, external-used, guarded, or fallback provider behavior without exposing secrets or raw logs. |
| `docs/V3_75_ASSISTANT_FOLLOWUP_CONTEXT_REPAIR.md` | SOC Assistant follow-up context repair so alert-scoped follow-ups keep the correct alert/log/source/case context and do not revive stale URL context. |
| `docs/V3_76_REAL_LLM_ASSISTANT_FULL_CHAT_PROBE.md` | Safe full assistant chat provider probe using a synthetic temporary database to validate configured real LLM behavior without exposing secrets or mutating ATDR data. |
| `docs/V3_87_REAL_LLM_SOC_ASSISTANT.md` | Completed optional real-provider SOC Assistant path with structured answers, bounded follow-up context, privacy filtering, reliability controls, deterministic fallback, and zero action capability. |
| `docs/V3_88_PRODUCT_BASELINE_CHECKPOINT.md` | Consolidated v3.78-v3.87 source/runtime/docs baseline, current safety posture, CI position, remaining risks, and next product phase. |
| `docs/V3_88_CHANGESET_MANIFEST.md` | Exact intended commit allowlist, ignored/private exclusions, external template change, rollback notes, risks, and staging commands. |
| `docs/V3_89_SHARED_LAB_PERSISTENCE_AND_BACKUP_RESTORE.md` | SQLite-preserving shared-lab persistence profile, safe backup/restore workflow, PostgreSQL CI validation design, and remaining operational limits. |
| `docs/V3_89_CHANGESET_MANIFEST.md` | Exact v3.89 source-controlled staging allowlist, private-output exclusions, review commands, and rollback notes. |
| `docs/changes/T1_T20_V3_89_SHARED_LAB_PERSISTENCE.md` | T1-T20 change record for the v3.89 persistence and backup/restore foundation. |
| `docs/V3_90_DURABLE_BACKGROUND_JOBS.md` | Opt-in durable operation queue, safe worker lifecycle, heartbeat/lease behavior, RBAC, and local/shared-lab limits. |
| `docs/changes/T1_T20_V3_90_DURABLE_BACKGROUND_JOBS.md` | T1-T20 change record for v3.90 durable operation reliability. |
| `docs/V3_91_MFU_OUTER_SHELL_SECURE_HANDOFF.md` | Canonical secure MFU outer-shell sign-in handoff: opaque code, server-side exchange, cookie session, and group-based role mapping. |
| `docs/V3_91_CHANGESET_MANIFEST.md` | v3.91 change scope, explicit exclusions, source evidence, rollback, and provider-side prerequisites. |
| `docs/security/ATDR_MFU_IAM_PREPROD_VALIDATION.md` | Preproduction test cases, required evidence, stop conditions, and rollback for the v3.91 handoff. |
| `docs/changes/T1_T20_V3_91_MFU_OUTER_SHELL_IAM_HANDOFF.md` | T1-T20 change record for the v3.91 secure MFU outer-shell handoff. |
| `docs/V3_73_DETECTION_ML_GOVERNANCE_DASHBOARD.md` | AI Governance dashboard integration for the read-only v3.72 Detection/ML productization evaluator. |
| `docs/DETECTION_RULE_CATALOG.md` | Source-backed catalog of deterministic detection rules, false positives, mappings, and analyst next steps. |
| `docs/ATDR_TEMPLATE_MERGE_ANALYSIS.md` | Current controlled template-merge analysis: adopt IAM/process concepts without migrating ATDR to Node/Vue/MongoDB. |

## Reference-Only Documents

For IAM history, v3.65-v3.86 token/session-handoff documents remain change evidence only. The current authentication contract is v3.91; do not reintroduce browser-token URLs from historical documents.

The repository may include NewSystem template documents for traceability. They are reference-only unless an ATDR-specific document explicitly adopts a rule.

| Reference | Rule |
| --- | --- |
| `NewSystem/` | University process/style/reference material only. Not ATDR runtime code. |
| `docs/AI-WORKFLOW.md` | Original NewSystem-oriented workflow reference. Active workflow is `docs/ATDR_AI_WORKFLOW.md`. |
| `docs/prd/PRD-NewSystem.md` | NewSystem PRD reference. Active PRD is `docs/prd/PRD-ATDR.md`. |
| `docs/agents/agent-*.md` when NewSystem-specific | Reference roles only; active ATDR model is `docs/agents/ATDR_AGENT_OPERATING_MODEL.md`. |

## Change Rules

- Source code and mounted routes beat docs when they conflict.
- Use ATDR source paths in new work: `atdr/app/main.py`, `atdr/app/routers/*.py`, `atdr/app/db/models.py`, `frontend/src/App.tsx`, `frontend/src/lib/api.ts`, and tests.
- Update `docs/tasks/tasklist-progress.md` and regenerate `docs/tasks/tasklist-progress.html` when system progress, blockers, verification, or readiness changes.
- Use a T1-T20 change record for non-trivial work.
- Update `docs/prd/PRD-ATDR.md` and `docs/ATDR_REQUIREMENT_TRACEABILITY.md` when behavior, API, UI, data model, permission, safety, ML, or release expectations change.
- Do not claim production readiness, automatic response, real firewall blocking, or full external IAM unless future source evidence proves it.

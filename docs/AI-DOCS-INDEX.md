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

## Security And IAM Documents

| Document | Purpose |
| --- | --- |
| `docs/security/ATDR_IAM_RBAC_MATRIX.md` | Current admin/analyst role matrix and access-control evidence. |
| `docs/security/ATDR_PERMISSION_PATHS.md` | NewSystem-style ATDR permission path registry for future IAM mapping. |
| `docs/security/ATDR_EXTERNAL_IAM_PLAN.md` | Disabled-by-default generic OIDC/school-email IAM plan. |
| `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md` | Safe mapping from supervisor MFU IAM/Google SSO/OTP/B2B guidance to ATDR without enabling external IAM. |
| `docs/security/ATDR_MFU_IAM_IMPLEMENTATION_PLAN.md` | Source-backed implementation path for MFU IAM SDK/token introspection and school-email role mapping, still disabled by default. |
| `docs/V3_64_MFU_IAM_TEMPLATE_ADAPTER.md` | Supervisor-template IAM env compatibility and non-secret readiness status for ATDR. |
| `docs/V3_65_MFU_IAM_AND_REAL_ASSISTANT_HARNESS.md` | Disabled-by-default MFU school-email token-login harness and safe real LLM provider probe. |
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
| `docs/DETECTION_RULE_CATALOG.md` | Source-backed catalog of deterministic detection rules, false positives, mappings, and analyst next steps. |
| `docs/ATDR_TEMPLATE_MERGE_ANALYSIS.md` | Current controlled template-merge analysis: adopt IAM/process concepts without migrating ATDR to Node/Vue/MongoDB. |

## Reference-Only Documents

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

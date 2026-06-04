# ATDR Requirement Traceability

This document maps major ATDR requirements to implementation evidence, tests, docs, and known gaps. It is intentionally source-backed so future AI/Codex work can avoid guessing.

## Source Evidence

| Evidence | Repository Source |
| --- | --- |
| Product scope and startup commands | `README.md` |
| PRD | `docs/prd/PRD-ATDR.md` |
| FastAPI route mounting | `atdr/app/main.py` |
| Database model truth | `atdr/app/db/models.py` |
| Backend routers | `atdr/app/routers/*.py` |
| React route/page truth | `frontend/src/App.tsx`, `frontend/src/pages/*` |
| Release gate | `atdr/scripts/verify_release.py` |
| Lab runbook and v0.3 status | `docs/LAB_RUNBOOK.md`, `docs/V0_3_STATUS.md` |

## Traceability Matrix

| Requirement | Status | Implementation Evidence | Test Evidence | Documentation Evidence | Remaining Gap |
| --- | --- | --- | --- | --- | --- |
| Log import preserves raw evidence | Implemented | `atdr/app/routers/logs.py`, `atdr/app/services/log_service.py`, `atdr/app/db/models.py` | `atdr/tests/test_import_and_detection.py`, `atdr/tests/test_api.py` | `README.md`, `docs/LAB_RUNBOOK.md` | Large imports should use PostgreSQL for shared lab scale. |
| Replay/syslog test support | Implemented | `atdr/scripts/replay_logs.py`, `atdr/scripts/run_syslog_receiver.py`, `atdr/scripts/send_sample_syslog.py` | `atdr/tests/test_replay_logs.py`, `atdr/tests/test_source_scenarios.py` | `docs/LAB_RUNBOOK.md`, `docs/V0_3_STATUS.md` | Real device forwarding still needs controlled hardware validation. |
| Source management and source health | Implemented | `atdr/app/routers/sources.py`, `atdr/app/services/source_service.py`, `atdr/app/db/models.py` | `atdr/tests/test_sources.py`, `atdr/tests/test_source_scenarios.py` | `docs/LAB_RUNBOOK.md`, `docs/V0_3_PLAN.md` | Disable behavior is non-destructive; production governance still future work. |
| Parser profiles and raw fallback | Implemented | `atdr/app/parsers/paloalto_parser.py`, `atdr/app/services/log_service.py` | `atdr/tests/test_parser.py`, `atdr/tests/test_source_scenarios.py` | `docs/LAB_RUNBOOK.md`, `docs/V0_3_STATUS.md` | Vendor-specific parser expansion is future work. |
| Rule-based detection | Implemented | `atdr/app/services/detection_service.py`, `atdr/app/detection/rules.py` | `atdr/tests/test_rules.py`, `atdr/tests/test_import_and_detection.py` | `README.md`, `docs/ARCHITECTURE.md` | Rules need continued tuning with live lab data. |
| Alerts and alert lifecycle | Implemented | `atdr/app/routers/alerts.py`, `atdr/app/db/models.py` | `atdr/tests/test_api.py` | `docs/ACCEPTANCE_TEST_CHECKLIST.md`, `docs/V0_1_STATUS.md` | Full ticketing integration is future work. |
| Alert deduplication and occurrence tracking | Implemented | `atdr/app/services/detection_service.py`, `atdr/app/db/models.py` | `atdr/tests/test_alert_deduplication.py`, `atdr/tests/test_source_scenarios.py` | `docs/V0_2_PLAN.md`, `docs/V0_3_STATUS.md` | Dedup windows may need tuning for real traffic. |
| Lightweight cases | Implemented | `atdr/app/services/case_service.py`, `atdr/app/routers/alerts.py` | `atdr/tests/test_api.py`, `atdr/tests/test_case_service.py` | `docs/V0_1_STATUS.md`, `docs/V0_2_PLAN.md` | Not a full incident-management system. |
| AI Governance and ML reports | Implemented as SOC triage decision support | `atdr/app/routers/ml.py`, `atdr/app/services/ml_service.py`, `atdr/app/detection/supervised_detector.py`, `frontend/src/pages/MLGovernance.tsx` | `atdr/tests/test_supervised_ml.py`, `atdr/tests/test_model_validation.py`, `frontend/tests/smoke.spec.ts` | `docs/AI_TRAINING_RUNBOOK.md`, `docs/ML_BASELINE_TUNING.md` | Not production-promoted; flat five-class benign/needs_context exact classification remains weak. |
| Reproducible supervised ML pipeline | Implemented as lab workflow | `atdr/app/detection/supervised_workflow.py`, `atdr/app/detection/model_comparison.py`, `atdr/scripts/export_supervised_dataset_snapshot.py`, `atdr/scripts/run_supervised_experiment.py`, `atdr/scripts/tune_supervised_model.py`, `atdr/scripts/supervised_sanity_report.py`, `atdr/scripts/analyze_supervised_errors.py`, `atdr/scripts/list_supervised_models.py`, `atdr/scripts/activate_supervised_model.py`, `atdr/scripts/rollback_supervised_model.py` | `atdr/tests/test_supervised_ml.py` | `docs/AI_TRAINING_RUNBOOK.md` | Generated snapshots/reports stay ignored; metrics are not production accuracy. |
| Supervised ML recovery workflow | Implemented as candidate-only diagnostic workflow | `atdr/app/detection/supervised_recovery.py`, `atdr/scripts/supervised_dataset_audit.py`, `atdr/scripts/rebuild_supervised_baseline.py`, `atdr/scripts/run_binary_threat_experiment.py`, `atdr/scripts/run_supervised_recovery_phase.py`, `atdr/scripts/export_supervised_recovery_review_sample.py`, `atdr/scripts/current_supervised_error_analysis.py`, `atdr/scripts/write_soc_triage_final_recommendation.py`, `atdr/scripts/export_final_small_label_gap_sample.py` | `atdr/tests/test_supervised_ml.py` | `docs/AI_TRAINING_RUNBOOK.md` | Rebuilt baselines and SOC triage profiles are registered/diagnostic candidates only; no automatic activation, promotion, or response automation. |
| Human label review workflow | Implemented | `atdr/app/routers/ml.py`, `atdr/app/services/ml_label_service.py` | `atdr/tests/test_label_workflow.py`, `atdr/tests/test_assisted_labeling.py` | `docs/AI_TRAINING_RUNBOOK.md` | Needs more reviewed data for stronger claims. |
| Simulated response only | Implemented | `atdr/app/routers/response.py`, `atdr/app/services/response_service.py` | `atdr/tests/test_response_safety.py`, `atdr/tests/test_api.py` | `docs/prd/PRD-ATDR.md`, `docs/LAB_RUNBOOK.md` | Real connector is future approved work only. |
| Audit trail | Implemented | `atdr/app/routers/audit.py`, `atdr/app/db/models.py`, service audit writes | `atdr/tests/test_api.py`, `atdr/tests/test_response_safety.py` | `docs/ACCEPTANCE_TEST_CHECKLIST.md`, `docs/LAB_RUNBOOK.md` | Audit retention policy is future hardening. |
| Ingestion and detection run history | Implemented | `atdr/app/db/models.py`, `atdr/app/routers/ingestion.py`, `atdr/app/routers/detection.py` | `atdr/tests/test_run_history.py`, `atdr/tests/test_replay_logs.py` | `docs/V0_2_PLAN.md`, `docs/LAB_RUNBOOK.md` | Long-term retention and archival are future work. |
| Performance smoke | Implemented | `atdr/scripts/performance_smoke.py` | `atdr/tests/test_performance_smoke.py` | `docs/LAB_RUNBOOK.md`, `docs/V0_2_PLAN.md` | Budgets are local-lab targets, not production SLAs. |
| IAM/RBAC | Implemented for admin/analyst lab roles; OIDC status groundwork added disabled by default | `atdr/app/core/security.py`, `atdr/app/routers/auth.py`, `atdr/app/routers/*.py`, `frontend/src/components/AdminRoute.tsx`, `frontend/src/pages/UserAdmin.tsx` | `atdr/tests/test_api.py`, `atdr/tests/test_response_safety.py`, `atdr/tests/test_iam_rbac.py`, `frontend/tests/smoke.spec.ts` | `docs/security/ATDR_IAM_RBAC_MATRIX.md`, `docs/security/ATDR_EXTERNAL_IAM_PLAN.md` | No full external login flow, SSO/OAuth callback, SAML, LDAP, or viewer role yet. |
| Local school-email accounts | Implemented for lab IAM support | `atdr/app/db/models.py`, `atdr/app/services/user_service.py`, `atdr/app/routers/users.py`, `frontend/src/pages/UserAdmin.tsx` | `atdr/tests/test_api.py`, `frontend/tests/smoke.spec.ts` | `docs/security/ATDR_EXTERNAL_IAM_PLAN.md`, `docs/security/ATDR_IAM_RBAC_MATRIX.md` | SMTP invite/reset email and full OIDC login remain future work. |
| NewSystem template alignment | Implemented as ATDR-specific governance/process adaptation | `atdr/app/main.py`, `atdr/app/core/security.py`, `atdr/app/routers/*.py`, `frontend/src/App.tsx` | Docs validation and release gate; future code changes must use T1-T20 evidence | `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md`, `docs/ATDR_TEMPLATE_MANIFEST.json`, `docs/security/ATDR_PERMISSION_PATHS.md`, `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md` | External IAM/B2B SDK, OAuth/SSO, and production hardening remain future work. |
| Quickstart/team setup | Implemented | `atdr/scripts/check_dev_environment.py`, `.env.example`, `.env.lab.example`, `frontend/package.json` | `atdr/tests/test_dev_onboarding.py`, release gate | `docs/QUICKSTART_FOR_TEAM.md`, `README.md` | Teammates should use Node.js 20.x; Node 16 may fail with current frontend tooling. |

## Traceability Rules For Future Changes

- Update this file when a new major capability, route family, role boundary, data model, safety behavior, or release workflow is added.
- Prefer repo source paths over narrative-only claims.
- If implementation and docs conflict, code/routes/tests are the source of truth and docs must be corrected.

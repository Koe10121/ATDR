# T1-T20 Change Document: Template Comparison And IAM Readiness Audit

## T1 Change Title

- Title: ATDR Supervisor Template Comparison And School Email IAM Readiness Audit
- Date: 2026-06-21
- Owner / acting agent: Codex
- Related version or sprint: v3.20 process/IAM readiness audit

## T2 Requirement

- User request: Compare the supervisor-provided template folder against the current ATDR project, identify completed and missing work, and determine whether enough school-email/IAM information exists to connect ATDR now.
- Business / lab goal: Keep ATDR aligned with advisor/university workflow expectations without unsafe stack migration or unapproved external IAM integration.
- Success outcome: Create ATDR-specific audit docs, update governance traceability, and clearly state what is complete, what is partial, what is missing, and what provider details are needed.
- Explicit non-goals:
  - No Node/Vue/MongoDB migration.
  - No real OAuth/OIDC/Google/MFU IAM login.
  - No external network calls to IAM providers.
  - No database reset or schema change.
  - No response automation or real firewall blocking.

## T3 Source Evidence

| Source | Path | Evidence / Finding |
| --- | --- | --- |
| Supervisor IAM PRD | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\backend-node\docs\IAM_PRD.md` | Defines authentication, Google SSO/MFU Mail, 2FA, account lifecycle, permission matrix, B2B introspection, audit, and environment expectations. |
| Supervisor IAM overview | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\backend-node\docs\IAM_SYSTEM_OVERVIEW.md` | Describes IAM-first/local permission sources, sign-in flow, authorization flow, and B2B token flow. |
| Supervisor IAM recommendations | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\backend-node\docs\IAM_RECOMMENDATIONS.md` | Provides security recommendations; secret values must not be copied. |
| Supervisor IAM source | `backend-node/server/integrations/iam/*`, `backend-node/server/Project/security/*` in the supervisor template | Shows IAM SDK adapter, token introspection, account access, permissions, and audit patterns. |
| Supervisor frontend IAM UI | `frontend-vue/src/projects/components/dialog/SignIn.vue`, `frontend-vue/src/projects/components/dialog/TwoFA.vue` in the supervisor template | Shows Google/MFU Mail sign-in and OTP UX patterns. |
| ATDR auth/config source | `atdr/app/core/config.py`, `atdr/app/core/security.py`, `atdr/app/routers/auth.py`, `atdr/app/routers/users.py` | Shows local JWT login, email login, disabled OIDC/MFU IAM placeholders, and user admin. |
| ATDR frontend source | `frontend/src/App.tsx`, `frontend/src/components/AppShell.tsx`, `frontend/src/pages/UserAdmin.tsx` | Shows React routes, account status, User Admin, and IAM status panels. |
| Existing ATDR IAM docs | `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md`, `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md`, `docs/security/ATDR_IAM_RBAC_MATRIX.md` | Already document disabled-by-default IAM planning and provider-detail questions. |
| ATDR governance docs | `docs/ATDR_REQUIREMENT_TRACEABILITY.md`, `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`, `docs/prd/PRD-ATDR.md`, `docs/tasks/tasklist-progress.md` | Source-backed workflow, PRD, traceability, compliance, and progress evidence. |

## T4 Current Behavior

- Current backend behavior: ATDR uses local JWT authentication with admin/analyst roles; OIDC and MFU IAM status/config placeholders are disabled by default.
- Current frontend behavior: React dashboard includes Admin/User Admin, account status, school-email policy status, and external IAM status panels.
- Current data model behavior: SQLAlchemy/Alembic stores users, logs, alerts, sources, audit, jobs, labels, and response actions; no schema change is required for this audit.
- Current AI/ML behavior: ML remains SOC triage decision support only; no model activation or promotion is changed.
- Current response/audit behavior: Response actions remain simulated and analyst-approved; IAM cannot trigger automatic response.
- Current known limitation: Real school-email/IAM login is not implemented because provider details and approval are missing.

## T5 Impacted Areas / Agents

| Area / Agent | Impacted? | Reason |
| --- | --- | --- |
| Orchestrator | yes | Coordinates source-backed audit and handoff. |
| Product Owner / Requirement Planner | yes | Confirms what is complete, partial, and future work. |
| Data Model / Database | no | No schema or database behavior change. |
| Backend / API | no | No runtime API behavior change. |
| Frontend / Dashboard | no | No UI behavior change. |
| AI/ML Governance | yes | Confirms no ML promotion/activation changes. |
| Security / Response Safety | yes | IAM readiness, secret handling, and response safety are central. |
| QA/UAT | yes | Runs docs/process and release checks. |
| Release/Ops / Lab Validation | yes | Confirms workflow, hygiene, and verification status. |

## T6 Scope

### In Scope

- Compare supervisor IAM/template expectations with ATDR.
- Create audit docs.
- Update traceability/compliance/tasklist.
- Run verification.

### Out Of Scope

- No real external IAM login.
- No OAuth/OIDC callback flow.
- No Google/MFU network call.
- No migration to Node/Vue/MongoDB.
- No response automation.
- No production readiness claim.

## T7 Functional Requirements

| ID | Requirement | Priority | Source |
| --- | --- | --- | --- |
| FR-V320-001 | Document supervisor template capabilities and ATDR mapping. | Must | User request |
| FR-V320-002 | Document school-email/IAM readiness and missing provider details. | Must | User request |
| FR-V320-003 | Keep ATDR runtime behavior unchanged. | Must | Safety constraints |
| FR-V320-004 | Update governance traceability and tasklist evidence. | Must | University workflow |

## T8 Acceptance Criteria

| ID | Acceptance Criteria | Verification |
| --- | --- | --- |
| AC-001 | Template comparison audit exists and cites source evidence. | `docs/ATDR_TEMPLATE_COMPARISON_AND_GAP_AUDIT.md` |
| AC-002 | School email IAM readiness audit exists and does not expose secrets. | `docs/security/ATDR_SCHOOL_EMAIL_IAM_READINESS_AUDIT.md` |
| AC-003 | Traceability/compliance/tasklist reflect the audit. | Updated governance docs |
| AC-004 | Verification commands pass. | T16 evidence |

## T9 API Contract

- New endpoints: none.
- Changed endpoints: none.
- Unchanged endpoints: local auth, user admin, OIDC/MFU IAM status, response safety, assistant, detection, logs.
- Auth/RBAC: unchanged.
- Backward compatibility: unchanged.

## T10 Data Model / Migration

- Schema changes: none.
- Alembic migration: none.
- Index changes: none.
- Existing data compatibility: unchanged.
- Rollback strategy: revert docs only if needed.
- No migration needed because this is a documentation/process audit.

## T11 Backend Plan / Changes

- Routers: no change.
- Schemas: no change.
- Services: no change.
- Scripts: no runtime script change.
- Error handling: no change.
- Audit behavior: no change.
- Tests: use existing verification and release checks.

## T12 Frontend Plan / Changes

- Routes/pages: no change.
- Components: no change.
- API client/hooks: no change.
- Loading/error/empty states: no change.
- Role visibility: no change.
- Playwright/manual checks: existing smoke/e2e checks.

## T13 Security / Response / AI Safety

- Response mode remains simulation: yes.
- Automatic response remains disabled: yes.
- Real firewall enforcement added: no.
- Protected IP handling: unchanged.
- Audit impact: unchanged.
- ML decision-support status: unchanged.
- Data privacy/repo hygiene: no secrets copied; no `.env`, DB, real logs, model artifacts, generated reports, `ml_baseline_reviews/`, or `demo_exports/` should be committed.
- Security reviewer decision: pass-with-risk because real IAM still requires provider details and approval.

## T14 Test Plan

| Test | Command / Method | Required? | Notes |
| --- | --- | --- | --- |
| Tasklist render | `node scripts/render-tasklist-progress-html.js .` | yes | Regenerate progress HTML. |
| Tasklist standard | `node scripts/check-tasklist-progress-standard.js .` | yes | Validate progress board. |
| Ruff | `ruff check .` | yes | Ensure no code/style regression. |
| Python compile | `python -m compileall -q atdr migrations` | yes | Compile gate. |
| Backend tests | `python -m pytest atdr/tests -q` | yes | Regression check. |
| Alembic drift | `alembic check` | yes | Ensure no schema drift. |
| Frontend lint/build | `cd frontend; npm.cmd run lint; npm.cmd run build` | yes | Frontend regression check. |
| Release gate | `python -m atdr.scripts.verify_release` | yes | Final release evidence. |

## T15 Implementation Summary

| File | Change Summary |
| --- | --- |
| `docs/ATDR_TEMPLATE_COMPARISON_AND_GAP_AUDIT.md` | Added supervisor-template vs ATDR comparison and gap audit. |
| `docs/security/ATDR_SCHOOL_EMAIL_IAM_READINESS_AUDIT.md` | Added school-email/IAM readiness audit and no-go criteria. |
| `docs/changes/T1_T20_TEMPLATE_COMPARISON_AND_IAM_READINESS_AUDIT.md` | Added completed T1-T20 evidence for this audit. |
| `docs/tasks/tasklist-progress.md` | Updated current progress board entry for the audit. |
| `docs/tasks/tasklist-progress.html` | Regenerated from Markdown. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | Added template comparison/IAM readiness traceability row. |
| `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md` | Added audit docs to compliance evidence/status. |

## T16 Tests Run / Evidence

| Command / Check | Result | Evidence |
| --- | --- | --- |
| `node scripts/render-tasklist-progress-html.js .` | pass | Regenerated `docs/tasks/tasklist-progress.html` for v3.20. |
| `node scripts/check-tasklist-progress-standard.js .` | pass | Validated tasklist/progress-board standard. |
| `.\.venv\Scripts\ruff.exe check .` | pass | Ruff reported all checks passed. |
| `.\.venv\Scripts\python.exe -m compileall -q atdr migrations` | pass | Compile gate passed. |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests -q` | blocked by environment | Direct run hit Windows temp/cache permission errors under `AppData\Local\Temp\pytest-of-User`, not ATDR test failures. |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests -q --basetemp .pytest_tmp\v320-full -p no:cacheprovider` | pass | `304 passed, 1 skipped`; warnings are existing sklearn/joblib warnings. |
| `.\.venv\Scripts\alembic.exe check` | pass | No new upgrade operations detected. |
| `cd frontend; npm.cmd run lint; npm.cmd run build` | pass | React lint/build passed. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` | pass | Release gate returned `ok: true`; backend tests `304 passed, 1 skipped`; Alembic check passed. |

Skipped checks:

- Playwright and performance smoke were not rerun for this docs/process-only audit because no runtime or frontend behavior changed. Release gate, backend tests, Alembic, and frontend lint/build passed.

## T17 PRD / Docs Updated

| Document | Updated? | Reason |
| --- | --- | --- |
| `docs/prd/PRD-ATDR.md` | no | Runtime behavior and product scope unchanged. Existing PRD already documents IAM constraints. |
| `docs/ATDR_AI_WORKFLOW.md` | no | Workflow behavior unchanged. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | yes | Added audit traceability. |
| `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md` | yes | Added audit evidence/status. |
| `docs/tasks/tasklist-progress.md` | yes | Updated active progress board. |

## T18 Risks / Blockers / Assumptions / Decisions

### Risks

- Real IAM implementation could be unsafe if based on guessed provider URLs or copied secrets.
- Auto-provisioning admin users from email domain alone would be unsafe.

### Blockers

- Provider choice, callback URLs, client ID/secret delivery, allowed domains, group mapping, token contract, and audit requirements are not yet confirmed.

### Assumptions

- ATDR should keep FastAPI + React + SQLAlchemy/Alembic.
- Supervisor template is a workflow/security reference, not a stack migration instruction.

### Decisions

- Do not implement real external IAM until advisor/provider details are confirmed.
- Keep local JWT login and disabled status placeholders as the current safe state.

## T19 Release / Rollback

- Release impact: documentation/process only.
- Deployment notes: none.
- Local workflow impact: unchanged.
- Rollback plan: revert the new/updated docs if needed.
- Data rollback: not applicable.
- Monitoring/checks after release: verify docs and release gate.

## T20 Final Handoff

- Status: completed after verification.
- Files changed: audit docs, tasklist, traceability, compliance.
- Behavior changed: none.
- Verification result: pending until commands run.
- Remaining risks: real school-email/IAM requires advisor/provider details and security review.
- Exact next command for user: ask advisor to complete `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md`.

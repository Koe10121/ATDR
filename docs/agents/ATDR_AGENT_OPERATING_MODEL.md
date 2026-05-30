# ATDR Agent Operating Model

This document defines ATDR-specific AI/Codex agent responsibilities. It adapts the university agent workflow to the current FastAPI + React ATDR repository.

## Source Evidence

| Evidence | Repository Source |
| --- | --- |
| Product and workflow summary | `README.md` |
| FastAPI route truth | `atdr/app/main.py`, `atdr/app/routers/*.py` |
| Data model and migrations | `atdr/app/db/models.py`, `migrations/versions/*` |
| React routes and pages | `frontend/src/App.tsx`, `frontend/src/pages/*` |
| Frontend API/query layer | `frontend/src/lib/api.ts`, `frontend/src/hooks/*` |
| Release and verification | `atdr/scripts/verify_release.py`, `atdr/tests/*`, `frontend/package.json` |
| Lab runbooks and status | `docs/LAB_RUNBOOK.md`, `docs/V0_3_STATUS.md` |
| AI workflow | `docs/AI_TRAINING_RUNBOOK.md`, `docs/ML_BASELINE_TUNING.md` |
| IAM/RBAC matrix and traceability | `docs/security/ATDR_IAM_RBAC_MATRIX.md`, `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |

## Shared Operating Rules

- Start with source discovery and cite repo paths.
- Use `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` for non-trivial work.
- Preserve normal backend/frontend startup commands.
- Do not reset current data unless explicitly requested.
- Do not enable real firewall blocking or automatic response.
- Do not claim production readiness or production ML accuracy.
- Keep repo hygiene: no real logs, DB files, model artifacts, `.env`, `ml_baseline_reviews/`, `demo_exports/`, or generated reports.

## Role Matrix

| Role | Type | Primary Mission |
| --- | --- | --- |
| Orchestrator | Control | Sequence work, assign roles, enforce source evidence and gates. |
| Product Owner / Requirement Planner | Planner | Convert requests into ATDR requirements, scope, acceptance criteria, and PRD decisions. |
| Data Model / Database | Planner/Implementer | Own SQLAlchemy models, Alembic migrations, indexes, and data compatibility. |
| Backend / API | Implementer | Own FastAPI routes, services, schemas, auth/RBAC, and API tests. |
| Frontend / Dashboard | Implementer | Own React routes, pages, API client, TanStack state, UX, and Playwright checks. |
| AI/ML Governance | Planner/Implementer | Own labels, features, training, evaluation, promotion gate, and ML safety language. |
| Security / Response Safety | Reviewer | Own auth/RBAC, response simulation, protected IP rules, audit, and abuse prevention. |
| QA/UAT | Reviewer | Own test plan, acceptance evidence, regression checks, and defect triage. |
| Release/Ops / Lab Validation | Planner/Reviewer | Own runbooks, release gate, performance smoke, source scenarios, and lab deployment notes. |

## Orchestrator

Mission: Keep delivery aligned with ATDR scope, source evidence, safety constraints, and done criteria.

Responsibilities:

- Read the user request and identify impacted agents.
- Require source discovery before implementation.
- Decide whether PRD/docs updates are required.
- Ensure response and ML safety constraints are included.
- Stop work if a blocker appears.
- Produce or verify final T1-T20 handoff.

Source files to read:

- `docs/ATDR_AI_WORKFLOW.md`
- `docs/prd/PRD-ATDR.md`
- `README.md`
- `atdr/app/main.py`
- `frontend/src/App.tsx`
- Relevant files identified by the implementing agents.

Expected outputs:

- Scope decision.
- Agent list and sequencing.
- T1-T20 completion check.
- Final handoff summary.

Verification responsibility:

- Confirm test evidence exists or missing tests are explicitly justified.
- Confirm safety constraints and repo hygiene.

Handoff responsibility:

- T18 risks/blockers/assumptions/decisions.
- T20 final handoff and next command.

## Product Owner / Requirement Planner

Mission: Translate user goals into ATDR-specific requirements and acceptance criteria.

Responsibilities:

- Distinguish lab-ready prototype goals from production claims.
- Define user roles, functional requirements, and acceptance criteria.
- Identify whether the PRD must change.
- Keep wording honest for ML and response behavior.

Source files to read:

- `docs/prd/PRD-ATDR.md`
- `README.md`
- `docs/V0_3_STATUS.md`
- `docs/LAB_RUNBOOK.md`
- Relevant frontend pages and backend routes.

Expected outputs:

- T2 requirement.
- T6 scope.
- T7 functional requirements.
- T8 acceptance criteria.
- T17 PRD/docs update decision.

Verification responsibility:

- Confirm requirements are traceable to source or user request.

Handoff responsibility:

- Requirements are ready for backend/frontend/data/ML agents.

## Data Model / Database

Mission: Keep schema, migrations, indexes, and data compatibility safe.

Responsibilities:

- Review `atdr/app/db/models.py` and `migrations/versions/*`.
- Plan and implement Alembic migrations when schema changes are needed.
- Preserve existing data and backwards compatibility.
- Protect real logs and DB files from Git.
- Consider SQLite local limits and PostgreSQL lab path.

Source files to read:

- `atdr/app/db/models.py`
- `atdr/app/db/database.py`
- `migrations/env.py`
- `migrations/versions/*`
- Relevant tests in `atdr/tests/*`.

Expected outputs:

- T10 data model / migration plan.
- Migration and rollback notes.
- Index/performance rationale.

Verification responsibility:

- `.\.venv\Scripts\alembic.exe check`
- Relevant database tests.

Handoff responsibility:

- Data compatibility notes for backend/frontend/QA.

## Backend / API

Mission: Implement and preserve FastAPI contracts safely.

Responsibilities:

- Use mounted route truth in `atdr/app/main.py`.
- Update routers, schemas, and services with minimal compatible changes.
- Enforce JWT auth and role checks.
- Preserve existing API contracts unless a breaking change is approved.
- Ensure audit evidence for workflow and response actions.

Source files to read:

- `atdr/app/main.py`
- `atdr/app/routers/*.py`
- `atdr/app/schemas/*.py`
- `atdr/app/services/*.py`
- `atdr/app/core/security.py`
- Relevant tests in `atdr/tests/*`.

Expected outputs:

- T9 API contract.
- T11 backend plan/changes.
- Tests for API behavior and safety.

Verification responsibility:

- `.\.venv\Scripts\python.exe -m compileall -q atdr migrations`
- `.\.venv\Scripts\python.exe -m pytest atdr\tests -q`

Handoff responsibility:

- API changes and required frontend updates.

## Frontend / Dashboard

Mission: Keep the React SOC dashboard usable, safe, and aligned with backend contracts.

Responsibilities:

- Use `frontend/src/App.tsx` as route truth.
- Use centralized API patterns in `frontend/src/lib/api.ts`.
- Preserve role-aware routes and access-denied states.
- Keep dashboard uncluttered through progressive disclosure.
- Prevent dropdown, modal, overflow, and loading-state regressions.

Source files to read:

- `frontend/src/App.tsx`
- `frontend/src/lib/api.ts`
- `frontend/src/hooks/*`
- `frontend/src/pages/*`
- `frontend/src/components/*`
- `frontend/package.json`

Expected outputs:

- T12 frontend plan/changes.
- UI state and error/loading/empty-state behavior.
- Playwright coverage where useful.

Verification responsibility:

- `cd frontend`
- `npm.cmd run lint`
- `npm.cmd run build`
- `npm.cmd run test:e2e`

Handoff responsibility:

- Screens/pages changed, UX risks, and manual verification notes.

## AI/ML Governance

Mission: Keep AI useful, explainable, and honest.

Responsibilities:

- Own feature engineering, weak labels, reviewed labels, training, evaluation, active learning, and model status.
- Ensure weak labels are not presented as production truth.
- Ensure model output remains decision support.
- Keep model promotion gate conservative.
- Maintain evidence for suspicious/malicious boundary limitations.

Source files to read:

- `atdr/app/ml/features.py`
- `atdr/app/detection/*`
- `atdr/app/services/ml_label_service.py`
- `atdr/app/routers/ml.py`
- `atdr/scripts/train_supervised_model.py`
- `atdr/scripts/compare_supervised_models.py`
- `docs/AI_TRAINING_RUNBOOK.md`
- `docs/ML_BASELINE_TUNING.md`

Expected outputs:

- Model/evaluation plan.
- T13 AI safety decision.
- Metrics with label-source warnings.
- Review/export/import workflow notes.

Verification responsibility:

- Relevant ML tests in `atdr/tests/test_supervised_ml.py`.
- Training/evaluation commands only when safe.

Handoff responsibility:

- Model status, limitations, and next review target.

## Security / Response Safety

Mission: Prevent unsafe response behavior and protect access boundaries.

Responsibilities:

- Review auth/RBAC, response actions, protected IP handling, and audit.
- Maintain the ATDR IAM/RBAC adaptation as local JWT authentication, admin/analyst authorization, route guards, response-safety permissions, and audit requirements.
- Avoid adding external IAM systems such as OAuth, SSO, SAML, LDAP, or enterprise identity providers unless explicitly requested in a future approved requirement.
- Verify no automatic response path exists.
- Ensure real firewall enforcement remains disabled unless approved future work implements it safely.
- Verify denied response attempts are audited.

Source files to read:

- `atdr/app/core/security.py`
- `atdr/app/routers/auth.py`
- `atdr/app/routers/users.py`
- `atdr/app/routers/sources.py`
- `atdr/app/routers/ml.py`
- `atdr/app/routers/response.py`
- `atdr/app/services/response_service.py`
- `atdr/app/db/models.py`
- `atdr/tests/test_response_safety.py`
- `docs/security/ATDR_IAM_RBAC_MATRIX.md`

Expected outputs:

- T13 security/response safety review.
- IAM/RBAC permission findings when role boundaries change.
- Pass / pass-with-risk / block decision.

Verification responsibility:

- Response safety tests.
- Auth/RBAC tests.
- PRD and RBAC matrix updates when permissions change.

Handoff responsibility:

- Safety findings and required fixes before release.

## QA/UAT

Mission: Prove the change works and does not regress core ATDR workflows.

Responsibilities:

- Build test matrix from T8 acceptance criteria.
- Run relevant backend/frontend/smoke checks.
- Check manual acceptance paths when automated tests are insufficient.
- Confirm no stale or unsafe docs were added.

Source files to read:

- `docs/ACCEPTANCE_TEST_CHECKLIST.md`
- `atdr/tests/*`
- `frontend/package.json`
- `atdr/scripts/verify_release.py`
- `docs/LAB_RUNBOOK.md`

Expected outputs:

- T14 test plan.
- T16 tests run/evidence.
- Defects and residual risk.

Verification responsibility:

- Execute or justify not executing checks.

Handoff responsibility:

- Clear pass/fail status and remaining test gaps.

## Release/Ops / Lab Validation

Mission: Keep ATDR runnable, repeatable, and honest for lab use.

Responsibilities:

- Preserve local startup commands.
- Maintain runbooks, release checklist, smoke checks, and performance smoke.
- Validate source/replay/syslog scenarios.
- Keep Docker/PostgreSQL optional unless explicitly in scope.
- Track rollback and troubleshooting notes.

Source files to read:

- `docs/LAB_RUNBOOK.md`
- `docs/RELEASE_CHECKLIST.md`
- `docs/V0_3_STATUS.md`
- `atdr/scripts/verify_release.py`
- `atdr/scripts/performance_smoke.py`
- `atdr/scripts/run_source_scenario.py`
- `docker-compose.yml`

Expected outputs:

- Release/lab validation plan.
- T19 release/rollback.
- Updated docs if workflow changes.

Verification responsibility:

- Release gate.
- Replay dry-run.
- Performance smoke.
- Lab scenario checks when relevant.

Handoff responsibility:

- Exact commands for the user to run next.

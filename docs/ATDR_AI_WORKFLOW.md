# ATDR AI Workflow

This document adapts the university AI workflow rules to ATDR. It is the operating workflow for AI/Codex-assisted work in this repository.

ATDR is a defensive FastAPI + React AI-assisted log-based threat detection and response prototype. It is lab-ready for controlled small-office validation, not certified production software. Response actions remain simulated and analyst-approved. ML remains decision support only.

## Source Evidence For This Workflow

| Evidence | Repository Source |
| --- | --- |
| Current product summary, startup commands, API highlights, React-first dashboard, lab scenario workflow | `README.md` |
| FastAPI route mounting and health behavior | `atdr/app/main.py` |
| Database entities for logs, sources, alerts, response, audit, run history, and ML labels | `atdr/app/db/models.py` |
| Backend route modules | `atdr/app/routers/*.py` |
| React route/page truth | `frontend/src/App.tsx`, `frontend/src/pages/*` |
| Frontend scripts and dependencies | `frontend/package.json` |
| Release gate commands | `atdr/scripts/verify_release.py` |
| Current lab status and limitations | `docs/V0_3_STATUS.md`, `docs/LAB_RUNBOOK.md` |
| IAM/RBAC adaptation and permission matrix | `docs/security/ATDR_IAM_RBAC_MATRIX.md` |
| External school-email IAM groundwork | `docs/security/ATDR_EXTERNAL_IAM_PLAN.md` |
| NewSystem template alignment, ATDR manifest, and permission path registry | `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md`, `docs/ATDR_TEMPLATE_MANIFEST.json`, `docs/security/ATDR_PERMISSION_PATHS.md` |
| Requirement traceability | `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |
| Test inventory | `atdr/tests/*`, `frontend/tests` where present |
| Migration truth | `migrations/versions/*`, `alembic.ini` |

## Core Rules

1. No guessing. Read the relevant repo source before planning, editing, or summarizing.
2. Every non-trivial change must cite source evidence in the T1-T20 change document.
3. Source code and mounted routes are the primary truth. Older docs are background only if they conflict with current code.
4. Preserve the normal local workflow unless the user explicitly approves a change:
   - Backend: `.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload`
   - Frontend: `cd frontend` then `npm.cmd run dev`
   - Dashboard: `http://127.0.0.1:5173`
5. Do not reset or delete the current database, logs, labels, alerts, users, model state, or review history unless explicitly requested.
6. Do not enable real firewall blocking or automatic response.
7. Do not claim production readiness. Use "lab-ready prototype" or "controlled lab-ready release candidate" where accurate.
8. Do not commit real logs, databases, model artifacts, private env files, review exports, demo exports, or generated reports.

## ATDR Source Truth Order

Use this order when a request, prompt, or older document conflicts:

1. Actual source code and mounted routes: `atdr/app/main.py`, `atdr/app/routers/*.py`, `frontend/src/App.tsx`.
2. Tests and smoke scripts: `atdr/tests/*`, `frontend/package.json`, `atdr/scripts/verify_release.py`, `atdr/scripts/performance_smoke.py`.
3. Current ATDR docs: `README.md`, `docs/LAB_RUNBOOK.md`, `docs/V0_1_STATUS.md`, `docs/V0_2_PLAN.md`, `docs/V0_3_PLAN.md`, `docs/V0_3_STATUS.md`.
4. Database models and migrations: `atdr/app/db/models.py`, `migrations/versions/*`.
5. Frontend pages, hooks, API client, and components: `frontend/src/pages/*`, `frontend/src/lib/api.ts`, `frontend/src/hooks/*`, `frontend/src/components/*`.
6. Older/template university docs only as reference for process structure, never as ATDR implementation truth.
7. User prompt requirements, after reconciling them with the current source and safety constraints.

## Required Change Flow

1. Source discovery:
   - Read the current relevant backend route/service/model files.
   - Read the current relevant frontend page/API hook files.
   - Read matching tests and current docs.
   - Record source evidence in T3.
2. Requirement shaping:
   - Convert the user request into ATDR-specific requirements.
   - Identify safety constraints: ML decision support, simulated response, no auto response, no real firewall enforcement.
3. Impact mapping:
   - Identify backend, frontend, data model, AI/ML, response safety, docs, tests, and release impacts.
4. Implementation:
   - Keep changes narrow.
   - Preserve backward compatibility unless an approved breaking change is explicitly requested.
   - Use Alembic for schema changes.
   - Use existing API/client/component patterns.
5. Verification:
   - Run the smallest meaningful checks for the change.
   - Run full release verification for code changes or risky workflow changes.
6. Documentation:
   - Update PRD/docs when behavior, API, data model, UI, safety constraints, tests, or release workflow changes.
7. Handoff:
   - Complete T15-T20 with files changed, tests run, risks, rollback, and exact next command.

## Testing Gate

For code changes, select the relevant checks and record exact output in T16:

```powershell
.\.venv\Scripts\python.exe -m compileall -q atdr migrations
.\.venv\Scripts\python.exe -m pytest atdr\tests -q
.\.venv\Scripts\alembic.exe check
cd frontend
npm.cmd run lint
npm.cmd run build
npm.cmd run test:e2e
cd ..
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release
```

If only documentation changes are made, at minimum:

```powershell
Test-Path docs\ATDR_AI_WORKFLOW.md
Test-Path docs\prd\PRD-ATDR.md
Test-Path docs\agents\ATDR_AGENT_OPERATING_MODEL.md
Test-Path docs\templates\ATDR_T1_T20_CHANGE_DOCUMENT.md
Test-Path docs\ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
rg -n "template-specific backend/frontend/permission terms from the university reference docs" docs\ATDR_AI_WORKFLOW.md docs\prd\PRD-ATDR.md docs\agents\ATDR_AGENT_OPERATING_MODEL.md docs\templates\ATDR_T1_T20_CHANGE_DOCUMENT.md docs\ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
```

## PRD / Docs Update Gate

Update `docs/prd/PRD-ATDR.md` when a change affects:

- Product scope, users, roles, workflow, or acceptance criteria.
- Backend API contract or auth/RBAC.
- Database model, migration, indexes, or data retention.
- React route, page behavior, filters, action flows, or dashboard wording.
- ML training, labeling, promotion, model status, or evaluation behavior.
- Response behavior, response safety, protected IP handling, audit behavior, or simulation mode.
- Lab scenario, source management, syslog/replay behavior, or release workflow.
- Testing gates, runbooks, startup commands, or known limitations.

Do not update the PRD for purely internal refactors with no behavior, contract, safety, or operational effect. Record the "no PRD update required" decision in T17.

## ATDR IAM / RBAC Adaptation

The university template uses the term IAM. In ATDR, IAM currently means local JWT authentication, role-based authorization, route protection, response-safety permission checks, and auditability. Do not add OAuth, SSO, SAML, LDAP, or enterprise identity-provider integration unless a future approved requirement explicitly asks for it.

Current ATDR roles are:

- `admin`: lab operator role for user management, source management, imports, model training/scoring, demo controls, and simulated response actions.
- `analyst`: SOC analyst role for alert/log investigation, detection runs, AI Governance review workflows, label import/export, and audit viewing.
- `viewer`: future work only; no read-only role is implemented yet.

For permission decisions, use `docs/security/ATDR_IAM_RBAC_MATRIX.md` as the current matrix and `docs/ATDR_REQUIREMENT_TRACEABILITY.md` for implementation evidence. Backend route dependencies are the authority; frontend hiding/disabling is only a usability layer.

Current IAM limitations must remain explicit:

- No external SSO/OAuth/SAML/LDAP.
- No enterprise identity provider.
- Demo JWT secrets must be replaced before shared lab or real deployment.
- Current role model is suitable for lab prototype validation, not production IAM.
- Role permissions must be reviewed before any real deployment or response connector work.

## NewSystem Template Adaptation Rule

The repository includes `NewSystem/` as the university template reference. Use it as a process and control reference only.

ATDR follows these NewSystem-style ideas:

- project manifest: `docs/ATDR_TEMPLATE_MANIFEST.json`
- permission paths: `docs/security/ATDR_PERMISSION_PATHS.md`
- IAM/RBAC matrix: `docs/security/ATDR_IAM_RBAC_MATRIX.md`
- PRD update gate: `docs/prd/PRD-ATDR.md`
- T1-T20 change handoff: `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md`
- security review discipline: `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md`

Do not copy NewSystem-specific Node.js, Vue, MongoDB, Google SSO, B2B IAM SDK, or Docker requirements into ATDR unless a future approved requirement explicitly asks for that migration. v0.4 uses generic OIDC groundwork only, disabled by default, so a future school-email provider can be added without changing the ATDR stack. The active adaptation guide is `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md`.

## T1-T20 Change Document Requirement

Every non-trivial change must use `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md`.

The change document can live under `docs/changes/` or be included in the final handoff, but it must contain:

- T3 source evidence with repo paths.
- T8 acceptance criteria.
- T13 security/response/AI safety decision.
- T14 test plan.
- T16 tests run and evidence.
- T17 PRD/docs update decision.
- T18 risks, blockers, assumptions, and decisions.
- T20 final handoff.

## Blocker Rules

Stop and ask or clearly mark blocked when:

- Required source files are missing or contradict each other.
- A request would reset/delete current data without explicit approval.
- A request would enable automatic response or real firewall blocking.
- A request would commit private logs, DB files, model artifacts, `.env`, `ml_baseline_reviews/`, or `demo_exports/`.
- A migration is needed but Alembic cannot be run or verified.
- The backend/frontend cannot be started and the failure blocks verification.
- Tests fail and the failure is not unrelated or understood.

## Done Criteria

A change is done only when:

- Relevant source evidence was read and recorded.
- Implementation is scoped and preserves existing workflows.
- Tests or checks were run, or the reason they were not run is stated.
- PRD/docs update decision is recorded.
- Safety constraints are unchanged unless explicitly approved.
- Repo hygiene is preserved.
- Final handoff names files changed, verification results, remaining risks, and exact next command.

## Repo Hygiene Rules

Do not commit:

- Real firewall/router logs.
- `atdr.db`, `*.sqlite`, `*.sqlite3`.
- `.env` or private environment files.
- `atdr/models/*.joblib` or generated model reports.
- `ml_baseline_reviews/`.
- `demo_exports/`.
- `atdr/data/processed/*` except `.gitkeep`.
- Generated Playwright reports or frontend build output.

These patterns are supported by `.gitignore`; verify with `git status --short` before handoff.

## AI And Response Safety Rules

- Rule evidence is primary.
- IsolationForest and supervised ML are decision-support signals.
- Weak/assisted labels are not production ground truth.
- Model status must not be described as production-promoted unless the PRD, model report, and promotion gate all explicitly support that claim.
- Response actions remain simulated unless a future approved connector is implemented.
- Any response action must require analyst/admin approval, reason/justification, protected-IP checks, and audit evidence.
- Model output must never trigger automatic containment.

# T1-T20: ATDR Tasklist / Progress-Board Compliance

## T1 Change Title

| Field | Value |
| --- | --- |
| Change ID | T1_T20_TASKLIST_PROGRESS_COMPLIANCE |
| Module | Governance / university-template process compliance |
| Date | 2026-06-19 |
| Owner / Agent | Codex / Orchestrator + Release-Ops |
| Status | Done |
| Active Tasklist | `docs/tasks/tasklist-progress.md` |

## T2 Requirement

- User request: Close the remaining university-template process compliance gap by adding ATDR-specific tasklist/progress-board workflow.
- Business goal: Make ATDR follow the supervisor template's progress and handoff discipline without changing ATDR runtime behavior.
- Success outcome: ATDR has canonical progress Markdown, generated HTML, validation scripts, docs index, and governance references.

## T3 Source Evidence

| Area | Source path / route / command | What was verified |
| --- | --- | --- |
| Supervisor tasklist guide | `<MFU_SHELL_ROOT>\docs\tasks\README.md` | Required tasklist storage, columns, statuses, progress gates, and HTML regeneration rule. |
| Supervisor progress file | `<MFU_SHELL_ROOT>\docs\tasks\tasklist-progress.md` | Required T1-T5 progress-board structure. |
| Supervisor T1-T20 template | `<MFU_SHELL_ROOT>\docs\templates\T1-T20-change-document.md` | Required handoff sections and evidence fields. |
| Supervisor progress scripts | `<MFU_SHELL_ROOT>\scripts\*.js` | Renderer/checker behavior to adapt. |
| Backend route truth | `atdr/app/main.py`, `atdr/app/routers/*.py` | ATDR remains FastAPI; no route/API behavior changed. |
| Frontend route/API truth | `frontend/src/App.tsx`, `frontend/src/lib/api.ts` | ATDR remains React; no route/UI behavior changed. |
| PRD/docs | `docs/ATDR_AI_WORKFLOW.md`, `docs/prd/PRD-ATDR.md`, `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`, `README.md` | Governance docs needed tasklist/progress-board references. |

## T4 Current Behavior

- Current API behavior: unchanged.
- Current UI behavior: unchanged.
- Current data behavior: unchanged.
- Current permission behavior: unchanged.
- Current process behavior: ATDR had workflow, PRD, T1-T20 template, RBAC matrix, and traceability, but lacked the supervisor-style canonical `docs/tasks/` progress board and render/check scripts.

## T5 Impacted Agents

| Agent | Required? | Reason |
| --- | --- | --- |
| Orchestrator | yes | Owns workflow, evidence, progress, and handoff. |
| Product Owner | yes | PRD/docs update decision. |
| Data Model | no | No schema/data change. |
| Backend | no | No backend runtime change. |
| Frontend | no | No frontend runtime change. |
| Security IAM | yes | Confirm NewSystem remains reference-only; no external IAM claim. |
| QA/UAT | yes | Verify docs/scripts and release checks. |
| Release/Ops | yes | Own progress board, release gate, repo hygiene. |

## T6 Scope

In scope:

- ATDR tasklist/progress-board docs.
- ATDR tasklist templates.
- Progress renderer/checker scripts.
- ATDR docs index.
- Governance and README references.

Out of scope:

- No FastAPI route changes.
- No React page behavior changes.
- No database reset or migration.
- No ML activation/promotion.
- No external IAM implementation.
- No real firewall blocking or automatic response.
- No Node/Vue/MongoDB migration.

## T7 Functional Requirements

| FR ID | Requirement | Actor | Priority |
| --- | --- | --- | --- |
| FR-TASKLIST-001 | Provide canonical ATDR progress Markdown and generated HTML view | Orchestrator / Release-Ops | Must |
| FR-TASKLIST-002 | Provide ATDR tasklist guide and templates | Orchestrator | Must |
| FR-TASKLIST-003 | Provide render/check scripts | Release-Ops | Must |
| FR-TASKLIST-004 | Keep NewSystem reference-only and ATDR source truth active | All agents | Must |

Privacy / PDPA requirements:

- Personal data displayed: none.
- Personal data hidden: no secret/env values are documented.
- Personal data stored or changed: none.
- Data export/download behavior: none.
- Production data-minimization decision: docs-only process update; no production data added.

## T8 Acceptance Criteria

| AC ID | FR ID | Given | When | Then |
| --- | --- | --- | --- | --- |
| AC-TASKLIST-001 | FR-TASKLIST-001 | ATDR docs are opened | User checks `docs/tasks/` | Progress Markdown and generated HTML exist. |
| AC-TASKLIST-002 | FR-TASKLIST-002 | A future task starts | Agent reads docs | Required columns, statuses, progress gates, and templates are available. |
| AC-TASKLIST-003 | FR-TASKLIST-003 | Progress changes | Script runs | HTML regenerates and checker validates T1-T5 sections. |
| AC-TASKLIST-004 | FR-TASKLIST-004 | NewSystem docs exist | Reader reviews ATDR docs | Active docs state ATDR remains FastAPI/React/SQLAlchemy and NewSystem is reference-only. |

## T9 API Contract

No API contract changes.

## T10 Data Model / Migration

| Item | Decision | Evidence |
| --- | --- | --- |
| Schema change | no | Docs/process only. |
| Migration | no | No SQLAlchemy model changes. |
| Seed/backfill | no | No data changes. |
| Index | no | No query changes. |
| Rollback | Revert docs/scripts | No runtime rollback needed. |

## T11 Backend Plan / Changes

No backend code changes.

## T12 Frontend Plan / Changes

No frontend code changes.

## T13 Security / Response / AI Safety

| Concern | Decision / Evidence |
| --- | --- |
| Authentication | No change; local JWT remains current. |
| Authorization path/action | No change; RBAC matrix remains current. |
| Data scope | No database or user data changed. |
| Audit | No runtime actions generated. |
| Input validation | Node scripts read local Markdown paths only. |
| Error/secret leakage | No `.env`, secrets, DB files, real logs, generated exports, or model artifacts are added. |
| AI safety | No model training, activation, promotion, or metric claims changed. |
| Response safety | No automatic response or real blocking enabled. |

## T14 Test Plan

| Test ID | Type | Role/User | Steps | Expected |
| --- | --- | --- | --- | --- |
| TC-001 | script syntax | release | `node -c scripts/render-tasklist-progress-html.js` | Pass |
| TC-002 | script syntax | release | `node -c scripts/check-tasklist-progress-standard.js` | Pass |
| TC-003 | docs render | release | `node scripts/render-tasklist-progress-html.js .` | Generates HTML |
| TC-004 | docs check | release | `node scripts/check-tasklist-progress-standard.js .` | Pass |
| TC-005 | regression | qa | backend/frontend/release verification | Pass |

## T15 Implementation Summary

| File | Change |
| --- | --- |
| `docs/tasks/README.md` | Added ATDR tasklist/progress-board rules. |
| `docs/tasks/tasklist-progress.md` | Added canonical ATDR progress board. |
| `docs/tasks/tasklist-progress.html` | Generated progress board view. |
| `docs/templates/PROJECT-TASKLIST-TEMPLATE.md` | Added feature/change tasklist template. |
| `docs/templates/PROJECT-SYSTEM-PROGRESS-TEMPLATE.md` | Added system progress template. |
| `docs/AI-DOCS-INDEX.md` | Added active ATDR docs index and reference-only boundary. |
| `scripts/render-tasklist-progress-html.js` | Added ATDR progress renderer. |
| `scripts/check-tasklist-progress-standard.js` | Added ATDR progress checker. |
| `docs/ATDR_AI_WORKFLOW.md` | Added tasklist/progress-board rule. |
| `docs/prd/PRD-ATDR.md` | Added tasklist/progress-board requirement references. |
| `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md` | Added tasklist/docs index compliance evidence. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | Added traceability row. |
| `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md` | Added tasklist/progress-board adaptation. |
| `README.md` | Added tasklist and docs index links. |

Tasklist progress:

| Task ID | Status | Progress % | Progress Basis | Blocker / Next Action |
| --- | --- | ---: | --- | --- |
| ATDR-TASKLIST-001 | done | 100 | Docs/scripts drafted, governance docs updated, verification completed, and handoff recorded | cold large-SQLite Overview query warning / monitor in next phase |

## T16 Tests Run / Evidence

| Command | Result | Evidence / Notes |
| --- | --- | --- |
| `node -c scripts/render-tasklist-progress-html.js` | pass | Renderer syntax valid. |
| `node -c scripts/check-tasklist-progress-standard.js` | pass | Checker syntax valid. |
| `node scripts/render-tasklist-progress-html.js .` | pass | Generated `docs/tasks/tasklist-progress.html`. |
| `node scripts/check-tasklist-progress-standard.js .` | pass | Validated required tasklist files and T1-T5 progress-board sections. |
| `.\.venv\Scripts\python.exe -m compileall -q atdr migrations` | pass | Python compile check passed. |
| `.\.venv\Scripts\ruff.exe check .` | pass | Ruff reported all checks passed. |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests -q --basetemp .pytest_tmp\tasklist-progress -p no:cacheprovider` | pass | `246 passed, 1 skipped`; local development env overrides were used because private `.env` points to production/PostgreSQL settings. |
| `.\.venv\Scripts\alembic.exe check` | pass | No new upgrade operations detected. |
| `cd frontend; npm.cmd run lint` | pass | Frontend lint passed. |
| `cd frontend; npm.cmd run build` | pass | Frontend production build passed. |
| `cd frontend; npm.cmd run test:e2e` | pass | Playwright `13 passed, 1 skipped`. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty` | pass | Safe sample dry-run read 2 rows and did not mutate the DB. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty` | pass with warning | `ok: true`; cold Overview/ingestion summary `9.9635s`, cached Overview `0.0066s`, ML Governance lightweight summary `1.9886s`. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` | pass | Release gate returned `ok: true`; required checks passed. |

Commands not run:

| Command | Reason | Risk |
| --- | --- | --- |
| none | Verification completed | Remaining item is performance monitoring, not a docs/process blocker. |

## T17 PRD / Docs Updated

| Document | Updated? | Reason |
| --- | --- | --- |
| `docs/prd/PRD-ATDR.md` | yes | Process requirement added. |
| `docs/ATDR_AI_WORKFLOW.md` | yes | Tasklist/progress-board rule added. |
| `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md` | yes | Compliance status updated. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | yes | Traceability row added. |
| `README.md` | yes | Documentation map updated. |

## T18 Risks / Blockers / Assumptions / Decisions

| ID | Type | Description | Owner | Status |
| --- | --- | --- | --- | --- |
| R-001 | Risk | Readers may confuse NewSystem runtime stack with ATDR runtime stack. | Orchestrator | open |
| A-001 | Assumption | Supervisor wants process compliance, not a forced stack migration. | Product Owner | open |
| D-001 | Decision | Keep ATDR stack and adapt the tasklist/progress-board workflow only. | Orchestrator | closed |
| R-002 | Risk | Large local SQLite cold Overview/ingestion summary can exceed budget before cache. | Release/Ops | open |

## T19 Release / Rollback

- Release steps: commit docs/scripts after verification.
- Smoke checks: Node script checks, backend/frontend verification, replay dry-run, performance smoke, release gate.
- Monitoring: future changes must keep tasklist-progress current.
- Rollback trigger: progress scripts fail or docs create false runtime claims.
- Rollback steps: revert docs/tasks, scripts, and related docs references.

## T20 Final Handoff

```text
Feature: ATDR tasklist/progress-board compliance
Status: done
Active tasklist: docs/tasks/tasklist-progress.md
Task IDs: ATDR-TASKLIST-001
Progress: 100%
Changed files: docs/tasks/*, docs/templates/PROJECT-*, docs/AI-DOCS-INDEX.md, progress scripts, governance docs, README
Routes: none
UI routes: none
Permission: no runtime change
Data migration: none
Tests run: Node script syntax/checks, generated HTML, ruff, compileall, backend tests, Alembic check, frontend lint/build/e2e, replay dry-run, performance smoke, release gate
PRD/docs: updated
Security decision: no secret/runtime/response/IAM change
Privacy/PDPA decision: no personal data changed
QA decision: accepted for process compliance
Release decision: docs/process update ready to commit
Open risks: NewSystem runtime confusion; external IAM remains future work; monitor cold Overview performance on large SQLite DB
Next owner: Product/Release-Ops for next production-readiness phase
```

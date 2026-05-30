# ATDR T1-T20 Change Document Template

Use this template for non-trivial ATDR changes. Keep source evidence concrete and cite repository paths.

## T1 Change Title

- Title:
- Date:
- Owner / acting agent:
- Related version or sprint:

## T2 Requirement

- User request:
- Business / lab goal:
- Success outcome:
- Explicit non-goals:

## T3 Source Evidence

| Source | Path | Evidence / Finding |
| --- | --- | --- |
| Product docs | `README.md` | |
| Workflow | `docs/ATDR_AI_WORKFLOW.md` | |
| PRD | `docs/prd/PRD-ATDR.md` | |
| Backend route truth | `atdr/app/main.py`, `atdr/app/routers/*.py` | |
| Backend services/schemas | `atdr/app/services/*`, `atdr/app/schemas/*` | |
| Data model/migration | `atdr/app/db/models.py`, `migrations/versions/*` | |
| Frontend route truth | `frontend/src/App.tsx` | |
| Frontend API/pages | `frontend/src/lib/api.ts`, `frontend/src/pages/*` | |
| Tests/scripts | `atdr/tests/*`, `frontend/package.json`, `atdr/scripts/*` | |
| Current runbooks/status | `docs/LAB_RUNBOOK.md`, `docs/V0_3_STATUS.md` | |

## T4 Current Behavior

- Current backend behavior:
- Current frontend behavior:
- Current data model behavior:
- Current AI/ML behavior:
- Current response/audit behavior:
- Current known limitation:

## T5 Impacted Areas / Agents

| Area / Agent | Impacted? | Reason |
| --- | --- | --- |
| Orchestrator | yes/no | |
| Product Owner / Requirement Planner | yes/no | |
| Data Model / Database | yes/no | |
| Backend / API | yes/no | |
| Frontend / Dashboard | yes/no | |
| AI/ML Governance | yes/no | |
| Security / Response Safety | yes/no | |
| QA/UAT | yes/no | |
| Release/Ops / Lab Validation | yes/no | |

## T6 Scope

### In Scope

- 

### Out Of Scope

- No real firewall blocking unless explicitly approved in future work.
- No automatic response.
- No production-readiness claim.
- No reset/delete of current data unless explicitly requested.

## T7 Functional Requirements

| ID | Requirement | Priority | Source |
| --- | --- | --- | --- |
| FR-ATDR-CHANGE-001 | | Must/Should/Could | |

## T8 Acceptance Criteria

| ID | Acceptance Criteria | Verification |
| --- | --- | --- |
| AC-001 | | |

## T9 API Contract

- New endpoints:
- Changed endpoints:
- Unchanged endpoints:
- Auth/RBAC:
- Request examples:
- Response examples:
- Backward compatibility:

## T10 Data Model / Migration

- Schema changes:
- Alembic migration:
- Index changes:
- Existing data compatibility:
- Rollback strategy:
- No migration needed because:

## T11 Backend Plan / Changes

- Routers:
- Schemas:
- Services:
- Scripts:
- Error handling:
- Audit behavior:
- Tests:

## T12 Frontend Plan / Changes

- Routes/pages:
- Components:
- API client/hooks:
- Loading/error/empty states:
- Role visibility:
- Accessibility/responsive notes:
- Playwright/manual checks:

## T13 Security / Response / AI Safety

- Response mode remains simulation: yes/no
- Automatic response remains disabled: yes/no
- Real firewall enforcement added: no unless future approved change
- Protected IP handling:
- Audit impact:
- ML decision-support status:
- Weak/reviewed label wording:
- Data privacy/repo hygiene:
- Security reviewer decision: pass / pass-with-risk / block

## T14 Test Plan

| Test | Command / Method | Required? | Notes |
| --- | --- | --- | --- |
| Python compile | `.\.venv\Scripts\python.exe -m compileall -q atdr migrations` | if code | |
| Backend tests | `.\.venv\Scripts\python.exe -m pytest atdr\tests -q` | if code | |
| Alembic drift | `.\.venv\Scripts\alembic.exe check` | if schema/code | |
| Frontend lint | `cd frontend; npm.cmd run lint` | if frontend | |
| Frontend build | `cd frontend; npm.cmd run build` | if frontend | |
| Playwright | `cd frontend; npm.cmd run test:e2e` | if UI | |
| Replay dry-run | `.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty` | if ingestion | |
| Performance smoke | `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty` | if performance/large data | |
| Release gate | `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` | release-risk changes | |

## T15 Implementation Summary

| File | Change Summary |
| --- | --- |
| | |

## T16 Tests Run / Evidence

| Command / Check | Result | Evidence |
| --- | --- | --- |
| | | |

Skipped checks:

- Check:
- Reason:
- Risk:

## T17 PRD / Docs Updated

| Document | Updated? | Reason |
| --- | --- | --- |
| `docs/prd/PRD-ATDR.md` | yes/no | |
| `docs/ATDR_AI_WORKFLOW.md` | yes/no | |
| `docs/LAB_RUNBOOK.md` | yes/no | |
| `docs/V0_3_STATUS.md` or later status doc | yes/no | |
| README | yes/no | |

## T18 Risks / Blockers / Assumptions / Decisions

### Risks

- 

### Blockers

- 

### Assumptions

- 

### Decisions

- 

## T19 Release / Rollback

- Release impact:
- Deployment notes:
- Local workflow impact:
- Rollback plan:
- Data rollback:
- Monitoring/checks after release:

## T20 Final Handoff

- Status: completed / blocked / partial
- Files changed:
- Behavior changed:
- Verification result:
- Remaining risks:
- Exact next command for user:

# Tasklist: <ATDR Topic>

| Field | Value |
| --- | --- |
| Date | YYYY-MM-DD |
| Project | MFU AI-Driven Log-Based Threat Detection and Response System |
| Module / Feature | |
| Requirement | |
| Source Request | |
| Active Change Record | `docs/changes/<change-id>.md` |
| Status | pending |
| Overall Progress | 0% |
| Progress Type | Evidence-backed delivery progress, not estimate |

## Source Evidence

| Area | Source | What was verified |
| --- | --- | --- |
| Workflow | `docs/ATDR_AI_WORKFLOW.md` | |
| Docs control index | `docs/AI-DOCS-INDEX.md` | |
| Tasklist guide | `docs/tasks/README.md` | |
| PRD | `docs/prd/PRD-ATDR.md` | |
| Backend route truth | `atdr/app/main.py`, `atdr/app/routers/*.py` | |
| Data model truth | `atdr/app/db/models.py`, `migrations/versions/*` | |
| Frontend route truth | `frontend/src/App.tsx` | |
| Frontend API truth | `frontend/src/lib/api.ts`, `frontend/src/hooks/*` | |
| Tests/scripts | `atdr/tests/*`, `frontend/tests/*`, `atdr/scripts/verify_release.py` | |
| Security/AI/response safety | `docs/security/*`, `atdr/app/core/security.py`, `atdr/app/routers/response.py` | |

## Tasks

| Task ID | Task | Agent | Owner | Depends On | Status | Progress % | Progress Basis | Source Evidence | Tests Evidence | Blocker | Next Action | Output |
| --- | --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| ATDR-TASK-001 | Source discovery | Orchestrator | TBD | none | pending | 0 | not started | | | none | read source | T1-T4 evidence |

## Risks / Blockers / Assumptions / Decisions

| ID | Type | Description | Owner | Status |
| --- | --- | --- | --- | --- |
| R-001 | Risk | | | open |
| B-001 | Blocker | | | open |
| A-001 | Assumption | | | open |
| D-001 | Decision | | | closed |

## Verification

| Command / Check | Result | Evidence / Notes |
| --- | --- | --- |
| | | |

## Final Handoff Link

- Change record: `docs/changes/<change-id>.md`


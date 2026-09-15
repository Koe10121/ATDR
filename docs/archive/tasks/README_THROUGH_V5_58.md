# ATDR Tasklist And Progress Tracking

This directory stores active execution tasklists and the canonical ATDR progress board. It adapts the university template tasklist standard to ATDR's actual FastAPI + React + SQLAlchemy/Alembic architecture.

ATDR remains a controlled lab prototype. Task tracking must not imply production readiness, automatic response, real firewall blocking, or external IAM completion.

## Storage

Use one active tasklist per feature, fix, docs/process change, readiness review, or release workflow when useful:

```text
docs/tasks/YYYY-MM-DD-<topic>.md
```

Use one canonical system progress file and generated HTML view:

```text
docs/tasks/tasklist-progress.md
docs/tasks/tasklist-progress.html
```

Update `docs/tasks/tasklist-progress.md` whenever system progress, verification status, blockers, release readiness, or active work changes. Then regenerate `docs/tasks/tasklist-progress.html`:

```powershell
node scripts/render-tasklist-progress-html.js .
node scripts/check-tasklist-progress-standard.js .
```

Completed or handed-off work should also have a T1-T20 change record under:

```text
docs/changes/
```

## Source Truth

Use ATDR source truth, not NewSystem runtime paths:

| Area | ATDR Source |
| --- | --- |
| Backend route truth | `atdr/app/main.py`, `atdr/app/routers/*.py` |
| Data model truth | `atdr/app/db/models.py`, `migrations/versions/*` |
| Frontend route truth | `frontend/src/App.tsx` |
| Frontend API/client truth | `frontend/src/lib/api.ts`, `frontend/src/hooks/*` |
| Frontend pages | `frontend/src/pages/*`, `frontend/src/components/*` |
| Backend tests | `atdr/tests/*` |
| Frontend tests | `frontend/tests/*` |
| Release gate | `atdr/scripts/verify_release.py` |
| Current PRD | `docs/prd/PRD-ATDR.md` |
| Active workflow | `docs/ATDR_AI_WORKFLOW.md` |

## Required Columns

Active task tables must include these columns:

| Column | Required content |
| --- | --- |
| Task ID | Stable ID such as `ATDR-SYS-001` |
| Task | Concise work item |
| Agent | Responsible ATDR role |
| Owner | Person/team/agent owner |
| Depends On | Prerequisite task IDs or `none` |
| Status | Approved status value |
| Progress % | Evidence-backed numeric progress |
| Progress Basis | Completed gates, not a guess |
| Source Evidence | Repo files/routes/tests/docs read |
| Tests Evidence | Commands/results or not-run reason |
| Blocker | Blocker ID or `none` |
| Next Action | Concrete next step |
| Output | Expected or produced artifact |

## Status Values

- `pending`
- `discovery`
- `ready`
- `in_progress`
- `verifying`
- `docs_prd`
- `blocked`
- `done`

## Evidence-Based Progress Gates

| Gate | Weight | Required evidence |
| --- | ---: | --- |
| Discovery evidence | 20% | Relevant source evidence recorded |
| Implementation or docs change | 30% | Files changed or drafted |
| Tests / smoke / verification evidence | 30% | Exact command results or docs-only validation |
| PRD / docs decision | 10% | PRD/docs updated or no-update reason |
| T1-T20 handoff | 10% | Final handoff or active next owner |

Rules:

- Do not use guessed percentages.
- Do not mark `done` or `100%` without verification evidence and handoff.
- If verification cannot run, keep progress below `100%`, record the reason, risk, owner, and next action.
- Docs-only changes may use docs validation and path/link checks instead of full app verification.
- Any personal-account, school-email, IAM, audit, response, or label workflow change must record visible data, hidden sensitive data, stored/changed data, and data-minimization decision in the T1-T20 record.

## Progress Report Format

`docs/tasks/tasklist-progress.md` is the editable source. `docs/tasks/tasklist-progress.html` is generated.

The generated HTML must show:

| Section | Purpose |
| --- | --- |
| Summary | Project/date/status/progress metadata |
| T1 Source Evidence | Source files and docs read |
| T2 Progress Calculation | Evidence-backed readiness/progress scoring |
| T3 Active Tasklist | Active work rows and status |
| T4 Verification Log | Commands and outcomes |
| T5 Blockers And Risks | Open risks/blockers and next actions |

## Templates

- Feature/change tasklist: `docs/templates/PROJECT-TASKLIST-TEMPLATE.md`
- System progress tasklist: `docs/templates/PROJECT-SYSTEM-PROGRESS-TEMPLATE.md`
- Change handoff: `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md`


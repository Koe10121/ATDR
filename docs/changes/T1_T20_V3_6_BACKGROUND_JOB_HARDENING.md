# T1-T20 Change Document: v3.6 Background Job And Long-Running Operation Hardening

## T1 Change Title

- Title: v3.6 background job and long-running operation hardening
- Date: 2026-06-19
- Owner / acting agent: Codex
- Related version or sprint: v3.6 production-readiness discipline

## T2 Requirement

- User request: Add safe background job/run tracking for long-running dashboard operations while skipping real-device validation.
- Business / lab goal: Make imports, replay, detection, ML, and exports easier to monitor from the dashboard.
- Success outcome: Operators can see latest operation jobs, status, progress, result summaries, and linked run history.
- Explicit non-goals: No Celery/Redis queue, no production claim, no response automation, no real firewall blocking, no ML activation.

## T3 Source Evidence

| Source | Path | Evidence / Finding |
| --- | --- | --- |
| FastAPI routes | `atdr/app/main.py`, `atdr/app/routers/*.py` | Existing operation endpoints are synchronous and protected by JWT/RBAC. |
| Existing run history | `atdr/app/db/models.py`, `atdr/app/services/operation_run_service.py` | Ingestion and detection runs already exist but do not cover all long-running actions. |
| Replay workflow | `atdr/scripts/replay_logs.py` | Direct replay records ingestion/detection runs; dry-run is read-only. |
| Frontend operations panel | `frontend/src/pages/ExecutiveOverview.tsx` | Overview already shows Operations Health and can host compact job visibility. |
| Release workflow | `atdr/scripts/verify_release.py`, `frontend/tests/smoke.spec.ts` | Existing verification gates must remain valid. |

## T4 Current Behavior

- Current backend behavior: Log import, detection, ML, demo export, and replay run synchronously. Ingestion/detection have run history; ML/demo/import actions have partial run records.
- Current frontend behavior: Overview shows ingestion/detection runs but not a unified job view.
- Current data model behavior: No generic operation job table existed.
- Current AI/ML behavior: Decision support only; not production promoted.
- Current response/audit behavior: Simulated and analyst-approved only.
- Current known limitation: Dashboard users cannot see one compact status trail across long-running operation types.

## T5 Impacted Areas / Agents

| Area / Agent | Impacted? | Reason |
| --- | --- | --- |
| Orchestrator | yes | Coordinates docs, safety, verification, and non-goals. |
| Product Owner / Requirement Planner | yes | Defines operation visibility expectations. |
| Data Model / Database | yes | Adds `operation_jobs` table via Alembic. |
| Backend / API | yes | Adds job service/router and endpoint wrappers. |
| Frontend / Dashboard | yes | Adds compact Overview job panel. |
| AI/ML Governance | yes | ML train/score operations are tracked, but model behavior is unchanged. |
| Security / Response Safety | yes | Confirms no automatic response or real blocking. |
| QA/UAT | yes | Adds backend and Playwright regression coverage. |
| Release/Ops / Lab Validation | yes | Adds operation visibility for lab runs. |

## T6 Scope

### In Scope

- Generic operation job history for important synchronous operations.
- Authenticated job API.
- Read-only job visibility in Overview.
- Replay direct job tracking; dry-run remains read-only.
- Docs, traceability, tasklist, and tests.

### Out Of Scope

- No real async queue or worker system.
- No real firewall blocking.
- No automatic response.
- No production-readiness claim.
- No reset/delete of current data.

## T7 Functional Requirements

| ID | Requirement | Priority | Source |
| --- | --- | --- | --- |
| FR-V36-001 | Record job type, status, actor, progress, result summary, error summary, timestamps, and related run IDs. | Must | User prompt |
| FR-V36-002 | Expose authenticated job list/detail/cancel endpoints. | Must | User prompt |
| FR-V36-003 | Track import, replay, detection, ML train/score, and export operations without changing their core behavior. | Must | User prompt |
| FR-V36-004 | Show latest jobs in the React operations panel without clutter. | Should | User prompt |
| FR-V36-005 | Keep response automation, real blocking, ML activation, and production claims disabled. | Must | Safety constraints |

## T8 Acceptance Criteria

| ID | Acceptance Criteria | Verification |
| --- | --- | --- |
| AC-001 | `/api/jobs` rejects unauthenticated requests. | Backend test |
| AC-002 | Detection run creates a completed job linked to detection run history. | Backend test |
| AC-003 | Demo import success and failure produce completed/failed job records. | Backend test |
| AC-004 | Replay dry-run does not write job history; direct replay does. | Backend test |
| AC-005 | Overview renders latest operation job information. | Playwright smoke |
| AC-006 | No ML output can trigger automatic response. | Existing IAM/response tests and release gate |

## T9 API Contract

- New endpoints:
  - `GET /api/jobs`
  - `GET /api/jobs/{job_id}`
  - `POST /api/jobs/{job_id}/cancel`
- Changed endpoints:
  - Selected existing operation endpoints include `job_id` in responses where response models allow it.
- Unchanged endpoints:
  - Existing startup commands, auth, response, detection logic, ML logic, and replay dry-run behavior remain unchanged.
- Auth/RBAC:
  - Admin and analyst can view jobs.
  - Cancellation is authenticated and conservative.
- Backward compatibility:
  - Existing clients can ignore `job_id`.

## T10 Data Model / Migration

- Schema changes: New `operation_jobs` table.
- Alembic migration: `migrations/versions/a1b2c3d4e5f7_add_operation_jobs.py`.
- Index changes: job type, status, actor, timestamps, and related run IDs are indexed.
- Existing data compatibility: Migration only adds a table; no existing rows are modified.
- Rollback strategy: Downgrade drops the new table and its indexes.

## T11 Backend Plan / Changes

- Routers: Add `jobs.py`; wrap logs/detection/ml/demo endpoints.
- Schemas: Add `OperationJobRead`; extend log import result with optional `job_id`.
- Services: Add `job_service.py`.
- Scripts: Update `replay_logs.py` for direct replay job tracking.
- Error handling: Failed operations record failed job status with short error summary.
- Audit behavior: Existing audit behavior remains unchanged.
- Tests: Add `atdr/tests/test_operation_jobs.py`.

## T12 Frontend Plan / Changes

- Routes/pages: Overview operations panel displays latest job.
- API client/hooks: Add `jobs`, `job`, and `cancelJob`.
- Loading/error/empty states: Latest job falls back to `none`.
- Role visibility: Follows existing authenticated dashboard access.
- Playwright/manual checks: Mock job API in smoke tests.

## T13 Security / Response / AI Safety

- No automatic response added.
- No real firewall connector added.
- No ML model activation or production promotion added.
- Job summaries avoid leaking private full paths.
- Cancel endpoint does not pretend to stop synchronous running work.

## T14 Test Plan

- Backend job API tests.
- Replay dry-run/direct replay tests.
- Existing response safety/IAM tests.
- Frontend smoke test with job API mock.
- Release gate and performance smoke.

## T15 Implementation Summary

- Added `OperationJob` model, migration, service, schema, and router.
- Wrapped key synchronous operation endpoints and direct replay.
- Added Overview job visibility.
- Updated docs, PRD, traceability, and tasklist.

## T16 Tests Run / Evidence

- `node -c scripts/render-tasklist-progress-html.js; node -c scripts/check-tasklist-progress-standard.js` - pass.
- `node scripts/render-tasklist-progress-html.js .` - pass.
- `node scripts/check-tasklist-progress-standard.js .` - pass.
- `.\.venv\Scripts\python.exe -m compileall -q atdr migrations` - pass.
- `.\.venv\Scripts\ruff.exe check .` - pass.
- `.\.venv\Scripts\python.exe -m pytest atdr\tests -q --basetemp .pytest_tmp\v36-full-dev -p no:cacheprovider` - pass, `261 passed, 1 skipped`.
- `.\.venv\Scripts\alembic.exe upgrade head` - pass, added `operation_jobs` table without resetting data.
- `.\.venv\Scripts\alembic.exe check` - pass, no drift.
- `cd frontend; npm.cmd run lint; npm.cmd run build; npm.cmd run test:e2e` - pass, Playwright `13 passed, 1 skipped`.
- `.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty` - pass, dry-run wrote no DB rows.
- `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty` - pass, no warnings.
- `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` - pass, `ok: true`.

## T17 PRD / Docs Updated

- `docs/V3_6_BACKGROUND_JOB_HARDENING.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/LAB_RUNBOOK.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- Risk: Synchronous jobs do not support true cancellation. Decision: expose only honest queued-job cancellation now.
- Risk: SQLite is not ideal for concurrent long-running shared-lab work. Decision: keep SQLite local and document PostgreSQL as future validation.
- Assumption: Operators need visibility more than real async execution in this phase.

## T19 Release / Rollback

- Release: Apply Alembic migration, restart backend, run verification.
- Rollback: Downgrade migration to remove `operation_jobs`; endpoint wrappers can be reverted without changing core detection/ML behavior.

## T20 Final Handoff

- ATDR v3.6 provides unified long-running operation visibility while preserving the current local workflow and safety constraints.
- Next recommended phase: async-worker design and retention policy only after PostgreSQL/shared-lab needs are confirmed.

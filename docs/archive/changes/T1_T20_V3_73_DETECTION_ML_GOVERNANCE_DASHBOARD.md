# T1-T20 Change Document: v3.73 Detection/ML Governance Dashboard Integration

## T1 Change Title

v3.73 Detection/ML Governance Dashboard Integration

## T2 Requirement

Expose the v3.72 unified Detection/ML productization evaluator through a safe authenticated API and show a concise status panel in AI Governance without changing detection logic, ML behavior, labels, artifacts, or response safety.

## T3 Source Evidence

- `atdr/app/detection/v372_unified_detection_ml_evaluation.py`
- `atdr/scripts/evaluate_detection_ml_productization.py`
- `atdr/app/routers/dashboard.py`
- `frontend/src/pages/MLGovernance.tsx`
- `frontend/src/lib/api.ts`
- `frontend/src/hooks/useApiQueries.ts`
- `frontend/src/types/api.ts`
- `atdr/tests/test_v372_unified_detection_ml_evaluation.py`
- `frontend/tests/smoke.spec.ts`
- `docs/V3_72_UNIFIED_DETECTION_ML_EVALUATION.md`

## T4 Current Behavior

Before this change, the unified evaluator was available as a CLI command. AI Governance showed many older diagnostic summaries, but not the current unified productization status in one compact panel.

## T5 Impacted Areas / Agents

- Backend / API
- Frontend / Dashboard
- AI/ML Governance
- QA
- Docs / Release-Ops

## T6 Scope

In scope:

- Authenticated read-only dashboard endpoint.
- AI Governance panel.
- TypeScript API types and hook.
- Backend and frontend regression tests.
- Docs and taskboard updates.

Out of scope:

- Detection rule changes.
- ML training changes.
- Model activation or promotion.
- Label writing.
- Response action execution.
- Schema changes.
- Real IAM or chatbot changes.

## T7 Functional Requirements

- Analyst/admin users can request Detection/ML productization status.
- Unauthenticated users are rejected.
- Dashboard shows concise status, not raw JSON.
- Default dashboard load avoids temporary-DB scenario execution.
- Safety fields remain visible.

## T8 Acceptance Criteria

- Endpoint returns v3.72 evaluator output for authenticated users.
- Endpoint rejects unauthenticated users.
- AI Governance renders the Detection / ML Productization panel.
- Panel shows no response actions created and no model activation.
- Tests pass.

## T9 API Contract

`GET /api/dashboard/detection-ml-productization`

Query parameters:

- `include_scenarios`: optional boolean, default `false`
- `use_ml`: optional boolean, default `false`

Default behavior is fast read-only dashboard mode.

## T10 Data Model / Migration

No schema or migration change.

## T11 Backend Plan / Changes

- Import and call `run_v372_unified_detection_ml_evaluation`.
- Add authenticated dashboard endpoint.
- Add API test for auth and safety response shape.

## T12 Frontend Plan / Changes

- Add TypeScript response type.
- Add API helper and React Query hook.
- Add compact AI Governance panel with collapsible check details.
- Update Playwright smoke fixture and assertions.

## T13 Security / Response / AI Safety

- Read-only endpoint.
- No raw logs.
- No secrets.
- No response actions.
- No model activation.
- No production readiness claim.
- Response automation remains disabled.

## T14 Test Plan

- Backend endpoint auth/safety test.
- Frontend smoke panel assertion.
- TypeScript lint/build.
- Existing release gate.

## T15 Implementation Summary

Added a read-only API endpoint for v3.72 productization evaluation, wired it to AI Governance, and updated tests/docs. The dashboard path stays lightweight by default and continues to treat ML as decision support.

## T16 Tests Run / Evidence

- `node scripts/render-tasklist-progress-html.js .`
- `node scripts/check-tasklist-progress-standard.js .`
- `.\.venv\Scripts\ruff.exe check .`
- `.\.venv\Scripts\python.exe -m compileall -q atdr migrations`
- `.\.venv\Scripts\python.exe -m pytest atdr\tests -q --basetemp .pytest_tmp\v373-full -p no:cacheprovider`
- `.\.venv\Scripts\alembic.exe check`
- `cd frontend; npm.cmd run lint`
- `cd frontend; npm.cmd run build`
- `cd frontend; npm.cmd run test:e2e`
- `.\.venv\Scripts\python.exe -m atdr.scripts.evaluate_detection_ml_productization --pretty`
- `.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty`
- `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty`
- `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release`

Results:

- Backend tests: `440 passed, 1 skipped`.
- Playwright: `16 passed, 1 skipped`.
- Performance smoke: `ok: true`, no warnings.
- Release gate: `ok: true`.

## T17 PRD / Docs Updated

- `docs/V3_73_DETECTION_ML_GOVERNANCE_DASHBOARD.md`
- `docs/changes/T1_T20_V3_73_DETECTION_ML_GOVERNANCE_DASHBOARD.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- The dashboard endpoint can run optional scenario validation, but the frontend does not request it by default.
- The endpoint depends on v3.59/v3.62 ignored artifacts for optional supervised policy details.
- Productization status is governance visibility, not runtime activation.

## T19 Release / Rollback

Rollback removes the endpoint, frontend hook/panel, tests, and docs references. Detection, ML, response, and database behavior remain unchanged.

## T20 Final Handoff

Recommended next phase: continue productization with either real MFU IAM live validation, assistant real-provider UX validation, or deeper detection/ML runtime integration only after explicit safety design.

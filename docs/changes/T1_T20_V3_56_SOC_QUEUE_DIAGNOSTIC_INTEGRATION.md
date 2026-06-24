# T1-T20 Change Document: v3.56 SOC Queue Diagnostic Integration

## T1 Change Title

v3.56 SOC Queue Diagnostic Integration

## T2 Requirement

Expose the stable v3.55 binary SOC review-queue diagnostic in ML Governance without activating a model or changing detection behavior.

## T3 Source Evidence

- `atdr/app/routers/dashboard.py`
- `frontend/src/pages/MLGovernance.tsx`
- `frontend/src/types/api.ts`
- `ml_baseline_reviews/v3_55_severity_target_policy_reframing_latest.json`
- `atdr/tests/test_api.py`
- `frontend/tests/smoke.spec.ts`
- `docs/V3_55_SEVERITY_TARGET_POLICY_REFRAMING.md`

## T4 Current Behavior

v3.55 diagnostic results exist locally, but ML Governance previously emphasized older v3.30 detection-quality diagnostics and the supervised model registry. Analysts could not easily see that the binary SOC review-queue policy was the stable supervised candidate direction.

## T5 Impacted Areas / Agents

- Backend/API
- Frontend/Dashboard
- AI/ML Governance
- QA/UAT
- Documentation

## T6 Scope

In scope:

- Add a safe dashboard validation-summary field for v3.55.
- Add compact ML Governance display.
- Add backend/frontend tests.
- Add docs and tasklist traceability.

Out of scope:

- Model activation
- Model artifact writing
- Label creation or import
- Threshold replacement
- Response automation
- Real firewall blocking
- Database migration

## T7 Functional Requirements

- Read the latest v3.55 report if present.
- Show split stability, queue F1, queue recall, queue precision, FPR, calibration, readiness, and safety flags.
- State exact severity is explanation/ranking only.
- Keep missing-report behavior graceful.

## T8 Acceptance Criteria

- API returns `v355_soc_queue.available=true` when the latest v3.55 report exists.
- UI renders **SOC Review Queue Diagnostic**.
- UI shows `5/5 splits`, queue metrics, calibration status, and candidate-only readiness.
- API and UI expose no activation path.
- Tests pass.

## T9 API Contract

`GET /api/dashboard/validation-summary` now includes:

- `v355_soc_queue.available`
- `v355_soc_queue.best_strategy`
- `v355_soc_queue.policy_name`
- `v355_soc_queue.passing_splits`
- `v355_soc_queue.evaluated_splits`
- `v355_soc_queue.queue_f1_min`
- `v355_soc_queue.queue_recall_min`
- `v355_soc_queue.queue_precision_min`
- `v355_soc_queue.benign_like_false_positive_rate_max`
- `v355_soc_queue.calibration_status`
- `v355_soc_queue.readiness_decision`
- safety flags

## T10 Data Model / Migration

No schema change.

## T11 Backend Plan / Changes

- Added `_latest_v355_soc_queue_summary`.
- Added `v355_soc_queue` to dashboard validation summary.
- Added regression coverage in `test_api.py`.

## T12 Frontend Plan / Changes

- Added `DashboardV355SocQueueSummary`.
- Added ML Governance queue diagnostic panel.
- Added Playwright smoke coverage.

## T13 Security / Response / AI Safety

- Production promotion remains false.
- Model activation remains false.
- Model artifact writing remains false.
- Labels are not written.
- Response automation remains disabled.
- Real firewall blocking remains disabled.

## T14 Test Plan

- Backend API test for safe v3.55 summary extraction.
- Frontend smoke test for queue diagnostic panel and safety wording.
- Existing release gates remain required.

## T15 Implementation Summary

v3.56 converts the latest v3.55 diagnostic report into a concise dashboard-facing summary and presents it as diagnostic-only SOC queue evidence in ML Governance.

## T16 Tests Run / Evidence

To be filled by verification output for this change.

## T17 PRD / Docs Updated

- `docs/V3_56_SOC_QUEUE_DIAGNOSTIC_INTEGRATION.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- Exact severity classification remains unstable.
- Queue diagnostic must not be interpreted as production readiness.
- Generated `ml_baseline_reviews/` reports remain ignored and must not be committed.

## T19 Release / Rollback

Rollback is safe by reverting dashboard summary/UI/test/doc changes. No database migration or active model artifact is involved.

## T20 Final Handoff

Use the ML Governance page to explain that supervised ML is currently strongest as a SOC review queue assistant, while exact severity stays in evidence/explanation mode.

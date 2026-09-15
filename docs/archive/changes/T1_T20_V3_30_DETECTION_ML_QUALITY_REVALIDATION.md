# T1-T20 Change Document: v3.30 Detection and ML Quality Revalidation

## T1 Change Title

v3.30 Detection and ML Quality Revalidation

## T2 Requirement

Revalidate the current supervised/SOC triage model on the current labeled firewall-log dataset, analyze false-positive noise, compare threshold profiles, check confidence calibration, export targeted review rows, and surface concise dashboard status without activating a model or enabling response automation.

## T3 Source Evidence

- `atdr/app/detection/v330_detection_ml_quality.py`
- `atdr/scripts/run_v330_detection_ml_quality_revalidation.py`
- `atdr/tests/test_v330_detection_ml_quality.py`
- `atdr/app/detection/supervised_detector.py`
- `atdr/app/ml/features.py`
- `atdr/app/routers/dashboard.py`
- `frontend/src/pages/MLGovernance.tsx`
- `frontend/tests/smoke.spec.ts`
- `docs/V3_30_DETECTION_ML_QUALITY_REVALIDATION.md`

## T4 Current Behavior

Before v3.30, ATDR had many historical validation reports and a strong assistant workflow, but the current labeled dataset needed a fresh diagnostic view focused on false positives, threshold tradeoffs, calibration, and review targets.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Detection quality
- Backend dashboard summary
- Frontend AI Governance dashboard
- QA / validation
- Documentation / university workflow

## T6 Scope

In scope:

- Current-dataset diagnostic revalidation.
- Threshold profile comparison.
- False-positive and false-negative root-cause analysis.
- Rule/anomaly/supervised/hybrid disagreement summary.
- Confidence calibration table.
- Targeted review CSV export.
- Compact AI Governance diagnostic panel.
- Tests and process docs.

Out of scope:

- Model activation.
- Production promotion.
- Detection threshold replacement.
- Automatic response.
- Real firewall blocking.
- Database reset or schema migration.
- Generated report commitment.

## T7 Functional Requirements

- Provide a script runnable with `python -m atdr.scripts.run_v330_detection_ml_quality_revalidation`.
- Generate an ignored markdown analysis report.
- Generate an ignored review sample CSV.
- Generate a compact ignored JSON summary for the dashboard.
- Show v3.30 status in AI Governance if the summary exists.
- Keep all safety flags false for promotion, activation, model artifact writing, and response automation.

## T8 Acceptance Criteria

- v3.30 tests pass.
- Report includes baseline metrics, threshold comparison, calibration, root causes, review sample, and safety status.
- Review sample columns are analyst-import friendly and exclude raw log text/private paths.
- Dashboard shows concise diagnostic status without clutter.
- No response actions or ML model runs are created by the diagnostic.

## T9 API Contract

No new public mutating API is added.

`GET /api/dashboard/validation-summary` now includes an optional `v330_detection_ml_quality` summary when `ml_baseline_reviews/v3_30_detection_ml_quality_latest.json` exists.

## T10 Data Model / Migration

No schema change.

## T11 Backend Plan / Changes

- Add `v330_detection_ml_quality.py` diagnostic service.
- Add CLI wrapper.
- Add dashboard summary reader for the latest v3.30 JSON summary.
- Keep diagnostic generated artifacts under ignored review/report directories.

## T12 Frontend Plan / Changes

- Add `Detection Quality Revalidation` panel in AI Governance.
- Show main blocker, baseline FPR, best diagnostic profile, threat F1, calibration, review sample count, and safety state.
- Keep detailed patterns in a collapsible section.

## T13 Security / Response / AI Safety

- No model activation.
- No model promotion.
- No automatic response.
- No real firewall blocking.
- No raw logs in review CSV.
- Generated outputs are ignored and must not be committed.

## T14 Test Plan

- Unit tests for v3.30 diagnostic output, CSV fields, generated reports, and no side effects.
- Frontend smoke test for the AI Governance v3.30 panel.
- Full release verification.

## T15 Implementation Summary

v3.30 adds a safe diagnostic quality pass for the current supervised ML dataset. It identifies false-positive noise as the current main blocker, compares threshold options, exports review rows, and makes the state visible in AI Governance without changing model or response behavior.

## T16 Tests Run / Evidence

Verification evidence is recorded in `docs/tasks/tasklist-progress.md`.

## T17 PRD / Docs Updated

- `docs/V3_30_DETECTION_ML_QUALITY_REVALIDATION.md`
- `docs/changes/T1_T20_V3_30_DETECTION_ML_QUALITY_REVALIDATION.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- Current-dataset metrics are not production accuracy.
- Time-window/source concentration can distort model validation.
- Calibration is weak and should not be treated as reliable confidence.
- The best low-noise profile is diagnostic only and not activated.

## T19 Release / Rollback

Rollback can remove v3.30 diagnostic files, dashboard summary reader, AI Governance panel, tests, and docs. No database rollback is required.

## T20 Final Handoff

Run the v3.30 script, then open AI Governance. The expected result is a diagnostic-only quality panel that clearly shows whether false positives, suspicious recall, and calibration are still blocking stronger model claims.

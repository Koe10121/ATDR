# T1-T20: v5.3 Temporal Generalization And OOD Validation

## T1 Change Title

v5.3 Temporal Generalization Repair and Independent Evidence Preparation.

## T2 Requirement

Diagnose the v5.2 temporal false-positive failure, add leakage-safe rolling
temporal validation and fit-only OOD/abstention diagnostics, compare safer
supervised queue strategies, and preserve shadow-only governance.

## T3 Source Evidence

- v5.2 baseline and splits: `v49_detection_ml_reliability.py`,
  `v52_shadow_reliability.py`, and the ignored v5.2 report.
- Governed lifecycle: `v51_supervised_lifecycle.py` and lifecycle status CLI.
- v5.3 evaluator: `v53_temporal_generalization.py` and its CLI.
- UI/API contract: `routers/ml.py`, `frontend/src/types/api.ts`, and
  `frontend/src/pages/MLGovernance.tsx`.
- Safety baselines: 24-scenario, 288-run layered, locked external, and private
  aggregate reports.

## T4 Current Behavior

v5.2 selected no candidate. Its leading comparator had temporal FPR 1.0,
source holdout failed closed, and the locked external benchmark failed. The
v5.1 governed artifact remained shadow-only.

## T5 Impacted Areas/Agents

Supervised evaluation, model governance, AI Governance UI, QA, security/safety,
release evidence, and documentation.

## T6 Scope

In scope: read-only temporal diagnosis, rolling windows, OOD/abstention,
strategy comparison, aggregate UI telemetry, tests, and governance records.

Out of scope: label authoring, artifact activation/promotion, response action,
real blocking, database reset, locked-label tuning, and fabricated source data.

## T7 Functional Requirements

1. Freeze and fingerprint the v5.2 evidence and state.
2. Keep fit, calibration, threshold, and final roles separate.
3. Evaluate three disjoint future windows without final-label reuse.
4. Fit OOD profiles only on fit evidence.
5. Route OOD/unstable rows to `insufficient_model_evidence`.
6. Count abstentions honestly in the analyst queue.
7. Fail closed on missing real-source or locked row-level evidence.
8. Keep every model diagnostic-only and rules alert-authoritative.

## T8 Acceptance Criteria

- Temporal root cause is measured rather than guessed.
- Rolling windows are disjoint and leakage-free.
- OOD/abstention cannot game FPR by discarding difficult rows.
- All required split failures remain visible.
- No database/artifact/label/response state changes.
- UI shows aggregate drift, OOD, abstention, and blocker evidence.
- Full verification and hygiene checks pass.

## T9 API Contract

No new endpoint. The existing supervised lifecycle payload gains safe optional
v5.3 aggregate fields. Existing v5.2 fields remain compatible. No raw logs,
identifiers, private paths, labels, or secrets are exposed.

## T10 Data Model / Migration

No schema or migration change. Evaluation output is generated under ignored
`ml_baseline_reviews/`; lifecycle UI data uses existing aggregate status.

## T11 Backend Plan / Changes

Add the v5.3 evaluator/CLI, baseline freeze, temporal diagnosis, three rolling
future windows, fit-only OOD profile, calibrated abstention semantics, strategy
matrix, strict readiness checks, and v5.3 lifecycle summary parsing.

## T12 Frontend Plan / Changes

Extend AI Governance with compact Temporal FPR, OOD Rate, Abstention Maximum,
rolling-window count, and root-cause visibility. Preserve responsive layout,
existing lifecycle cards, and no-action behavior.

## T13 Security / Response / AI Safety

No label write, model activation/promotion, active artifact write, detection
authority change, response action, automation, or blocking. No private/raw
evidence enters the UI or tracked reports.

## T14 Test Plan

Test rolling role separation, disjoint final windows, fit-only OOD behavior,
unseen/missing schema handling, honest abstention FPR accounting, v5.1 reference
exclusion, conservative readiness, lifecycle summary, frontend telemetry, and
the complete existing release matrix.

## T15 Implementation Summary

v5.3 confirms the temporal failure is driven by chronological target,
provenance, application, and behavior-context shift. No tested model or
abstention strategy passes all strict views. The diagnostic leader remains
unselected and the lifecycle remains shadow observation.

## T16 Tests Run / Evidence

Targeted backend tests passed 19 tests. The read-only v5.3 evaluator completed
in 55.4101 seconds, evaluated all three rolling future windows, selected no
candidate, preserved all database/artifact counts, and created zero responses.
Taskboard checks, whole-repo Ruff/compileall, and Alembic passed. The full
backend and release-gate suites each passed 656 tests with one hardware skip.
React lint/build passed; Playwright passed 26 with one live-scenario skip;
controlled scenarios passed 24/24; layered validation passed 288/288; assistant
QA passed 20/20; private disposable shadow, replay dry-run, warning-free
performance smoke, hygiene checks, and the official release gate all passed.

## T17 PRD / Docs Updated

v5.3 status, this record, exact allowlist, PRD, traceability, compliance, AI
runbook, current AI/ML status, docs index, and taskboard.

## T18 Risks / Blockers / Assumptions / Decisions

- Temporal FPR is `0.9976`; rolling FPR is `0.9923` to `1.0000`.
- Threshold/final queue prevalence shifts from `0.8640` to `0.2218`.
- OOD rate alone is only `0.0733`, so OOD filtering is not the main repair.
- Source holdout lacks two real devices and fails closed.
- Locked external evidence remains failed and was not reopened for tuning.
- Decision: no candidate, no activation, no promotion, shadow only.

## T19 Release / Rollback

No commit or push is authorized by this record. No migration or active artifact
was written. Rollback is an ordinary source/UI revert; the existing governed
shadow lifecycle remains unchanged.

## T20 Final Handoff

The supervised queue now has stronger failure diagnostics and honest OOD/
abstention semantics, but it is not stable across time. The next legitimate
model phase requires new independently governed chronological and multi-device
evidence, not threshold tuning on the locked final windows.

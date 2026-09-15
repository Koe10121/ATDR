# T1-T20: v5.5 Development Model Repair And Anomaly Reliability Audit

## T1 Change Title

v5.5 Development-Only Detection Model Repair and Anomaly Reliability Audit.

## T2 Requirement

Use only the governed v5.4 development evidence to compare supervised SOC
queue strategies, audit the existing IsolationForest, freeze at most one
diagnostic leader, and then perform one read-only locked-final regression.

## T3 Source Evidence

- Evidence lock and development roles:
  `atdr/app/detection/v54_temporal_evidence.py` and
  `data/samples/benchmarks/v53_temporal_evidence_lock.json`.
- Frozen split/leakage metrics:
  `atdr/app/detection/v398_independent_holdout_validation.py`.
- Current reliability/lifecycle:
  `atdr/app/detection/v49_detection_ml_reliability.py`,
  `atdr/app/detection/v51_supervised_lifecycle.py`, and
  `atdr/app/detection/v52_shadow_reliability.py`.
- Existing anomaly model:
  `atdr/app/detection/ml_detector.py`.
- Governed labels/features:
  `atdr/app/db/models.py`, `atdr/app/ml/features.py`, and
  `atdr/app/detection/supervised_detector.py`.

## T4 Current Behavior

v5.3 temporal and rolling FPR were near 1.0. v5.4 locked the final evidence and
curated 1,467 development rows, but one real source and material chronological
drift prevented lifecycle advancement. IsolationForest reliability across
governed labels and benign scenarios had not been audited as a separate
quality track.

## T5 Impacted Areas/Agents

Detection, AI/ML governance, evidence management, backend CLI, AI Governance
UI, QA, documentation, and release governance.

## T6 Scope

In scope: lock validation, development-only nested temporal folds,
duplicate-group isolation, provenance balancing, five strategy comparisons,
development-only calibration/thresholds, diagnostic freeze, one locked-final
regression, IsolationForest audit, aggregate UI status, tests, and docs.

Out of scope: label creation, final-window tuning, active artifact writes,
model activation/promotion, alert authority changes, response automation, real
blocking, and fabricated source evidence.

## T7 Functional Requirements

1. Refuse evaluation if the v5.4 evidence lock changes.
2. Exclude temporal-final and quarantine rows from all selection roles.
3. Keep leakage groups disjoint in nested chronological folds.
4. Balance development provenance without overwriting labels.
5. Compare calibrated ExtraTrees, HistGradientBoosting, Logistic Regression,
   three-class SOC queue, and hierarchical two-stage strategies.
6. Freeze a diagnostic leader before reading locked-final labels.
7. Audit IsolationForest as advisory evidence only.
8. Return aggregate status without raw/private evidence.
9. Preserve database, artifact, alert, and response state.

## T8 Acceptance Criteria

- Evidence lock reproduces exactly.
- Locked labels used for model selection equal zero.
- Every development partition passes leakage isolation.
- A source-aware view fails closed when fewer than two sources exist.
- Candidate freeze precedes locked-final evaluation.
- No label/model/detection/response/artifact write occurs.
- Lifecycle remains conservative when any fixed gate fails.
- Full release and repository hygiene checks pass.

## T9 API Contract

No new route. Existing supervised lifecycle/governance output gains optional
aggregate v5.5 status, development leader, locked-final metrics,
IsolationForest estimates, and blockers. Existing clients remain compatible.

## T10 Data Model / Migration

No database schema or migration change. Generated diagnostic reports remain
ignored under `ml_baseline_reviews/`.

## T11 Backend Plan / Changes

Add the v5.5 evaluator and CLI, nested temporal partitioning,
provenance-balanced fitting, development-only calibration/thresholding,
diagnostic candidate freeze, one-shot locked-final regression, read-only
IsolationForest scoring, controlled benign scenario audit, and lifecycle
aggregate summary.

## T12 Frontend Plan / Changes

Show concise v5.5 aggregate leader, locked F1/FPR/recall/calibration,
IsolationForest reliability, and blockers within the existing AI Governance
technical details. Do not expose row evidence or add activation controls.

## T13 Security / Response / AI Safety

No raw/private evidence enters API/UI or tracked output. ML remains advisory;
rules remain alert-authoritative. No model, label, alert, detection, response,
user, firewall, or active artifact mutation is permitted.

## T14 Test Plan

Test locked/final exclusion, nested leakage isolation, bounded provenance
weights, freeze-before-final ordering, aggregate-only lifecycle output, no
activation/artifact/label/response writes, and conservative readiness.

## T15 Implementation Summary

v5.5 compares five supervised strategies across three development-only
chronological folds. The three-class ExtraTrees SOC queue is frozen as the
diagnostic leader but passes 0/3 strict folds. Its locked-final FPR improves to
`0.0773`, while F1 `0.4925`, suspicious recall `0.3824`, malicious recall
`0.4143`, and ECE `0.5405` remain unacceptable. IsolationForest development
FPR is `0.2773` with threat capture `0.0818`.

## T16 Tests Run / Evidence

The governed evaluator completed in `18.9769s`, reproduced the v5.4 lock,
used 1,467 development rows, and preserved all database/artifact counts.
Taskboard checks, whole-repo Ruff, compileall, and Alembic passed. Focused
v5.4/v5.5 tests passed `13/13`; full backend and release-gate suites passed
`669 passed, 1 skipped`. React lint/build passed; Playwright passed
`26 passed, 1 skipped`; controlled detection passed `24/24`; layered
validation passed `288/288`; assistant QA passed `20/20`; replay dry-run and
performance smoke passed; the official release gate returned `ok: true`.

## T17 PRD / Docs Updated

v5.5 status, this T1-T20 record, exact allowlist, PRD, traceability,
compliance checklist, AI training runbook, current AI/ML status, docs index,
and taskboard.

## T18 Risks / Blockers / Assumptions / Decisions

- Only one real source identity is present.
- No strategy passes all development temporal gates.
- Locked-final recall and calibration fail.
- IsolationForest is unstable across chronological regimes.
- The old locked external benchmark remains failed and unavailable for tuning.
- Decision: lifecycle remains `shadow_observation`; no lifecycle candidate is
  selected or activated.

## T19 Release / Rollback

No migration, configured-data write, active artifact write, commit, or push is
authorized. Rollback is a normal source/UI/docs revert; ignored aggregate
reports can be discarded without affecting runtime state.

## T20 Final Handoff

v5.5 proves that queue noise can be reduced without leaking locked labels, but
also proves that recall, calibration, source independence, and anomaly
reliability are not complete. The next legitimate quality phase requires new
independent reviewed evidence, not repeated tuning on the locked final role.

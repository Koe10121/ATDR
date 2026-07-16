# T1-T20: v3.98 Independent Detection/ML Holdout Validation

## T1 Change Title

v3.98 Leakage-Controlled Independent Detection/ML Holdout Validation.

## T2 Requirement

Validate ATDR rule, anomaly, supervised SOC queue, and hybrid decision-support quality with frozen fit/calibration/threshold/final-test boundaries, multiple split modes, explicit leakage checks, conservative readiness, and no runtime model or response side effects.

## T3 Source Evidence

`atdr/app/detection/rules.py`, `anomaly_detector.py`, `supervised_detector.py`, `hybrid_detector.py`, `v330_detection_ml_quality.py`, v3.48-v3.62 supervised queue phases, `v372_unified_detection_ml_evaluation.py`, `atdr/app/ml/features.py`, `atdr/app/db/models.py`, existing validation tests/docs, and current reviewed-label provenance.

## T4 Current Behavior

ATDR already provided controlled rule/scenario checks, IsolationForest anomaly support, supervised candidate experiments, a repaired binary review-queue target, and conservative governance. Prior evidence did not provide one unified four-part frozen protocol across temporal, source, and repeated random splits with exact/near/feature leakage grouping.

## T5 Impacted Areas/Agents

AI/ML Governance, detection engineering, data quality, QA/UAT, Release/Ops, documentation, and response-safety review. No runtime API, dashboard, ingestion, IAM, or response action behavior changes.

## T6 Scope

In scope: reviewed-label provenance audit, leakage grouping, frozen holdouts, diagnostic strategy comparison, calibration, bootstrap intervals, source/pattern error analysis, ignored reports, tests, and docs. Out of scope: model activation/promotion, artifact publication, automatic labeling, automatic response, real firewall enforcement, current-DB migration, or production claims.

## T7 Functional Requirements

The evaluator must reserve fit, calibration, threshold-selection, and final-test partitions; fail closed on leakage; evaluate all required split modes; compare existing decision-support layers and simple baselines; report stability and calibration; never use final-test labels for tuning; and leave database/model/response state unchanged.

## T8 Acceptance Criteria

Targeted tests prove grouping, overlap rejection, source disjointness, determinism, final-test isolation, report safety, conservative readiness, and zero side effects. A full run against a migrated disposable copy must produce ignored reports and distinguish internal unseen holdout evidence from external independence.

## T9 API Contract

No API endpoint, authentication rule, or startup command changes. The new interface is the explicit CLI `python -m atdr.scripts.run_v398_independent_holdout_validation`.

## T10 Data Model / Migration

No v3.98 schema change. v3.98 relies on the v3.97 `raw_logs.raw_line_hash` migration when using current data but never applies that migration itself. The configured database is not migrated during this change without explicit approval.

## T11 Backend Plan / Changes

Add a read-only evaluator with reviewed latest-label selection, safe binary targets, local evidence features, leakage groups, frozen partitions, metrics/calibration/bootstrap/error summaries, diagnostic comparisons, report rendering, and a CLI entry point.

## T12 Frontend Plan / Changes

No frontend behavior change. AI Governance remains the runtime decision-support surface; generated v3.98 reports are engineering evidence and are not automatically promoted into active model status.

## T13 Security / Response / AI Safety

Reports exclude raw lines and IP values. No label is created or modified. No model run is activated/promoted and no active artifact is written. No detection run or response action is created. Automatic response and real firewall blocking remain disabled. Readiness remains conservative and external independence is not claimed.

## T14 Test Plan

Run focused v3.98 tests, Ruff, compileall, complete backend tests, Alembic check, React lint/build/Playwright regressions, replay dry-run, performance smoke, release gate, and the v3.97 disposable migration/100k validation closure checks.

## T15 Implementation Summary

`v398_independent_holdout_validation.py` implements the read-only protocol; `run_v398_independent_holdout_validation.py` exposes it; focused tests verify the protocol; canonical and T1-T20 docs record claims and limits.

## T16 Tests Run / Evidence

Focused v3.98 protocol tests pass (`6 passed`). The disposable-copy evaluator completed on 2,235 reviewed latest labels with unchanged database counts, active artifact, and SQLAlchemy session state; temporal/source splits failed closed, three random splits evaluated, and readiness stayed `candidate_only`. Ruff and compileall passed. Full backend tests passed (`544 passed, 1 skipped`). The disposable database is at `b4c5d6e7f8a9 (head)` with no Alembic drift while the configured database remains `a3b4c5d6e7f8`. React lint/build passed and Playwright passed (`21 passed, 1 skipped`). Replay dry-run wrote zero rows. A cold large-SQLite smoke warned, while its immediate warm rerun passed all budgets with Overview `0.4427s`, cached Overview `0.0063s`, ML Governance `1.2281s`, alert list `0.0330s`, case summary `0.0769s`, and feature sample `0.4419s`. The release gate returned `ok: true`: config doctor, compileall, repeated full pytest, Alembic check, and deployment-operations validation all passed; only the optional running-stack smoke was skipped.

## T17 PRD / Docs Updated

Canonical v3.98 doc, this change record, current-state lock, productization roadmap, PRD, requirement traceability, compliance checklist/docs index as appropriate, and tasklist/progress board.

## T18 Risks / Blockers / Assumptions / Decisions

The current reviewed corpus may retain source/time bias even after leakage controls. Quarantine may reduce support. Internal unseen holdouts are not external independent evidence. The primary candidate is fixed before final scoring, exact severity remains non-authoritative, and failures remain visible rather than being tuned away.

## T19 Release / Rollback

This evaluator is additive and diagnostic. Rollback removes the evaluator, CLI, tests, and docs; it must not delete labels, logs, model history, or reports needed as private evidence. No active model rollback is required because v3.98 performs no activation.

## T20 Final Handoff

Status: complete for repository/local internal-holdout scope with documented quality/evidence blockers. No commit or push is authorized by this change. The configured database remains on its pre-v3.97 revision until the user explicitly approves migration.

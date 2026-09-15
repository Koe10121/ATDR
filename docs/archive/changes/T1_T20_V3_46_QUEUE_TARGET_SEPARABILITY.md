# T1-T20 Change Document: v3.46 Queue Target Separability And Training Signal Audit

## T1 Change Title

v3.46 Queue Target Separability And Training Signal Audit

## T2 Requirement

Diagnose why supervised SOC queue models remain unstable by auditing queue target ambiguity, feature separability, source concentration, and split drift.

## T3 Source Evidence

- `ml_baseline_reviews/v3_45_queue_precision_severity_recall_latest.json`
- `atdr/app/detection/v345_queue_precision_severity_recall.py`
- `atdr/app/detection/v346_queue_target_separability.py`
- `atdr/scripts/run_v346_queue_target_separability.py`
- `atdr/tests/test_v346_queue_target_separability.py`

## T4 Current Behavior

v3.45 reduces queue noise with logistic queueing, but queue recall collapses. ExtraTrees preserves recall but over-admits benign-like rows. Readiness remains `candidate_only`.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Detection quality
- Label semantics
- Feature engineering
- QA/release validation
- Documentation

## T6 Scope

In scope:

- Queue target separability audit.
- Pattern/source/family ambiguity analysis.
- Numeric feature separator analysis.
- Split drift analysis.
- Safety/no-side-effect tests.

Out of scope:

- Human-reviewed label creation.
- Model activation/promotion.
- Automatic response.
- Real firewall blocking.
- Database schema changes.

## T7 Functional Requirements

- Audit current queue targets without changing labels.
- Identify ambiguous queue patterns and evidence buckets.
- Identify split drift in needs-review rate.
- Identify strongest numeric separators.
- Reports must remain diagnostic-only.

## T8 Acceptance Criteria

- v3.46 diagnostic runs successfully.
- No labels are written.
- No model activation or active artifact write occurs.
- No response actions are created.
- Tests pass.

## T9 API Contract

No API changes.

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

- Add `atdr/app/detection/v346_queue_target_separability.py`.
- Add `atdr/scripts/run_v346_queue_target_separability.py`.
- Add focused tests.

## T12 Frontend Plan / Changes

No frontend changes.

## T13 Security / Response / AI Safety

ML remains decision support only. Response automation and real firewall blocking stay disabled. No model is activated or promoted.

## T14 Test Plan

- Categorical ambiguity helper test.
- Numeric separability helper test.
- Diagnostic run no-side-effect test.
- Full verification gate.

## T15 Implementation Summary

Implemented diagnostic queue-target separability and training-signal audit. The audit found strong numeric separators but excessive app/action/port and traffic-family ambiguity, plus large time-split queue target drift. The result explains why previous queue classifiers oscillate between noisy and over-conservative behavior.

## T16 Tests Run / Evidence

Targeted v3.46 tests and verification gates are recorded in the final handoff for this phase.

## T17 PRD / Docs Updated

- `docs/V3_46_QUEUE_TARGET_SEPARABILITY.md`
- `docs/changes/T1_T20_V3_46_QUEUE_TARGET_SEPARABILITY.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

The strategy remains diagnostic. Current blockers are ambiguous pattern share `0.4308`, traffic-family ambiguity `0.8046`, and time split needs-review-rate shift `0.2636`. The next phase should repair queue target definitions or add benchmark/source coverage before another model strategy.

## T19 Release / Rollback

Diagnostic-only. Rollback is removing the v3.46 module, script, tests, and docs. No database rollback is required.

## T20 Final Handoff

v3.46 confirms unstable supervised queue behavior is driven by mixed queue semantics and time/source drift, not only poor thresholds. No model should be activated; the next phase should propose target repair rules and benchmark coverage without auto-labeling.

# T1-T20 Change Document: v3.45 Queue Precision And Severity Recall Repair

## T1 Change Title

v3.45 Queue Precision And Severity Recall Repair

## T2 Requirement

Evaluate whether a stricter, evidence-aware queue gate plus recall-aware severity scoring can reduce benign queue noise without suppressing true malicious/high-confidence behavior.

## T3 Source Evidence

- `atdr/app/detection/v344_two_stage_soc_queue.py`
- `ml_baseline_reviews/v3_44_two_stage_soc_queue_latest.json`
- `atdr/app/detection/v345_queue_precision_severity_recall.py`
- `atdr/scripts/run_v345_queue_precision_severity_recall.py`
- `atdr/tests/test_v345_queue_precision_severity_recall.py`

## T4 Current Behavior

v3.44 separates queue admission from severity, but the best diagnostic candidate still fails independent split stability. Logistic regression controls threat-positive FPR while malicious recall collapses. ExtraTrees keeps more recall but remains too noisy.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Detection quality
- SOC queue design
- QA/release validation
- Documentation

## T6 Scope

In scope:

- Diagnostic queue precision gate.
- Evidence rescue for rule/anomaly/scan-backed rows.
- Recall-aware severity thresholds.
- Split stability comparison.
- Safety/no-side-effect tests.

Out of scope:

- Human-reviewed label creation.
- Model activation/promotion.
- Automatic response.
- Real firewall blocking.
- Database schema changes.

## T7 Functional Requirements

- Low-signal web traffic must not enter the queue from model score alone.
- Strong rule/anomaly/scan evidence should still enter the queue.
- Severity rescue should prevent obvious malicious/high-confidence evidence from collapsing to unusual-only.
- Threshold selection must use train-internal calibration only.
- Reports must remain diagnostic-only.

## T8 Acceptance Criteria

- v3.45 diagnostic runs successfully.
- No labels are written.
- No model activation or active artifact write occurs.
- No response actions are created.
- Tests pass.

## T9 API Contract

No API changes.

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

- Add `atdr/app/detection/v345_queue_precision_severity_recall.py`.
- Add `atdr/scripts/run_v345_queue_precision_severity_recall.py`.
- Add focused tests.

## T12 Frontend Plan / Changes

No frontend changes.

## T13 Security / Response / AI Safety

ML remains decision support only. Response automation and real firewall blocking stay disabled. No model is activated or promoted.

## T14 Test Plan

- Low-signal queue rejection behavior test.
- Strong evidence queue rescue behavior test.
- Strong malicious severity rescue behavior test.
- Diagnostic run no-side-effect test.
- Full verification gate.

## T15 Implementation Summary

Implemented diagnostic v3.45 queue precision and severity recall evaluation. The best candidate was `precision_queue_logistic_regression_recall_severity_extra_trees`, but readiness remains `candidate_only` because queue recall, threat FPR, threat F1, malicious recall, and split stability remain below target.

## T16 Tests Run / Evidence

Targeted v3.45 tests and verification gates are recorded in the final handoff for this phase.

## T17 PRD / Docs Updated

- `docs/V3_45_QUEUE_PRECISION_AND_SEVERITY_RECALL.md`
- `docs/changes/T1_T20_V3_45_QUEUE_PRECISION_AND_SEVERITY_RECALL.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

The strategy remains diagnostic. v3.45 shows the current features/targets force an unstable tradeoff: ExtraTrees keeps recall but is noisy, while logistic regression reduces noise but suppresses too many review-worthy rows. The next phase should focus on queue-target disagreement, benchmark design, and feature separability rather than activation.

## T19 Release / Rollback

Diagnostic-only. Rollback is removing the v3.45 module, script, tests, and docs. No database rollback is required.

## T20 Final Handoff

v3.45 confirms stricter queue admission can reduce queue noise, but not without losing too much recall. No model should be activated; the next phase should diagnose why the queue target is not separable enough across time/source/random splits.

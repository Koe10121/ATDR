# T1-T20 Change Document: v3.44 Two-Stage SOC Queue Admission And Severity Separation

## T1 Change Title

v3.44 Two-Stage SOC Queue Admission And Severity Separation

## T2 Requirement

Evaluate whether separating SOC queue admission from severity classification reduces threat-positive false positives while preserving review-worthy event recall.

## T3 Source Evidence

- `atdr/app/detection/v343_hybrid_soc_queue.py`
- `ml_baseline_reviews/v3_43_hybrid_soc_queue_latest.json`
- `atdr/app/detection/v344_two_stage_soc_queue.py`
- `atdr/scripts/run_v344_two_stage_soc_queue.py`
- `atdr/tests/test_v344_two_stage_soc_queue.py`

## T4 Current Behavior

v3.43 has strong SOC review queue recall but over-promotes queued rows into threat-positive classes. The best v3.43 candidate still has unacceptable split stability and threat-positive false-positive behavior.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Detection quality
- SOC queue design
- QA/release validation
- Documentation

## T6 Scope

In scope:

- Two-stage diagnostic design.
- Queue admission vs severity separation.
- Split stability comparison.
- Safety/no-side-effect tests.

Out of scope:

- Human-reviewed label creation.
- Model activation/promotion.
- Automatic response.
- Real firewall blocking.
- Database schema changes.

## T7 Functional Requirements

- Stage A evaluates `non_threat` vs `needs_review`.
- Stage B evaluates queued-row severity only.
- Low-signal web traffic should not enter the queue from probability alone.
- Strong scan/rule/anomaly evidence should enter the queue.
- Threshold selection must use train-internal calibration only.
- Reports must remain diagnostic-only.

## T8 Acceptance Criteria

- v3.44 diagnostic runs successfully.
- No labels are written.
- No model activation or active artifact write occurs.
- No response actions are created.
- Tests pass.

## T9 API Contract

No API changes.

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

- Add `atdr/app/detection/v344_two_stage_soc_queue.py`.
- Add `atdr/scripts/run_v344_two_stage_soc_queue.py`.
- Add focused tests.

## T12 Frontend Plan / Changes

No frontend changes.

## T13 Security / Response / AI Safety

ML remains decision support only. Response automation and real firewall blocking stay disabled. No model is activated or promoted.

## T14 Test Plan

- Queue/severity separation behavior test.
- Hybrid queue low-signal web suppression test.
- Hybrid queue evidence-backed scan admission test.
- Diagnostic run no-side-effect test.
- Full verification gate.

## T15 Implementation Summary

Implemented diagnostic two-stage SOC queue evaluation with independent queue and severity reporting. The current DB result selected `ml_queue_ml_severity_logistic_regression` as the safest false-positive candidate, but readiness remains `candidate_only` because split stability, queue false-positive control, and threat-positive F1 are not acceptable.

## T16 Tests Run / Evidence

Targeted v3.44 tests and verification gates are recorded in the final handoff for this phase.

## T17 PRD / Docs Updated

- `docs/V3_44_TWO_STAGE_SOC_QUEUE.md`
- `docs/changes/T1_T20_V3_44_TWO_STAGE_SOC_QUEUE.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

The strategy remains diagnostic. v3.44 improves the interpretation of queue admission vs severity, but it still exposes unstable tradeoffs: logistic regression controls threat-positive FPR while missing too many malicious/high-confidence rows, and ExtraTrees preserves recall while staying too noisy. The next phase should focus on queue target quality and calibrated severity modeling rather than activation.

## T19 Release / Rollback

Diagnostic-only. Rollback is removing the v3.44 module, script, tests, and docs. No database rollback is required.

## T20 Final Handoff

v3.44 confirms that queue admission and severity should remain separate design problems. No model should be activated yet; the next phase should repair queue precision and severity recall with better targets/features before promotion is reconsidered.

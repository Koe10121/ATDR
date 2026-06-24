# T1-T20 Change Document: v3.43 Hybrid Evidence-First SOC Queue Candidate

## T1 Change Title

v3.43 Hybrid Evidence-First SOC Queue Candidate

## T2 Requirement

Evaluate whether evidence-first SOC queue admission plus bounded supervised ML confidence improves stability without relying on model-only threat predictions.

## T3 Source Evidence

- `atdr/app/detection/v342_label_policy_reframing.py`
- `ml_baseline_reviews/v3_42_label_policy_reframing_latest.json`
- `atdr/app/detection/v343_hybrid_soc_queue.py`
- `atdr/scripts/run_v343_hybrid_soc_queue.py`
- `atdr/tests/test_v343_hybrid_soc_queue.py`

## T4 Current Behavior

v3.42 reframed labels into SOC targets but did not meet split-stability requirements. The best v3.42 candidate controlled false positives but recall collapsed.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Detection quality
- SOC queue design
- QA/release validation
- Documentation

## T6 Scope

In scope:

- Evidence-first SOC queue diagnostic.
- Bounded ML-assisted queue diagnostic.
- Split stability comparison.
- Safety/no-side-effect tests.

Out of scope:

- Human-reviewed label creation.
- Model activation/promotion.
- Automatic response.
- Real firewall blocking.
- Database schema changes.

## T7 Functional Requirements

- Low-signal web/utility rows should not become threat-positive from model confidence alone.
- Strong scan/anomaly/rule evidence should enter SOC review.
- ML-assisted variants must use train-internal threshold selection.
- Reports must remain diagnostic-only.

## T8 Acceptance Criteria

- v3.43 diagnostic runs successfully.
- No labels are written.
- No model activation or active artifact write occurs.
- No response actions are created.
- Tests pass.

## T9 API Contract

No API changes.

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

- Add `atdr/app/detection/v343_hybrid_soc_queue.py`.
- Add `atdr/scripts/run_v343_hybrid_soc_queue.py`.
- Add focused tests.

## T12 Frontend Plan / Changes

No frontend changes.

## T13 Security / Response / AI Safety

ML remains decision support only. Response automation and real firewall blocking stay disabled. No model is activated or promoted.

## T14 Test Plan

- Evidence-first low-signal web behavior test.
- Evidence-first strong scan-context behavior test.
- Diagnostic run no-side-effect test.
- Full verification gate.

## T15 Implementation Summary

Implemented evidence-first and bounded ML-assisted SOC queue diagnostics.

## T16 Tests Run / Evidence

Targeted v3.43 tests passed. Full verification evidence is recorded in the phase report/final handoff.

## T17 PRD / Docs Updated

- `docs/V3_43_HYBRID_EVIDENCE_FIRST_SOC_QUEUE.md`
- `docs/changes/T1_T20_V3_43_HYBRID_EVIDENCE_FIRST_SOC_QUEUE.md`

## T18 Risks / Blockers / Assumptions / Decisions

v3.43 catches review-worthy rows but over-promotes many into threat-positive classes. The next design should separate queue admission from severity classification.

## T19 Release / Rollback

Diagnostic-only. Rollback is removing the v3.43 module, script, tests, and docs. No database rollback is required.

## T20 Final Handoff

v3.43 confirms evidence-first queue admission is promising for review recall, but severity needs a separate second stage before any candidate can be considered stable.


# T1-T20 Change Document: v3.42 Label Policy And SOC Target Reframing

## T1 Change Title

v3.42 Label Policy And SOC Target Reframing

## T2 Requirement

Create an explicit ATDR label policy and diagnostic SOC target mapping to investigate whether supervised ML instability is caused by inconsistent label semantics.

## T3 Source Evidence

- `atdr/app/detection/v341_label_semantics_audit.py`
- `ml_baseline_reviews/v3_41_label_semantics_audit_latest.json`
- `atdr/app/detection/v337_evidence_feature_enrichment.py`
- `atdr/app/detection/v338_calibrated_threshold_search.py`
- `atdr/app/detection/v342_label_policy_reframing.py`
- `atdr/scripts/run_v342_label_policy_reframing.py`
- `atdr/tests/test_v342_label_policy_reframing.py`

## T4 Current Behavior

Prior v3.31-v3.41 work showed that threshold tuning, low-signal guards, and boundary overlays could not produce stable supervised ML results across time, grouped/source-aware, and random splits. v3.41 identified many high-severity label-semantic conflicts.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Detection quality
- Label semantics
- QA/release validation
- Documentation

## T6 Scope

In scope:

- Define diagnostic label policy.
- Add diagnostic SOC target mapping.
- Evaluate target mappings across split modes.
- Generate ignored reports.
- Add tests proving no labels/models/responses are changed.

Out of scope:

- Human-reviewed label creation.
- Model activation or promotion.
- Automatic response.
- Real firewall blocking.
- Database reset or schema change.

## T7 Functional Requirements

- Compare current flat/binary/three-class mappings against new SOC target mappings.
- Use train-internal threshold selection only.
- Report split stability, false-positive rate, recall, calibration, and readiness.
- Keep all outputs diagnostic-only.

## T8 Acceptance Criteria

- v3.42 diagnostic runs successfully.
- Generated reports remain under ignored `ml_baseline_reviews/`.
- No labels are written.
- No ML model run is activated/promoted.
- No response actions are created.
- Tests pass.

## T9 API Contract

No API contract changes.

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

- Add `atdr/app/detection/v342_label_policy_reframing.py`.
- Add `atdr/scripts/run_v342_label_policy_reframing.py`.

## T12 Frontend Plan / Changes

No frontend changes.

## T13 Security / Response / AI Safety

- ML remains decision support only.
- Response automation remains disabled.
- Real firewall blocking remains disabled.
- AI-generated target mappings are diagnostic only and must not be imported as human-reviewed labels.

## T14 Test Plan

- Mapping unit tests for low-signal threat and strong malicious evidence.
- End-to-end diagnostic test with seeded data.
- No-side-effect assertions for labels, model runs, and response actions.

## T15 Implementation Summary

Implemented v3.42 diagnostic target mapping and split-stability evaluation.

## T16 Tests Run / Evidence

- Targeted v3.42 tests: passed.
- Full verification to be recorded in final response for this phase.

## T17 PRD / Docs Updated

- `docs/V3_42_LABEL_POLICY_SOC_TARGET_REFRAMING.md`
- `docs/changes/T1_T20_V3_42_LABEL_POLICY_SOC_TARGET_REFRAMING.md`

## T18 Risks / Blockers / Assumptions / Decisions

The best diagnostic candidate controls false positives but recall collapses across independent splits. The blocker is still label/target stability, not only calibration.

## T19 Release / Rollback

This is diagnostic-only code. Rollback is removing the v3.42 module, script, tests, and docs. No database rollback is needed.

## T20 Final Handoff

v3.42 confirms that SOC target reframing is useful for analysis but not sufficient for promotion. The next phase should focus on safe label-policy-assisted training-data repair or hybrid detector design, without auto-reviewing labels.


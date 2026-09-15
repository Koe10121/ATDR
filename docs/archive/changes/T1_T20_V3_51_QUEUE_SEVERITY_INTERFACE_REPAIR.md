# T1-T20 Change Document: v3.51 Queue / Severity Target Interface Repair

## T1 Change Title

v3.51 Queue / Severity Target Interface Repair

## T2 Requirement

Compare diagnostic queue/severity target-interface repairs after v3.50 found that repaired queue rows can still map to downstream `non_threat`.

## T3 Source Evidence

- `atdr/app/detection/v348_repaired_queue_target_model.py`
- `atdr/app/detection/v350_queued_severity_semantics.py`
- `atdr/app/detection/v351_queue_severity_interface.py`
- `atdr/scripts/run_v351_queue_severity_interface.py`
- `atdr/tests/test_v351_queue_severity_interface.py`
- `docs/V3_50_QUEUED_SEVERITY_SEMANTICS.md`

## T4 Current Behavior

v3.50 found `449` repaired-queue rows that were admitted to the SOC queue but still mapped to downstream `non_threat`. This target-interface mismatch blocks stable downstream severity modeling.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Detection quality
- Label semantics
- QA/release validation
- Documentation

## T6 Scope

In scope:

- Compare target-interface variants.
- Keep all outputs diagnostic-only.
- Preserve labels, model registry, artifacts, and response actions.

Out of scope:

- Human-reviewed label creation.
- Auto-labeling.
- Model activation/promotion.
- Automatic response.
- Real firewall blocking.
- Database schema changes.

## T7 Functional Requirements

- Reuse the v3.48 repaired queue.
- Compare current interface against repair candidates.
- Report retained rows, dropped rows, target mismatch, split drift, ambiguity, and support.
- Select a diagnostic-only best interface.

## T8 Acceptance Criteria

- v3.51 diagnostic runs successfully.
- No labels are written.
- No model activation or active artifact write occurs.
- No response actions are created.
- Tests pass.

## T9 API Contract

No API changes.

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

- Add `atdr/app/detection/v351_queue_severity_interface.py`.
- Add `atdr/scripts/run_v351_queue_severity_interface.py`.
- Add focused tests.

## T12 Frontend Plan / Changes

No frontend changes.

## T13 Security / Response / AI Safety

ML remains decision support only. Response automation and real firewall blocking stay disabled. No model is activated or promoted.

## T14 Test Plan

- Interface repair helper tests.
- Evidence-aware promotion/demotion helper test.
- Diagnostic no-side-effect test.
- Full verification gate.

## T15 Implementation Summary

Implemented diagnostic queue/severity interface comparison with five variants.

## T16 Tests Run / Evidence

- Diagnostic run: compact execution of `run_v351_queue_severity_interface`
- Result: `ok=True`
- Rows audited: `2252`
- Best interface: `map_non_threat_to_unusual`
- Best interface retained rows: `2252`
- Best interface dropped rows: `0`
- Best interface non-threat mismatch rows: `0`
- Best interface split drift: `0.1552`
- Best interface pattern ambiguity: `0.7278`
- Assessment: `diagnostic_only`
- Checks passed: `8 / 9`
- Remaining blocker: pattern ambiguity remains high
- Safety: no labels written, no model activation, no active artifact written, no response actions created.
- Targeted v3.51 tests: `4 passed`.

## T17 PRD / Docs Updated

- `docs/V3_51_QUEUE_SEVERITY_INTERFACE_REPAIR.md`
- `docs/changes/T1_T20_V3_51_QUEUE_SEVERITY_INTERFACE_REPAIR.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

The best interface removes the queue/severity mismatch but does not solve high pattern ambiguity. The next model pass should remain diagnostic-only.

## T19 Release / Rollback

Diagnostic-only. Rollback is removing the v3.51 module, script, tests, and docs. No database rollback is required.

## T20 Final Handoff

v3.51 recommends `map_non_threat_to_unusual` as the next diagnostic severity target interface. ATDR should test downstream severity classification against this interface next, without writing labels or activating a model.

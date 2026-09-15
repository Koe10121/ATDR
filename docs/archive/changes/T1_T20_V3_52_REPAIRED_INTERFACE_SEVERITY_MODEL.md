# T1 Change Title

v3.52 Repaired Interface Severity Model Revalidation

# T2 Requirement

Revalidate downstream severity modeling using the v3.51 repaired queue/severity target interface without activating or promoting any model.

# T3 Source Evidence

- `docs/V3_51_QUEUE_SEVERITY_INTERFACE_REPAIR.md`
- `atdr/app/detection/v349_repaired_queue_severity_model.py`
- `atdr/app/detection/v351_queue_severity_interface.py`
- `atdr/app/detection/v342_label_policy_reframing.py`

# T4 Current Behavior

The baseline severity model can admit rows into the review queue while their downstream severity target remains `non_threat`. v3.51 showed that `map_non_threat_to_unusual` removes this mismatch diagnostically.

# T5 Impacted Areas / Agents

- AI/ML Governance
- Detection quality
- QA/UAT
- Release/Ops

# T6 Scope

Diagnostic-only backend ML evaluation and documentation. No frontend runtime behavior, database schema, model activation, label import, or response behavior changes.

# T7 Functional Requirements

- Compare baseline and repaired queue/severity interfaces.
- Evaluate multiple downstream severity model/decision-mode variants.
- Validate across the existing split suite.
- Record calibration, false-positive, recall, queue, and stability metrics.
- Keep all outputs generated/ignored.

# T8 Acceptance Criteria

- v3.52 command runs successfully.
- Generated report clearly marks diagnostic-only status.
- Repaired interface strategies report zero retained queued `non_threat` mismatch.
- Safety counters prove no labels, model runs, or response actions were created.
- Tests cover interface repair and no-side-effect behavior.

# T9 API Contract

No API changes.

# T10 Data Model / Migration

No schema changes.

# T11 Backend Plan / Changes

- Add `atdr/app/detection/v352_repaired_interface_severity_model.py`.
- Add `atdr/scripts/run_v352_repaired_interface_severity_model.py`.
- Add backend tests for interface behavior and safety.

# T12 Frontend Plan / Changes

No frontend changes.

# T13 Security / Response / AI Safety

- No automatic response.
- No real firewall blocking.
- No model activation.
- No label writes.
- No generated reports committed.

# T14 Test Plan

- Targeted v3.52 backend tests.
- Ruff.
- compileall.
- Alembic check.
- performance smoke.
- release gate.

# T15 Implementation Summary

Implemented a diagnostic evaluator that compares `baseline_current_interface` and `map_non_threat_to_unusual` across severity classifier variants and validation splits.

# T16 Tests Run / Evidence

- `.\.venv\Scripts\python.exe -m atdr.scripts.run_v352_repaired_interface_severity_model --test-size 0.3 --min-samples 6`
  - `ok=True`
  - best strategy `map_non_threat_to_unusual_extra_trees_severity_logistic_regression_probability_only`
  - readiness `candidate_only`
  - checks `8 / 12`
  - passing severity splits `0 / 5`
  - queued non-threat mismatch `0`
  - queue F1 minimum `0.972`
  - benign-like FPR maximum `0.1333`
  - threat-positive F1 minimum `0.2296`
  - suspicious recall minimum `0.2214`
  - malicious recall minimum `0.0`
  - calibration `passed`
  - labels/model runs/response actions unchanged
- Targeted v3.52 tests passed.

# T17 PRD / Docs Updated

- `docs/V3_52_REPAIRED_INTERFACE_SEVERITY_MODEL.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

# T18 Risks / Blockers / Assumptions / Decisions

- Pattern ambiguity may still limit severity classification.
- This phase does not solve target ambiguity by itself.
- All candidates remain diagnostic unless independent stability and calibration gates pass.

# T19 Release / Rollback

Rollback is removal of the v3.52 diagnostic module, script, tests, and docs. No DB rollback is needed.

# T20 Final Handoff

v3.52 proved the repaired interface removes the queued non-threat mismatch, but downstream severity classification remains unstable. The next phase should focus on severity target separability and evidence-feature ambiguity, not model activation.

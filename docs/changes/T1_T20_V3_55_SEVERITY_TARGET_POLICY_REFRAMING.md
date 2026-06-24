# T1 Change Title

v3.55 Severity Target Policy Reframing

# T2 Requirement

Test simpler downstream severity target policies after v3.54 proved that the current three-way severity target is semantically ambiguous.

# T3 Source Evidence

- `docs/V3_54_SEVERITY_TARGET_SEMANTICS_AUDIT.md`
- `atdr/app/detection/v354_severity_target_semantics_audit.py`
- `atdr/app/detection/v352_repaired_interface_severity_model.py`
- `atdr/app/detection/v353_severity_feature_repair.py`
- `atdr/app/detection/v348_repaired_queue_target_model.py`

# T4 Current Behavior

The queue target is stable, but exact downstream severity classification fails because the three severity classes overlap by evidence pattern and label semantics.

# T5 Impacted Areas / Agents

- AI/ML Governance
- Detection quality
- Label semantics
- QA/UAT
- Documentation

# T6 Scope

Diagnostic-only target-policy reframing. No schema changes, no frontend changes, no label writes, no model activation, no model artifact writing, and no response behavior changes.

# T7 Functional Requirements

- Evaluate current three-severity policy.
- Evaluate `review_needed` vs `malicious_high_confidence`.
- Evaluate `unusual_needs_review` vs `threat_evidence`.
- Evaluate binary review queue: `non_threat` vs `needs_review`.
- Use repaired queue target and v353 evidence features.
- Run across the standard independent split suite.
- Preserve all safety constraints.

# T8 Acceptance Criteria

- v3.55 command runs successfully.
- Reports remain diagnostic-only.
- Tests prove no labels, model runs, or response actions are created.
- Readiness remains conservative.
- Exact severity is not activated or promoted.

# T9 API Contract

No API changes.

# T10 Data Model / Migration

No schema changes.

# T11 Backend Plan / Changes

- Add `atdr/app/detection/v355_severity_target_policy_reframing.py`.
- Add `atdr/scripts/run_v355_severity_target_policy_reframing.py`.
- Add targeted backend tests.

# T12 Frontend Plan / Changes

No frontend changes.

# T13 Security / Response / AI Safety

- No automatic response.
- No real firewall blocking.
- No model activation.
- No model artifact writing.
- No label writes.
- No generated reports committed.
- ML remains decision support only.

# T14 Test Plan

- Targeted v3.55 backend tests.
- Ruff.
- compileall.
- Alembic check.
- performance smoke.
- release gate.

# T15 Implementation Summary

Implemented diagnostic policy reframing that compares the current exact severity target against simpler two-tier and binary SOC queue targets.

# T16 Tests Run / Evidence

- `.\.venv\Scripts\python.exe -m atdr.scripts.run_v355_severity_target_policy_reframing --test-size 0.3 --min-samples 6`
  - `ok=True`
  - best strategy `binary_review_queue_queue_only`
  - readiness `candidate_only`
  - checks `10 / 10`
  - passing splits `5 / 5`
  - policy positive F1 min `0.9725`
  - positive FPR max `0.04`
  - critical recall min `0.948`
  - queue F1 min `0.9725`
  - macro F1 min `0.7481`
  - calibration `passed`
  - labels/model runs/response actions unchanged
- Targeted v3.55 tests passed.

# T17 PRD / Docs Updated

- `docs/V3_55_SEVERITY_TARGET_POLICY_REFRAMING.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

# T18 Risks / Blockers / Assumptions / Decisions

- Binary SOC queue classification is stable, but exact severity classification remains unstable.
- The stable queue candidate must not be confused with production promotion or exact malicious/suspicious classification.
- Any future integration must remain diagnostic until separately reviewed and approved.

# T19 Release / Rollback

Rollback is removal of the v3.55 diagnostic module, script, tests, and docs. No database rollback is needed.

# T20 Final Handoff

v3.55 found that ATDR’s supervised ML path is currently strongest as a SOC queue model: `non_threat` vs `needs_review`. Exact severity should remain explanation/ranking support until target semantics improve.

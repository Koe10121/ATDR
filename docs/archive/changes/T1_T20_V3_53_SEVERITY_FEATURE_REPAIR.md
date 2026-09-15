# T1 Change Title

v3.53 Severity Target Separability And Evidence Feature Repair

# T2 Requirement

Diagnose whether severity-specific evidence features improve downstream severity separability after v3.52 removed the queue/severity interface mismatch.

# T3 Source Evidence

- `docs/V3_52_REPAIRED_INTERFACE_SEVERITY_MODEL.md`
- `atdr/app/detection/v337_evidence_feature_enrichment.py`
- `atdr/app/detection/v352_repaired_interface_severity_model.py`
- `atdr/app/detection/v342_label_policy_reframing.py`

# T4 Current Behavior

The repaired interface removes queued `non_threat` mismatch, but downstream severity stability remains blocked by suspicious and malicious recall collapse.

# T5 Impacted Areas / Agents

- AI/ML Governance
- Detection quality
- QA/UAT
- Release/Ops
- Documentation

# T6 Scope

Diagnostic-only feature enrichment and severity model comparison. No schema changes, no model activation, no label writes, and no frontend behavior changes.

# T7 Functional Requirements

- Add severity-specific diagnostic features.
- Compare current v337 features with v353 candidate features.
- Evaluate across the standard independent split suite.
- Report separability, calibration, false-positive, recall, and stability behavior.
- Preserve all safety constraints.

# T8 Acceptance Criteria

- v3.53 command runs successfully.
- Report remains diagnostic-only.
- Tests prove feature creation and no side effects.
- Labels, model registry runs, and response actions remain unchanged.

# T9 API Contract

No API changes.

# T10 Data Model / Migration

No schema changes.

# T11 Backend Plan / Changes

- Add `atdr/app/detection/v353_severity_feature_repair.py`.
- Add `atdr/scripts/run_v353_severity_feature_repair.py`.
- Add targeted backend tests.

# T12 Frontend Plan / Changes

No frontend changes.

# T13 Security / Response / AI Safety

- No automatic response.
- No real firewall blocking.
- No model activation.
- No label writes.
- No generated reports committed.

# T14 Test Plan

- Targeted v3.53 backend tests.
- Ruff.
- compileall.
- Alembic check.
- performance smoke.
- release gate.

# T15 Implementation Summary

Implemented v353 severity-specific diagnostic features and a comparison workflow against the current v337 evidence feature set.

# T16 Tests Run / Evidence

- `.\.venv\Scripts\python.exe -m atdr.scripts.run_v353_severity_feature_repair --test-size 0.3 --min-samples 6`
  - `ok=True`
  - best strategy `v337_current_features_map_non_threat_to_unusual_extra_trees_severity_logistic_regression_probability_only`
  - readiness `candidate_only`
  - checks `8 / 12`
  - passing severity splits `0 / 5`
  - queue F1 minimum `0.972`
  - benign-like FPR maximum `0.1333`
  - threat-positive F1 minimum `0.2296`
  - suspicious recall minimum `0.2214`
  - malicious recall minimum `0.0`
  - calibration `passed`
  - strongest v353 feature `v353_scan_pressure_score`, minimum pairwise effect size `0.5012`
  - labels/model runs/response actions unchanged
- Targeted v3.53 tests passed.

# T17 PRD / Docs Updated

- `docs/V3_53_SEVERITY_FEATURE_REPAIR.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

# T18 Risks / Blockers / Assumptions / Decisions

- Feature repair may not solve class ambiguity if the severity targets themselves are too mixed.
- All model outputs remain diagnostic and candidate-only.

# T19 Release / Rollback

Rollback is removal of the v3.53 diagnostic module, script, tests, and docs. No database rollback is needed.

# T20 Final Handoff

v3.53 found useful feature signal but did not improve the best diagnostic strategy. The next phase should audit severity target semantics directly because simple feature repair did not resolve recall collapse.

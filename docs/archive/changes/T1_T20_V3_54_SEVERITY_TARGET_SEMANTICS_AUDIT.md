# T1 Change Title

v3.54 Severity Target Semantics Audit

# T2 Requirement

Audit whether the downstream severity targets are semantically separable enough to justify continued severity model tuning after v3.52 and v3.53 failed independent severity stability.

# T3 Source Evidence

- `docs/V3_53_SEVERITY_FEATURE_REPAIR.md`
- `atdr/app/detection/v352_repaired_interface_severity_model.py`
- `atdr/app/detection/v353_severity_feature_repair.py`
- `atdr/app/detection/v341_label_semantics_audit.py`
- `atdr/app/detection/v348_repaired_queue_target_model.py`

# T4 Current Behavior

The repaired queue/severity interface removes queued `non_threat` mismatch, and v3.53 adds severity-specific features. Despite that, downstream severity models still fail split stability with low threat-positive F1 and recall collapse.

# T5 Impacted Areas / Agents

- AI/ML Governance
- Detection quality
- Label semantics
- QA/UAT
- Documentation

# T6 Scope

Diagnostic-only target semantics audit. No schema changes, no frontend changes, no label writes, no model activation, no model artifact writing, and no response behavior changes.

# T7 Functional Requirements

- Analyze target support for `unusual_needs_review`, `evidence_backed_suspicious`, and `malicious_high_confidence`.
- Analyze categorical ambiguity by evidence/pattern/source fields.
- Analyze numeric separability for v337/v353 evidence features.
- Analyze split target-rate drift.
- Analyze semantic contradictions.
- Test simple policy reframing variants without training or activation.
- Preserve all safety constraints.

# T8 Acceptance Criteria

- v3.54 command runs successfully.
- Report remains diagnostic-only.
- Tests prove no labels, model runs, or response actions are created.
- Readiness remains conservative.
- Residual sample is not import-ready.

# T9 API Contract

No API changes.

# T10 Data Model / Migration

No schema changes.

# T11 Backend Plan / Changes

- Add `atdr/app/detection/v354_severity_target_semantics_audit.py`.
- Add `atdr/scripts/run_v354_severity_target_semantics_audit.py`.
- Add targeted backend tests.

# T12 Frontend Plan / Changes

No frontend changes.

# T13 Security / Response / AI Safety

- No automatic response.
- No real firewall blocking.
- No model activation.
- No label writes.
- No generated reports committed.
- ML remains decision support only.

# T14 Test Plan

- Targeted v3.54 backend tests.
- Ruff.
- compileall.
- Alembic check.
- performance smoke.
- release gate.

# T15 Implementation Summary

Implemented a diagnostic severity semantics audit that measures target support, ambiguity, numeric separability, split drift, semantic contradictions, and simple target policy variants.

# T16 Tests Run / Evidence

- `.\.venv\Scripts\python.exe -m atdr.scripts.run_v354_severity_target_semantics_audit --test-size 0.3 --min-samples 6`
  - `ok=True`
  - rows analyzed `2252`
  - target distribution `unusual_needs_review=1365`, `evidence_backed_suspicious=498`, `malicious_high_confidence=389`
  - readiness `diagnostic_only`
  - checks `6 / 9`
  - blockers `categorical ambiguity acceptable`, `numeric separability acceptable`, `semantic contradictions low`
  - max split target-rate shift `0.1552`
  - strongest numeric minimum pairwise effect size `0.5345`
  - top categorical conflict ratio `0.625`
  - high-severity semantic issue rows `1300`
  - unusual strong-evidence rows `1353`
  - residual sample generated, not import-ready
  - labels/model runs/response actions unchanged
- Targeted v3.54 tests passed.

# T17 PRD / Docs Updated

- `docs/V3_54_SEVERITY_TARGET_SEMANTICS_AUDIT.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

# T18 Risks / Blockers / Assumptions / Decisions

- Current three-way downstream severity target is semantically ambiguous.
- Continuing to add guards/features is unlikely to fully solve severity instability.
- Next phase should test target-policy reframing while staying diagnostic-only.

# T19 Release / Rollback

Rollback is removal of the v3.54 diagnostic module, script, tests, and docs. No database rollback is needed.

# T20 Final Handoff

v3.54 found that target semantics, not just model selection or feature engineering, are blocking stable severity classification. v3.55 should test cleaner two-class downstream severity policies without activation or response automation.

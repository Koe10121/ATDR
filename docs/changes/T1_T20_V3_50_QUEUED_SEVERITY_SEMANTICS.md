# T1-T20 Change Document: v3.50 Queued Severity Target Semantics And Feature Support Audit

## T1 Change Title

v3.50 Queued Severity Target Semantics And Feature Support Audit

## T2 Requirement

Audit why repaired-queue downstream severity classification remains unstable, without writing labels, activating models, writing active artifacts, or enabling response automation.

## T3 Source Evidence

- `atdr/app/detection/v342_label_policy_reframing.py`
- `atdr/app/detection/v348_repaired_queue_target_model.py`
- `atdr/app/detection/v349_repaired_queue_severity_model.py`
- `atdr/app/detection/v350_queued_severity_semantics.py`
- `atdr/scripts/run_v350_queued_severity_semantics.py`
- `atdr/tests/test_v350_queued_severity_semantics.py`
- `docs/V3_49_REPAIRED_QUEUE_SEVERITY_MODEL.md`

## T4 Current Behavior

v3.49 confirmed stable queue admission but unstable downstream severity classification. The exact reason was not clear enough for another model pass.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Detection quality
- Label semantics
- QA/release validation
- Documentation

## T6 Scope

In scope:

- Diagnostic queued-row severity target audit.
- Pattern, traffic-family, evidence-bucket, source, support, and split-drift analysis.
- Numeric feature separability analysis.
- No-side-effect tests.

Out of scope:

- Human-reviewed label creation.
- Auto-labeling.
- Model activation/promotion.
- Automatic response.
- Real firewall blocking.
- Database schema changes.

## T7 Functional Requirements

- Reuse the v3.48 repaired queue target.
- Audit only rows admitted to the repaired queue.
- Report downstream severity target support and ambiguity.
- Identify whether queued rows still map to `non_threat`.
- Keep readiness diagnostic-only and conservative.

## T8 Acceptance Criteria

- v3.50 diagnostic runs successfully.
- No labels are written.
- No model activation or active artifact write occurs.
- No response actions are created.
- Tests pass.

## T9 API Contract

No API changes.

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

- Add `atdr/app/detection/v350_queued_severity_semantics.py`.
- Add `atdr/scripts/run_v350_queued_severity_semantics.py`.
- Add focused tests.

## T12 Frontend Plan / Changes

No frontend changes.

## T13 Security / Response / AI Safety

ML remains decision support only. Response automation and real firewall blocking stay disabled. No model is activated or promoted.

## T14 Test Plan

- Categorical ambiguity helper test.
- Numeric separability helper test.
- Diagnostic no-side-effect test.
- Full verification gate.

## T15 Implementation Summary

Implemented a diagnostic audit for queued severity target semantics and feature support.

## T16 Tests Run / Evidence

- Diagnostic run: compact execution of `run_v350_queued_severity_semantics`
- Result: `ok=True`
- Queued rows audited: `2252`
- Severity distribution: `unusual_needs_review=916`, `evidence_backed_suspicious=498`, `malicious_high_confidence=389`, `non_threat=449`
- Queued non-threat target mismatch: `449` rows, `0.1994` share
- Assessment: `diagnostic_only`
- Checks passed: `7 / 12`
- Main blockers: queued non-threat target mismatch, pattern ambiguity, traffic-family ambiguity, evidence-bucket ambiguity, split drift
- Safety: no labels written, no model activation, no active artifact written, no response actions created.
- Targeted v3.50 tests: `3 passed`.

## T17 PRD / Docs Updated

- `docs/V3_50_QUEUED_SEVERITY_SEMANTICS.md`
- `docs/changes/T1_T20_V3_50_QUEUED_SEVERITY_SEMANTICS.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

The audit found that the repaired queue admits rows that still map to `non_threat` downstream. This target-interface mismatch should be repaired before another severity classifier pass.

## T19 Release / Rollback

Diagnostic-only. Rollback is removing the v3.50 module, script, tests, and docs. No database rollback is required.

## T20 Final Handoff

v3.50 identifies the current severity blocker as a queue/severity target-interface problem, not a simple model tuning problem. ATDR should keep ML as decision support only and proceed to v3.51 queue/severity target interface repair before activation discussion.

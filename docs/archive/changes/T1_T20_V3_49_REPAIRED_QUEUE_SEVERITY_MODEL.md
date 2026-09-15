# T1-T20 Change Document: v3.49 Repaired Queue Severity Classification

## T1 Change Title

v3.49 Repaired Queue Severity Classification

## T2 Requirement

Evaluate downstream severity classification for rows admitted by the repaired v3.48 queue without writing labels, activating models, writing active artifacts, or enabling response automation.

## T3 Source Evidence

- `atdr/app/detection/v348_repaired_queue_target_model.py`
- `atdr/app/detection/v349_repaired_queue_severity_model.py`
- `atdr/scripts/run_v349_repaired_queue_severity_model.py`
- `atdr/tests/test_v349_repaired_queue_severity_model.py`
- `docs/V3_48_REPAIRED_QUEUE_TARGET_MODEL.md`

## T4 Current Behavior

v3.48 proved repaired queue admission can be stable. It did not validate whether queued rows can be classified into unusual, suspicious, and malicious severity levels.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Detection quality
- Label semantics
- QA/release validation
- Documentation

## T6 Scope

In scope:

- Repaired queue plus severity classifier diagnostics.
- ExtraTrees and Logistic Regression severity models.
- Probability-only and evidence-guarded severity decisions.
- Multi-split stability comparison.
- No-side-effect tests.

Out of scope:

- Human-reviewed label creation.
- Auto-labeling.
- Model activation/promotion.
- Automatic response.
- Real firewall blocking.
- Database schema changes.

## T7 Functional Requirements

- Preserve repaired queue admission as the first stage.
- Select thresholds using train-internal calibration only.
- Report threat-positive F1, benign-like false-positive rate, suspicious recall, malicious recall, queue metrics, calibration, and severity confusions.
- Keep readiness conservative and diagnostic-only.

## T8 Acceptance Criteria

- v3.49 diagnostic runs successfully.
- No labels are written.
- No model activation or active artifact write occurs.
- No response actions are created.
- Tests pass.

## T9 API Contract

No API changes.

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

- Add `atdr/app/detection/v349_repaired_queue_severity_model.py`.
- Add `atdr/scripts/run_v349_repaired_queue_severity_model.py`.
- Add focused tests.

## T12 Frontend Plan / Changes

No frontend changes.

## T13 Security / Response / AI Safety

ML remains decision support only. Response automation and real firewall blocking stay disabled. No model is activated or promoted.

## T14 Test Plan

- Severity decision tests.
- Final prediction queue-preservation test.
- Diagnostic no-side-effect test.
- Full verification gate.

## T15 Implementation Summary

Implemented diagnostic repaired-queue severity classification workflow. The run compared ExtraTrees and Logistic Regression severity models with probability-only and evidence-guarded decision modes after repaired queue admission.

## T16 Tests Run / Evidence

- Diagnostic run: `.\.venv\Scripts\python.exe -m atdr.scripts.run_v349_repaired_queue_severity_model --test-size 0.3 --min-samples 6`
- Result: `ok=True`
- Best diagnostic strategy: `repaired_queue_extra_trees_severity_logistic_regression_evidence_guarded`
- Readiness: `candidate_only`
- Checks passed: `7 / 11`
- Passing severity splits: `0 / 5`
- Queue F1 range: `0.9720-0.9969`
- Queue false-positive rate range: `0.0000-0.0467`
- Threat-positive F1 range: `0.6545-0.9341`
- Suspicious recall range: `0.2286-0.7200`
- Malicious recall range: `0.4358-0.8403`
- Calibration: passed
- Safety: no labels written, no model activation, no active artifact written, no response actions created.
- Targeted v3.49 tests: `4 passed`.

## T17 PRD / Docs Updated

- `docs/V3_49_REPAIRED_QUEUE_SEVERITY_MODEL.md`
- `docs/changes/T1_T20_V3_49_REPAIRED_QUEUE_SEVERITY_MODEL.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

The severity classifier is diagnostic only. Queue admission remains strong, but severity separation is not stable enough for activation. The next phase should focus on severity label support, class definitions, evidence features, and benchmark coverage rather than activation.

## T19 Release / Rollback

Diagnostic-only. Rollback is removing the v3.49 module, script, tests, and docs. No database rollback is required.

## T20 Final Handoff

v3.49 confirms that repaired queue admission is stable, but downstream severity classification still fails independent split stability. ATDR should keep ML as decision support only and proceed to a severity-label/feature support audit before any model activation or production-promotion discussion.

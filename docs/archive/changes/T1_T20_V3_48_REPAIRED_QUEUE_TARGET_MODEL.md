# T1-T20 Change Document: v3.48 Repaired Queue Target Model Evaluation

## T1 Change Title

v3.48 Repaired Queue Target Model Evaluation

## T2 Requirement

Evaluate whether the v3.47 repaired queue target trains a more stable diagnostic SOC queue model without writing labels, activating models, writing active artifacts, or enabling response automation.

## T3 Source Evidence

- `atdr/app/detection/v347_queue_target_repair_proposal.py`
- `atdr/app/detection/v348_repaired_queue_target_model.py`
- `atdr/scripts/run_v348_repaired_queue_target_model.py`
- `atdr/tests/test_v348_repaired_queue_target_model.py`
- `docs/V3_47_QUEUE_TARGET_REPAIR_PROPOSAL.md`

## T4 Current Behavior

v3.47 proposes repaired queue targets and improves ambiguity/drift as a diagnostic target analysis. It does not prove that a supervised queue model trained on the repaired target is stable.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Detection quality
- Label semantics
- QA/release validation
- Documentation

## T6 Scope

In scope:

- Original versus repaired queue-target model comparison.
- ExtraTrees and Logistic Regression diagnostic queue classifiers.
- Multi-split stability comparison.
- Calibration and threshold-selection diagnostics.
- No-side-effect tests.

Out of scope:

- Human-reviewed label creation.
- Auto-labeling.
- Model activation/promotion.
- Automatic response.
- Real firewall blocking.
- Database schema changes.

## T7 Functional Requirements

- Use train-internal threshold selection only.
- Compare original and repaired queue targets across standard splits.
- Report queue precision, recall, F1, false-positive rate, calibration, and false-positive patterns.
- Keep readiness conservative and diagnostic-only.

## T8 Acceptance Criteria

- v3.48 diagnostic runs successfully.
- No labels are written.
- No model activation or active artifact write occurs.
- No response actions are created.
- Tests pass.

## T9 API Contract

No API changes.

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

- Add `atdr/app/detection/v348_repaired_queue_target_model.py`.
- Add `atdr/scripts/run_v348_repaired_queue_target_model.py`.
- Add focused tests.

## T12 Frontend Plan / Changes

No frontend changes.

## T13 Security / Response / AI Safety

ML remains decision support only. Response automation and real firewall blocking stay disabled. No model is activated or promoted.

## T14 Test Plan

- Queue threshold prediction test.
- Train-internal threshold selection test.
- Repaired target behavior test.
- Diagnostic no-side-effect test.
- Full verification gate.

## T15 Implementation Summary

Implemented diagnostic repaired queue-target model evaluation workflow. The current DB run compared original and repaired queue targets across five splits with ExtraTrees and Logistic Regression.

## T16 Tests Run / Evidence

- `.\.venv\Scripts\python.exe -m atdr.scripts.run_v348_repaired_queue_target_model --test-size 0.3 --min-samples 6`
  - `ok=True`
  - best strategy `repaired_queue_target_extra_trees`
  - readiness `candidate_only`
  - checks passed `9/9`
  - passing splits `5/5`
  - queue precision range `0.9886-1.0000`
  - queue recall range `0.9559-0.9937`
  - queue F1 range `0.9720-0.9969`
  - queue false-positive rate range `0.0000-0.0467`
  - calibration passed
  - threshold selection train-internal only
  - labels/model runs/response actions unchanged
- `.\.venv\Scripts\ruff.exe check atdr\app\detection\v348_repaired_queue_target_model.py atdr\scripts\run_v348_repaired_queue_target_model.py atdr\tests\test_v348_repaired_queue_target_model.py`
  - passed
- `.\.venv\Scripts\python.exe -m compileall -q atdr\app\detection\v348_repaired_queue_target_model.py atdr\scripts\run_v348_repaired_queue_target_model.py atdr\tests\test_v348_repaired_queue_target_model.py`
  - passed
- `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_v348_repaired_queue_target_model.py -q --basetemp .pytest_tmp\v348-targeted -p no:cacheprovider`
  - `4 passed`

## T17 PRD / Docs Updated

- `docs/V3_48_REPAIRED_QUEUE_TARGET_MODEL.md`
- `docs/changes/T1_T20_V3_48_REPAIRED_QUEUE_TARGET_MODEL.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

The repaired target is diagnostic only. Queue stability improved strongly, but this does not validate downstream suspicious/malicious severity classification. The next phase should test severity separation for rows admitted by the repaired queue before any activation discussion.

## T19 Release / Rollback

Diagnostic-only. Rollback is removing the v3.48 module, script, tests, and docs. No database rollback is required.

## T20 Final Handoff

v3.48 shows the repaired target can train a stable diagnostic queue model while preserving label integrity and response safety. No labels, model registry entries, response actions, active artifacts, or automation settings changed.

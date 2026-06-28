# T1-T20 Change Document: v3.72 Unified Detection/ML Evaluation

## T1 Change Title

v3.72 Unified Detection/ML Evaluation

## T2 Requirement

Add one safe command that summarizes ATDR rule-pack status, scenario-corpus status, supervised policy status, safe training-target status, lightweight label status, and response-safety invariants without changing runtime behavior.

## T3 Source Evidence

- `atdr/app/detection/rules.py`
- `atdr/scripts/validate_rule_pack_contract.py`
- `atdr/scripts/validate_detection_quality.py`
- `atdr/app/detection/v359_supervised_output_policy_contract.py`
- `atdr/app/detection/v362_supervised_training_target_contract.py`
- `docs/detection/ATDR_RULE_PACK_CONTRACT.md`
- `docs/detection/ATDR_SCENARIO_CORPUS_CONTRACT.md`
- `docs/DETECTION_ML_PRODUCTIZATION_PLAN.md`
- Supervisor template workflow/taskboard evidence under `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response`

## T4 Current Behavior

ATDR already has separate validators and diagnostic scripts. Operators must know which script to run for rule contracts, scenario validation, supervised policy artifacts, safe training target artifacts, and safety checks.

## T5 Impacted Areas / Agents

- Detection
- AI/ML Governance
- QA
- Release/Ops
- Docs

## T6 Scope

In scope:

- Read-only unified evaluator.
- CLI command and product alias.
- Targeted tests.
- Docs, traceability, and taskboard updates.

Out of scope:

- Parser behavior changes.
- Detection threshold changes.
- ML training or model activation.
- Model artifact writing.
- Label writing.
- Response automation.
- Real firewall blocking.
- Schema changes.
- Frontend behavior changes.

## T7 Functional Requirements

- Validate rule/scenario contract status.
- Optionally run controlled scenario validation in a temporary DB.
- Summarize latest v3.59 supervised output policy artifact when present.
- Summarize latest v3.62 safe training-target artifact when present.
- Report lightweight label/model/response counts without feature generation.
- Confirm no DB mutation, no model activation, no response action creation, and no automatic response.

## T8 Acceptance Criteria

- `python -m atdr.scripts.evaluate_detection_ml_productization --pretty` exits successfully.
- Optional `--include-scenarios` mode passes for a controlled scenario subset.
- Targeted tests pass.
- No protected local artifacts are printed or committed.

## T9 API Contract

No API change.

## T10 Data Model / Migration

No schema or migration change.

## T11 Backend Plan / Changes

- Add `atdr/app/detection/v372_unified_detection_ml_evaluation.py`.
- Add `atdr/scripts/run_v372_unified_detection_ml_evaluation.py`.
- Add `atdr/scripts/evaluate_detection_ml_productization.py`.
- Add `atdr/tests/test_v372_unified_detection_ml_evaluation.py`.

## T12 Frontend Plan / Changes

No frontend change.

## T13 Security / Response / AI Safety

- Command is read-only.
- Raw logs are not included.
- Response automation remains disabled.
- Real firewall blocking remains disabled.
- Model activation and production promotion remain false.
- Missing ignored ML artifacts are advisory, not a reason to mutate state.

## T14 Test Plan

- Focused Ruff.
- Targeted pytest.
- Quick command execution.
- Optional scenario command execution.
- Taskboard render/check.
- Hygiene checks.

## T15 Implementation Summary

Added a unified evaluator that combines rule/scenario contract validation, optional temp-DB scenario validation, latest ignored supervised policy summaries, latest ignored safe training-target summaries, lightweight label counts, and safety invariants. The default path avoids feature generation for fast local/CI use.

## T16 Tests Run / Evidence

- `.\.venv\Scripts\ruff.exe check atdr\app\detection\v372_unified_detection_ml_evaluation.py atdr\scripts\run_v372_unified_detection_ml_evaluation.py atdr\tests\test_v372_unified_detection_ml_evaluation.py`
- `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_v372_unified_detection_ml_evaluation.py -q --basetemp .pytest_tmp\v372-unified-eval -p no:cacheprovider`
- `.\.venv\Scripts\python.exe -m atdr.scripts.run_v372_unified_detection_ml_evaluation --pretty`
- `.\.venv\Scripts\python.exe -m atdr.scripts.run_v372_unified_detection_ml_evaluation --include-scenarios --scenario normal_allowed_traffic --scenario port_scan_like_traffic --pretty`

## T17 PRD / Docs Updated

- `docs/V3_72_UNIFIED_DETECTION_ML_EVALUATION.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- This is a diagnostic/productization command only.
- It does not regenerate v3.59 or v3.62 artifacts.
- It intentionally does not generate features by default.
- Production readiness remains unclaimed.

## T19 Release / Rollback

Rollback is limited to removing the v3.72 evaluator, CLI wrappers, tests, and docs references. Runtime detection behavior is unchanged.

## T20 Final Handoff

Recommended next phase: v3.73 Detection/ML Governance Dashboard Integration or v3.73 Real MFU IAM Live Validation, depending on whether the next priority is dashboard operator visibility or school-email login.

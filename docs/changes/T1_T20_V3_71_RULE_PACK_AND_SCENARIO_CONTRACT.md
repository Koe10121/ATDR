# T1-T20 Change Document: v3.71 Rule Pack And Scenario Contract

## T1 Change Title

v3.71 Rule Pack And Scenario Contract

## T2 Requirement

Make ATDR deterministic detection rules and controlled scenario corpus product-grade by documenting them as source-backed contracts and adding a validator.

## T3 Source Evidence

- `atdr/app/detection/rules.py`
- `atdr/app/detection/attack_mapping.py`
- `atdr/app/services/detection_service.py`
- `atdr/scripts/run_source_scenario.py`
- `data/samples/scenarios/scenario_expectations.json`
- `docs/DETECTION_RULE_CATALOG.md`
- `docs/DETECTION_ML_PRODUCTIZATION_PLAN.md`
- Supervisor template workflow/taskboard evidence under `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response`

## T4 Current Behavior

ATDR already has deterministic rule detection and a safe scenario corpus, but the source-to-doc contract was not machine-validated.

## T5 Impacted Areas / Agents

- Detection
- QA
- Docs
- Release/Ops
- AI/ML Governance

## T6 Scope

In scope:

- Rule-pack contract documentation.
- Scenario-corpus contract documentation.
- Validator script.
- Targeted backend tests.

Out of scope:

- Detection threshold changes.
- ML model changes or activation.
- Response automation.
- Database schema changes.
- Frontend behavior changes.

## T7 Functional Requirements

- All implemented rule IDs must be documented.
- All registered scenarios must have expectations.
- All registered scenarios must be documented.
- Scenario files must exist.
- Scenarios must preserve raw evidence and require zero response actions.
- Attack types must use the controlled taxonomy.

## T8 Acceptance Criteria

- `python -m atdr.scripts.validate_rule_pack_contract --pretty` returns `ok: true`.
- Targeted tests pass.
- No database mutation or response action capability is introduced.

## T9 API Contract

No API change.

## T10 Data Model / Migration

No schema or migration change.

## T11 Backend Plan / Changes

- Add `atdr/scripts/validate_rule_pack_contract.py`.
- Add tests in `atdr/tests/test_rule_pack_contract.py`.

## T12 Frontend Plan / Changes

No frontend change.

## T13 Security / Response / AI Safety

- Rules remain SOC triage evidence.
- Response automation remains disabled.
- Real firewall blocking remains disabled.
- ML remains decision support only.
- Validator is read-only and does not touch the database.

## T14 Test Plan

- Run validator.
- Run Ruff on changed Python files.
- Run targeted pytest.
- Regenerate task board.
- Run hygiene checks.

## T15 Implementation Summary

Added rule-pack and scenario-corpus contracts plus a validator that checks implemented rule IDs, registered scenarios, expectations, sample files, parser profiles, attack-type taxonomy, and safety invariants.

## T16 Tests Run / Evidence

- `.\.venv\Scripts\python.exe -m atdr.scripts.validate_rule_pack_contract --pretty`
- `.\.venv\Scripts\ruff.exe check atdr\scripts\validate_rule_pack_contract.py atdr\tests\test_rule_pack_contract.py`
- `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_rule_pack_contract.py -q --basetemp .pytest_tmp\v371-rule-contract -p no:cacheprovider`

## T17 PRD / Docs Updated

- `docs/detection/ATDR_RULE_PACK_CONTRACT.md`
- `docs/detection/ATDR_SCENARIO_CORPUS_CONTRACT.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/tasks/tasklist-progress.md`

## T18 Risks / Blockers / Assumptions / Decisions

- This phase validates contracts, not runtime detection accuracy.
- Future rule changes must update the contract and validator.
- Real-source validation remains separate.

## T19 Release / Rollback

Rollback is limited to removing the contracts, validator, tests, and docs references. Runtime behavior is unchanged.

## T20 Final Handoff

Recommended next phase: v3.72 Unified Detection/ML Evaluation Command.

# T1-T20 Change Document: v3.47 Queue Target Repair Proposal

## T1 Change Title

v3.47 Queue Target Repair Proposal

## T2 Requirement

Propose conservative, diagnostic-only queue target repairs based on v3.46 ambiguity and drift findings without writing labels or activating models.

## T3 Source Evidence

- `ml_baseline_reviews/v3_46_queue_target_separability_latest.json`
- `atdr/app/detection/v346_queue_target_separability.py`
- `atdr/app/detection/v347_queue_target_repair_proposal.py`
- `atdr/scripts/run_v347_queue_target_repair_proposal.py`
- `atdr/tests/test_v347_queue_target_repair_proposal.py`

## T4 Current Behavior

v3.46 found strong numeric separators but high ambiguous pattern/family share and time-split queue drift. More model tuning without target repair is unlikely to stabilize the supervised queue.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Detection quality
- Label semantics
- Feature engineering
- QA/release validation
- Documentation

## T6 Scope

In scope:

- Diagnostic queue target repair rules.
- Before/after ambiguity comparison.
- Proposal CSV marked not import-ready.
- Safety/no-side-effect tests.

Out of scope:

- Human-reviewed label creation.
- Auto-labeling.
- Model activation/promotion.
- Automatic response.
- Real firewall blocking.
- Database schema changes.

## T7 Functional Requirements

- Preserve strong evidence rows in the review queue.
- Propose demoting low-signal web/utility review rows.
- Propose promoting strong-evidence non-threat rows.
- Mark proposal outputs as not import-ready and human-confirm-required.
- Reports must remain diagnostic-only.

## T8 Acceptance Criteria

- v3.47 diagnostic runs successfully.
- No labels are written.
- No model activation or active artifact write occurs.
- No response actions are created.
- Tests pass.

## T9 API Contract

No API changes.

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

- Add `atdr/app/detection/v347_queue_target_repair_proposal.py`.
- Add `atdr/scripts/run_v347_queue_target_repair_proposal.py`.
- Add focused tests.

## T12 Frontend Plan / Changes

No frontend changes.

## T13 Security / Response / AI Safety

ML remains decision support only. Response automation and real firewall blocking stay disabled. No model is activated or promoted. Proposal CSVs are not import-ready.

## T14 Test Plan

- Low-signal demotion proposal test.
- Strong evidence preservation test.
- Strong evidence promotion proposal test.
- Diagnostic run no-side-effect test.
- Full verification gate.

## T15 Implementation Summary

Implemented diagnostic queue target repair proposal workflow. The current DB run audited 2672 rows and proposed changing 505 queue targets: 449 strong-evidence `non_threat` rows promoted to `needs_review`, 53 low-signal web/utility rows demoted to `non_threat`, and 3 low-context allowed-service rows demoted to `non_threat`.

## T16 Tests Run / Evidence

- `.\.venv\Scripts\python.exe -m atdr.scripts.run_v347_queue_target_repair_proposal --test-size 0.3 --min-samples 6`
  - `ok=True`
  - rows audited `2672`
  - current distribution `needs_review=1859`, `non_threat=813`
  - proposed distribution `needs_review=2252`, `non_threat=420`
  - changed rows `505`
  - pattern ambiguity `0.4308 -> 0.3990`
  - traffic-family ambiguity `0.8046 -> 0.7186`
  - max split drift `0.2636 -> 0.2193`
  - assessment `diagnostic_only`, 7 / 7 checks passed
- `.\.venv\Scripts\ruff.exe check atdr\app\detection\v347_queue_target_repair_proposal.py atdr\scripts\run_v347_queue_target_repair_proposal.py atdr\tests\test_v347_queue_target_repair_proposal.py`
  - passed
- `.\.venv\Scripts\python.exe -m compileall -q atdr\app\detection\v347_queue_target_repair_proposal.py atdr\scripts\run_v347_queue_target_repair_proposal.py atdr\tests\test_v347_queue_target_repair_proposal.py`
  - passed
- `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_v347_queue_target_repair_proposal.py -q --basetemp .pytest_tmp\v347-targeted -p no:cacheprovider`
  - `4 passed`

## T17 PRD / Docs Updated

- `docs/V3_47_QUEUE_TARGET_REPAIR_PROPOSAL.md`
- `docs/changes/T1_T20_V3_47_QUEUE_TARGET_REPAIR_PROPOSAL.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

The proposal is not a label import file. Ambiguity and split drift improved, but the proposal increases `needs_review` volume. The next phase should evaluate a diagnostic model trained against the repaired target and compare it to v3.45/v3.46 before considering any further target policy changes.

## T19 Release / Rollback

Diagnostic-only. Rollback is removing the v3.47 module, script, tests, and docs. No database rollback is required.

## T20 Final Handoff

v3.47 proposes candidate queue target repairs while preserving label integrity and response safety. No labels, model registry entries, response actions, active artifacts, or automation settings changed.

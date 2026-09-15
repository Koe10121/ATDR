# T1-T20 Change Document: v3.62 Supervised Training Target Contract

## T1 Change Title

v3.62 Supervised Training Target Contract

## T2 Requirement

Create a reusable, diagnostic-only training-target adapter that turns unstable exact labels into a safe binary SOC review-queue target without writing labels, training active models, activating artifacts, or enabling response automation.

## T3 Source Evidence

- `atdr/app/detection/v342_label_policy_reframing.py`
- `atdr/app/detection/v347_queue_target_repair_proposal.py`
- `atdr/app/detection/v348_repaired_queue_target_model.py`
- `atdr/app/detection/v359_supervised_output_policy_contract.py`
- `docs/V3_59_SUPERVISED_OUTPUT_POLICY_CONTRACT.md`
- `ml_baseline_reviews/v3_59_supervised_output_policy_contract_latest.json`

## T4 Current Behavior

Before v3.62, ATDR had a policy saying binary SOC review queue is the safe supervised output, but the target adapter and current dataset semantic summary were not packaged as a focused reusable diagnostic contract.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Detection strategy
- QA
- Documentation/governance

## T6 Scope

In scope:

- Build a diagnostic-only safe queue target adapter.
- Summarize exact-label to safe-target mapping.
- Report semantic conflicts and split target drift.
- Add no-side-effect tests.

Out of scope:

- Label review or label import.
- Model retraining, activation, or promotion.
- Dashboard/API behavior changes.
- Automatic response or real firewall blocking.

## T7 Functional Requirements

- Map current exact labels to `non_threat` or `needs_review`.
- Keep exact labels as explanation/ranking only.
- Block flat exact-label production training targets.
- Produce ignored markdown/JSON reports under `ml_baseline_reviews/`.
- Preserve label, model-run, and response-action counts.

## T8 Acceptance Criteria

- Adapter maps all rows to safe queue targets.
- Contract explicitly blocks exact class production targets.
- Runner writes reports only.
- No labels, model runs, response actions, or active artifacts are written.
- Tests cover target mapping, blocked targets, and runner side effects.

## T9 API Contract

No new API endpoint in v3.62.

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

- Added `atdr/app/detection/v362_supervised_training_target_contract.py`.
- Added `atdr/scripts/run_v362_supervised_training_target_contract.py`.
- Added `atdr/tests/test_v362_supervised_training_target_contract.py`.

## T12 Frontend Plan / Changes

No frontend changes in v3.62.

## T13 Security / Response / AI Safety

- Production promoted: false.
- Model activated: false.
- Model artifact written: false.
- Labels written: false.
- Raw logs included: false.
- Response automation allowed: false.
- Real firewall blocking enabled: false.
- AI-generated labels remain non-human-reviewed.

## T14 Test Plan

- Adapter mapping test.
- Contract blocked-target test.
- Runner no-side-effect test.
- Ruff.
- Compileall.
- Targeted backend tests.
- Alembic check.
- Performance smoke.
- Release gate.

## T15 Implementation Summary

v3.62 adds a canonical safe training target adapter for supervised diagnostics. It reinforces the current supervised strategy: use binary SOC review queue decision support and keep exact suspicious/malicious labels as supporting explanation only.

## T16 Tests Run / Evidence

Verification evidence is recorded in `docs/tasks/tasklist-progress.md`.

## T17 PRD / Docs Updated

- `docs/V3_62_SUPERVISED_TRAINING_TARGET_CONTRACT.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/tasks/tasklist-progress.md`

## T18 Risks / Blockers / Assumptions / Decisions

- The adapter shows many label/evidence semantic conflicts, so exact label training remains blocked.
- Time split target distribution shift remains a quality warning.
- This phase is diagnostic-only and does not improve active model metrics by itself.

## T19 Release / Rollback

Rollback is low risk: remove the v3.62 diagnostic module, script, tests, and docs. No schema or database changes are involved.

## T20 Final Handoff

v3.62 gives future supervised ML work a safer target contract: binary queue admission may be used for diagnostic training, while exact classes remain explanation/ranking only and response automation stays disabled.

# T1-T20 Change Document: v3.59 Supervised Output Policy Contract

## T1 Change Title

v3.59 Supervised Output Policy Contract

## T2 Requirement

Turn the supervised ML label-semantics findings into a safe, machine-readable contract that identifies which supervised outputs are allowed for SOC decision support and which uses remain blocked.

## T3 Source Evidence

- `atdr/app/detection/v355_severity_target_policy_reframing.py`
- `atdr/app/detection/v357_queue_rule_hybrid_agreement.py`
- `atdr/app/detection/v359_supervised_output_policy_contract.py`
- `atdr/scripts/run_v359_supervised_output_policy_contract.py`
- `atdr/tests/test_v359_supervised_output_policy_contract.py`
- `ml_baseline_reviews/v3_55_severity_target_policy_reframing_latest.json`
- `ml_baseline_reviews/v3_57_queue_rule_hybrid_agreement_latest.json`

## T4 Current Behavior

Before v3.59, the project had diagnostics showing that the binary SOC review queue was stable and exact severity labels were unstable, but there was no single contract defining safe downstream use.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Detection strategy
- SOC Assistant
- Dashboard wording
- QA
- Documentation/governance

## T6 Scope

In scope:

- Create a diagnostic-only supervised output policy contract.
- Read existing v3.55 and v3.57 ignored reports.
- Define allowed outputs and blocked uses.
- Write an ignored markdown and JSON report.
- Add tests proving no side effects.

Out of scope:

- Model retraining.
- Model activation or promotion.
- Label mutation.
- Dashboard behavior changes.
- Automatic response.
- Real firewall blocking.

## T7 Functional Requirements

- Recommend `binary_soc_review_queue` as the safe supervised strategy when v3.55/v3.57 evidence supports it.
- Mark exact class/severity output as explanation/ranking only.
- Block automatic response, model promotion, label auto-review, and raw-log sharing.
- Preserve existing database state.

## T8 Acceptance Criteria

- Contract builds from v3.55/v3.57 reports.
- Missing upstream reports keep the contract diagnostic-only.
- Runner writes ignored reports only.
- Label, model-run, and response-action counts are unchanged.

## T9 API Contract

No new API endpoint in v3.59.

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

- Added `atdr/app/detection/v359_supervised_output_policy_contract.py`.
- Added `atdr/scripts/run_v359_supervised_output_policy_contract.py`.

## T12 Frontend Plan / Changes

No frontend changes in v3.59.

## T13 Security / Response / AI Safety

- Production promoted: false.
- Model activated: false.
- Model artifact written: false.
- Labels written: false.
- Raw logs included: false.
- Response automation allowed: false.
- Real firewall blocking enabled: false.

## T14 Test Plan

- Contract derivation test.
- Missing-report fallback test.
- Runner no-side-effect test.

## T15 Implementation Summary

Implemented a safe supervised output policy contract that makes queue admission the recommended supervised decision-support target while keeping exact severity/class labels as supporting explanation only.

## T16 Tests Run / Evidence

Verification evidence is recorded in `docs/tasks/tasklist-progress.md`.

## T17 PRD / Docs Updated

- `docs/V3_59_SUPERVISED_OUTPUT_POLICY_CONTRACT.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/tasks/tasklist-progress.md`

## T18 Risks / Blockers / Assumptions / Decisions

- The contract is not runtime activation.
- Evidence-only disagreements still require analyst review.
- Exact severity policies remain unstable.

## T19 Release / Rollback

Rollback is low risk: remove the v3.59 diagnostic module, script, tests, and docs. No schema or database changes are involved.

## T20 Final Handoff

v3.59 provides a clear supervised ML usage contract: queue score is decision support; exact labels are explanation/ranking; automation and promotion remain blocked.

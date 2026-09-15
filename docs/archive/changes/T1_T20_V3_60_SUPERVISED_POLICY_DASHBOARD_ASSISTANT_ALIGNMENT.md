# T1-T20 v3.60 Supervised Policy Dashboard And Assistant Alignment

## T1 Change Title

v3.60 Supervised Policy Dashboard And Assistant Alignment

## T2 Requirement

Expose the v3.59 supervised output policy contract in ATDR surfaces that analysts actually use, without changing model behavior or enabling automation.

## T3 Source Evidence

- `ml_baseline_reviews/v3_59_supervised_output_policy_contract_latest.json`
- `atdr/app/routers/dashboard.py`
- `atdr/app/services/assistant_service.py`
- `frontend/src/pages/MLGovernance.tsx`
- `docs/V3_59_SUPERVISED_OUTPUT_POLICY_CONTRACT.md`

## T4 Current Behavior

v3.59 created a safe-use contract, but the dashboard and assistant did not yet show that policy as a first-class explanation.

## T5 Impacted Areas / Agents

Backend/API, Frontend/Dashboard, AI/ML Governance, SOC Assistant, QA, Docs.

## T6 Scope

Display and explanation only. No retraining, activation, promotion, response action, or label mutation.

## T7 Functional Requirements

- Add `v359_supervised_output_policy` to dashboard validation summary.
- Add a concise AI Governance policy panel.
- Add deterministic SOC Assistant answers for safe supervised ML usage.
- Preserve safety status: response automation disabled and model activation false.

## T8 Acceptance Criteria

- Analysts can see queue score as decision support.
- Analysts can see exact labels as explanation/ranking only.
- Assistant explains the same policy with citations.
- Tests prove no response/model side effects.

## T9 API Contract

`GET /api/dashboard/validation-summary` includes `v359_supervised_output_policy` with safe non-secret fields only.

## T10 Data Model / Migration

No schema change.

## T11 Backend Plan / Changes

Read the latest ignored v3.59 report, summarize safe policy fields, and route relevant assistant questions to deterministic policy text.

## T12 Frontend Plan / Changes

Add a compact **Supervised Output Policy** card to AI Governance with metrics and collapsible blocked-use details.

## T13 Security / Response / AI Safety

ML remains decision support only. Assistant remains read-only. Automatic response, real firewall blocking, model activation, label writes, and raw-log sharing remain disabled.

## T14 Test Plan

- Backend dashboard summary test.
- Assistant policy answer test.
- Playwright AI Governance card assertion.
- Standard verification gates.

## T15 Implementation Summary

Implemented in `atdr/app/routers/dashboard.py`, `atdr/app/services/assistant_service.py`, `frontend/src/types/api.ts`, and `frontend/src/pages/MLGovernance.tsx`.

## T16 Tests Run / Evidence

To be filled after verification in the final handoff.

## T17 PRD / Docs Updated

Updated v3.60 docs, docs index, traceability, and task progress board.

## T18 Risks / Blockers / Assumptions / Decisions

The v3.59 contract depends on generated local ignored reports. If missing, the dashboard/assistant show a run command rather than guessing.

## T19 Release / Rollback

Rollback is limited to removing the summary field, dashboard card, and assistant intent. No data migration or runtime activation is involved.

## T20 Final Handoff

Use AI Governance and SOC Assistant to explain: queue score is decision support; exact severity is explanation/ranking only; automation remains disabled.

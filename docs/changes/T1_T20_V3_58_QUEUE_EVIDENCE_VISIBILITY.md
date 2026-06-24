# T1-T20 Change Document: v3.58 Queue/Evidence Agreement Visibility

## T1 Change Title

v3.58 Queue/Evidence Agreement Visibility

## T2 Requirement

Expose the v3.57 queue-vs-rule/hybrid agreement diagnostic in ML Governance and the read-only SOC Assistant without changing detection behavior, activating models, writing labels, or enabling response actions.

## T3 Source Evidence

- `atdr/app/routers/dashboard.py`
- `atdr/app/services/assistant_service.py`
- `frontend/src/types/api.ts`
- `frontend/src/pages/MLGovernance.tsx`
- `atdr/tests/test_api.py`
- `atdr/tests/test_assistant.py`
- `frontend/tests/smoke.spec.ts`
- `docs/V3_57_QUEUE_RULE_HYBRID_AGREEMENT.md`

## T4 Current Behavior

Before v3.58, v3.57 generated a safe ignored diagnostic report, but the dashboard and assistant did not surface the latest agreement summary directly.

## T5 Impacted Areas / Agents

- Backend/API
- Frontend/dashboard
- SOC Assistant
- AI/ML Governance
- QA
- Documentation/governance

## T6 Scope

In scope:

- Read latest v3.57 diagnostic JSON safely.
- Return aggregate-only fields through dashboard validation summary.
- Show a compact ML Governance panel.
- Let the assistant answer queue/evidence agreement questions.
- Add tests and docs.

Out of scope:

- Model activation or promotion.
- New model training.
- Label writing.
- Threshold changes.
- Response automation.
- Real firewall blocking.

## T7 Functional Requirements

- Dashboard validation summary includes `v357_queue_evidence_agreement`.
- ML Governance displays split stability, queue metrics, agreement metrics, and disagreement patterns.
- SOC Assistant answers queue/evidence agreement questions with citations.
- Missing v3.57 report state remains clear and safe.

## T8 Acceptance Criteria

- Dashboard API does not expose private paths or raw logs.
- ML Governance panel renders without overflow.
- Assistant answer remains deterministic, read-only, redacted, and cited.
- Safety fields remain false for production promotion, model activation, label writing, raw-log inclusion, and response automation.

## T9 API Contract

`GET /api/dashboard/validation-summary` may include:

- `v357_queue_evidence_agreement.available`
- `phase`
- `policy_name`
- `evaluated_splits`
- `passing_splits`
- `queue_f1_min`
- `queue_false_positive_rate_max`
- `agreement_rate_min`
- `category_counts`
- `top_evidence_only_patterns`
- `readiness_decision`
- safety booleans

No secrets, raw logs, or full local report paths are returned.

## T10 Data Model / Migration

No schema changes.

## T11 Backend Plan / Changes

- Added a dashboard helper for the latest v3.57 report.
- Added a deterministic assistant answer for queue/evidence agreement questions.

## T12 Frontend Plan / Changes

- Added TypeScript API shape for v3.57 summary.
- Added a compact ML Governance card with collapsible disagreement notes.

## T13 Security / Response / AI Safety

- Assistant remains read-only.
- External LLM remains disabled by default.
- Raw logs remain excluded.
- Response automation remains disabled.
- No model is activated or promoted.

## T14 Test Plan

- Backend API summary fixture for v3.57 report.
- Assistant response test using a temporary v3.57 report.
- Playwright ML Governance smoke coverage for the new panel.

## T15 Implementation Summary

Implemented read-only visibility for v3.57 queue/evidence agreement diagnostics in API, ML Governance, and SOC Assistant.

## T16 Tests Run / Evidence

Verification results are recorded in `docs/tasks/tasklist-progress.md`.

## T17 PRD / Docs Updated

- `docs/V3_58_QUEUE_EVIDENCE_VISIBILITY.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/tasks/tasklist-progress.md`

## T18 Risks / Blockers / Assumptions / Decisions

- v3.57 remains diagnostic-only because evidence-only disagreement remains above budget in one split.
- The panel summarizes aggregate report data; deeper example drilldown remains future work.

## T19 Release / Rollback

Rollback is low risk: remove the v3.57 dashboard summary helper, ML Governance card, assistant intent, and related tests/docs. No migrations or data changes are involved.

## T20 Final Handoff

v3.58 makes the latest queue/evidence agreement diagnostic explainable in the dashboard and assistant while preserving all safety boundaries.

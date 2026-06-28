# T1-T20 Change Document: v3.75 SOC Assistant Follow-Up Context Repair

## T1 Change Title

v3.75 SOC Assistant Follow-Up Context Repair

## T2 Requirement

The SOC Assistant must keep the correct alert/log/source/case context across follow-up questions. It must not imply that alert 1 or log 1 is active unless that is truly the current context.

## T3 Source Evidence

- `atdr/app/services/assistant_service.py`
- `frontend/src/pages/AssistantPage.tsx`
- `atdr/tests/test_assistant.py`
- `frontend/tests/smoke.spec.ts`
- `docs/V3_75_ASSISTANT_FOLLOWUP_CONTEXT_REPAIR.md`

## T4 Current Behavior

Before this repair, the assistant could show or carry stale URL-scoped alert context after the user thought context had been cleared. Some backend suggested follow-ups used hard-coded `alert 1` / `log 1` wording.

## T5 Impacted Areas / Agents

- Backend / API
- Frontend / Dashboard
- AI Assistant / Analyst Workflow
- QA / UAT
- Security / Response Safety

## T6 Scope

In scope:

- Assistant intent routing for alert follow-ups.
- Assistant suggested follow-up wording.
- Frontend clear-context behavior.
- Regression tests.

Out of scope:

- Detection logic.
- ML model logic.
- External LLM provider activation.
- IAM activation.
- Database schema.
- Response actions.

## T7 Functional Requirements

- Alert follow-ups with carried alert context should stay alert-scoped.
- "What logs are related?" should answer from the current alert when an alert is active.
- "What should an analyst verify before response?" should answer for the current alert when an alert is active.
- Clear context should remove URL-scoped context before the next question.
- Assistant suggestions should use actual context IDs where available.

## T8 Acceptance Criteria

- Backend test proves alert 35 follow-ups remain alert 35 scoped.
- Frontend test proves clearing `/assistant?alert=1` removes stale alert context before the next question.
- No response, label, detection, model, data, or IAM side effects are introduced.

## T9 API Contract

No public API contract change. Existing `POST /api/assistant/chat` payload fields are unchanged.

## T10 Data Model / Migration

No schema change and no Alembic migration.

## T11 Backend Plan / Changes

- Add explicit assistant intent helpers for alert explanation, related-log, and next-step follow-up phrases.
- Route carried alert context before log-context fallback.
- Remove misleading hard-coded alert/log 1 suggestions.

## T12 Frontend Plan / Changes

- Update Assistant page clear-context action so it removes URL parameters and in-memory context.
- Preserve existing route and SafeSelect behavior.

## T13 Security / Response / AI Safety

- Assistant remains read-only.
- No automatic response.
- No real firewall blocking.
- No label/model/detection mutation.
- Raw log context remains disabled by default.

## T14 Test Plan

- Backend assistant context tests.
- Frontend Playwright assistant context tests.
- Frontend lint and build.
- Python compile/lint checks.

## T15 Implementation Summary

Implemented alert-scoped follow-up helpers, context-aware backend suggestions, frontend URL-context clearing, and regression tests.

## T16 Tests Run / Evidence

- `ruff check atdr/app/services/assistant_service.py atdr/tests/test_assistant.py`
- `python -m pytest atdr/tests/test_assistant.py::test_assistant_follow_up_uses_explicit_non_default_alert_context atdr/tests/test_assistant.py::test_assistant_follow_up_phrases_keep_alert_context_over_related_log_or_source_ids -q`
- `cd frontend && npm.cmd run lint`
- `cd frontend && npm.cmd run build`
- `cd frontend && npm.cmd run test:e2e -- --grep "SOC assistant.*context|SOC assistant clear context"`

## T17 PRD / Docs Updated

- `docs/V3_75_ASSISTANT_FOLLOWUP_CONTEXT_REPAIR.md`
- `docs/changes/T1_T20_V3_75_ASSISTANT_FOLLOWUP_CONTEXT_REPAIR.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- This is a single-turn plus carried-context repair, not a full multi-message conversational memory system.
- Real external LLM quality still depends on provider configuration and existing safety guards.

## T19 Release / Rollback

Rollback is code-only and can revert the assistant service/frontend page/test changes. No database rollback is required.

## T20 Final Handoff

Manual dashboard check:

1. Open Assistant.
2. Ask `Why was alert 35 flagged?`.
3. Click or ask `What should an analyst verify before response?`.
4. Confirm the answer references alert 35, not alert 1.
5. Open `/assistant?alert=1`, click `Clear context`, ask a source-health question, and confirm no stale alert badge remains.

# T1-T20 Change Document: v3.27 SOC Assistant Feedback And Answer Quality Review

## T1 Change Title

v3.27 SOC Assistant Feedback And Answer Quality Review

## T2 Requirement

Add a safe answer-quality feedback workflow for SOC Assistant responses while preserving read-only assistant behavior.

## T3 Source Evidence

- `atdr/app/services/assistant_service.py`
- `atdr/app/routers/assistant.py`
- `atdr/app/schemas/assistant.py`
- `atdr/app/db/models.py`
- `migrations/versions/d4e5f6a7b8c9_add_assistant_feedback.py`
- `frontend/src/pages/AssistantPage.tsx`
- `frontend/src/lib/api.ts`
- `frontend/src/hooks/useApiQueries.ts`
- `frontend/src/types/api.ts`
- `atdr/tests/test_assistant.py`
- `frontend/tests/smoke.spec.ts`
- `atdr/scripts/evaluate_assistant_qa.py`

## T4 Current Behavior

Before v3.27, the assistant could answer and cite investigation questions, and v3.26 could evaluate answer correctness in controlled QA. Analysts could not yet record answer-quality feedback from the dashboard.

## T5 Impacted Areas / Agents

- Backend / Assistant API
- Data Model / Alembic
- Frontend / SOC Assistant
- Security / Response Safety
- QA / UAT
- Documentation / Governance

## T6 Scope

In scope:

- Add compact assistant feedback storage.
- Add authenticated submit/summary/recent endpoints.
- Add dashboard feedback controls and answer-quality summary.
- Add tests for feedback auth, invalid ratings, scoped visibility, audit, and no side effects.
- Update PRD, traceability, compliance, tasklist, and docs index.

Out of scope:

- External LLM integration.
- Raw-log context sharing by default.
- Automatic assistant tuning or retraining.
- Response actions from chat.
- Detection execution from chat.
- Model activation/promotion.
- Persisted investigation notebooks or incidents.

## T7 Functional Requirements

- Analysts/admins can submit feedback after an assistant answer.
- Feedback supports helpful, not helpful, incorrect, unsafe, and unclear ratings.
- Feedback stores compact answer summary/hash, question, context, flags, and note.
- Feedback never executes actions.
- Admin sees all feedback; analyst sees own feedback.
- Feedback submission is audited.

## T8 Acceptance Criteria

- `POST /api/assistant/feedback` requires auth.
- Invalid rating returns validation error.
- Feedback summary/recent do not expose secrets or raw logs.
- Feedback controls render in React.
- Clicking a feedback rating records feedback and shows success.
- No response actions, detection runs, model runs, label changes, or automation are triggered.

## T9 API Contract

```json
POST /api/assistant/feedback
{
  "question": "Why was alert 1 flagged?",
  "rating": "helpful",
  "answer": "Short assistant answer text...",
  "feedback_note": "Clear enough for triage.",
  "context_type": "alert",
  "context_reference": "1",
  "external_provider_used": false,
  "raw_log_context_included": false,
  "action_requested": false,
  "assistant_audit_id": 12
}
```

Response returns a safe feedback item. Summary and recent endpoints return counts and compact rows.

## T10 Data Model / Migration

Adds `assistant_feedback` through Alembic revision `d4e5f6a7b8c9`.

## T11 Backend Plan / Changes

- Add SQLAlchemy model.
- Add Alembic migration.
- Add assistant service helpers for submit/list/summary.
- Add router endpoints under `/api/assistant`.
- Keep endpoint outputs non-secret and compact.

## T12 Frontend Plan / Changes

- Add feedback API types and calls.
- Add React query hooks.
- Add rating buttons and optional note under assistant answers.
- Add compact answer-quality summary/recent feedback section.

## T13 Security / Response / AI Safety

- Assistant remains read-only.
- Feedback cannot execute response actions.
- `action_executed` remains false.
- Raw logs are not stored.
- External LLM remains disabled by default.
- Response automation and real firewall blocking remain disabled.

## T14 Test Plan

- Backend assistant feedback auth and validation tests.
- Backend scoping tests for analyst/admin feedback visibility.
- Backend no-side-effect tests.
- Frontend feedback controls and success-state smoke test.
- Full release verification.

## T15 Implementation Summary

v3.27 adds answer-quality feedback to the SOC Assistant. It gives analysts a way to flag helpful, incorrect, unsafe, unclear, or not-helpful answers without granting the assistant any action capability.

## T16 Tests Run / Evidence

- Targeted backend assistant tests passed with feedback coverage.
- Targeted evaluator checks passed with answer-quality metadata.
- Full verification evidence is recorded in the v3.27 handoff.

## T17 PRD / Docs Updated

- `docs/V3_27_ASSISTANT_FEEDBACK_AND_ANSWER_QUALITY.md`
- `docs/changes/T1_T20_V3_27_ASSISTANT_FEEDBACK_AND_ANSWER_QUALITY.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- Feedback does not automatically improve the assistant; review and future tuning remain manual.
- Feedback is not a full chat transcript or notebook.
- External LLM and raw-log context remain future reviewed work only.

## T19 Release / Rollback

Rollback requires reverting the feedback endpoints/UI/docs/tests and downgrading the `assistant_feedback` migration if already applied. No raw evidence tables are modified.

## T20 Final Handoff

Manual testers should open `/assistant`, ask a question, submit feedback with a note, confirm `Feedback recorded`, and verify the Assistant Feedback summary updates. No response action, detection run, model activation, or label change should occur.

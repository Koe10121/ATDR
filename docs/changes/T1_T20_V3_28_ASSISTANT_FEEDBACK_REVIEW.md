# T1-T20 Change Document: v3.28 Assistant Feedback Review Dashboard And Quality Triage

## T1 Change Title

v3.28 Assistant Feedback Review Dashboard And Quality Triage

## T2 Requirement

Make SOC Assistant feedback useful for quality review by adding filters, quality summary fields, and a compact dashboard review panel while preserving read-only assistant behavior.

## T3 Source Evidence

- `atdr/app/services/assistant_service.py`
- `atdr/app/routers/assistant.py`
- `atdr/app/schemas/assistant.py`
- `atdr/app/db/models.py`
- `frontend/src/pages/AssistantPage.tsx`
- `frontend/src/lib/api.ts`
- `frontend/src/hooks/useApiQueries.ts`
- `frontend/src/types/api.ts`
- `atdr/tests/test_assistant.py`
- `frontend/tests/smoke.spec.ts`
- `docs/V3_27_ASSISTANT_FEEDBACK_AND_ANSWER_QUALITY.md`

## T4 Current Behavior

Before v3.28, ATDR could record assistant feedback and show a small summary/recent table. It did not yet provide useful filtering or a clear quality-triage summary for unsafe, incorrect, unclear, or not-helpful feedback.

## T5 Impacted Areas / Agents

- Backend / Assistant API
- Frontend / SOC Assistant
- Security / Response Safety
- QA / UAT
- Documentation / Governance

## T6 Scope

In scope:

- Add safe rating/context/date/limit filters.
- Add richer feedback summary fields.
- Add compact React feedback review panel.
- Add backend tests for scoping, filters, unsafe/incorrect summary, and no side effects.
- Add frontend smoke coverage for filters and review panel.
- Update PRD, traceability, compliance, docs index, tasklist, and T1-T20 evidence.

Out of scope:

- New schema for feedback review status.
- Automatic assistant tuning or retraining.
- Full chat transcript persistence.
- External LLM enablement.
- Raw-log context sharing.
- Response, detection, label, source, user, email, model, or data actions from chat.

## T7 Functional Requirements

- Admin can list all feedback.
- Analyst can list only own feedback.
- Feedback list supports rating, context type, recent window, and row-limit filters.
- Summary exposes unsafe/incorrect and needs-review counts.
- Dashboard shows review filters, priority feedback, compact rows, and safety badges.
- Feedback review must not expose secrets or raw logs.

## T8 Acceptance Criteria

- Admin sees all feedback rows with filters.
- Analyst is server-side scoped to own feedback rows.
- Unsafe/incorrect feedback appears as review recommended.
- `action_executed_count` remains `0`.
- No response action, detection run, label change, model run, or data mutation occurs.
- React page renders without horizontal overflow or raw JSON panels.

## T9 API Contract

Existing endpoints are extended:

```text
GET /api/assistant/feedback/summary?rating=incorrect&context_type=alert&since_days=30
GET /api/assistant/feedback/recent?rating=unsafe&context_type=source&since_days=7&limit=20
```

Responses remain non-secret and compact. Feedback rows include review metadata such as `review_recommended` and `review_reason`.

## T10 Data Model / Migration

No new migration. v3.28 reuses the v3.27 `assistant_feedback` table.

## T11 Backend Plan / Changes

- Add filtered feedback query helpers.
- Extend summary with review counts and priority feedback rows.
- Keep role scoping server-side.
- Keep endpoint output free of raw logs and secrets.

## T12 Frontend Plan / Changes

- Add feedback review filters to the Assistant page.
- Add summary metrics for needs-review, unsafe/incorrect, action execution, external provider, and raw logs.
- Add priority feedback cards and a compact table.
- Keep action controls absent from assistant review.

## T13 Security / Response / AI Safety

- Assistant remains read-only.
- Feedback review cannot execute response actions.
- Feedback review cannot run detection.
- Feedback review cannot activate or promote ML models.
- Feedback review cannot tune assistant behavior automatically.
- Raw logs and secrets are not exposed.

## T14 Test Plan

- Backend tests for filters, role scoping, unsafe/incorrect summary, secret/raw-log absence, and no side effects.
- Frontend smoke test for review panel, filters, safety badges, long text safety, and no action controls.
- Full release verification.

## T15 Implementation Summary

v3.28 adds a quality-triage layer over the existing assistant feedback table. It helps admins and analysts find problematic answers while keeping the assistant deterministic, local, read-only, and non-mutating by default.

## T16 Tests Run / Evidence

Verification evidence is recorded in `docs/tasks/tasklist-progress.md`.

## T17 PRD / Docs Updated

- `docs/V3_28_ASSISTANT_FEEDBACK_REVIEW.md`
- `docs/changes/T1_T20_V3_28_ASSISTANT_FEEDBACK_REVIEW.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- Feedback review is manual. It does not automatically tune assistant answers.
- Feedback lifecycle status is future work if the team wants open/reviewed/dismissed tracking.
- External LLM and raw-log context remain future reviewed work only.

## T19 Release / Rollback

Rollback can remove the filtered endpoint parameters, dashboard review panel, docs, and tests. No database downgrade is required because no v3.28 schema change was added.

## T20 Final Handoff

Manual testers should open `/assistant`, submit feedback on an answer, then use Feedback Review filters for rating/context/date. Unsafe or incorrect feedback should show as review recommended, while action execution remains disabled and no response actions are created.

# v3.28 Assistant Feedback Review Dashboard And Quality Triage

## Status

Implemented as a safe feedback-review workflow for the SOC Assistant.

## Purpose

v3.28 makes assistant answer feedback useful for analyst review and admin quality triage. It adds filtering, quality summary fields, and a cleaner dashboard review panel without giving the assistant any action capability.

## Source Evidence

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

## What Changed

- Feedback summary and recent-feedback endpoints now support safe filters:
  - rating
  - context type
  - recent window in days
  - row limit
- Feedback summary now reports:
  - total feedback
  - count by rating
  - unsafe or incorrect feedback count
  - total feedback needing review
  - latest unsafe or incorrect items
  - external provider usage count
  - raw-log context count
  - action-executed count
- SOC Assistant page now has a compact Feedback Review section with:
  - filter controls
  - quality metrics
  - priority feedback cards
  - compact feedback table
  - safety badges for read-only/no-auto-tuning behavior

## Access Behavior

- Admin users see all assistant feedback.
- Analyst users see only their own assistant feedback.
- The same endpoints enforce scope server-side; the dashboard is not the only protection.

## Safety Controls

- Feedback review is read-only.
- Feedback review does not execute response actions.
- Feedback review does not run detection.
- Feedback review does not create labels.
- Feedback review does not activate or promote ML models.
- Feedback review does not tune/retrain the assistant automatically.
- Raw logs and secrets are not returned by feedback endpoints.
- `action_executed_count` should remain `0`.

## Manual Test Flow

1. Start backend and frontend normally.
2. Open `/assistant`.
3. Ask a question such as `Why was alert 1 flagged?`.
4. Submit feedback using `Helpful`, `Incorrect`, `Unsafe`, `Unclear`, or `Not helpful`.
5. Use Feedback Review filters for rating, context, date, and row limit.
6. Confirm unsafe/incorrect feedback appears as `Review Recommended`.
7. Confirm no response action controls appear in the assistant.
8. Confirm Response & Audit does not show automatic response actions created by assistant feedback.

## Known Limitations

- Feedback is metadata for quality review, not a full conversation transcript.
- There is no feedback status lifecycle yet, such as open/reviewed/dismissed.
- The workflow does not automatically tune prompts, rules, ML, or assistant logic.
- External LLM provider support remains disabled by default.
- Raw-log assistant context remains disabled by default.

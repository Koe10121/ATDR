# v3.27 SOC Assistant Feedback And Answer Quality Review

## Status

Implemented as a safe, read-only feedback workflow for SOC Assistant answers.

## Purpose

v3.27 lets analysts rate assistant answers so ATDR can review answer quality without allowing the assistant to execute actions, mutate data, expose raw logs, or use external LLMs by default.

## What Changed

- Added an `assistant_feedback` table.
- Added authenticated assistant feedback endpoints:
  - `POST /api/assistant/feedback`
  - `GET /api/assistant/feedback/summary`
  - `GET /api/assistant/feedback/recent`
- Added compact React feedback controls under assistant answers.
- Added answer-quality summary and recent feedback visibility on the SOC Assistant page.
- Extended assistant QA evaluator output with answer-quality case count, citation pass rate, unsafe refusal status, and feedback availability.
- Added backend and frontend regression coverage.

## Feedback Ratings

- `helpful`
- `not_helpful`
- `incorrect`
- `unsafe`
- `unclear`

## Safety Controls

- Feedback does not execute actions.
- `action_executed` is always false.
- Feedback submission does not run detection.
- Feedback submission does not create response actions.
- Feedback submission does not activate or promote ML models.
- Feedback submission does not change labels.
- Full raw logs and API secrets are not stored.
- Answer text is compacted into a short summary and hash.
- External provider and raw-log context flags are recorded for review.
- Feedback submission is audited.

## Role Behavior

- Admin and analyst users can submit feedback.
- Admin users can view all feedback summary/recent rows.
- Analyst users can view only their own recent feedback and scoped summary.

## Manual Test Flow

1. Start backend and frontend normally.
2. Open `/assistant`.
3. Ask `Why was alert 1 flagged?`.
4. Confirm safety badges remain visible.
5. Enter a short feedback note.
6. Click `Helpful`, `Incorrect`, `Unsafe`, or another rating.
7. Confirm `Feedback recorded`.
8. Confirm Assistant Feedback summary updates.
9. Confirm no response action controls appear and no automatic response is triggered.

## Known Limitations

- Feedback is answer-quality metadata, not a full conversation transcript.
- Feedback review does not retrain or tune the assistant automatically.
- No external LLM provider is enabled.
- Raw-log context remains disabled by default.
- This does not add persisted investigation notebooks or incident records.

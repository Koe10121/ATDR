# T1-T20 Change Document: v3.70 SOC Assistant Provider Telemetry

## T1 Change Title

v3.70 SOC Assistant Provider Telemetry

## T2 Requirement

Make real-LLM assistant behavior visible to analysts without exposing secrets or raw logs.

## T3 Source Evidence

- `frontend/src/pages/AssistantPage.tsx`
- `frontend/tests/smoke.spec.ts`
- `atdr/app/services/assistant_service.py`
- `atdr/app/services/assistant_llm.py`
- `docs/V3_68_REAL_LLM_ASSISTANT_QUALITY_GUARD.md`
- `docs/V3_69_REAL_LLM_PROMPT_QUALITY_CONTRACT.md`

## T4 Current Behavior

Backend responses include safe `details.llm` metadata, but the dashboard previously exposed most of it only in Technical Context JSON.

## T5 Impacted Areas / Agents

- Frontend / Dashboard
- AI Assistant
- Security / Response Safety
- QA
- Docs

## T6 Scope

In scope:

- Display safe provider telemetry in the Assistant response panel.
- Add frontend regression coverage.
- Update documentation and task board.

Out of scope:

- Detection, ML, IAM, database schema, or response behavior changes.
- Enabling external LLM by default.
- Running live provider calls in CI.

## T7 Functional Requirements

- Show whether the answer is local, external-used, external-guarded, or fallback.
- Show provider name and prompt contract when available.
- Show raw-log, redaction, and secret safety status.
- Show guard reason for guarded provider answers.

## T8 Acceptance Criteria

- Dashboard does not expose API keys or raw logs.
- Guarded LLM output is clearly labeled.
- Local deterministic answers remain clearly labeled.
- Existing assistant controls and follow-ups still work.

## T9 API Contract

No API contract change. The UI consumes existing `AssistantChatResponse.details.llm` metadata when present and degrades safely when absent.

## T10 Data Model / Migration

No schema or migration change.

## T11 Backend Plan / Changes

No backend code change in this step.

## T12 Frontend Plan / Changes

- Add a Provider Status card to `AssistantPage`.
- Add defensive parsing for `details.llm`.
- Add Playwright coverage for guarded external LLM telemetry.

## T13 Security / Response / AI Safety

- Read-only assistant behavior is unchanged.
- No response actions are exposed or executed.
- Secrets are not displayed.
- Raw-log context remains disabled by default.

## T14 Test Plan

- Frontend lint.
- Frontend production build.
- Playwright smoke/e2e tests with guarded provider mock.

## T15 Implementation Summary

Implemented a compact provider telemetry panel and smoke coverage for local deterministic and guarded external provider states.

## T16 Tests Run / Evidence

- `cd frontend && npm.cmd run lint`
- `cd frontend && npm.cmd run build`
- `cd frontend && npm.cmd run test:e2e` after final verification

## T17 PRD / Docs Updated

- `docs/V3_70_ASSISTANT_PROVIDER_TELEMETRY.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/tasks/tasklist-progress.md`

## T18 Risks / Blockers / Assumptions / Decisions

- Real provider execution remains private/local because it requires `.env` secrets.
- Provider answer quality still varies; v3.68 guard remains the backstop.

## T19 Release / Rollback

Rollback is limited to reverting the `AssistantPage` telemetry card and the related Playwright assertions.

## T20 Final Handoff

Manual dashboard check: open SOC Assistant, ask a real alert question, and confirm the Provider Status card shows local, external-used, or guarded state without displaying secrets or raw logs.

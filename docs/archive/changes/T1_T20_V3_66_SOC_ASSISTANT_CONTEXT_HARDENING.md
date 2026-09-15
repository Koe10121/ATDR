# T1-T20: v3.66 SOC Assistant Context Hardening

## T1 Change Title

v3.66 SOC Assistant follow-up context and stale-alert hardening.

## T2 Requirement

Make the SOC Assistant preserve the correct alert/log/source/case context across follow-up questions and prevent stale UI payload IDs from overriding explicitly typed analyst questions.

## T3 Source Evidence

- `docs/CURRENT_SYSTEM_STATE_LOCK.md`
- `docs/ATDR_PRODUCTIZATION_ROADMAP.md`
- `atdr/app/services/assistant_service.py`
- `atdr/app/routers/assistant.py`
- `atdr/app/schemas/assistant.py`
- `frontend/src/pages/AssistantPage.tsx`
- `frontend/src/lib/api.ts`
- `atdr/tests/test_assistant.py`
- `frontend/tests/smoke.spec.ts`

## T4 Current Behavior

Before this change, the assistant could show or carry stale context after related-log citations, source citations, or previous alert answers. A typed question such as `Why was alert 35 flagged?` could be vulnerable to a stale payload ID if the frontend carried an older context.

## T5 Impacted Areas / Agents

- Backend / Assistant
- Frontend / Dashboard
- QA
- Documentation / Governance

## T6 Scope

In scope:

- Backend typed-ID precedence.
- Frontend primary context tracking.
- Alert/log follow-up regression tests.
- Tasklist and traceability updates.

Out of scope:

- External LLM provider behavior changes.
- New assistant action capability.
- Detection, ML, response, database schema, IAM, or startup-command changes.

## T7 Functional Requirements

- Explicit alert/log/source/case IDs typed in a question must override stale payload context.
- Follow-up questions like `What logs are related?` should keep the previous alert context.
- Follow-up questions like `What should an analyst verify before response?` should stay scoped to the active alert.
- Log follow-ups should show log context when the assistant answers about a log.
- The assistant must not get stuck on alert 1 after using presets.

## T8 Acceptance Criteria

- Backend regression proves typed alert ID overrides stale `alert_id`, `log_id`, and `source_id` payload values.
- Frontend smoke coverage proves follow-up payloads preserve alert context.
- Frontend smoke coverage proves explicit new alert IDs replace previous context.
- Assistant remains read-only and no side effects are introduced.

## T9 API Contract

No API contract change. Existing `POST /api/assistant/chat` request fields remain:

- `question`
- `alert_id`
- `log_id`
- `source_id`
- `case_id`
- `include_recent_context`

## T10 Data Model / Migration

No migration required.

## T11 Backend Plan / Changes

- Prefer IDs parsed from the analyst question over explicit payload IDs.
- Preserve payload IDs for true follow-up questions where no ID is typed.
- Keep raw-log exclusion and audit behavior unchanged.

## T12 Frontend Plan / Changes

- Add primary context tracking for alert/log/source/case.
- Use primary context for the visible context badge.
- Preserve alert context for alert-oriented follow-ups.
- Allow log follow-ups to become log-scoped.
- Keep presets and safety badges unchanged.

## T13 Security / Response / AI Safety

- No response action execution.
- No detection run execution.
- No label mutation.
- No model activation or promotion.
- No user/account mutation.
- No raw log context sharing.
- No real firewall blocking.
- No automatic response.

## T14 Test Plan

- Focused Ruff check on assistant service and assistant tests.
- Targeted backend assistant tests.
- Frontend lint.
- Frontend build.
- Existing Playwright assistant follow-up smoke coverage updated.

## T15 Implementation Summary

Implemented backend typed-ID precedence and frontend primary context state. Updated Playwright mock coverage to distinguish alert and log follow-up context.

## T16 Tests Run / Evidence

- `.\.venv\Scripts\ruff.exe check atdr\app\services\assistant_service.py atdr\tests\test_assistant.py` passed.
- `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_assistant.py::test_assistant_follow_up_phrases_keep_alert_context_over_related_log_or_source_ids atdr\tests\test_assistant.py::test_assistant_typed_alert_id_overrides_stale_payload_context -q --basetemp .pytest_tmp\assistant-followup-2 -p no:cacheprovider` passed.
- `cd frontend && npm.cmd run lint` passed.
- `cd frontend && npm.cmd run build` passed.

## T17 PRD / Docs Updated

- `docs/V3_66_SOC_ASSISTANT_CONTEXT_HARDENING.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- Real provider wording can still vary when external LLM is enabled, but context packaging and safety controls remain deterministic.
- Full manual QA should be run against the user's current large local database before a high-stakes demo.
- If analysts regularly switch among many alerts, a future explicit context selector may be better than automatic context inference.

## T19 Release / Rollback

Rollback is limited to assistant context logic and tests:

- revert `atdr/app/services/assistant_service.py`;
- revert `frontend/src/pages/AssistantPage.tsx`;
- revert related tests/docs.

No database rollback is needed.

## T20 Final Handoff

The assistant now honors explicit analyst IDs over stale UI payload context and tracks the primary investigation context more accurately. It remains read-only and does not broaden authority.


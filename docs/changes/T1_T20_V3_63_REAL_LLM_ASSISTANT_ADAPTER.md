# T1-T20 Change Document: v3.63 Real LLM Assistant Adapter

## T1 Change Title

v3.63 Real LLM Assistant Adapter

## T2 Requirement

Prepare the ATDR SOC Assistant to support Gemini, OpenAI-compatible APIs, and Claude through a provider adapter while keeping external LLM use disabled by default and preserving deterministic local fallback.

## T3 Source Evidence

- `atdr/app/services/assistant_service.py`
- `atdr/app/services/assistant_llm.py`
- `atdr/app/core/config.py`
- `atdr/app/schemas/assistant.py`
- `atdr/app/routers/assistant.py`
- `frontend/src/pages/AssistantPage.tsx`
- `frontend/src/types/api.ts`
- `atdr/tests/test_assistant.py`
- `docs/security/ATDR_REAL_LLM_ASSISTANT_PLAN.md`

## T4 Current Behavior

Before v3.63, ATDR exposed disabled-by-default LLM config/status placeholders but did not implement provider adapters. The assistant used deterministic local answers only.

## T5 Impacted Areas / Agents

- Backend / API
- SOC Assistant
- Frontend / Dashboard
- Security / Response Safety
- QA
- Documentation / Governance

## T6 Scope

In scope:

- provider adapter service;
- safe bounded context packaging;
- optional provider enhancement after deterministic answer generation;
- provider-used audit flag;
- frontend status display;
- docs and tests.

Out of scope:

- enabling real provider calls by default;
- committing keys;
- raw log sharing;
- response execution;
- detection execution;
- label/model/user mutation;
- model activation or promotion.

## T7 Functional Requirements

- Deterministic fallback must remain active.
- External LLM calls must require explicit configuration.
- Provider secrets must never be returned by status or chat responses.
- Raw logs must not be included in provider context by default.
- Provider failures must fall back to deterministic local help.
- Assistant audit must record whether an external provider was used.

## T8 Acceptance Criteria

- Gemini, OpenAI-compatible, Claude, and mock provider paths exist.
- Default status reports no provider usage.
- Mock provider test can exercise external-provider path without a real key.
- No response action is created by assistant chat.
- Backend and frontend verification pass.

## T9 API Contract

Existing endpoints remain unchanged:

- `GET /api/assistant/status`
- `POST /api/assistant/chat`

Status adds safe non-secret fields:

- `llm_base_url_configured`
- `llm_timeout_seconds`
- `llm_provider_name`
- `llm_ready`

## T10 Data Model / Migration

No database schema change.

## T11 Backend Plan / Changes

- Add `assistant_llm.py`.
- Add LLM base URL and timeout settings.
- Wire optional provider enhancement after deterministic answer creation.
- Audit final provider-used state.

## T12 Frontend Plan / Changes

- Update Assistant API types.
- Show provider readiness without exposing secrets or endpoints.

## T13 Security / Response / AI Safety

- External LLM disabled by default.
- Raw log context disabled by default.
- IP redaction remains enabled by default.
- Assistant remains read-only.
- No response automation or real firewall blocking.
- No ML model activation or promotion.

## T14 Test Plan

- Assistant status hides secrets.
- Mock provider path is explicit, redacted, audited, and read-only.
- Existing assistant intents remain safe.
- Full release verification.

## T15 Implementation Summary

Implemented provider adapter with Gemini, OpenAI-compatible, Claude, and mock provider support. Chat responses first use deterministic ATDR logic, then optionally use configured LLM wording enhancement. Provider failures fail closed to deterministic output.

## T16 Tests Run / Evidence

Targeted verification during implementation:

- `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_assistant.py -q --basetemp .pytest_tmp\v363-assistant -p no:cacheprovider`
- `.\.venv\Scripts\ruff.exe check atdr\app\services\assistant_llm.py atdr\app\services\assistant_service.py atdr\app\core\config.py atdr\tests\test_assistant.py`

Final verification should also include the repository release gate.

## T17 PRD / Docs Updated

- `docs/V3_63_REAL_LLM_ASSISTANT_ADAPTER.md`
- `docs/security/ATDR_REAL_LLM_ASSISTANT_PLAN.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/tasks/tasklist-progress.md`

## T18 Risks / Blockers / Assumptions / Decisions

- Real provider keys and data-sharing approval are not present.
- Prompt-injection and privacy testing should continue before private-data use.
- `mock` provider exists for tests only.
- No production readiness is claimed.

## T19 Release / Rollback

Rollback by reverting the adapter module and assistant/config/frontend changes. No migration rollback is needed.

## T20 Final Handoff

ATDR now has a safe real-LLM adapter foundation while preserving deterministic local answers and strict read-only assistant behavior. External providers remain disabled unless explicitly configured through local environment variables.

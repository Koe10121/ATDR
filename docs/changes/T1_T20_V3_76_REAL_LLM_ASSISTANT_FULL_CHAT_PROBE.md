# T1-T20 Change Document: v3.76 Real LLM Assistant Full Chat Probe

## T1 Change Title

v3.76 Real LLM Assistant Full Chat Probe

## T2 Requirement

ATDR needs a safe way to validate that the real configured LLM provider works through the full SOC Assistant service path, without touching the current database or exposing secrets.

## T3 Source Evidence

- `atdr/scripts/test_assistant_chat_provider.py`
- `atdr/app/services/assistant_service.py`
- `atdr/app/services/assistant_llm.py`
- `atdr/tests/test_assistant.py`
- `docs/V3_76_REAL_LLM_ASSISTANT_FULL_CHAT_PROBE.md`

## T4 Current Behavior

Before this change, ATDR had a provider-level probe, but no command that exercised the full assistant service with synthetic alert context and a temporary database.

## T5 Impacted Areas / Agents

- AI/ML Governance
- Backend / API
- Security / Response Safety
- QA/UAT
- Release/Ops / Lab Validation

## T6 Scope

In scope:

- Add a temp-DB full assistant chat provider probe.
- Add tests for status-only and mock execution paths.
- Document usage and safety boundaries.

Out of scope:

- Dashboard UI changes.
- Real IAM/OIDC implementation.
- Detection or ML model changes.
- Response action changes.
- Database schema changes.

## T7 Functional Requirements

- Status-only mode must not call the provider.
- Execute mode must use a synthetic temporary database.
- Execute mode must report provider usage, raw-log policy, redaction, side effects, and audit behavior.
- The command must not expose secrets.
- The command must not mutate the current database.

## T8 Acceptance Criteria

- Probe returns safe booleans and metadata only.
- Probe can execute mock/full service path without raw logs or mutating side effects.
- Real provider execution can be run manually from private `.env` without printing secrets.
- Tests pass.

## T9 API Contract

No API contract change. This is a script-only validation helper.

## T10 Data Model / Migration

No schema change. The script uses an in-memory SQLite database.

## T11 Backend Plan / Changes

- Add `atdr/scripts/test_assistant_chat_provider.py`.
- Seed synthetic source/log/alert/evidence data in memory.
- Call `answer_assistant_question`.
- Report safe status and side-effect deltas.

## T12 Frontend Plan / Changes

No frontend change.

## T13 Security / Response / AI Safety

- No raw log context by default.
- IP redaction remains enabled when configured.
- No secrets printed.
- No response actions, detection runs, labels, or model runs are created.
- Assistant remains read-only.

## T14 Test Plan

- Ruff and compile checks for the new script.
- Backend tests for status-only and mock execute modes.
- Manual private-provider execution with safe JSON output.

## T15 Implementation Summary

Implemented the full assistant chat provider probe and tests proving status-only and mock execution safety.

## T16 Tests Run / Evidence

- `ruff check atdr/scripts/test_assistant_chat_provider.py atdr/tests/test_assistant.py`
- `python -m pytest atdr/tests/test_assistant.py::test_assistant_chat_provider_probe_is_status_only_by_default_and_hides_secret atdr/tests/test_assistant.py::test_assistant_chat_provider_probe_mock_executes_without_mutating_side_effects -q`
- `python -m atdr.scripts.test_assistant_chat_provider --pretty`
- `python -m atdr.scripts.test_assistant_chat_provider --execute --pretty`

## T17 PRD / Docs Updated

- `docs/V3_76_REAL_LLM_ASSISTANT_FULL_CHAT_PROBE.md`
- `docs/changes/T1_T20_V3_76_REAL_LLM_ASSISTANT_FULL_CHAT_PROBE.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- The probe uses synthetic data; dashboard behavior still needs manual UI confirmation.
- Provider response quality may require future prompt tuning, but deterministic safety guardrails remain active.

## T19 Release / Rollback

Rollback is script/test/docs only. No database rollback is required.

## T20 Final Handoff

Run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_chat_provider --execute --pretty
```

Then manually open the dashboard Assistant page and ask an alert question to confirm provider telemetry shows the expected real provider behavior.

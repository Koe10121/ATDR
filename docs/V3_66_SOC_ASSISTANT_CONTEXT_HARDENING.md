# v3.66 SOC Assistant Context Hardening

Date: 2026-06-26

## Summary

v3.66 hardens SOC Assistant follow-up behavior so analyst questions keep the intended alert/log/source/case context and newly typed IDs override stale UI state. The change preserves the assistant's read-only safety boundary.

## Problem

The assistant could show or reuse stale context after an analyst moved between prompts. The most visible failure mode was:

- ask about one alert;
- click or type a follow-up such as "What logs are related?" or "What should an analyst verify before response?";
- then type a different alert ID;
- stale alert/log/source context could remain in the payload or UI badge.

This made answers look like they were about the wrong alert.

## Changes

- Backend ID parsing now lets explicitly typed IDs in the question win over stale payload context.
- Frontend assistant context now tracks a primary context type: alert, log, source, case, or none.
- The active context badge now uses the primary context instead of always preferring alert IDs when several citations exist.
- Log follow-ups can become log-scoped even when the log is linked to an alert.
- Alert follow-ups keep alert scope for related logs and safe next-step questions.
- Regression tests cover stale payload IDs and follow-up context retention.

## Safety

Unchanged safety boundaries:

- Assistant remains read-only.
- No response action is executed.
- No detection run is started by the assistant.
- No labels are changed.
- No model is activated or promoted.
- No users/accounts are changed.
- Raw log context remains disabled by default.
- External LLM provider behavior is unchanged.
- Real firewall blocking remains disabled.

## Verification

Focused checks completed:

- `.\.venv\Scripts\ruff.exe check atdr\app\services\assistant_service.py atdr\tests\test_assistant.py`
- `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_assistant.py::test_assistant_follow_up_phrases_keep_alert_context_over_related_log_or_source_ids atdr\tests\test_assistant.py::test_assistant_typed_alert_id_overrides_stale_payload_context -q --basetemp .pytest_tmp\assistant-followup-2 -p no:cacheprovider`
- `cd frontend && npm.cmd run lint`
- `cd frontend && npm.cmd run build`

Broader verification is recorded in `docs/tasks/tasklist-progress.md`.

## Manual Dashboard Checks

1. Open SOC Assistant.
2. Ask: `Why was alert 1717 flagged?`
3. Click or ask: `What logs are related?`
4. Ask: `What should an analyst verify before response?`
5. Confirm the context badge still shows alert 1717.
6. Ask a log follow-up such as `Why was that log flagged?`
7. Confirm the context badge changes to the log when a related log is selected by context.
8. Type a new explicit alert such as `Why was alert 35 flagged?`
9. Confirm the assistant answers for alert 35 and does not stay stuck on alert 1 or the previous alert.

## Remaining Work

- Continue improving real external LLM provider QA when configured through private `.env`.
- Add more live dashboard/manual QA around current database alert IDs.
- Consider an explicit context selector/dropdown if analysts frequently work across multiple alerts/logs at once.


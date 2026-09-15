# v3.75 SOC Assistant Follow-Up Context Repair

Date: 2026-06-27

## Summary

v3.75 fixes a presentation- and product-readiness issue in the SOC Assistant where follow-up questions could keep or revive stale alert context from the URL, and backend suggestions could show generic `alert 1` / `log 1` examples that looked like real active context.

The assistant remains read-only. This change does not modify detection logic, ML logic, IAM activation, database schema, response safety, or external LLM provider behavior.

## What Changed

- Backend assistant intent routing now treats carried alert context as primary for alert follow-ups such as:
  - related logs
  - recommended next step
  - analyst verification before response
  - missing evidence
  - false-positive/noise review
  - ATT&CK / attack mapping
- Backend follow-up suggestions now use the actual alert ID from current context instead of hard-coded `alert 1`.
- Generic log-help suggestions no longer invent `log 1`.
- Frontend "Clear context" now clears both in-memory assistant context and URL parameters such as `alert`, `log`, `source`, `case`, and `prompt`.
- Regression tests cover:
  - explicit non-default alert context such as alert 35
  - related-log and next-step follow-ups staying alert-scoped
  - URL-scoped alert context clearing before the next question

## Safety Boundaries

- No response action is created.
- No detection run is triggered.
- No labels are changed.
- No model artifact is activated or promoted.
- Raw log context remains disabled by default.
- External LLM use remains governed by existing disabled-by-default/provider-safety settings.

## Verification

Focused verification run:

- `ruff check atdr/app/services/assistant_service.py atdr/tests/test_assistant.py`
- `python -m pytest atdr/tests/test_assistant.py::test_assistant_follow_up_uses_explicit_non_default_alert_context atdr/tests/test_assistant.py::test_assistant_follow_up_phrases_keep_alert_context_over_related_log_or_source_ids -q`
- `cd frontend && npm.cmd run lint`
- `cd frontend && npm.cmd run build`
- `cd frontend && npm.cmd run test:e2e -- --grep "SOC assistant.*context|SOC assistant clear context"`

## Remaining Work

- Continue improving real LLM answer quality once provider configuration is stable.
- Add a stronger conversation-state model later if ATDR moves beyond single-turn plus carried context.
- Keep testing assistant side effects any time prompts, provider adapters, or dashboard handoff behavior changes.

# T1-T20 Change Document: v3.24 SOC Assistant Investigation Context Upgrade

## T1 Change Title

v3.24 SOC Assistant Investigation Context Upgrade

## T2 Requirement

Improve SOC Assistant usefulness during investigations by supporting explicit alert, log, source, and computed case/group context while preserving read-only behavior and safety boundaries.

## T3 Source Evidence

- `atdr/app/services/assistant_service.py`
- `atdr/app/routers/assistant.py`
- `atdr/app/schemas/assistant.py`
- `atdr/app/services/case_service.py`
- `atdr/app/detection/explanations.py`
- `frontend/src/pages/AssistantPage.tsx`
- `frontend/src/pages/AlertsTriage.tsx`
- `frontend/src/pages/LogExplorer.tsx`
- `atdr/tests/test_assistant.py`
- `frontend/tests/smoke.spec.ts`
- `docs/V3_23_ASSISTANT_CONTEXT_LINKING.md`

## T4 Current Behavior

Before v3.24, assistant citations linked to dashboard context and alert/source context could be passed through the Assistant page. Log context was mostly inferred from typed text, related-log summaries were limited, and computed case/group context did not have a dedicated assistant answer path.

## T5 Impacted Areas / Agents

- Backend / Assistant API
- Frontend / Dashboard
- Security / Response Safety
- QA / UAT
- Documentation / Governance

## T6 Scope

In scope:

- Add explicit `log_id` and `case_id` assistant request context.
- Enrich alert answers with related-log summaries and citations.
- Add deterministic log, source, and computed case/group summaries.
- Add navigation-only Ask Assistant links from investigation surfaces.
- Add backend and frontend regression tests.

Out of scope:

- External LLM enablement.
- Raw-log sharing by default.
- Response execution.
- Detection execution.
- Label/model/data mutation.
- Persisted incident/case records.

## T7 Functional Requirements

- Assistant must answer alert, log, source, and computed case/group investigation questions.
- Alert answers must cite related normalized logs when available.
- Log answers must explain why a log was flagged or not flagged.
- Source answers must include health, parser/data-quality notes, and recent source-linked alerts when available.
- Case/group answers must state that they are computed summaries only.
- Dashboard handoff buttons must be navigation-only.

## T8 Acceptance Criteria

- `/assistant?alert=<id>` shows alert context.
- `/assistant?log=<id>` shows log context.
- `/assistant?case=<id>` shows case context.
- Alert detail related-log chips can open Assistant with alert and log context.
- Log detail can open Assistant with log context.
- Active case grouping can open Assistant with case context.
- Assistant answers do not include raw log context by default.
- Assistant cannot execute response, detection, label, model, source, or data actions.

## T9 API Contract

`POST /api/assistant/chat` keeps existing fields and adds optional context fields:

```json
{
  "question": "Why was this log flagged?",
  "alert_id": 1,
  "log_id": 10,
  "source_id": 2,
  "case_id": "abc123",
  "include_recent_context": true
}
```

The response contract remains unchanged.

## T10 Data Model / Migration

No schema or migration changes.

## T11 Backend Plan / Changes

- Add optional `log_id` and `case_id` request fields.
- Route explicit log/source/case context to deterministic read-only answer builders.
- Strip raw-line context from assistant details.
- Add related-log, source-linked-alert, and case citations.
- Add tests for context handling and no side effects.

## T12 Frontend Plan / Changes

- Add Assistant page support for alert/log/source/case context badges.
- Add citation mapping for `/api/alerts/cases`.
- Add Ask Assistant links in alert detail, related-log chips, Log Explorer, and case grouping.
- Add Playwright coverage for deep links and context badges.

## T13 Security / Response / AI Safety

- Assistant remains read-only.
- Response automation remains disabled.
- Real firewall blocking remains disabled.
- No model activation or promotion is added.
- No external LLM call is enabled.
- Raw log context remains disabled by default.

## T14 Test Plan

- Backend assistant tests for explicit log context, alert related-log citations, source recent-alert context, case summaries, and no mutation.
- Playwright smoke tests for Ask Assistant links and context badges.
- Existing release gates remain required.

## T15 Implementation Summary

v3.24 adds explicit investigation context to the SOC Assistant and dashboard handoff buttons. Answers now cover alert evidence, related logs, log triage reasoning, source health, and computed case/group summaries without adding action capability.

## T16 Tests Run / Evidence

- `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_assistant.py -q --basetemp .pytest_tmp\v324-assistant -p no:cacheprovider`: pass, `13 passed`.

Full release verification is recorded in the v3.24 handoff report.

## T17 PRD / Docs Updated

- `docs/V3_24_SOC_ASSISTANT_INVESTIGATION_CONTEXT.md`
- `docs/changes/T1_T20_V3_24_SOC_ASSISTANT_INVESTIGATION_CONTEXT.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- Computed case/group answers summarize current grouping logic only; persisted incident management remains future work.
- External LLM and raw-log context remain future privacy/security work.
- Dedicated run/job detail pages remain future UX work.

## T19 Release / Rollback

Rollback is limited to reverting assistant request-field handling, deterministic answer additions, dashboard handoff links, and docs/tests. No database rollback is needed.

## T20 Final Handoff

Manual testers should open Alerts, Investigation, and Assistant; use the new Ask Assistant links for alert, related log, source, and case context; and confirm responses stay read-only, evidence-grounded, and safe.

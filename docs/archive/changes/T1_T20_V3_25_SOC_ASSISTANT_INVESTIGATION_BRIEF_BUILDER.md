# T1-T20 Change Document: v3.25 SOC Assistant Investigation Brief Builder

## T1 Change Title

v3.25 SOC Assistant Investigation Brief Builder

## T2 Requirement

Add a read-only investigation brief builder to the SOC Assistant so analysts can summarize alert, log, source, and computed case/group evidence for handoff or advisor review without changing ATDR state.

## T3 Source Evidence

- `atdr/app/services/assistant_service.py`
- `atdr/app/routers/assistant.py`
- `atdr/app/schemas/assistant.py`
- `atdr/app/routers/alerts.py`
- `atdr/app/routers/logs.py`
- `atdr/app/routers/sources.py`
- `frontend/src/pages/AssistantPage.tsx`
- `frontend/src/pages/AlertsTriage.tsx`
- `frontend/src/pages/LogExplorer.tsx`
- `frontend/src/types/api.ts`
- `atdr/tests/test_assistant.py`
- `frontend/tests/smoke.spec.ts`
- `docs/V3_24_SOC_ASSISTANT_INVESTIGATION_CONTEXT.md`

## T4 Current Behavior

Before v3.25, the assistant could answer context-specific alert, log, source, and computed case/group questions. Analysts still had to manually reshape those answers into a report-style investigation brief.

## T5 Impacted Areas / Agents

- Backend / Assistant API
- Frontend / Dashboard
- Security / Response Safety
- QA / UAT
- Documentation / Governance

## T6 Scope

In scope:

- Add deterministic investigation brief routing.
- Produce structured brief sections from existing evidence-grounded assistant context.
- Add brief preset buttons and context-aware `Generate Brief` in React.
- Add copy support for the generated brief.
- Add backend and frontend regression tests.
- Update ATDR governance and traceability docs.

Out of scope:

- External LLM enablement.
- Raw-log sharing by default.
- Response execution.
- Detection execution.
- Label/model/source/user/data mutation.
- Persisted notebook or incident-report records.
- Production promotion or model activation.

## T7 Functional Requirements

- Assistant must create alert, log, source, and computed case/group investigation briefs.
- Briefs must include summary, what happened, why flagged/not flagged, evidence, related context, safe next steps, limitations, and citations.
- Briefs must cite source references when available.
- Frontend must expose brief presets and contextual brief generation.
- Assistant must remain read-only and non-mutating.

## T8 Acceptance Criteria

- `Create investigation brief for alert 1` returns an alert brief.
- `Create investigation brief for log 1` returns a log brief.
- `Create investigation brief for source 1` returns a source brief.
- `Create investigation brief for case <id>` returns a computed case/group brief.
- `/assistant?alert=<id>`, `/assistant?log=<id>`, `/assistant?source=<id>`, or `/assistant?case=<id>` shows `Generate Brief`.
- `Copy brief` does not break layout or reveal raw logs.
- No response action, detection run, model run, label change, or data mutation is created.

## T9 API Contract

Existing endpoint remains:

```json
POST /api/assistant/chat
{
  "question": "Create investigation brief for alert 1.",
  "alert_id": 1,
  "log_id": null,
  "source_id": null,
  "case_id": null,
  "include_recent_context": true
}
```

Response keeps the existing assistant response shape and adds brief-oriented `details.answer_sections` when applicable.

## T10 Data Model / Migration

No schema or migration changes.

## T11 Backend Plan / Changes

- Add deterministic brief intent detection.
- Add source-id parsing for assistant questions.
- Reuse existing alert/log/source/case answer builders as source context.
- Compose safe brief sections from existing evidence and citations.
- Keep raw-line fields stripped and redacted.

## T12 Frontend Plan / Changes

- Add `Investigation Brief` preset group.
- Add contextual `Generate Brief` button when Assistant has alert/log/source/case context.
- Add `Copy brief` action for the current answer.
- Render new answer sections without raw JSON overflow.

## T13 Security / Response / AI Safety

- Assistant remains read-only.
- Response automation remains disabled.
- Real firewall blocking remains disabled.
- No model activation or promotion is added.
- No external LLM call is enabled.
- Raw log context remains disabled by default.
- Brief generation is not a response approval or incident-closing action.

## T14 Test Plan

- Backend tests for alert, log, source, and case brief generation.
- Backend tests for citations, no raw context, no external provider use, and no side effects.
- Frontend tests for brief presets, contextual brief generation, copy action, safety badges, and overflow safety.
- Existing release gates remain required.

## T15 Implementation Summary

v3.25 adds an investigation brief builder on top of the existing read-only SOC Assistant. It turns existing evidence-grounded context into a structured handoff while preserving all assistant and response safety boundaries.

## T16 Tests Run / Evidence

- `.\.venv\Scripts\ruff.exe check atdr\app\services\assistant_service.py atdr\tests\test_assistant.py`: pass.
- `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_assistant.py -q --basetemp .pytest_tmp\v325-assistant -p no:cacheprovider`: pass, `15 passed`.

Full verification evidence is recorded in the final v3.25 handoff.

## T17 PRD / Docs Updated

- `docs/V3_25_SOC_ASSISTANT_INVESTIGATION_BRIEF_BUILDER.md`
- `docs/changes/T1_T20_V3_25_SOC_ASSISTANT_INVESTIGATION_BRIEF_BUILDER.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18 Risks / Blockers / Assumptions / Decisions

- Briefs are deterministic summaries, not approved incident reports.
- Computed case/group briefs do not create persisted incidents.
- External LLM, raw-log context, and persistent notebook records remain future reviewed work.

## T19 Release / Rollback

Rollback is limited to reverting assistant brief routing, source-id parsing, Assistant page brief controls, docs, and tests. No database rollback is needed.

## T20 Final Handoff

Manual testers should open `/assistant`, use the `Investigation Brief` presets, open Assistant through alert/log/source/case deep links, click `Generate Brief`, and confirm the output is structured, cited, copyable, and read-only.

# T1-T20 Change Document: v3.9 Analyst Assistant Hardening

## T1. Change Title

v3.9 ATDR Analyst Assistant hardening and usability.

## T2. Requirement

Improve the v3.8 SOC Assistant so it is more useful for analysts while keeping it deterministic, read-only, locally safe by default, and unable to execute response, detection, model, label, source, user, or data mutation actions.

## T3. Source Evidence

| Evidence | Source |
| --- | --- |
| Assistant router | `atdr/app/routers/assistant.py` |
| Assistant service | `atdr/app/services/assistant_service.py` |
| Assistant schemas | `atdr/app/schemas/assistant.py` |
| Auth and role dependencies | `atdr/app/core/security.py` |
| Alerts, sources, jobs, ML, audit context | `atdr/app/routers/alerts.py`, `atdr/app/routers/sources.py`, `atdr/app/routers/jobs.py`, `atdr/app/routers/ml.py`, `atdr/app/routers/audit.py` |
| Data model truth | `atdr/app/db/models.py` |
| React assistant page and hooks | `frontend/src/pages/AssistantPage.tsx`, `frontend/src/lib/api.ts`, `frontend/src/hooks/useApiQueries.ts`, `frontend/src/types/api.ts` |
| Workflow and PRD docs | `docs/LAB_RUNBOOK.md`, `docs/prd/PRD-ATDR.md`, `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |

## T4. Current Behavior

v3.8 added authenticated status/chat endpoints and a React SOC Assistant page. It could answer common alert, source, operations, ML, and workflow questions with safe local deterministic responses. It already excluded raw logs by default, redacted IPs, audited questions, and did not create response actions.

## T5. Impacted Areas / Agents

Backend/API, Frontend Dashboard, Security/Response Safety, AI/ML Governance, QA/UAT, Documentation, and Release/Ops.

## T6. Scope

In scope:

- Add deterministic intents for latest/open alerts, warning sources, recent changes, failed jobs, model promotion explanation, safe alert next steps, reviewed-label import help, and safe scenario help.
- Add assistant history endpoint based on safe audit summaries.
- Add React prompt presets grouped by Alerts, Sources, Operations, AI Governance, and How-to.
- Add React assistant history panel.
- Improve citations for alerts, sources, jobs, ML reports, docs, and API routes.
- Add backend and frontend regression tests.
- Update PRD, traceability, compliance, task board, and v3.9 documentation.

Out of scope:

- External LLM provider calls.
- Raw-log context sharing.
- Response action execution.
- Detection or ingestion execution from chat.
- Label/model/source/user/data mutation from chat.
- ML activation or production promotion.
- Schema migrations.

## T7. Functional Requirements

- Authenticated admin/analyst users can ask the new supported questions.
- Unauthenticated assistant requests are rejected.
- `GET /api/assistant/history` returns recent assistant question summaries from audit logs.
- History responses must not expose secrets or raw logs.
- Assistant answers must identify context and citations where possible.
- Assistant use must not create response actions or mutate data.

## T8. Acceptance Criteria

- Assistant status and chat remain authenticated.
- External provider remains disabled by default.
- `external_provider_used=false` in local deterministic mode.
- `raw_log_context_included=false` by default.
- IP redaction still works.
- API key is not exposed.
- New intents return useful, safe answers.
- Assistant history is audit-backed and safe.
- Frontend presets submit questions.
- Frontend history renders without overflow.
- Safety badges remain visible.
- No response action controls appear in the assistant UI.

## T9. API Contract

Existing:

```text
GET /api/assistant/status
POST /api/assistant/chat
```

Added:

```text
GET /api/assistant/history?limit=20
```

History returns:

```json
[
  {
    "id": 1,
    "actor": "analyst",
    "question": "Summarize failed jobs.",
    "created_at": "2026-06-20T00:00:00",
    "context_used": ["operation_jobs", "failed_jobs"],
    "external_provider_used": false
  }
]
```

## T10. Data Model / Migration

No schema migration was added. Assistant history uses existing `audit_logs` rows with `action="assistant_question"`.

## T11. Backend Plan / Changes

- Extend `assistant_service.py` with new deterministic answer helpers.
- Add `list_assistant_history`.
- Add `AssistantHistoryItem`.
- Add `GET /api/assistant/history`.
- Add tests for new intents, history, and no response actions.

## T12. Frontend Plan / Changes

- Add assistant history API type, client method, and query hook.
- Add prompt preset groups.
- Add audit-backed history panel.
- Extend Playwright coverage for presets, history, long responses, and safety controls.

## T13. Security / Response / AI Safety

- No automatic response.
- No real firewall blocking.
- No model activation or promotion.
- No raw-log context by default.
- No external LLM calls by default.
- API secrets are not returned.
- Assistant history is audit-derived and safe.
- Assistant output remains decision support only.

## T14. Test Plan

- Backend assistant auth tests.
- Backend new-intent answer tests.
- Backend history safety test.
- Backend no-response-action regression.
- Frontend preset rendering and click test.
- Frontend history rendering test.
- Frontend overflow and no response-control test.
- Full release verification.

## T15. Implementation Summary

v3.9 hardens the assistant with broader deterministic question coverage, grouped prompt presets, safe audit-backed history, and improved citations. The assistant remains local and read-only by default.

## T16. Tests Run / Evidence

Final verification evidence is recorded in `docs/tasks/tasklist-progress.md`.

## T17. PRD / Docs Updated

Updated or added:

- `docs/V3_9_ASSISTANT_HARDENING.md`
- `docs/changes/T1_T20_V3_9_ASSISTANT_HARDENING.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18. Risks / Blockers / Assumptions / Decisions

- Decision: keep deterministic local assistant behavior as the default.
- Decision: do not enable external providers or raw-log context.
- Decision: use existing audit logs for assistant history instead of adding a new table.
- Risk: deterministic answers are useful but limited.
- Risk: external LLM integration requires a future privacy/security review.

## T19. Release / Rollback

Rollback:

- Remove `/api/assistant/history` route.
- Revert frontend prompt presets and history panel.
- Revert new helper branches in `assistant_service.py`.
- Existing audit rows can remain because they are normal audit records.

No destructive migration is introduced.

## T20. Final Handoff

ATDR v3.9 improves the SOC Assistant for day-to-day analyst questions while preserving the v3.8 safety model. It is not an automation agent and cannot execute response actions or mutate system state.

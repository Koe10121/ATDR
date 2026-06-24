# T1-T20 Change Document: v3.8 Analyst Assistant MVP

## T1. Change Title

v3.8 Safe Read-Only ATDR Analyst Assistant MVP.

## T2. Requirement

Add a chatbot-style SOC assistant that helps analysts understand alerts, source health, operations, ML governance, and lab workflow while remaining read-only and safe by default.

## T3. Source Evidence

| Evidence | Source |
| --- | --- |
| FastAPI router mounting | `atdr/app/main.py` |
| Auth and role dependencies | `atdr/app/core/security.py` |
| Alert APIs and services | `atdr/app/routers/alerts.py`, `atdr/app/services/alert_service.py` |
| Source APIs and services | `atdr/app/routers/sources.py`, `atdr/app/services/source_service.py` |
| ML Governance APIs and services | `atdr/app/routers/ml.py`, `atdr/app/services/ml_service.py`, `atdr/app/detection/supervised_detector.py` |
| Operation job APIs and services | `atdr/app/routers/jobs.py`, `atdr/app/services/job_service.py` |
| Audit model/API | `atdr/app/db/models.py`, `atdr/app/routers/audit.py` |
| React routes and API client | `frontend/src/App.tsx`, `frontend/src/lib/api.ts`, `frontend/src/hooks/useApiQueries.ts` |
| Lab and PRD docs | `docs/LAB_RUNBOOK.md`, `docs/prd/PRD-ATDR.md`, `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |

## T4. Current Behavior

Before v3.8, analysts could inspect alerts, sources, jobs, ML Governance, and docs separately. There was no single read-only assistant surface to summarize this context.

## T5. Impacted Areas / Agents

Backend/API, Frontend Dashboard, AI/ML Governance, Security/Response Safety, QA/UAT, Documentation, and Release/Ops.

## T6. Scope

In scope:

- Disabled-by-default assistant configuration placeholders.
- Read-only assistant status and chat endpoints.
- Deterministic fallback answers when no external LLM is configured.
- Limited context builder for alerts, sources, operations, ML governance, and workflow help.
- IP redaction and raw-log exclusion by default.
- Audit logging for assistant questions.
- React SOC Assistant page.
- Backend and Playwright safety tests.
- Docs, PRD, traceability, compliance, and task-board updates.

Out of scope:

- External LLM provider implementation.
- OAuth/OIDC callback login flow.
- Raw log sharing.
- Response action execution.
- Detection runs, label changes, model activation, or ML promotion through chat.

## T7. Functional Requirements

- `GET /api/assistant/status` returns non-secret assistant safety/config status.
- `POST /api/assistant/chat` answers authenticated analyst/admin questions.
- Assistant must not expose API keys.
- Assistant must not include raw logs unless explicitly enabled in future reviewed work.
- Assistant must redact IPs when configured.
- Assistant must create audit records for questions.
- Assistant must not create response actions.

## T8. Acceptance Criteria

- Unauthenticated requests are rejected.
- Admin and analyst users can ask read-only questions.
- External provider is disabled by default.
- API key is never returned.
- Raw log context is disabled by default.
- IP redaction works.
- Assistant questions are audited.
- Response actions are not created by assistant use.
- Frontend page renders with safety badges and no response controls.
- Long assistant responses/details do not overflow.

## T9. API Contract

Added:

```text
GET /api/assistant/status
POST /api/assistant/chat
```

Status returns mode, provider configuration state, redaction state, raw-log context state, context-row limit, and safety labels. Chat returns answer, mode, safety labels, context used, citations, redaction flags, suggested follow-ups, and technical details.

## T10. Data Model / Migration

No schema migration was added. Assistant activity uses the existing `audit_logs` table.

## T11. Backend Plan / Changes

- Add assistant settings to `atdr/app/core/config.py`.
- Add request/response schemas in `atdr/app/schemas/assistant.py`.
- Add deterministic assistant service in `atdr/app/services/assistant_service.py`.
- Add authenticated router in `atdr/app/routers/assistant.py`.
- Mount router in `atdr/app/main.py`.
- Add backend tests in `atdr/tests/test_assistant.py`.

## T12. Frontend Plan / Changes

- Add assistant TypeScript types and API methods.
- Add React query hooks for status and chat.
- Add `SOC Assistant` route/page.
- Add navigation entry.
- Add Playwright coverage for page rendering, safety badges, long details, and absence of response controls.

## T13. Security / Response / AI Safety

- No automatic response added.
- No real firewall blocking added.
- No response action controls exposed in assistant.
- No model activation or promotion added.
- External LLM disabled by default.
- API secrets are not returned.
- Raw log context is disabled by default.
- IP redaction is enabled by default.

## T14. Test Plan

- Backend auth-required test.
- Backend assistant status secret-safety test.
- Backend redaction and audit test.
- Backend no response-action test.
- Backend analyst/admin read-only access test.
- Frontend assistant render and safety-badge test.
- Frontend no response-control test.
- Full release verification.

## T15. Implementation Summary

v3.8 adds a safe assistant MVP as a read-only analyst guidance layer over existing ATDR context. It is deterministic by default and does not call external providers unless future reviewed configuration enables one.

## T16. Tests Run / Evidence

Final verification evidence should be recorded in `docs/tasks/tasklist-progress.md` after gate execution.

## T17. PRD / Docs Updated

Updated or added:

- `docs/V3_8_ANALYST_ASSISTANT_MVP.md`
- `docs/LAB_RUNBOOK.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18. Risks / Blockers / Assumptions / Decisions

- Decision: keep deterministic local fallback first.
- Decision: no external provider integration until privacy/security details are known.
- Decision: no raw-log context by default.
- Risk: assistant answers can be incomplete and must remain analyst decision support.
- Risk: external LLM use requires data-handling approval and `.env` secret management.

## T19. Release / Rollback

Rollback:

- Remove assistant router mount and files.
- Remove frontend route/nav/page.
- Remove assistant config placeholders.
- Keep audit log records already created; they are normal audit entries.

No destructive data migration is introduced.

## T20. Final Handoff

ATDR now includes a safe read-only SOC assistant MVP. It helps analysts interpret existing ATDR context and workflow, but it cannot execute response actions, activate models, or send raw logs to external systems by default.

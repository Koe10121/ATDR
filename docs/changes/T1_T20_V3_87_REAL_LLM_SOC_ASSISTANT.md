# T1-T20 Change Document: v3.87 Real LLM SOC Assistant Integration And Reliability

## T1 Change Title

- Title: v3.87 Real LLM SOC Assistant Integration And Reliability
- Date: 2026-07-12
- Owner / acting agent: Codex
- Related version or sprint: v3.87

## T2 Requirement

- User request: Finish a real API-backed AI assistant that remains safe, evidence-grounded, conversational, and read-only.
- Business goal: Give analysts professional LLM-assisted investigation summaries without transferring control of ATDR actions or evidence retrieval to the provider.
- Success outcome: A configured provider can produce validated structured answers through the dashboard and full service path with no mutation side effects.
- Non-goals: No autonomous response, detection execution, labeling, model activation, account administration, data deletion, raw-log sharing, or production claim.

## T3 Source Evidence

| Source | Path | Evidence / Finding |
| --- | --- | --- |
| Backend configuration | `atdr/app/core/config.py` | Existing provider adapter was opt-in; bounded retries, prompt size, history, and rate limits were needed. |
| Provider adapter | `atdr/app/services/assistant_llm.py` | Existing provider path needed strict structured output, retry telemetry, and provider-specific reliability handling. |
| Assistant orchestration | `atdr/app/services/assistant_service.py` | Deterministic retrieval existed; server-owned conversation context and safe structured provider context were needed. |
| API | `atdr/app/routers/assistant.py`, `atdr/app/schemas/assistant.py` | Authenticated chat/status/history endpoints already existed and were extended compatibly. |
| Dashboard | `frontend/src/pages/AssistantPage.tsx`, `frontend/src/types/api.ts` | Context and provider state needed to reflect backend-authoritative conversation data. |
| Tests/probes | `atdr/tests/test_assistant.py`, `atdr/scripts/test_assistant_llm_provider.py`, `atdr/scripts/test_assistant_chat_provider.py` | Existing safety probes provided the base for real-provider, structured-output, and zero-side-effect validation. |

## T4 Current Behavior

- Backend: Retrieves bounded safe evidence, maintains actor-scoped conversation context, validates structured provider output, retries transient failures, and falls back deterministically.
- Frontend: Shows authoritative active context, citations, safety badges, provider status, loading/error states, and a clear-context control.
- Data model: No migration. Existing audit rows hold bounded, non-secret assistant metadata.
- AI/ML: External LLM improves wording and synthesis only; ATDR detection and supervised models are unchanged.
- Response/audit: Assistant questions are audited; action execution remains impossible.
- Limitation: Provider mode requires explicit private configuration and external availability.

## T5 Impacted Areas / Agents

| Area / Agent | Impacted? | Reason |
| --- | --- | --- |
| Orchestrator | yes | Cross-layer assistant completion and verification. |
| Product Owner / Requirement Planner | yes | Defines read-only assistant outcome and non-goals. |
| Data Model / Database | no | No schema change. |
| Backend / API | yes | Provider, context, privacy, reliability, and response contracts. |
| Frontend / Dashboard | yes | Conversation context and provider visibility. |
| AI/ML Governance | yes | External generative model remains decision support only. |
| Security / Response Safety | yes | Redaction, secret filtering, prompt-injection defense, and no actions. |
| QA/UAT | yes | Backend, provider, frontend, and side-effect regression checks. |
| Release/Ops / Lab Validation | yes | Private-provider probes and release gate. |

## T6 Scope

In scope: Gemini/OpenAI-compatible/Claude adapter reliability, structured answers, bounded context/history, citations, redaction, rate limiting, safe audit telemetry, deterministic fallback, dashboard context UX, tests, and docs.

Out of scope: Autonomous actions, raw-log provider context, full transcript persistence, model promotion, firewall enforcement, and production certification.

## T7 Functional Requirements

| ID | Requirement | Priority | Source |
| --- | --- | --- | --- |
| FR-V387-001 | Provider mode must remain explicit and secret-safe. | Must | User requirement |
| FR-V387-002 | Answers must use bounded ATDR evidence and validated citations. | Must | User requirement |
| FR-V387-003 | Follow-ups must preserve actor-scoped structured context without stale-ID lock-in. | Must | Observed assistant defect history |
| FR-V387-004 | Provider failure or malformed output must fall back safely. | Must | Reliability requirement |
| FR-V387-005 | Assistant operations must produce zero detection/label/model/response side effects. | Must | ATDR safety policy |

## T8 Acceptance Criteria

| ID | Acceptance Criteria | Verification |
| --- | --- | --- |
| AC-001 | Real provider returns valid structured output through the full service probe. | `test_assistant_chat_provider --execute --pretty` |
| AC-002 | Raw logs and secrets are absent and IP redaction remains enabled. | Provider probes and backend tests |
| AC-003 | Follow-up context is actor-scoped and explicit/global prompts clear stale context. | `atdr/tests/test_assistant.py` |
| AC-004 | UI displays current context, provider/fallback status, citations, and no action controls. | React build and Playwright |
| AC-005 | Response, detection, label, and model counts remain unchanged. | Full assistant probe and tests |

## T9 API Contract

- Changed request fields: optional `conversation_id`, `reset_context`.
- Changed response fields: `conversation_id`, `active_context`, expanded safe LLM telemetry.
- Existing endpoints remain: `GET /api/assistant/status`, `POST /api/assistant/chat`, `GET /api/assistant/history`.
- Auth/RBAC: Admin and analyst authentication remains required; history remains actor-scoped for analysts.
- Backward compatibility: New request fields are optional and existing deterministic behavior remains available.

## T10 Data Model / Migration

- Schema changes: none.
- Alembic migration: none.
- Existing data compatibility: preserved.
- Rollback: revert service/schema/frontend changes; no data migration rollback required.

## T11 Backend Plan / Changes

- Add strict structured prompt/response validation and safe citation filtering.
- Add provider timeout/retry/usage/latency telemetry without secrets.
- Add actor-scoped bounded conversation state derived from existing audit metadata.
- Add safe context sanitization, rate limiting, prompt-injection refusal, and deterministic fallback.
- Extend provider probes and backend regression tests.

## T12 Frontend Plan / Changes

- Use backend-authoritative active context.
- Add clear-context behavior and avoid stale URL/entity context.
- Show provider validation/fallback telemetry and safe citations.
- Preserve responsive, overflow-safe, read-only presentation.

## T13 Security / Response / AI Safety

- Response simulation remains enabled: yes.
- Automatic response remains disabled: yes.
- Real firewall enforcement added: no.
- Audit impact: safe metadata only; no prompt, key, token, raw log, or secret values.
- AI status: decision support only.
- Data privacy: bounded structured context; raw logs disabled; IP redaction on by default.
- Security decision: pass with deployment risks for provider privacy, quota, and availability.

## T14 Test Plan

- Ruff and compileall.
- Full backend tests and Alembic drift check.
- React lint/build and Playwright.
- Provider status, minimal execute, and full synthetic chat execute probes.
- Replay dry-run, performance smoke, and release gate.

## T15 Implementation Summary

| File | Change Summary |
| --- | --- |
| `atdr/app/core/config.py` | Added bounded retry, prompt, history, and rate-limit settings. |
| `atdr/app/services/assistant_llm.py` | Added structured contract, validation, retries, telemetry, and Gemini 2.5 reliability fix. |
| `atdr/app/services/assistant_service.py` | Added safe context, actor-scoped conversation state, rate limiting, audit metadata, and provider integration. |
| `atdr/app/routers/assistant.py`, `atdr/app/schemas/assistant.py` | Extended authenticated API contracts and clean 429 handling. |
| `frontend/src/pages/AssistantPage.tsx`, `frontend/src/types/api.ts` | Added authoritative conversation context and provider/fallback visibility. |
| `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` | Added conversation, safety, reliability, provider, and UI regressions. |

## T16 Tests Run / Evidence

| Command / Check | Result | Evidence |
| --- | --- | --- |
| Tasklist render/standard check | pass | HTML regenerated; standard checker returned `ok: true`. |
| Ruff / compileall | pass | Repository lint and Python compilation passed. |
| Backend tests | pass | `471 passed, 1 skipped`; focused assistant suite `42 passed`. |
| Alembic check | pass | No new upgrade operations detected. |
| React lint/build | pass | ESLint, TypeScript, and Vite production build passed. |
| Playwright | pass | `19 passed, 1 skipped`. |
| Real provider probes | pass | Minimal and full Gemini probes returned valid structured output; no raw logs/secrets and zero mutation side effects. |
| Replay dry-run | pass | Parsed safe sample and wrote no rows. |
| Performance smoke | pass | No warnings; Overview `0.4715s`, cached `0.0073s`, ML Governance `1.314s`. |
| Release gate | pass | `ok: true`; all required checks passed. |

## T17 PRD / Docs Updated

- `docs/V3_87_REAL_LLM_SOC_ASSISTANT.md`
- `docs/security/ATDR_REAL_LLM_ASSISTANT_PLAN.md`
- `docs/LAB_RUNBOOK.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/tasks/tasklist-progress.md` and generated HTML

## T18 Risks / Blockers / Assumptions / Decisions

- Risk: External provider latency, quota, outages, and data-sharing policy remain operational concerns.
- Blocker: None for private local Gemini validation; organizational deployment approval remains separate.
- Assumption: Provider keys remain in ignored private `.env` only.
- Decision: ATDR owns evidence retrieval and safety; the LLM only structures and explains supplied safe context.

## T19 Release / Rollback

- Release impact: Optional real-provider assistant improvements; deterministic mode remains available.
- Local workflow impact: No startup command changes.
- Rollback: Disable `ASSISTANT_LLM_ENABLED` immediately or revert code; no database rollback.
- Monitoring: Provider-used/fallback telemetry, latency, attempts, audit events, rate-limit responses, and answer feedback.

## T20 Final Handoff

- Status: completed.
- Behavior changed: Real provider can produce validated structured SOC answers with bounded conversation context and deterministic fallback.
- Verification result: All required backend, frontend, provider, performance, migration, and release checks passed.
- Remaining risks: Provider privacy/approval, quota, availability, bounded-memory limitations, and analyst validation.
- Exact manual check: Open `/assistant`, ask about a valid alert, ask a follow-up about related logs, verify context/citations, then clear context and ask for the latest critical alert.

# T1-T20: v4.2 Presentation-Ready SOC Assistant

## T1 Change Title

v4.2 Presentation-Ready SOC Assistant, Persistent Investigation Context, and MFU UI Alignment.

## T2 Requirement

Make assistant answers concise and evidence-grounded, preserve safe investigation context across route navigation, report Gemini use truthfully, and align the React dashboard with the supervisor shell's MFU visual language.

## T3 Source Evidence

- `atdr/app/services/assistant_service.py`
- `atdr/app/services/assistant_llm.py`
- `atdr/app/routers/assistant.py`
- `atdr/app/schemas/assistant.py`
- `frontend/src/App.tsx`
- `frontend/src/pages/AssistantPage.tsx`
- `frontend/src/components/AppShell.tsx`
- `frontend/src/hooks/useAuth.tsx`
- official supervisor shell SCSS and layout files under the external `frontend-vue/src` tree

## T4 Current Behavior

Assistant evidence and citations existed, but provider provenance was visually dense. Route changes unmounted the Assistant page and discarded page-local mutation data. Long answer sections, telemetry, presets, history, and feedback competed for attention.

## T5 Impacted Areas / Agents

Backend assistant safety and provenance, React assistant state and rendering, shared dashboard theme, QA, governance documentation, and release verification.

## T6 Scope

In scope: safe grounding metadata, concise provider contract, session-scoped assistant snapshot, logout/context clearing, truthful provider labels, compact answer hierarchy, MFU color/token alignment, tests, and docs.

Out of scope: database migration, server-side chat archive, detection/model changes, model activation/promotion, automatic response, firewall control, IAM changes, startup changes, or provider secret management.

## T7 Functional Requirements

- Show actual ATDR citation sources for every answer.
- Treat Gemini as explanation/summarization only.
- Preserve safe question, answer, citations, context, and follow-ups across navigation without another provider call.
- Never persist raw logs, secrets, tokens, or arbitrary technical payloads.
- Keep follow-ups bound to the active evidence ID.
- Clear state on Clear Context, logout, and session expiry.
- Keep the default answer compact and move detail behind disclosure controls.
- Use MFU burgundy/gold tokens while retaining React and ATDR navigation.

## T8 Acceptance Criteria

- Alert context survives Assistant -> Alerts -> Assistant.
- Navigation does not resend the question.
- Explicit alert IDs do not revert to Alert #1.
- Malformed storage cannot crash the page.
- Gemini Assisted appears only on a successful provider-backed answer.
- Grounded In shows returned citations; missing evidence is stated.
- Raw-log context and action controls remain absent.
- Main routes have no horizontal overflow in Playwright regression coverage.

## T9 API Contract

Existing endpoints remain unchanged. `POST /api/assistant/chat` retains its schema and adds a non-secret `details.grounding` object containing policy, evidence availability, source count/types, provider role, and `raw_logs_included=false`.

## T10 Data Model / Migration

No SQLAlchemy or Alembic change. Persistence uses a versioned browser `sessionStorage` snapshot and is cleared at session boundaries.

## T11 Backend Plan / Changes

- Add centralized grounding metadata derived only from returned citations.
- Tighten Gemini structured output limits and anti-repetition rules.
- Preserve fallback, redaction, citation allowlisting, and no-action guards.

## T12 Frontend Plan / Changes

- Add a strict session snapshot serializer/parser.
- Restore assistant context without replaying the request.
- Clear state on context reset/logout/session expiry.
- Render concise sections and compact Grounded In references.
- Collapse secondary playbooks and QA panels.
- Apply MFU visual tokens to the shared shell and controls.

## T13 Security / Response / AI Safety

The snapshot rejects responses containing raw-log context and whitelists safe fields. API keys, tokens, arbitrary details, raw logs, and paths are not persisted. Gemini receives bounded redacted evidence only. No response, detection, label, model, account, deletion, or firewall action is exposed.

## T14 Test Plan

- Backend grounding/provenance assertions.
- Provider secret hiding, redaction, raw-context, fallback, and no-side-effect regression.
- Frontend state persistence and no-resend check.
- Correct alert follow-up binding.
- Clear Context, logout, and malformed-storage behavior.
- Truthful Gemini label behavior.
- Concise rendering, disclosure controls, citation links, overflow, navigation, and no-action checks.

## T15 Implementation Summary

Added `assistantSession.ts`; updated assistant service/LLM contract; simplified the Assistant page; added truthful provider labeling; updated the shared MFU theme and shell; and expanded backend/Playwright regressions.

## T16 Tests Run / Evidence

Gemini safe status and one bounded provider probe passed with structured output, redaction enabled, raw logs excluded, and no secret exposure. A live authenticated assistant request used Gemini, returned ten ATDR citations, and left response actions `0 -> 0`, detection runs `31 -> 31`, labels `2672 -> 2672`, and model runs `41 -> 41` on the disposable copy. Focused assistant backend tests passed `42 passed`; focused SOC Assistant Playwright passed `6 passed`. Ruff, compileall, full backend `568 passed, 1 skipped`, disposable Alembic no-drift, React lint/build, full Playwright `23 passed, 1 skipped`, replay dry-run, warning-free read-only performance smoke, and release gate `ok: true` all passed. The configured database was not written or migrated; the inherited v3.97 additive migration remains an explicit operator step before current-model dashboard queries.

## T17 PRD / Docs Updated

- `docs/V4_2_PRESENTATION_READY_SOC_ASSISTANT.md`
- this T1-T20 record
- `docs/LAB_RUNBOOK.md`
- `docs/prd/PRD-ATDR.md`
- traceability, compliance, docs index, state lock, and task board

## T18 Risks / Blockers / Assumptions / Decisions

Provider quota/network failure can still occur, so deterministic fallback remains mandatory. Browser persistence is intentionally session-only. The provider is not trusted as a database source; only ATDR citations are authoritative.

## T19 Release / Rollback

No migration or startup change. Rollback removes the v4.2 frontend/session/provenance changes and restores the previous prompt contract. No configured database or active model rollback is needed.

## T20 Final Handoff

Use the manual checklist in `docs/V4_2_PRESENTATION_READY_SOC_ASSISTANT.md`. Present Gemini as an optional explanation layer over bounded ATDR evidence, not as the detector or autonomous responder.

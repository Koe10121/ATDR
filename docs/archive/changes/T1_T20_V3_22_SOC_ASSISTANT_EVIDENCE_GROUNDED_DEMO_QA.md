# T1-T20 Change Document: v3.22 SOC Assistant Evidence-Grounded Demo QA

## T1 Change Title

- Title: v3.22 SOC Assistant Evidence-Grounded Demo QA
- Date: 2026-06-21
- Owner / acting agent: Codex
- Related version or sprint: v3.22

## T2 Requirement

- User request: Make the ATDR chatbot more trustworthy and demo-ready by grounding every answer in system evidence.
- Business / lab goal: Let an advisor see that assistant answers are tied to ATDR alerts, sources, jobs, ML status, docs, and safety constraints.
- Success outcome: Assistant answers show summary, evidence, safe next steps, safety limitation, and citations while refusing unsafe commands.
- Explicit non-goals:
  - No external LLM calls by default.
  - No raw log context by default.
  - No response execution.
  - No detection execution.
  - No label mutation, model activation, model promotion, data deletion, real SMTP, or real firewall blocking.

## T3 Source Evidence

| Source | Path | Evidence / Finding |
| --- | --- | --- |
| Assistant service | `atdr/app/services/assistant_service.py` | Deterministic answer routing, citations, redaction, audit logging, no-side-effect safety. |
| Assistant router/schema | `atdr/app/routers/assistant.py`, `atdr/app/schemas/assistant.py` | Authenticated status/chat/history contracts. |
| Assistant page | `frontend/src/pages/AssistantPage.tsx` | Safety badges, prompt presets, citations, history, response panel. |
| Alert page | `frontend/src/pages/AlertsTriage.tsx` | Alert-detail Ask Assistant handoff. |
| Tests | `atdr/tests/test_assistant.py`, `frontend/tests/smoke.spec.ts` | Backend and frontend assistant regression coverage. |
| Prior docs | `docs/V3_21_SOC_ASSISTANT_DEMO_QUALITY.md` | Previous demo-quality assistant checkpoint. |

## T4 Current Behavior

- Backend assistant already answers alert, source, job, ML, and workflow questions.
- Frontend assistant already shows safety badges, presets, history, citations, and technical context.
- v3.21 already refuses unsafe command-like requests.
- Missing polish: answer sections were not rendered as first-class UI sections and suggested follow-up buttons only filled the input.

## T5 Impacted Areas / Agents

| Area / Agent | Impacted? | Reason |
| --- | --- | --- |
| Backend / API | yes | Add guaranteed structured answer sections. |
| Frontend / Dashboard | yes | Render evidence sections and make follow-ups actionable. |
| Security / Response Safety | yes | Preserve and test refusal/no-side-effect behavior. |
| AI/ML Governance | yes | Assistant explains ML status without changing it. |
| QA/UAT | yes | Add tests for sections, citations, follow-ups, and no side effects. |
| Data Model / Database | no | No schema change. |

## T6 Scope

### In Scope

- Structured assistant answer sections.
- Richer alert-specific evidence sections.
- Citation display polish.
- Suggested follow-up buttons that ask read-only questions.
- Demo question set documentation.
- Tests and governance docs.

### Out Of Scope

- External LLM integration.
- Raw-log context sharing.
- Real response, automation, SMTP, OIDC, model activation, or schema changes.

## T7 Functional Requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-V322-001 | Assistant responses expose structured sections for summary, evidence, next steps, safety, and citations. | Must |
| FR-V322-002 | Alert explanations include alert evidence, source context, related logs, ATT&CK mapping, and safe next steps. | Must |
| FR-V322-003 | Follow-up buttons remain read-only and ask the assistant directly. | Must |
| FR-V322-004 | Unsafe requests still refuse with no response/model/detection side effects. | Must |

## T8 Acceptance Criteria

| ID | Acceptance Criteria | Verification |
| --- | --- | --- |
| AC-001 | Alert answer includes `details.answer_sections` and citations. | `atdr/tests/test_assistant.py` |
| AC-002 | Generic assistant answers include default evidence-grounded sections. | `atdr/tests/test_assistant.py` |
| AC-003 | Unsafe requests are refused and create no side effects. | `atdr/tests/test_assistant.py` |
| AC-004 | Assistant UI renders answer sections, citations, and follow-up buttons without overflow. | `frontend/tests/smoke.spec.ts` |

## T9 API Contract

- New endpoints: none.
- Changed endpoint shape: `POST /api/assistant/chat` remains backward compatible and adds structured section data inside `details.answer_sections`.
- Auth/RBAC: unchanged; analyst/admin required.

## T10 Data Model / Migration

- Schema changes: none.
- Alembic migration: none.

## T11 Backend Plan / Changes

- Add `details.answer_sections` fallback for all assistant answers.
- Add richer alert-specific answer sections.
- Keep existing citations and audit behavior.
- Preserve redaction and raw-log exclusion.

## T12 Frontend Plan / Changes

- Render answer sections in the SOC Assistant page.
- Keep narrative answer available behind a detail panel.
- Render citations as compact badges/rows.
- Make suggested follow-ups ask the assistant directly.

## T13 Security / Response / AI Safety

- Assistant remains read-only.
- External LLM remains disabled by default.
- Raw log context remains disabled by default.
- No response action controls are exposed in Assistant.
- No action side effects are created by assistant requests.

## T14 Test Plan

- Backend assistant tests for citations, answer sections, follow-ups, unsafe refusals, and no side effects.
- Frontend smoke tests for visible answer sections, citations, suggested follow-up behavior, badges, and overflow.
- Full release verification.

## T15 Implementation Summary

- `atdr/app/services/assistant_service.py`: added structured answer-section helper and alert-specific section payload.
- `frontend/src/pages/AssistantPage.tsx`: added section rendering and follow-up execution.
- `atdr/tests/test_assistant.py`: added answer-section and follow-up safety assertions.
- `frontend/tests/smoke.spec.ts`: added section/citation/follow-up UI assertions.
- Added v3.22 docs and governance references.

## T16 Tests Run / Evidence

| Command / Check | Result | Evidence |
| --- | --- | --- |
| Targeted Ruff | pass | `.\.venv\Scripts\ruff.exe check atdr\app\services\assistant_service.py atdr\tests\test_assistant.py` passed. |
| Targeted assistant tests | pass | `8 passed` for `atdr/tests/test_assistant.py`. |
| Frontend lint | pass | `npm.cmd run lint` passed before full verification. |
| `node scripts/render-tasklist-progress-html.js .` | pass | Regenerated the ATDR tasklist progress board. |
| `node scripts/check-tasklist-progress-standard.js .` | pass | Tasklist/progress-board standard check passed. |
| `.\.venv\Scripts\ruff.exe check .` | pass | Ruff reported all checks passed. |
| `.\.venv\Scripts\python.exe -m compileall -q atdr migrations` | pass | Backend and migration compile check passed. |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests -q --basetemp .pytest_tmp\v322-full -p no:cacheprovider` | pass | `305 passed, 1 skipped`; warnings are existing sklearn/joblib warnings. |
| `.\.venv\Scripts\alembic.exe check` | pass | No new upgrade operations detected. |
| `cd frontend; npm.cmd run lint; npm.cmd run build; npm.cmd run test:e2e` | pass | Frontend lint/build passed; Playwright `14 passed, 1 skipped`. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty` | pass | Safe sample dry-run parsed 2 rows and wrote no DB rows. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty` | pass | `ok: true`; Overview `0.4216s`, cached Overview `0.0063s`, ML Governance `1.241s`, alert list `0.0371s`, case summary `0.0402s`, no warnings. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` | pass | Release gate returned `ok: true`; backend tests `305 passed, 1 skipped`; Alembic check passed. |

## T17 PRD / Docs Updated

| Document | Updated? |
| --- | --- |
| `docs/V3_22_SOC_ASSISTANT_EVIDENCE_GROUNDED_DEMO_QA.md` | yes |
| `docs/V3_22_ASSISTANT_DEMO_QUESTION_SET.md` | yes |
| `docs/prd/PRD-ATDR.md` | yes |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | yes |
| `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md` | yes |
| `docs/tasks/tasklist-progress.md` | yes |
| `docs/AI-DOCS-INDEX.md` | yes |

## T18 Risks / Blockers / Assumptions / Decisions

- Risk: deterministic assistant wording may still need advisor-specific phrasing polish.
- Risk: external LLM integration remains future reviewed work.
- Decision: preserve current API compatibility and store structured sections under `details`.
- Decision: do not implement action execution, raw-log sharing, or external provider calls.

## T19 Release / Rollback

- Release: safe because no schema/startup/detection/ML/response behavior changes.
- Rollback: revert assistant service/page/test/docs changes.

## T20 Final Handoff

- Status: completed.
- Behavior changed: assistant answers are more evidence-grounded and UI follow-ups ask read-only questions.
- Safety changed: no new privileged capability added.
- Verification result: passed; release gate returned `ok: true`.

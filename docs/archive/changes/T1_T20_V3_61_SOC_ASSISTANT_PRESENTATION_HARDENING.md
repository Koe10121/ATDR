# T1-T20 v3.61 SOC Assistant Presentation Hardening

## T1 Change Title

v3.61 SOC Assistant Presentation Hardening

## T2 Requirement

Make the read-only SOC Assistant easier and safer to demonstrate as a professional analyst tool by adding SOC playbook presets, clearer fallbacks, stronger guardrails, and source-backed answer behavior.

## T3 Source Evidence

- `atdr/app/services/assistant_service.py`
- `atdr/app/routers/assistant.py`
- `atdr/app/schemas/assistant.py`
- `frontend/src/pages/AssistantPage.tsx`
- `atdr/tests/test_assistant.py`
- `frontend/tests/smoke.spec.ts`
- `docs/WEEKLY_PROGRESS_PRESENTATION_HANDOFF.md`
- `docs/V3_60_SUPERVISED_POLICY_DASHBOARD_ASSISTANT_ALIGNMENT.md`

## T4 Current Behavior

The assistant already supports alert/source/job/ML/how-to questions, citations, feedback, and investigation briefs. The analyst walkthrough flow still needed a compact playbook preset group and more graceful fallback answers when local scenario data is missing.

## T5 Impacted Areas / Agents

SOC Assistant, Frontend/Dashboard, Backend service logic, QA, Docs.

## T6 Scope

Presentation and answer-quality hardening only. No model retraining, model activation, label mutation, detection threshold change, response execution, schema change, or external LLM enablement.

## T7 Functional Requirements

- Add SOC Playbook assistant presets.
- Answer response-safety questions directly.
- Refuse raw-log exposure and account mutation requests.
- Give clear fallback steps when alerts or sources are missing.
- Keep citations and structured answer sections.
- Preserve read-only behavior and audit logging.

## T8 Acceptance Criteria

- Preset buttons are visible in the SOC Assistant page.
- Analyst walkthrough questions return useful deterministic answers.
- Missing alerts/sources do not produce confusing answers.
- Unsafe requests are refused.
- No response actions, detection runs, model runs, label changes, or account changes are created.

## T9 API Contract

No new endpoint. Existing endpoint remains:

- `POST /api/assistant/chat`

Existing response fields continue to include answer text, citations, context used, safety metadata, and details.

## T10 Data Model / Migration

No schema change.

## T11 Backend Plan / Changes

Update assistant service intent handling, response-safety answer, unsafe phrase detection, alert fallback, and source fallback.

## T12 Frontend Plan / Changes

Add a SOC Playbook preset group to the existing SOC Assistant page. Preserve existing layout, safety badges, feedback controls, and technical detail behavior.

## T13 Security / Response / AI Safety

Assistant remains read-only. External LLM, raw-log context, response execution, detection execution, label/model mutation, user/account mutation, email sending, automatic response, and real firewall blocking remain disabled/out of scope.

## T14 Test Plan

- Backend targeted tests for presentation questions and fallbacks.
- Playwright smoke coverage for presentation presets.
- Standard release verification.

## T15 Implementation Summary

Implemented in `atdr/app/services/assistant_service.py`, `frontend/src/pages/AssistantPage.tsx`, `atdr/tests/test_assistant.py`, and `frontend/tests/smoke.spec.ts`.

## T16 Tests Run / Evidence

- `node scripts/render-tasklist-progress-html.js .` passed.
- `node scripts/check-tasklist-progress-standard.js .` passed.
- `.\.venv\Scripts\ruff.exe check .` passed.
- `.\.venv\Scripts\python.exe -m compileall -q atdr migrations` passed.
- `.\.venv\Scripts\python.exe -m pytest atdr\tests -q --basetemp .pytest_tmp\v361-full -p no:cacheprovider` passed with `417 passed, 1 skipped`.
- `.\.venv\Scripts\alembic.exe check` passed.
- `cd frontend; npm.cmd run lint; npm.cmd run build; npm.cmd run test:e2e` passed with Playwright `14 passed, 1 skipped`.
- `.\.venv\Scripts\python.exe -m atdr.scripts.evaluate_assistant_qa --pretty` passed with `ok: true` and 20 controlled assistant questions.
- `.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty` passed and wrote no DB rows.
- `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty` passed with no warnings.
- `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` passed with `ok: true`.

## T17 PRD / Docs Updated

Updated v3.61 status doc, weekly presentation handoff, docs index, traceability, and task progress board.

## T18 Risks / Blockers / Assumptions / Decisions

The assistant is still deterministic/local. It is intentionally not an autonomous SOC agent and does not call an external LLM by default. If demo data is absent, it suggests safe scenario setup rather than inventing alerts.

## T19 Release / Rollback

Rollback is limited to removing the new preset group and assistant fallback/guardrail additions. No migration or data rollback is required.

## T20 Final Handoff

Use the SOC Assistant page for analyst walkthroughs. Start with the SOC Playbook preset group and emphasize that answers are cited, read-only, decision-support guidance only.
